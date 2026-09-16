//! Time attestations: the leaves of a timestamp proof tree.
//!
//! Mirrors `opentimestamps.core.notary`.

use crate::ots::serialize::{DeserializeError, Reader, Result, Writer};

pub const PENDING_TAG: [u8; 8] = [0x83, 0xdf, 0xe3, 0x0d, 0x2e, 0xf9, 0x0c, 0x8e];
pub const BITCOIN_TAG: [u8; 8] = [0x05, 0x88, 0x96, 0x0d, 0x73, 0xd7, 0x19, 0x01];
pub const LITECOIN_TAG: [u8; 8] = [0x06, 0x86, 0x9a, 0x0d, 0x73, 0xd7, 0x1b, 0x45];
pub const ETHEREUM_TAG: [u8; 8] = [0x30, 0xfe, 0x80, 0x87, 0xb5, 0xc7, 0xea, 0xd7];

pub const MAX_PAYLOAD_SIZE: usize = 8192;
pub const MAX_URI_LENGTH: usize = 1000;

const ALLOWED_URI_CHARS: &[u8] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._/:";

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TimeAttestation {
    Pending { uri: String },
    Bitcoin { height: u64 },
    Litecoin { height: u64 },
    Ethereum { height: u64 },
    Unknown { tag: [u8; 8], payload: Vec<u8> },
}

impl TimeAttestation {
    pub fn tag(&self) -> [u8; 8] {
        match self {
            TimeAttestation::Pending { .. } => PENDING_TAG,
            TimeAttestation::Bitcoin { .. } => BITCOIN_TAG,
            TimeAttestation::Litecoin { .. } => LITECOIN_TAG,
            TimeAttestation::Ethereum { .. } => ETHEREUM_TAG,
            TimeAttestation::Unknown { tag, .. } => *tag,
        }
    }

    pub fn check_uri(uri: &str) -> std::result::Result<(), String> {
        if uri.len() > MAX_URI_LENGTH {
            return Err("URI exceeds maximum length".into());
        }
        for c in uri.bytes() {
            if !ALLOWED_URI_CHARS.contains(&c) {
                return Err(format!("URI contains invalid character {:?}", c as char));
            }
        }
        Ok(())
    }

    #[allow(dead_code)]
    pub fn pending(uri: impl Into<String>) -> std::result::Result<Self, String> {
        let uri = uri.into();
        Self::check_uri(&uri)?;
        Ok(TimeAttestation::Pending { uri })
    }

    fn serialize_payload(&self, w: &mut Writer) {
        match self {
            TimeAttestation::Pending { uri } => w.write_varbytes(uri.as_bytes()),
            TimeAttestation::Bitcoin { height }
            | TimeAttestation::Litecoin { height }
            | TimeAttestation::Ethereum { height } => w.write_varuint(*height),
            TimeAttestation::Unknown { payload, .. } => w.write_bytes(payload),
        }
    }

    pub fn serialize(&self, w: &mut Writer) {
        w.write_bytes(&self.tag());
        let mut payload = Writer::new();
        self.serialize_payload(&mut payload);
        w.write_varbytes(&payload.into_bytes());
    }

    pub fn deserialize(r: &mut Reader) -> Result<TimeAttestation> {
        let tag_bytes = r.read_bytes(8)?;
        let mut tag = [0u8; 8];
        tag.copy_from_slice(tag_bytes);

        let payload = r.read_varbytes(MAX_PAYLOAD_SIZE)?.to_vec();
        let mut pr = Reader::new(&payload);

        let result = match tag {
            PENDING_TAG => {
                let uri_bytes = pr.read_varbytes(MAX_URI_LENGTH)?;
                let uri = String::from_utf8(uri_bytes.to_vec())
                    .map_err(|e| DeserializeError::Invalid(format!("invalid URI utf8: {e}")))?;
                TimeAttestation::check_uri(&uri)
                    .map_err(|e| DeserializeError::Invalid(format!("invalid URI: {e}")))?;
                TimeAttestation::Pending { uri }
            }
            BITCOIN_TAG => TimeAttestation::Bitcoin {
                height: pr.read_varuint()?,
            },
            LITECOIN_TAG => TimeAttestation::Litecoin {
                height: pr.read_varuint()?,
            },
            ETHEREUM_TAG => TimeAttestation::Ethereum {
                height: pr.read_varuint()?,
            },
            _ => return Ok(TimeAttestation::Unknown { tag, payload }),
        };

        pr.assert_eof()?;
        Ok(result)
    }
}

impl std::fmt::Display for TimeAttestation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TimeAttestation::Pending { uri } => write!(f, "pending '{uri}'"),
            TimeAttestation::Bitcoin { height } => write!(f, "Bitcoin block {height}"),
            TimeAttestation::Litecoin { height } => write!(f, "Litecoin block {height}"),
            TimeAttestation::Ethereum { height } => write!(f, "Ethereum block {height}"),
            TimeAttestation::Unknown { tag, .. } => {
                write!(f, "unknown attestation {}", hex::encode(tag))
            }
        }
    }
}

/// Ordering used to canonically sort sibling attestations during serialization,
/// and (for Bitcoin/Litecoin attestations specifically) to prefer the
/// lowest/most-specific height when pruning duplicates.
impl PartialOrd for TimeAttestation {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for TimeAttestation {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        use TimeAttestation::*;
        match (self, other) {
            (Pending { uri: a }, Pending { uri: b }) => a.cmp(b),
            (Bitcoin { height: a }, Bitcoin { height: b }) => a.cmp(b),
            (Litecoin { height: a }, Litecoin { height: b }) => a.cmp(b),
            (Ethereum { height: a }, Ethereum { height: b }) => a.cmp(b),
            (
                Unknown {
                    tag: ta,
                    payload: pa,
                },
                Unknown {
                    tag: tb,
                    payload: pb,
                },
            ) => ta.cmp(tb).then_with(|| pa.cmp(pb)),
            _ => self.tag().cmp(&other.tag()),
        }
    }
}
