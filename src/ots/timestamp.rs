//! The timestamp proof tree, and the `.ots` detached timestamp file format.
//!
//! Mirrors `opentimestamps.core.timestamp`.

use crate::ots::notary::TimeAttestation;
use crate::ots::op::{Op, OpError};
use crate::ots::serialize::{DeserializeError, Reader, Writer};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, thiserror::Error)]
pub enum TimestampError {
    #[error("can't merge timestamps for different messages")]
    MsgMismatch,
    #[error("an empty timestamp can't be serialized")]
    EmptySerialize,
    #[error(transparent)]
    Op(#[from] OpError),
    #[error(transparent)]
    Deser(#[from] DeserializeError),
}

pub type Result<T> = std::result::Result<T, TimestampError>;

/// A node in the timestamp proof tree: a message, the attestations that
/// directly vouch for it, and the operations leading to child nodes.
#[derive(Debug, Clone)]
pub struct Timestamp {
    pub msg: Vec<u8>,
    pub attestations: BTreeSet<TimeAttestation>,
    pub ops: BTreeMap<Op, Timestamp>,
}

impl Timestamp {
    pub fn new(msg: impl Into<Vec<u8>>) -> Self {
        Timestamp {
            msg: msg.into(),
            attestations: BTreeSet::new(),
            ops: BTreeMap::new(),
        }
    }

    /// Get (or create, applying `op` to `self.msg`) the child timestamp for `op`.
    pub fn add_op(&mut self, op: Op) -> Result<&mut Timestamp> {
        if !self.ops.contains_key(&op) {
            let result = op.apply(&self.msg)?;
            self.ops.insert(op.clone(), Timestamp::new(result));
        }
        Ok(self.ops.get_mut(&op).unwrap())
    }

    pub fn merge(&mut self, other: Timestamp) -> Result<()> {
        if self.msg != other.msg {
            return Err(TimestampError::MsgMismatch);
        }
        self.attestations.extend(other.attestations);
        for (op, other_stamp) in other.ops {
            let our_stamp = self.add_op(op)?;
            our_stamp.merge(other_stamp)?;
        }
        Ok(())
    }

    pub fn serialize(&self, w: &mut Writer) -> Result<()> {
        if self.attestations.is_empty() && self.ops.is_empty() {
            return Err(TimestampError::EmptySerialize);
        }

        let sorted_attestations: Vec<&TimeAttestation> = self.attestations.iter().collect();

        if sorted_attestations.len() > 1 {
            for attestation in &sorted_attestations[0..sorted_attestations.len() - 1] {
                w.write_bytes(&[0xff, 0x00]);
                attestation.serialize(w);
            }
        }

        if self.ops.is_empty() {
            w.write_bytes(&[0x00]);
            sorted_attestations[sorted_attestations.len() - 1].serialize(w);
        } else {
            if !sorted_attestations.is_empty() {
                w.write_bytes(&[0xff, 0x00]);
                sorted_attestations[sorted_attestations.len() - 1].serialize(w);
            }

            let n = self.ops.len();
            for (i, (op, stamp)) in self.ops.iter().enumerate() {
                if i + 1 < n {
                    w.write_bytes(&[0xff]);
                    op.serialize(w);
                    stamp.serialize(w)?;
                } else {
                    op.serialize(w);
                    stamp.serialize(w)?;
                }
            }
        }
        Ok(())
    }

    pub fn deserialize(r: &mut Reader, initial_msg: Vec<u8>) -> Result<Timestamp> {
        Self::deserialize_with_limit(r, initial_msg, 256)
    }

    fn deserialize_with_limit(
        r: &mut Reader,
        initial_msg: Vec<u8>,
        recursion_limit: u32,
    ) -> Result<Timestamp> {
        if recursion_limit == 0 {
            return Err(TimestampError::Deser(DeserializeError::RecursionLimit));
        }

        let mut this = Timestamp::new(initial_msg.clone());

        let do_tag_or_attestation = |this: &mut Timestamp, tag: u8, r: &mut Reader| -> Result<()> {
            if tag == 0x00 {
                let attestation = TimeAttestation::deserialize(r)?;
                this.attestations.insert(attestation);
            } else {
                let op = Op::deserialize_from_tag(r, tag)?;
                let result = op.apply(&initial_msg)?;
                let stamp = Timestamp::deserialize_with_limit(r, result, recursion_limit - 1)?;
                this.ops.insert(op, stamp);
            }
            Ok(())
        };

        let mut tag = r.read_byte()?;
        while tag == 0xff {
            let inner_tag = r.read_byte()?;
            do_tag_or_attestation(&mut this, inner_tag, r)?;
            tag = r.read_byte()?;
        }
        do_tag_or_attestation(&mut this, tag, r)?;

        Ok(this)
    }

    /// Recursively collect every (sub-message, attestation) pair in the tree.
    pub fn all_attestations(&self) -> Vec<(&[u8], &TimeAttestation)> {
        let mut out = Vec::new();
        self.collect_attestations(&mut out);
        out
    }

    fn collect_attestations<'a>(&'a self, out: &mut Vec<(&'a [u8], &'a TimeAttestation)>) {
        for a in &self.attestations {
            out.push((&self.msg, a));
        }
        for stamp in self.ops.values() {
            stamp.collect_attestations(out);
        }
    }

    /// Human-readable proof tree, mirroring `Timestamp.str_tree()`.
    pub fn str_tree(&self, indent: usize, verbosity: i32) -> String {
        let mut out = String::new();
        for attestation in &self.attestations {
            out.push_str(&" ".repeat(indent));
            out.push_str(&format!("verify {attestation}\n"));
            if let TimeAttestation::Bitcoin { .. } = attestation {
                out.push_str(&" ".repeat(indent));
                out.push_str(&format!(
                    "# Bitcoin block merkle root {}\n",
                    hex::encode(reversed(&self.msg))
                ));
            }
            if let TimeAttestation::Litecoin { .. } = attestation {
                out.push_str(&" ".repeat(indent));
                out.push_str(&format!(
                    "# Litecoin block merkle root {}\n",
                    hex::encode(reversed(&self.msg))
                ));
            }
        }

        if self.ops.len() > 1 {
            for (op, stamp) in &self.ops {
                out.push_str(&" ".repeat(indent));
                out.push_str(&format!(" -> {op}"));
                if verbosity > 0
                    && let Ok(res) = op.apply(&self.msg)
                {
                    out.push_str(&format!(" == {}", hex::encode(res)));
                }
                out.push('\n');
                out.push_str(&stamp.str_tree(indent + 4, verbosity));
            }
        } else if let Some((op, stamp)) = self.ops.iter().next() {
            out.push_str(&" ".repeat(indent));
            out.push_str(&format!("{op}"));
            if verbosity > 0
                && let Ok(res) = op.apply(&self.msg)
            {
                out.push_str(&format!(" == {}", hex::encode(res)));
            }
            out.push('\n');
            out.push_str(&stamp.str_tree(indent, verbosity));
        }

        out
    }
}

fn reversed(b: &[u8]) -> Vec<u8> {
    let mut v = b.to_vec();
    v.reverse();
    v
}

/// `.ots` file: a hash algorithm tag, the file's digest, and a `Timestamp` proof for it.
pub struct DetachedTimestampFile {
    pub file_hash_op: Op,
    pub timestamp: Timestamp,
}

impl DetachedTimestampFile {
    pub const HEADER_MAGIC: [u8; 31] = [
        0x00, b'O', b'p', b'e', b'n', b'T', b'i', b'm', b'e', b's', b't', b'a', b'm', b'p', b's',
        0x00, 0x00, b'P', b'r', b'o', b'o', b'f', 0x00, 0xbf, 0x89, 0xe2, 0xe8, 0x84, 0xe8, 0x92,
        0x94,
    ];
    pub const MAJOR_VERSION: u64 = 1;

    pub fn new(file_hash_op: Op, timestamp: Timestamp) -> Self {
        Self {
            file_hash_op,
            timestamp,
        }
    }

    pub fn file_digest(&self) -> &[u8] {
        &self.timestamp.msg
    }

    pub fn serialize(&self, w: &mut Writer) -> Result<()> {
        w.write_bytes(&Self::HEADER_MAGIC);
        w.write_varuint(Self::MAJOR_VERSION);
        self.file_hash_op.serialize(w);
        w.write_bytes(&self.timestamp.msg);
        self.timestamp.serialize(w)
    }

    pub fn deserialize(r: &mut Reader) -> Result<DetachedTimestampFile> {
        r.assert_magic(&Self::HEADER_MAGIC)?;
        let major = r.read_varuint()?;
        if major != Self::MAJOR_VERSION {
            return Err(TimestampError::Deser(DeserializeError::UnsupportedVersion(
                major,
            )));
        }

        let tag = r.read_byte()?;
        let file_hash_op = Op::deserialize_from_tag(r, tag)?;
        let digest_len = file_hash_op
            .digest_length()
            .ok_or_else(|| DeserializeError::Invalid("file hash op is not a digest op".into()))?;
        let file_hash = r.read_bytes(digest_len)?.to_vec();
        let timestamp = Timestamp::deserialize(r, file_hash)?;
        r.assert_eof()?;

        Ok(DetachedTimestampFile {
            file_hash_op,
            timestamp,
        })
    }
}
