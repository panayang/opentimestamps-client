//! Timestamp proof operations (edges of the commitment tree).
//!
//! Mirrors `opentimestamps.core.op`. Ordering matters: `Timestamp` serialization
//! sorts sibling ops by `(tag, args)`, so `Op` must implement a total order that
//! matches the Python tuple-comparison semantics exactly or proofs round-trip
//! incorrectly between implementations.

use crate::ots::serialize::{DeserializeError, Reader, Result, Writer};
use ripemd::Ripemd160;
use sha1::Sha1;
use sha2::{Digest, Sha256};
use tiny_keccak::{Hasher, Keccak};

pub const MAX_RESULT_LENGTH: usize = 4096;
pub const MAX_MSG_LENGTH: usize = 4096;

#[derive(Debug, thiserror::Error)]
pub enum OpError {
    #[error("message too long: {0} > {1}")]
    MsgTooLong(usize, usize),
    #[error("result too long: {0} > {1}")]
    ResultTooLong(usize, usize),
    #[error("can't hexlify an empty message")]
    EmptyHexlify,
    #[error("can't reverse an empty message")]
    EmptyReverse,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Op {
    Append(Vec<u8>),
    Prepend(Vec<u8>),
    Reverse,
    Hexlify,
    Sha1,
    Ripemd160,
    Sha256,
    Keccak256,
}

impl Op {
    pub fn tag(&self) -> u8 {
        match self {
            Op::Append(_) => 0xf0,
            Op::Prepend(_) => 0xf1,
            Op::Reverse => 0xf2,
            Op::Hexlify => 0xf3,
            Op::Sha1 => 0x02,
            Op::Ripemd160 => 0x03,
            Op::Sha256 => 0x08,
            Op::Keccak256 => 0x67,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Op::Append(_) => "append",
            Op::Prepend(_) => "prepend",
            Op::Reverse => "reverse",
            Op::Hexlify => "hexlify",
            Op::Sha1 => "sha1",
            Op::Ripemd160 => "ripemd160",
            Op::Sha256 => "sha256",
            Op::Keccak256 => "keccak256",
        }
    }

    #[allow(dead_code)]
    pub fn is_crypt_op(&self) -> bool {
        matches!(self, Op::Sha1 | Op::Ripemd160 | Op::Sha256 | Op::Keccak256)
    }

    pub fn digest_length(&self) -> Option<usize> {
        match self {
            Op::Sha1 | Op::Ripemd160 => Some(20),
            Op::Sha256 | Op::Keccak256 => Some(32),
            _ => None,
        }
    }

    fn arg(&self) -> Option<&[u8]> {
        match self {
            Op::Append(a) | Op::Prepend(a) => Some(a),
            _ => None,
        }
    }

    /// Apply the operation to `msg`, producing the resulting digest/message.
    pub fn apply(&self, msg: &[u8]) -> std::result::Result<Vec<u8>, OpError> {
        if msg.len() > MAX_MSG_LENGTH {
            return Err(OpError::MsgTooLong(msg.len(), MAX_MSG_LENGTH));
        }

        let r = match self {
            Op::Append(suffix) => {
                let mut v = msg.to_vec();
                v.extend_from_slice(suffix);
                v
            }
            Op::Prepend(prefix) => {
                let mut v = prefix.clone();
                v.extend_from_slice(msg);
                v
            }
            Op::Reverse => {
                if msg.is_empty() {
                    return Err(OpError::EmptyReverse);
                }
                let mut v = msg.to_vec();
                v.reverse();
                v
            }
            Op::Hexlify => {
                if msg.is_empty() {
                    return Err(OpError::EmptyHexlify);
                }
                hex::encode(msg).into_bytes()
            }
            Op::Sha1 => Sha1::digest(msg).to_vec(),
            Op::Ripemd160 => Ripemd160::digest(msg).to_vec(),
            Op::Sha256 => Sha256::digest(msg).to_vec(),
            Op::Keccak256 => {
                let mut hasher = Keccak::v256();
                hasher.update(msg);
                let mut out = [0u8; 32];
                hasher.finalize(&mut out);
                out.to_vec()
            }
        };

        if r.len() > MAX_RESULT_LENGTH {
            return Err(OpError::ResultTooLong(r.len(), MAX_RESULT_LENGTH));
        }
        Ok(r)
    }

    pub fn serialize(&self, w: &mut Writer) {
        w.write_bytes(&[self.tag()]);
        if let Some(a) = self.arg() {
            w.write_varbytes(a);
        }
    }

    #[allow(dead_code)]
    pub fn deserialize(r: &mut Reader) -> Result<Op> {
        let tag = r.read_byte()?;
        Self::deserialize_from_tag(r, tag)
    }

    pub fn deserialize_from_tag(r: &mut Reader, tag: u8) -> Result<Op> {
        Ok(match tag {
            0xf0 => Op::Append(r.read_varbytes(MAX_RESULT_LENGTH)?.to_vec()),
            0xf1 => Op::Prepend(r.read_varbytes(MAX_RESULT_LENGTH)?.to_vec()),
            0xf2 => Op::Reverse,
            0xf3 => Op::Hexlify,
            0x02 => Op::Sha1,
            0x03 => Op::Ripemd160,
            0x08 => Op::Sha256,
            0x67 => Op::Keccak256,
            t => {
                return Err(DeserializeError::Invalid(format!(
                    "unknown operation tag {t:#x}"
                )));
            }
        })
    }
}

impl std::fmt::Display for Op {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.arg() {
            Some(a) => write!(f, "{} {}", self.name(), hex::encode(a)),
            None => write!(f, "{}", self.name()),
        }
    }
}

impl PartialOrd for Op {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Op {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.tag()
            .cmp(&other.tag())
            .then_with(|| self.arg().cmp(&other.arg()))
    }
}
