//! Consensus-critical binary (de)serialization for the OpenTimestamps wire format.
//!
//! Mirrors `opentimestamps.core.serialize` from the reference Python implementation:
//! LEB128 varuints, length-prefixed varbytes, and magic/EOF assertions.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum DeserializeError {
    #[error("expected magic bytes {expected}, got {actual}")]
    BadMagic { expected: String, actual: String },
    #[error("unsupported major version {0}")]
    UnsupportedVersion(u64),
    #[error("truncated data: wanted {wanted} bytes, got {got}")]
    Truncation { wanted: usize, got: usize },
    #[error("trailing garbage after end of data")]
    TrailingGarbage,
    #[error("recursion limit reached while deserializing")]
    RecursionLimit,
    #[error("varbytes length {0} exceeds max {1}")]
    VarbytesTooLong(usize, usize),
    #[error("invalid data: {0}")]
    Invalid(String),
}

pub type Result<T> = std::result::Result<T, DeserializeError>;

/// Append-only byte buffer writer.
#[derive(Default)]
pub struct Writer(pub Vec<u8>);

impl Writer {
    pub fn new() -> Self {
        Self(Vec::new())
    }

    pub fn write_bytes(&mut self, b: &[u8]) {
        self.0.extend_from_slice(b);
    }

    #[allow(dead_code)]
    pub fn write_bool(&mut self, v: bool) {
        self.0.push(if v { 0xff } else { 0x00 });
    }

    /// LEB128 unsigned varint.
    pub fn write_varuint(&mut self, mut value: u64) {
        if value == 0 {
            self.0.push(0);
            return;
        }
        while value != 0 {
            let mut b = (value & 0x7f) as u8;
            if value > 0x7f {
                b |= 0x80;
            }
            self.0.push(b);
            if value <= 0x7f {
                break;
            }
            value >>= 7;
        }
    }

    pub fn write_varbytes(&mut self, b: &[u8]) {
        self.write_varuint(b.len() as u64);
        self.write_bytes(b);
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

/// Cursor-based reader over an in-memory byte slice.
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    pub fn read_bytes(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.remaining() < n {
            return Err(DeserializeError::Truncation {
                wanted: n,
                got: self.remaining(),
            });
        }
        let r = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(r)
    }

    pub fn read_byte(&mut self) -> Result<u8> {
        Ok(self.read_bytes(1)?[0])
    }

    #[allow(dead_code)]
    pub fn read_bool(&mut self) -> Result<bool> {
        match self.read_byte()? {
            0xff => Ok(true),
            0x00 => Ok(false),
            b => Err(DeserializeError::Invalid(format!(
                "read_bool expected 0xff or 0x00, got {b:#x}"
            ))),
        }
    }

    pub fn read_varuint(&mut self) -> Result<u64> {
        let mut value: u64 = 0;
        let mut shift = 0u32;
        loop {
            let b = self.read_byte()?;
            value |= ((b & 0x7f) as u64) << shift;
            if b & 0x80 == 0 {
                break;
            }
            shift += 7;
        }
        Ok(value)
    }

    pub fn read_varbytes(&mut self, max_len: usize) -> Result<&'a [u8]> {
        let len = self.read_varuint()? as usize;
        if len > max_len {
            return Err(DeserializeError::VarbytesTooLong(len, max_len));
        }
        self.read_bytes(len)
    }

    pub fn assert_magic(&mut self, expected: &[u8]) -> Result<()> {
        if self.remaining() < expected.len() {
            return Err(DeserializeError::BadMagic {
                expected: hex::encode(expected),
                actual: hex::encode(&self.buf[self.pos..]),
            });
        }
        let actual = &self.buf[self.pos..self.pos + expected.len()];
        if actual != expected {
            return Err(DeserializeError::BadMagic {
                expected: hex::encode(expected),
                actual: hex::encode(actual),
            });
        }
        self.pos += expected.len();
        Ok(())
    }

    pub fn assert_eof(&self) -> Result<()> {
        if self.remaining() > 0 {
            Err(DeserializeError::TrailingGarbage)
        } else {
            Ok(())
        }
    }
}
