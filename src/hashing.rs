//! Streaming file hashing (1MB chunks), matching `CryptOp.hash_fd`.

use crate::ots::op::Op;
use ripemd::Ripemd160;
use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::io::{self, Read};
use tiny_keccak::{Hasher, Keccak};

const CHUNK_SIZE: usize = 1 << 20;

fn stream_chunks(r: &mut impl Read, mut f: impl FnMut(&[u8])) -> io::Result<()> {
    let mut buf = vec![0u8; CHUNK_SIZE];
    loop {
        let n = r.read(&mut buf)?;
        if n == 0 {
            break;
        }
        f(&buf[..n]);
    }
    Ok(())
}

/// Hash `r`'s full contents with the digest algorithm named by `op`.
///
/// Panics if `op` is not one of the cryptographic digest ops.
pub fn hash_reader(mut r: impl Read, op: &Op) -> io::Result<Vec<u8>> {
    match op {
        Op::Sha1 => {
            let mut h = Sha1::new();
            stream_chunks(&mut r, |chunk| Digest::update(&mut h, chunk))?;
            Ok(h.finalize().to_vec())
        }
        Op::Ripemd160 => {
            let mut h = Ripemd160::new();
            stream_chunks(&mut r, |chunk| Digest::update(&mut h, chunk))?;
            Ok(h.finalize().to_vec())
        }
        Op::Sha256 => {
            let mut h = Sha256::new();
            stream_chunks(&mut r, |chunk| Digest::update(&mut h, chunk))?;
            Ok(h.finalize().to_vec())
        }
        Op::Keccak256 => {
            let mut h = Keccak::v256();
            stream_chunks(&mut r, |chunk| h.update(chunk))?;
            let mut out = [0u8; 32];
            h.finalize(&mut out);
            Ok(out.to_vec())
        }
        _ => panic!("hash_reader called with non-digest op {op:?}"),
    }
}

pub fn parse_hash_algo(name: &str) -> Option<Op> {
    match name {
        "sha1" => Some(Op::Sha1),
        "ripemd160" => Some(Op::Ripemd160),
        "sha256" => Some(Op::Sha256),
        "keccak256" => Some(Op::Keccak256),
        _ => None,
    }
}
