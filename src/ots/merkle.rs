//! Merkle tree construction for batching multiple file digests into one commitment.
//!
//! Builds the same merkle-mountain-range structure as
//! `opentimestamps.core.timestamp.make_merkle_tree`, but instead of mutating a
//! shared object graph (as the Python implementation does, relying on aliased
//! mutable dict entries) it tracks, for each leaf, the explicit list of
//! [`Op`]s needed to walk from that leaf up to the tree's tip digest. The
//! caller applies that path to the leaf's own owned `Timestamp` node and then
//! merges in whatever attestation ends up on the tip - functionally identical
//! to the Python approach without needing shared mutable references.

use crate::ots::op::Op;
use sha2::{Digest, Sha256};

struct Group {
    value: Vec<u8>,
    members: Vec<usize>,
}

fn sha256d_concat(left: &[u8], right: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(left.len() + right.len());
    buf.extend_from_slice(left);
    buf.extend_from_slice(right);
    Sha256::digest(&buf).to_vec()
}

/// Build a merkle tree over `leaf_msgs`, returning the tip digest and, for
/// each leaf (by index), the ops needed to derive the tip digest from it.
pub fn merkle_paths(leaf_msgs: Vec<Vec<u8>>) -> (Vec<u8>, Vec<Vec<Op>>) {
    let n = leaf_msgs.len();
    assert!(n > 0, "need at least one leaf");

    let mut paths: Vec<Vec<Op>> = vec![Vec::new(); n];
    let mut groups: Vec<Group> = leaf_msgs
        .into_iter()
        .enumerate()
        .map(|(i, m)| Group {
            value: m,
            members: vec![i],
        })
        .collect();

    loop {
        if groups.len() == 1 {
            return (groups.pop().unwrap().value, paths);
        }

        let mut next_groups = Vec::with_capacity(groups.len() / 2 + 1);
        let mut prev: Option<Group> = None;
        for g in groups {
            match prev.take() {
                Some(p) => {
                    for &idx in &p.members {
                        paths[idx].push(Op::Append(g.value.clone()));
                        paths[idx].push(Op::Sha256);
                    }
                    for &idx in &g.members {
                        paths[idx].push(Op::Prepend(p.value.clone()));
                        paths[idx].push(Op::Sha256);
                    }
                    let value = sha256d_concat(&p.value, &g.value);
                    let mut members = p.members;
                    members.extend(g.members);
                    next_groups.push(Group { value, members });
                }
                None => prev = Some(g),
            }
        }
        if let Some(p) = prev {
            next_groups.push(p);
        }
        groups = next_groups;
    }
}
