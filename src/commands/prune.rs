use crate::cli::PruneArgs;
use crate::context::Context;
use crate::ots::notary::TimeAttestation;
use crate::ots::op::Op;
use crate::ots::serialize::{Reader, Writer};
use crate::ots::timestamp::{DetachedTimestampFile, Timestamp};
use std::collections::HashSet;

struct DiscardSpec {
    btc: bool,
    ltc: bool,
    unknown: bool,
    pending_all: bool,
    pending_uris: HashSet<String>,
}

impl DiscardSpec {
    fn matches(&self, a: &TimeAttestation) -> bool {
        match a {
            TimeAttestation::Pending { uri } => self.pending_all || self.pending_uris.contains(uri),
            TimeAttestation::Bitcoin { .. } => self.btc,
            TimeAttestation::Litecoin { .. } => self.ltc,
            TimeAttestation::Unknown { .. } => self.unknown,
            TimeAttestation::Ethereum { .. } => false,
        }
    }
}

pub async fn run(args: PruneArgs, ctx: &Context) -> anyhow::Result<()> {
    let log = ctx.log;

    let bytes = std::fs::read(&args.file)
        .map_err(|e| anyhow::anyhow!("could not read {}: {e}", args.file.display()))?;
    let mut r = Reader::new(&bytes);
    let mut detached = DetachedTimestampFile::deserialize(&mut r)
        .map_err(|e| anyhow::anyhow!("invalid timestamp file {}: {e}", args.file.display()))?;

    let verify_btc = if !args.attestations_to_verify.is_empty() {
        for s in &args.attestations_to_verify {
            if s != "btc" {
                anyhow::bail!("argument --verify: invalid choice '{s}' (choose from 'btc')");
            }
        }
        true
    } else {
        !args.no_verify
    };

    let mut spec = DiscardSpec {
        btc: false,
        ltc: false,
        unknown: false,
        pending_all: false,
        pending_uris: HashSet::new(),
    };
    if args.attestations_to_discard.is_empty() {
        spec.pending_all = true;
    } else {
        for s in &args.attestations_to_discard {
            match s.as_str() {
                "btc" => spec.btc = true,
                "ltc" => spec.ltc = true,
                "unknown" => spec.unknown = true,
                "pending:*" => spec.pending_all = true,
                _ if s.starts_with("pending:") => {
                    spec.pending_uris.insert(s["pending:".len()..].to_string());
                }
                _ => anyhow::bail!(
                    "argument --discard: invalid choice '{s}' (choose from 'btc', 'ltc', 'unknown', 'pending:*', 'pending:uri')"
                ),
            }
        }
    }

    if verify_btc {
        verify_all_btc_attestations(&detached.timestamp, ctx).await?;
    }

    discard_attestations(&mut detached.timestamp, &spec);
    discard_suboptimal(&mut detached.timestamp, AttKind::Bitcoin);
    discard_suboptimal(&mut detached.timestamp, AttKind::Litecoin);
    let (empty, changed) = prune_tree(&mut detached.timestamp);

    if empty {
        anyhow::bail!("Failed! All attestations have been discarded");
    } else if !changed {
        anyhow::bail!("Failed! Nothing has been discarded");
    }

    let backup = backup_path(&args.file);
    if backup.exists() {
        anyhow::bail!("could not back up timestamp: {} already exists", backup.display());
    }
    std::fs::rename(&args.file, &backup)?;

    let mut w = Writer::new();
    detached.serialize(&mut w)?;
    std::fs::write(&args.file, w.into_bytes())?;

    log.info("Success! Timestamp pruned");
    Ok(())
}

async fn verify_all_btc_attestations(timestamp: &Timestamp, ctx: &Context) -> anyhow::Result<()> {
    for (msg, attestation) in timestamp.all_attestations() {
        if let TimeAttestation::Bitcoin { height } = attestation {
            let esplora = ctx
                .esplora
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("Bitcoin disabled, could not check attestations"))?;
            esplora
                .verify_merkle_root(msg, *height)
                .await
                .map_err(|e| anyhow::anyhow!("Bitcoin verification failed: {e}"))?;
        }
    }
    Ok(())
}

fn discard_attestations(stamp: &mut Timestamp, spec: &DiscardSpec) {
    let to_remove: Vec<TimeAttestation> = stamp
        .attestations
        .iter()
        .filter(|a| spec.matches(a))
        .cloned()
        .collect();
    for a in to_remove {
        stamp.attestations.remove(&a);
    }
    for child in stamp.ops.values_mut() {
        discard_attestations(child, spec);
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum AttKind {
    Bitcoin,
    Litecoin,
}

impl AttKind {
    fn height_of(&self, a: &TimeAttestation) -> Option<u64> {
        match (self, a) {
            (AttKind::Bitcoin, TimeAttestation::Bitcoin { height }) => Some(*height),
            (AttKind::Litecoin, TimeAttestation::Litecoin { height }) => Some(*height),
            _ => None,
        }
    }
}

fn op_cost(op: &Op) -> usize {
    1 + match op {
        Op::Append(a) | Op::Prepend(a) => a.len(),
        _ => 0,
    }
}

fn collect_kind_positions(
    stamp: &Timestamp,
    kind: AttKind,
    path: &[Op],
    depth: usize,
    out: &mut Vec<(Vec<Op>, u64, usize)>,
) {
    for a in &stamp.attestations {
        if let Some(h) = kind.height_of(a) {
            out.push((path.to_vec(), h, depth));
        }
    }
    for (op, child) in &stamp.ops {
        let mut p = path.to_vec();
        p.push(op.clone());
        collect_kind_positions(child, kind, &p, depth + op_cost(op), out);
    }
}

fn remove_suboptimal_at(stamp: &mut Timestamp, kind: AttKind, path: &[Op], best_path: &[Op]) {
    if path != best_path {
        let to_remove: Vec<TimeAttestation> = stamp
            .attestations
            .iter()
            .filter(|a| kind.height_of(a).is_some())
            .cloned()
            .collect();
        for a in to_remove {
            stamp.attestations.remove(&a);
        }
    }
    for (op, child) in stamp.ops.iter_mut() {
        let mut p = path.to_vec();
        p.push(op.clone());
        remove_suboptimal_at(child, kind, &p, best_path);
    }
}

/// Keep only the cheapest (lowest height, then shallowest) attestation of a
/// given class, discarding any others. Equivalent in effect to the Python
/// client's `discard_suboptimal`, computed in two simpler passes instead of
/// one mutually-recursive one.
fn discard_suboptimal(stamp: &mut Timestamp, kind: AttKind) {
    let mut positions = Vec::new();
    collect_kind_positions(stamp, kind, &[], 0, &mut positions);
    if positions.len() <= 1 {
        return;
    }
    let best = positions
        .iter()
        .min_by_key(|(_, h, d)| (*h, *d))
        .unwrap()
        .0
        .clone();
    remove_suboptimal_at(stamp, kind, &[], &best);
}

fn prune_tree(stamp: &mut Timestamp) -> (bool, bool) {
    let mut prunable = stamp.attestations.is_empty();
    let mut changed = false;

    let keys: Vec<Op> = stamp.ops.keys().cloned().collect();
    for op in keys {
        let (child_prunable, child_changed) = {
            let child = stamp.ops.get_mut(&op).unwrap();
            prune_tree(child)
        };
        changed = changed || child_changed || child_prunable;
        if child_prunable {
            stamp.ops.remove(&op);
        } else {
            prunable = false;
        }
    }

    (prunable, changed)
}

fn backup_path(path: &std::path::Path) -> std::path::PathBuf {
    let mut s = path.as_os_str().to_os_string();
    s.push(".bak");
    std::path::PathBuf::from(s)
}
