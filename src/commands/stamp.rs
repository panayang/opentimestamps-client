use crate::calendar::DEFAULT_AGGREGATORS;
use crate::cli::StampArgs;
use crate::context::Context;
use crate::hashing::{hash_reader, parse_hash_algo};
use crate::ots::merkle::merkle_paths;
use crate::ots::op::Op;
use crate::ots::serialize::Writer;
use crate::ots::timestamp::{DetachedTimestampFile, Timestamp};
use crate::upgrade::{create_timestamp, upgrade_timestamp};
use crate::util::expand_globs;
use rand::Rng;
use rayon::prelude::*;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;

struct FileEntry {
    /// None for stdin (written to stdout instead of a sibling .ots file).
    out_path: Option<PathBuf>,
    digest: Vec<u8>,
}

pub async fn run(args: StampArgs, ctx: &Context) -> anyhow::Result<()> {
    let hash_op = parse_hash_algo(&args.hash)
        .ok_or_else(|| anyhow::anyhow!("unknown hash algorithm '{}'", args.hash))?;

    let is_stdin =
        args.files.is_empty() || (args.files.len() == 1 && args.files[0].as_os_str() == "-");

    let entries = if is_stdin {
        let mut buf = Vec::new();
        std::io::stdin().read_to_end(&mut buf)?;
        let digest = hash_reader(&buf[..], &hash_op)?;
        vec![FileEntry {
            out_path: None,
            digest,
        }]
    } else {
        let paths = expand_globs(&args.files)?;
        let hash_op = hash_op.clone();
        tokio::task::spawn_blocking(move || hash_files_parallel(&paths, &hash_op)).await??
    };

    // Each file gets its own nonce so detached timestamps don't leak
    // information about sibling files' digests.
    let mut file_timestamps: Vec<DetachedTimestampFile> = Vec::with_capacity(entries.len());
    let mut leaf_msgs: Vec<Vec<u8>> = Vec::with_capacity(entries.len());

    for entry in &entries {
        let mut ts = Timestamp::new(entry.digest.clone());
        let mut nonce = [0u8; 16];
        rand::rng().fill_bytes(&mut nonce);
        let merkle_root = ts.add_op(Op::Append(nonce.to_vec()))?.add_op(Op::Sha256)?;
        leaf_msgs.push(merkle_root.msg.clone());
        file_timestamps.push(DetachedTimestampFile::new(hash_op.clone(), ts));
    }

    let (tip_digest, paths) = merkle_paths(leaf_msgs);
    let mut tip = Timestamp::new(tip_digest);

    let calendar_urls = if args.calendars.is_empty() {
        DEFAULT_AGGREGATORS.iter().map(|s| s.to_string()).collect()
    } else {
        args.calendars.clone()
    };

    let log = ctx.log;
    create_timestamp(
        &mut tip,
        &calendar_urls,
        args.m,
        Duration::from_secs(args.timeout),
        |m| log.info(m),
    )
    .await?;

    if ctx.wait {
        log.info("Timestamp submitted; waiting for Bitcoin confirmation...");
        upgrade_timestamp(
            &mut tip,
            &calendar_urls,
            &ctx.whitelist,
            &ctx.cache,
            true,
            ctx.wait_interval,
            |m| log.info(m),
        )
        .await;
        log.info("Timestamp complete; saving");
    }

    if tip.all_attestations().is_empty() {
        tip.attestations
            .insert(crate::ots::notary::TimeAttestation::Pending {
                uri: "local".to_string(),
            });
    }

    // Splice the (now possibly attested) tip back into each file's own leaf
    // node, by walking the same path of ops used to build the merkle tree.
    for (entry, file_timestamp, path) in itertools_zip(&entries, &mut file_timestamps, &paths) {
        let mut node = leaf_node_mut(&mut file_timestamp.timestamp);
        for op in path {
            node = node.add_op(op.clone())?;
        }
        node.merge(tip.clone())?;

        let mut w = Writer::new();
        file_timestamp.serialize(&mut w)?;
        let bytes = w.into_bytes();

        match &entry.out_path {
            Some(out_path) => {
                if out_path.exists() {
                    anyhow::bail!("timestamp file already exists: {}", out_path.display());
                }
                std::fs::write(out_path, &bytes)?;
                log.info(&format!("Wrote {}", out_path.display()));
            }
            None => {
                use std::io::Write;
                std::io::stdout().write_all(&bytes)?;
            }
        }
    }

    Ok(())
}

/// Walk to the merkle-root leaf node added by `add_op(Append(nonce)).add_op(Sha256)`.
fn leaf_node_mut(root: &mut Timestamp) -> &mut Timestamp {
    root.ops
        .values_mut()
        .next()
        .expect("nonce append op present")
        .ops
        .values_mut()
        .next()
        .expect("sha256 op present")
}

fn itertools_zip<'a>(
    entries: &'a [FileEntry],
    file_timestamps: &'a mut [DetachedTimestampFile],
    paths: &'a [Vec<Op>],
) -> impl Iterator<Item = (&'a FileEntry, &'a mut DetachedTimestampFile, &'a Vec<Op>)> {
    entries
        .iter()
        .zip(file_timestamps.iter_mut())
        .zip(paths.iter())
        .map(|((e, f), p)| (e, f, p))
}

fn hash_files_parallel(paths: &[PathBuf], op: &Op) -> anyhow::Result<Vec<FileEntry>> {
    paths
        .par_iter()
        .map(|path| -> anyhow::Result<FileEntry> {
            let file = std::fs::File::open(path)
                .map_err(|e| anyhow::anyhow!("could not read {}: {e}", path.display()))?;
            let digest = hash_reader(file, op)?;
            Ok(FileEntry {
                out_path: Some(append_ots_ext(path)),
                digest,
            })
        })
        .collect()
}

fn append_ots_ext(path: &Path) -> PathBuf {
    let mut s = path.as_os_str().to_os_string();
    s.push(".ots");
    PathBuf::from(s)
}
