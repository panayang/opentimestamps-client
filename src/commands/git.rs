use crate::calendar::DEFAULT_AGGREGATORS;
use crate::cli::{GitArgs, GitCommand, GitStampArgs, GitVerifyArgs};
use crate::context::Context;
use crate::git::{
    deserialize_ascii_armored_timestamp, extract_sig_from_git_commit, extract_sig_from_git_tag,
    find_git_repo_root, hash_signed_commit, read_git_object, rev_parse,
};
use crate::ots::notary::TimeAttestation;
use crate::ots::op::Op;
use crate::ots::serialize::{Reader, Writer};
use crate::ots::timestamp::{DetachedTimestampFile, Timestamp};
use crate::upgrade::{create_timestamp, upgrade_timestamp};
use anyhow::Context as _;
use std::path::PathBuf;
use std::time::Duration;

pub async fn run(args: GitArgs, ctx: &Context) -> anyhow::Result<()> {
    match args.command {
        GitCommand::Stamp(stamp_args) => run_stamp(stamp_args, ctx).await,
        GitCommand::Verify(verify_args) => run_verify(verify_args, ctx).await,
        GitCommand::Extract(extract_args) => {
            crate::commands::git_extract::run(extract_args, ctx).await
        }
        GitCommand::GpgWrapper(wrapper_args) => {
            crate::git::run_gpg_wrapper(
                &wrapper_args.gpg_args,
                ctx,
                Some(&wrapper_args.gpg_program),
                &wrapper_args.calendars,
            )
            .await
        }
    }
}

pub async fn run_stamp(args: GitStampArgs, ctx: &Context) -> anyhow::Result<()> {
    let log = ctx.log;
    let commit_hash = rev_parse(&args.reference)?;
    let (obj_type, raw_data) = read_git_object(&args.reference)?;

    log.info(&format!("Timestamping git {obj_type} {commit_hash}"));

    let digest = if obj_type == "commit" {
        let (unsigned, sig) = extract_sig_from_git_commit(&raw_data);
        if !sig.is_empty() {
            log.info("Found PGP signature on commit; hashing signed commit structure");
            hash_signed_commit(&unsigned, &sig).to_vec()
        } else {
            log.info("Unsigned commit; hashing raw commit object");
            use sha2::{Digest, Sha256};
            Sha256::digest(&raw_data).to_vec()
        }
    } else if obj_type == "tag" {
        let (unsigned, sig) = extract_sig_from_git_tag(&raw_data);
        if !sig.is_empty() {
            log.info("Found PGP signature on tag; hashing signed tag structure");
            hash_signed_commit(&unsigned, &sig).to_vec()
        } else {
            log.info("Unsigned tag; hashing raw tag object");
            use sha2::{Digest, Sha256};
            Sha256::digest(&raw_data).to_vec()
        }
    } else {
        use sha2::{Digest, Sha256};
        Sha256::digest(&raw_data).to_vec()
    };

    let mut ts = Timestamp::new(digest.clone());

    let calendar_urls = if args.calendars.is_empty() {
        DEFAULT_AGGREGATORS
            .iter()
            .map(|s| (*s).to_string())
            .collect()
    } else {
        args.calendars.clone()
    };

    create_timestamp(
        &mut ts,
        &calendar_urls,
        args.m,
        Duration::from_secs(args.timeout),
        |m| log.info(m),
    )
    .await?;

    if ctx.wait {
        log.info("Waiting for Bitcoin confirmation...");
        upgrade_timestamp(
            &mut ts,
            &calendar_urls,
            &ctx.whitelist,
            &ctx.cache,
            true,
            ctx.wait_interval,
            |m| log.info(m),
        )
        .await;
    }

    if ts.all_attestations().is_empty() {
        ts.attestations.insert(TimeAttestation::Pending {
            uri: "local".to_string(),
        });
    }

    let detached = DetachedTimestampFile::new(Op::Sha256, ts);
    let mut w = Writer::new();
    detached.serialize(&mut w)?;
    let ots_bytes = w.into_bytes();

    let out_path = if let Some(p) = args.output {
        p
    } else if let Ok(repo_root) = find_git_repo_root() {
        let ots_dir = repo_root.join(".git").join("ots");
        let _ = std::fs::create_dir_all(&ots_dir);
        ots_dir.join(format!("{commit_hash}.ots"))
    } else {
        PathBuf::from(format!("{commit_hash}.ots"))
    };

    if let Some(parent) = out_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    std::fs::write(&out_path, ots_bytes)
        .with_context(|| format!("failed to write timestamp to {}", out_path.display()))?;

    log.info(&format!("Saved timestamp proof to {}", out_path.display()));
    Ok(())
}

pub async fn run_verify(args: GitVerifyArgs, ctx: &Context) -> anyhow::Result<()> {
    let log = ctx.log;
    let commit_hash = rev_parse(&args.reference)?;
    let (obj_type, raw_data) = read_git_object(&args.reference)?;

    // 1. Check for embedded ASCII-armored OpenTimestamps proof
    let mut embedded_stamp: Option<Timestamp> = None;
    if obj_type == "commit" {
        let (unsigned, sig) = extract_sig_from_git_commit(&raw_data);
        if !sig.is_empty()
            && let Ok(Some((_maj, _min, stamp))) =
                deserialize_ascii_armored_timestamp(&unsigned, &sig)
        {
            embedded_stamp = Some(stamp);
        }
    } else if obj_type == "tag" {
        let (unsigned, sig) = extract_sig_from_git_tag(&raw_data);
        if !sig.is_empty()
            && let Ok(Some((_maj, _min, stamp))) =
                deserialize_ascii_armored_timestamp(&unsigned, &sig)
        {
            embedded_stamp = Some(stamp);
        }
    }

    // 2. Check for detached timestamp proof if no embedded proof found
    let (mut stamp, source_description) = if let Some(s) = embedded_stamp {
        (s, "embedded OpenTimestamps git signature".to_string())
    } else {
        let candidate_paths = if let Some(explicit) = &args.timestamp {
            vec![explicit.clone()]
        } else {
            let mut paths = vec![
                PathBuf::from(format!("{commit_hash}.ots")),
                PathBuf::from(format!("{}.ots", args.reference)),
            ];
            if let Ok(repo_root) = find_git_repo_root() {
                paths.push(
                    repo_root
                        .join(".git")
                        .join("ots")
                        .join(format!("{commit_hash}.ots")),
                );
            }
            paths
        };

        let mut found = None;
        for p in candidate_paths {
            if p.exists()
                && let Ok(bytes) = std::fs::read(&p)
            {
                let mut r = Reader::new(&bytes);
                if let Ok(detached) = DetachedTimestampFile::deserialize(&mut r) {
                    found = Some((detached.timestamp, format!("detached file {}", p.display())));
                    break;
                }
            }
        }

        found.ok_or_else(|| {
            anyhow::anyhow!(
                "no OpenTimestamps proof found for {obj_type} {commit_hash} (neither embedded nor detached .ots)"
            )
        })?
    };

    log.info(&format!(
        "Verifying {source_description} for {obj_type} {commit_hash}"
    ));

    upgrade_timestamp(
        &mut stamp,
        &[],
        &ctx.whitelist,
        &ctx.cache,
        ctx.wait,
        ctx.wait_interval,
        |m| log.info(m),
    )
    .await;

    let mut attestations = stamp.all_attestations();
    attestations.sort_by_key(|(_, a)| match a {
        TimeAttestation::Bitcoin { height } => *height,
        _ => u64::MAX,
    });

    let mut verified = false;
    let mut btc_height: Option<u64> = None;
    let mut btc_time: Option<u64> = None;
    let mut btc_root: Option<String> = None;

    for (msg, attestation) in &attestations {
        if let TimeAttestation::Bitcoin { height } = attestation {
            if let Some(esplora) = &ctx.esplora {
                if let Ok(v) = esplora.verify_merkle_root(msg, *height).await {
                    verified = true;
                    btc_height = Some(*height);
                    btc_time = Some(v.block_time);
                    let mut rev = msg.to_vec();
                    rev.reverse();
                    btc_root = Some(hex::encode(rev));
                    break;
                }
            } else {
                verified = true;
                btc_height = Some(*height);
                let mut rev = msg.to_vec();
                rev.reverse();
                btc_root = Some(hex::encode(rev));
                break;
            }
        }
    }

    let has_pending = attestations
        .iter()
        .any(|(_, a)| matches!(a, TimeAttestation::Pending { .. }));

    if args.json {
        let json_obj = serde_json::json!({
            "reference": args.reference,
            "commit": commit_hash,
            "object_type": obj_type,
            "verified": verified,
            "pending": has_pending,
            "source": source_description,
            "bitcoin_block": btc_height,
            "block_time": btc_time,
            "merkle_root": btc_root,
            "attestations_count": attestations.len(),
        });
        println!("{}", serde_json::to_string_pretty(&json_obj)?);
    } else if verified {
        if let (Some(height), Some(time)) = (btc_height, btc_time) {
            let dt = crate::commands::verify::chrono_like_format(time);
            log.info(&format!(
                "Success! Bitcoin block {height} attests existence of {commit_hash} as of {dt}"
            ));
        } else if let Some(height) = btc_height {
            log.info(&format!(
                "Success! Bitcoin block {height} attests existence of {commit_hash}"
            ));
        }
    } else if has_pending {
        log.warn(&format!(
            "Timestamp for {commit_hash} is pending confirmation"
        ));
    }

    if !verified {
        anyhow::bail!(
            "timestamp for {commit_hash} could not be verified against Bitcoin blockchain"
        );
    }

    Ok(())
}
