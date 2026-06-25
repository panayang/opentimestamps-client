use crate::cli::VerifyArgs;
use crate::context::Context;
use crate::ots::notary::TimeAttestation;
use crate::ots::serialize::Reader;
use crate::ots::timestamp::DetachedTimestampFile;
use crate::upgrade::upgrade_timestamp;

pub async fn run(args: VerifyArgs, ctx: &Context) -> anyhow::Result<()> {
    let log = ctx.log;

    let bytes = std::fs::read(&args.timestamp)
        .map_err(|e| anyhow::anyhow!("could not read {}: {e}", args.timestamp.display()))?;
    let mut r = Reader::new(&bytes);
    let mut detached = DetachedTimestampFile::deserialize(&mut r)
        .map_err(|e| anyhow::anyhow!("invalid timestamp file {}: {e}", args.timestamp.display()))?;

    if let Some(hex_digest) = &args.digest {
        let digest = hex::decode(hex_digest.trim())
            .map_err(|_| anyhow::anyhow!("digest must be hexadecimal"))?;
        if digest != detached.file_digest() {
            anyhow::bail!(
                "digest provided does not match digest in timestamp, {} ({})",
                hex::encode(detached.file_digest()),
                detached.file_hash_op.name()
            );
        }
    } else {
        let target_path = match &args.target {
            Some(p) => p.clone(),
            None => {
                let name = args.timestamp.to_string_lossy();
                let stripped = name
                    .strip_suffix(".ots")
                    .ok_or_else(|| anyhow::anyhow!("timestamp filename does not end in .ots"))?;
                log.info(&format!("Assuming target filename is {stripped:?}"));
                std::path::PathBuf::from(stripped)
            }
        };

        let file = std::fs::File::open(&target_path)
            .map_err(|e| anyhow::anyhow!("could not open target: {e}"))?;
        let actual = crate::hashing::hash_reader(file, &detached.file_hash_op)?;
        if actual != detached.file_digest() {
            anyhow::bail!("file does not match original!");
        }
    }

    // No calendar override for verify; rely on cache + whitelisted calendars.
    upgrade_timestamp(
        &mut detached.timestamp,
        &[],
        &ctx.whitelist,
        &ctx.cache,
        ctx.wait,
        ctx.wait_interval,
        |m| log.info(m),
    )
    .await;

    let mut attestations = detached.timestamp.all_attestations();
    attestations.sort_by_key(|(_, a)| match a {
        TimeAttestation::Bitcoin { height } => *height,
        _ => u64::MAX,
    });

    let mut good = false;
    for (msg, attestation) in attestations {
        match attestation {
            TimeAttestation::Pending { .. } => {}
            TimeAttestation::Bitcoin { height } => {
                let Some(esplora) = &ctx.esplora else {
                    log.warn("Not checking Bitcoin attestation; Bitcoin disabled");
                    log.info(&format!(
                        "To verify manually, check that Bitcoin block {height} has merkleroot {}",
                        hex::encode(reversed(msg))
                    ));
                    continue;
                };

                match esplora.verify_merkle_root(msg, *height).await {
                    Ok(v) => {
                        let dt = chrono_like_format(v.block_time);
                        log.info(&format!(
                            "Success! Bitcoin block {height} attests existence as of {dt}"
                        ));
                        good = true;
                        break;
                    }
                    Err(e) => {
                        log.error(&format!("Bitcoin verification failed: {e}"));
                    }
                }
            }
            other => {
                log.error(&format!("Could not verify; verification with {other} not supported"));
            }
        }
    }

    if !good {
        anyhow::bail!("verification failed");
    }
    Ok(())
}

fn reversed(b: &[u8]) -> Vec<u8> {
    let mut v = b.to_vec();
    v.reverse();
    v
}

/// Format a unix timestamp as `YYYY-MM-DD HH:MM:SS UTC` without pulling in a
/// date/time crate.
fn chrono_like_format(unix_time: u64) -> String {
    const SECS_PER_DAY: u64 = 86400;
    let days = unix_time / SECS_PER_DAY;
    let secs_of_day = unix_time % SECS_PER_DAY;

    // Civil-from-days algorithm (Howard Hinnant's date algorithms), proleptic Gregorian.
    let z = days as i64 + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };

    let h = secs_of_day / 3600;
    let min = (secs_of_day % 3600) / 60;
    let s = secs_of_day % 60;

    format!("{y:04}-{m:02}-{d:02} {h:02}:{min:02}:{s:02} UTC")
}
