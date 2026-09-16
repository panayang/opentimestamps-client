use crate::cli::UpgradeArgs;
use crate::context::Context;
use crate::ots::serialize::{Reader, Writer};
use crate::ots::timestamp::DetachedTimestampFile;
use crate::upgrade::{is_timestamp_complete, upgrade_timestamp};

pub async fn run(args: UpgradeArgs, ctx: &Context) -> anyhow::Result<()> {
    let log = ctx.log;

    for path in &args.files {
        log.debug(&format!("Upgrading {}", path.display()));

        let bytes = std::fs::read(path)
            .map_err(|e| anyhow::anyhow!("could not read {}: {e}", path.display()))?;
        let mut r = Reader::new(&bytes);
        let mut detached = DetachedTimestampFile::deserialize(&mut r)
            .map_err(|e| anyhow::anyhow!("invalid timestamp file {}: {e}", path.display()))?;

        let changed = upgrade_timestamp(
            &mut detached.timestamp,
            &args.calendars,
            &ctx.whitelist,
            &ctx.cache,
            ctx.wait,
            ctx.wait_interval,
            |m| log.info(m),
        )
        .await;

        if changed && !args.dry_run {
            let backup = backup_path(path);
            if backup.exists() {
                anyhow::bail!(
                    "could not back up timestamp: {} already exists",
                    backup.display()
                );
            }
            std::fs::rename(path, &backup)?;

            let mut w = Writer::new();
            detached.serialize(&mut w)?;
            std::fs::write(path, w.into_bytes())?;
        }

        if is_timestamp_complete(&detached.timestamp) {
            log.info(&format!(
                "Success! Timestamp for {} is complete",
                path.display()
            ));
        } else {
            anyhow::bail!("Failed! Timestamp for {} is not complete", path.display());
        }
    }

    Ok(())
}

fn backup_path(path: &std::path::Path) -> std::path::PathBuf {
    let mut s = path.as_os_str().to_os_string();
    s.push(".bak");
    std::path::PathBuf::from(s)
}
