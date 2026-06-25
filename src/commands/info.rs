use crate::cli::InfoArgs;
use crate::context::Context;
use crate::ots::serialize::Reader;
use crate::ots::timestamp::DetachedTimestampFile;

pub async fn run(args: InfoArgs, ctx: &Context) -> anyhow::Result<()> {
    let bytes = std::fs::read(&args.file)
        .map_err(|e| anyhow::anyhow!("could not read {}: {e}", args.file.display()))?;
    let mut r = Reader::new(&bytes);
    let detached = DetachedTimestampFile::deserialize(&mut r)
        .map_err(|e| anyhow::anyhow!("invalid timestamp file {}: {e}", args.file.display()))?;

    println!(
        "File {} hash: {}",
        detached.file_hash_op.name(),
        hex::encode(detached.file_digest())
    );
    println!("Timestamp:");
    print!("{}", detached.timestamp.str_tree(0, ctx.log.level.max(0)));

    Ok(())
}
