use crate::cli::InfoArgs;
use crate::context::Context;
use crate::ots::notary::TimeAttestation;
use crate::ots::serialize::Reader;
use crate::ots::timestamp::DetachedTimestampFile;
use std::io::Read;

pub async fn run(args: InfoArgs, ctx: &Context) -> anyhow::Result<()> {
    let bytes = if args.file.as_os_str() == "-" {
        let mut buf = Vec::new();
        std::io::stdin().read_to_end(&mut buf)?;
        buf
    } else {
        std::fs::read(&args.file)
            .map_err(|e| anyhow::anyhow!("could not read {}: {e}", args.file.display()))?
    };

    let mut r = Reader::new(&bytes);
    let detached = DetachedTimestampFile::deserialize(&mut r)
        .map_err(|e| anyhow::anyhow!("invalid timestamp file {}: {e}", args.file.display()))?;

    if args.json {
        let attestations: Vec<serde_json::Value> = detached
            .timestamp
            .all_attestations()
            .into_iter()
            .map(|(msg, a)| match a {
                TimeAttestation::Bitcoin { height } => {
                    let mut rev = msg.to_vec();
                    rev.reverse();
                    serde_json::json!({
                        "type": "bitcoin",
                        "height": height,
                        "merkle_root": hex::encode(rev)
                    })
                }
                TimeAttestation::Litecoin { height } => {
                    let mut rev = msg.to_vec();
                    rev.reverse();
                    serde_json::json!({
                        "type": "litecoin",
                        "height": height,
                        "merkle_root": hex::encode(rev)
                    })
                }
                TimeAttestation::Pending { uri } => serde_json::json!({
                    "type": "pending",
                    "uri": uri
                }),
                TimeAttestation::Unknown { tag, payload } => serde_json::json!({
                    "type": "unknown",
                    "tag": tag,
                    "payload": hex::encode(payload)
                }),
                TimeAttestation::Ethereum { .. } => serde_json::json!({
                    "type": "ethereum"
                }),
            })
            .collect();

        let json_val = serde_json::json!({
            "file": if args.file.as_os_str() == "-" { "stdin" } else { args.file.to_str().unwrap_or("") },
            "hash_algorithm": detached.file_hash_op.name(),
            "digest": hex::encode(detached.file_digest()),
            "attestations": attestations,
        });
        println!("{}", serde_json::to_string_pretty(&json_val)?);
    } else {
        println!(
            "File {} hash: {}",
            detached.file_hash_op.name(),
            hex::encode(detached.file_digest())
        );
        println!("Timestamp:");
        print!("{}", detached.timestamp.str_tree(0, ctx.log.level.max(0)));
    }

    Ok(())
}
