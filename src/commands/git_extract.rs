use crate::cli::GitExtractArgs;
use crate::context::Context;
use crate::git::{
    GitTreeTimestamper, deserialize_ascii_armored_timestamp, extract_sig_from_git_commit,
    find_git_repo_root, read_git_object, rev_parse,
};
use crate::ots::serialize::Writer;
use anyhow::Context as _;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::Command;

pub async fn run(args: GitExtractArgs, ctx: &Context) -> anyhow::Result<()> {
    let log = ctx.log;
    let commit_hash = rev_parse(&args.commit)?;
    let (obj_type, raw_data) = read_git_object(&args.commit)?;

    if obj_type != "commit" {
        anyhow::bail!("git-extract requires a commit object, found '{obj_type}'");
    }

    let (unsigned, sig) = extract_sig_from_git_commit(&raw_data);
    if sig.is_empty() {
        anyhow::bail!("commit {commit_hash} is not signed");
    }

    let Some((_maj, _minor, commit_stamp)) = deserialize_ascii_armored_timestamp(&unsigned, &sig)?
    else {
        anyhow::bail!(
            "commit {commit_hash} is signed, but does not contain an OpenTimestamps proof"
        );
    };

    let _repo_root = find_git_repo_root()?;

    // Read files in commit using git ls-tree -r
    let output = Command::new("git")
        .args(["ls-tree", "-r", &commit_hash])
        .output()
        .context("failed to run git ls-tree")?;
    if !output.status.success() {
        anyhow::bail!("failed to inspect tree for commit {commit_hash}");
    }

    let ls_tree_out = String::from_utf8_lossy(&output.stdout);
    let mut file_digests: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    let mut target_digest: Option<Vec<u8>> = None;

    for line in ls_tree_out.lines() {
        // Format: <mode> SP <type> SP <object> TAB <file>
        let parts: Vec<&str> = line.splitn(2, '\t').collect();
        if parts.len() != 2 {
            continue;
        }
        let file_path = parts[1].to_string();
        let meta: Vec<&str> = parts[0].split_whitespace().collect();
        if meta.len() < 3 || meta[1] != "blob" {
            continue;
        }
        let blob_sha1 = meta[2];

        // Hash blob contents with sha256
        let blob_out = Command::new("git")
            .args(["cat-file", "-p", blob_sha1])
            .output()?;
        if blob_out.status.success() {
            use sha2::{Digest, Sha256};
            let digest = Sha256::digest(&blob_out.stdout).to_vec();
            if file_path == args.path {
                target_digest = Some(digest.clone());
            }
            file_digests.insert(file_path, digest);
        }
    }

    let target_hash = target_digest.ok_or_else(|| {
        anyhow::anyhow!("file '{}' not found in commit {}", args.path, commit_hash)
    })?;

    let timestamper = GitTreeTimestamper::new(file_digests)?;
    let mut detached = timestamper.extract_timestamp_for_file(&args.path, &target_hash)?;

    // Splice in the root commitment from the commit
    detached.timestamp.merge(commit_stamp)?;

    let mut w = Writer::new();
    detached.serialize(&mut w)?;
    let bytes = w.into_bytes();

    let out_file = args
        .timestamp_file
        .unwrap_or_else(|| PathBuf::from(format!("{}.ots", args.path)));

    if let Some(p) = out_file.parent() {
        let _ = std::fs::create_dir_all(p);
    }
    std::fs::write(&out_file, bytes)?;

    log.info(&format!(
        "Extracted timestamp for '{}' to '{}'",
        args.path,
        out_file.display()
    ));

    Ok(())
}
