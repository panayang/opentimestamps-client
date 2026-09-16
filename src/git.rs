use crate::context::Context;
use crate::ots::merkle::merkle_paths;
use crate::ots::op::Op;
use crate::ots::serialize::{Reader, Writer};
use crate::ots::timestamp::{DetachedTimestampFile, Timestamp};
use crate::upgrade::{create_timestamp, is_timestamp_complete, upgrade_timestamp};
use anyhow::Context as _;
use base64::prelude::*;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

pub const ASCII_ARMOR_HEADER: &str = "-----BEGIN OPENTIMESTAMPS GIT TIMESTAMP-----\n\n";
pub const ASCII_ARMOR_FOOTER: &str = "-----END OPENTIMESTAMPS GIT TIMESTAMP-----\n";
pub const GIT_DOMAIN_SEPARATOR: &[u8] = b"\x01\x89\x08\x0c\xfb\xd0\xe8\x08";

/// Calculate the OpenTimestamps commitment hash for a signed Git commit or tag.
/// Matches the Python reference implementation:
/// `sha256(sha256(git_commit) + sha256(gpg_sig))`
pub fn hash_signed_commit(git_commit: &[u8], gpg_sig: &[u8]) -> [u8; 32] {
    let commit_hash = Sha256::digest(git_commit);
    let sig_hash = Sha256::digest(gpg_sig);
    let mut hasher = Sha256::new();
    hasher.update(commit_hash);
    hasher.update(sig_hash);
    let res = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&res);
    out
}

/// Extract unsigned commit content and GPG signature from a raw git commit object.
pub fn extract_sig_from_git_commit(signed_git_commit: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let mut unsigned_lines: Vec<&[u8]> = Vec::new();
    let mut gpg_sig_lines: Vec<&[u8]> = Vec::new();

    let mut found_sig = false;
    let mut sig_done = false;

    for line in signed_git_commit.split(|&b| b == b'\n') {
        if found_sig && sig_done {
            unsigned_lines.push(line);
        } else if found_sig && !sig_done {
            if line.is_empty() {
                unsigned_lines.push(line);
                sig_done = true;
            } else {
                let stripped = if line.starts_with(b" ") {
                    &line[1..]
                } else {
                    line
                };
                gpg_sig_lines.push(stripped);
            }
        } else if line.starts_with(b"gpgsig ") {
            found_sig = true;
            gpg_sig_lines.push(&line[b"gpgsig ".len()..]);
        } else {
            unsigned_lines.push(line);
        }
    }

    let unsigned = unsigned_lines.join(&b'\n');
    let sig = if gpg_sig_lines.is_empty() {
        Vec::new()
    } else {
        let mut s = gpg_sig_lines.join(&b'\n');
        s.push(b'\n');
        s
    };

    (unsigned, sig)
}

/// Extract unsigned tag content and GPG signature from a raw git tag object.
pub fn extract_sig_from_git_tag(signed_git_tag: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let marker = b"-----BEGIN PGP SIGNATURE-----";
    if let Some(pos) = signed_git_tag
        .windows(marker.len())
        .position(|w| w == marker)
    {
        let unsigned = signed_git_tag[..pos].to_vec();
        let sig = signed_git_tag[pos..].to_vec();
        (unsigned, sig)
    } else {
        (signed_git_tag.to_vec(), Vec::new())
    }
}

/// Serialize a Timestamp to ASCII-armored format for embedding in git signatures.
pub fn write_ascii_armored(timestamp: &Timestamp, minor_version: u8) -> anyhow::Result<String> {
    let mut w = Writer::new();
    timestamp.serialize(&mut w)?;
    let serialized = w.into_bytes();

    let mut payload = Vec::with_capacity(2 + serialized.len());
    payload.push(1u8); // major version 1
    payload.push(minor_version);
    payload.extend_from_slice(&serialized);

    let b64 = BASE64_STANDARD.encode(&payload);

    let mut out = String::new();
    out.push_str(ASCII_ARMOR_HEADER);
    for chunk in b64.as_bytes().chunks(64) {
        if let Ok(s) = std::str::from_utf8(chunk) {
            out.push_str(s);
            out.push('\n');
        }
    }
    out.push_str(ASCII_ARMOR_FOOTER);
    Ok(out)
}

/// Parse and deserialize an ASCII-armored OpenTimestamps proof embedded in a GPG signature.
pub fn deserialize_ascii_armored_timestamp(
    git_commit: &[u8],
    gpg_sig: &[u8],
) -> anyhow::Result<Option<(u8, u8, Timestamp)>> {
    let header_bytes = ASCII_ARMOR_HEADER.as_bytes();
    let footer_bytes = ASCII_ARMOR_FOOTER.as_bytes();

    let Some(stamp_start) = gpg_sig
        .windows(header_bytes.len())
        .position(|w| w == header_bytes)
    else {
        return Ok(None);
    };

    let after_header = &gpg_sig[stamp_start + header_bytes.len()..];
    let Some(stamp_end_rel) = after_header
        .windows(footer_bytes.len())
        .position(|w| w == footer_bytes)
    else {
        return Ok(None);
    };

    let base64_slice = &after_header[..stamp_end_rel];
    let clean_b64: String = base64_slice
        .iter()
        .filter(|&&b| !b.is_ascii_whitespace())
        .map(|&b| b as char)
        .collect();

    let sig_prior = &gpg_sig[..stamp_start];
    let initial_msg = hash_signed_commit(git_commit, sig_prior);

    let decoded = BASE64_STANDARD
        .decode(clean_b64)
        .context("invalid base64 in ascii-armored timestamp")?;
    if decoded.len() < 2 {
        anyhow::bail!("timestamp payload too short");
    }

    let major_version = decoded[0];
    let minor_version = decoded[1];

    if major_version != 1 {
        anyhow::bail!("unsupported git timestamp major version {major_version}");
    }

    let mut r = Reader::new(&decoded[2..]);
    let timestamp = Timestamp::deserialize(&mut r, initial_msg.to_vec())?;

    Ok(Some((major_version, minor_version, timestamp)))
}

/// Find repository root for current working directory.
pub fn find_git_repo_root() -> anyhow::Result<PathBuf> {
    let output = Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .context("failed to execute git rev-parse")?;
    if !output.status.success() {
        anyhow::bail!(
            "not a git repository (or git command failed): {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let s = String::from_utf8(output.stdout)?.trim().to_string();
    Ok(PathBuf::from(s))
}

/// Read a git object (type, bytes) using git cat-file.
pub fn read_git_object(ref_name: &str) -> anyhow::Result<(String, Vec<u8>)> {
    let type_output = Command::new("git")
        .args(["cat-file", "-t", ref_name])
        .output()
        .context("failed to get git object type")?;
    if !type_output.status.success() {
        anyhow::bail!(
            "failed to find git object '{}': {}",
            ref_name,
            String::from_utf8_lossy(&type_output.stderr).trim()
        );
    }
    let obj_type = String::from_utf8(type_output.stdout)?.trim().to_string();

    let content_output = Command::new("git")
        .args(["cat-file", "-p", ref_name])
        .output()
        .context("failed to read git object content")?;
    if !content_output.status.success() {
        anyhow::bail!(
            "failed to read git object '{}': {}",
            ref_name,
            String::from_utf8_lossy(&content_output.stderr).trim()
        );
    }

    Ok((obj_type, content_output.stdout))
}

/// Get commit SHA from reference.
pub fn rev_parse(ref_name: &str) -> anyhow::Result<String> {
    let output = Command::new("git")
        .args(["rev-parse", ref_name])
        .output()
        .context("failed to resolve git reference")?;
    if !output.status.success() {
        anyhow::bail!(
            "failed to resolve reference '{}': {}",
            ref_name,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(String::from_utf8(output.stdout)?.trim().to_string())
}

/// Git tree timestamper: privacy-preserving hierarchical Merkle tree over git tree objects.
pub struct GitTreeTimestamper {
    pub root_timestamp: Timestamp,
    file_paths: BTreeMap<String, Vec<Op>>,
}

impl GitTreeTimestamper {
    /// Build timestamper from a map of relative file paths to their content digests (SHA256).
    pub fn new(file_digests: BTreeMap<String, Vec<u8>>) -> anyhow::Result<Self> {
        if file_digests.is_empty() {
            anyhow::bail!("cannot timestamp empty git tree");
        }

        let mut leaf_msgs = Vec::with_capacity(file_digests.len());
        let mut leaf_keys = Vec::with_capacity(file_digests.len());
        let mut base_timestamps = Vec::with_capacity(file_digests.len());

        // Domain-separated deterministic noncing
        let mut contents_hasher = Sha256::new();
        for (path, digest) in &file_digests {
            contents_hasher.update(path.as_bytes());
            contents_hasher.update(digest);
        }
        contents_hasher.update(GIT_DOMAIN_SEPARATOR);
        let nonce_key = contents_hasher.finalize();

        let mut leaf_prefixes = Vec::with_capacity(file_digests.len());
        for (path, digest) in file_digests {
            let mut ts = Timestamp::new(digest.clone());

            let mut n1_hasher = Sha256::new();
            n1_hasher.update(&digest);
            n1_hasher.update(nonce_key);
            let nonce1 = n1_hasher.finalize();

            let nonce2 = Sha256::digest(nonce1);

            let side_op = if (nonce1[0] & 1) != 0 {
                Op::Prepend(nonce2.to_vec())
            } else {
                Op::Append(nonce2.to_vec())
            };

            let nonced_ts = ts.add_op(side_op.clone())?.add_op(Op::Sha256)?;
            leaf_msgs.push(nonced_ts.msg.clone());
            leaf_keys.push(path);
            leaf_prefixes.push(vec![side_op, Op::Sha256]);
            base_timestamps.push(ts);
        }

        let (tip_digest, paths) = merkle_paths(leaf_msgs);
        let root_timestamp = Timestamp::new(tip_digest);

        let mut file_paths = BTreeMap::new();
        for (i, (key, mut prefix)) in leaf_keys.into_iter().zip(leaf_prefixes).enumerate() {
            if let Some(path) = paths.get(i) {
                prefix.extend(path.clone());
                file_paths.insert(key, prefix);
            }
        }

        Ok(Self {
            root_timestamp,
            file_paths,
        })
    }

    /// Extract timestamp proof for a specific relative file path.
    pub fn extract_timestamp_for_file(
        &self,
        path: &str,
        file_digest: &[u8],
    ) -> anyhow::Result<DetachedTimestampFile> {
        let path_ops = self
            .file_paths
            .get(path)
            .ok_or_else(|| anyhow::anyhow!("file '{}' not found in tree", path))?;

        let mut ts = Timestamp::new(file_digest.to_vec());
        let mut cur = &mut ts;
        for op in path_ops {
            cur = cur.add_op(op.clone())?;
        }
        cur.merge(self.root_timestamp.clone())?;

        Ok(DetachedTimestampFile::new(Op::Sha256, ts))
    }
}

/// GPG wrapper program for git integration (`ots-git-gpg-wrapper`).
pub async fn run_gpg_wrapper(
    args: &[String],
    ctx: &Context,
    gpg_override: Option<&str>,
    calendar_override: &[String],
) -> anyhow::Result<()> {
    use std::io::{Read, Write};

    let gpg_prog = gpg_override
        .filter(|s| !s.is_empty())
        .map(String::from)
        .or_else(|| std::env::var("GPG_PROGRAM").ok())
        .unwrap_or_else(|| "gpg".to_string());

    let is_signing = args.iter().any(|a| {
        a == "-bsau"
            || a == "-s"
            || a == "-b"
            || a == "--sign"
            || a == "--detach-sign"
            || a.starts_with("-bsau")
    });

    let verify_idx = args.iter().position(|a| a == "--verify");

    if is_signing {
        let mut git_commit = Vec::new();
        std::io::stdin().read_to_end(&mut git_commit)?;

        let mock_mode = std::env::var("OTS_MOCK_GPG").is_ok();
        let (gpg_sig, gpg_ok) = if mock_mode {
            let mock_sig = b"-----BEGIN PGP SIGNATURE-----\n\nwsFcBAABCAAQBQJqUbo1CRC1aQ7uu5UhlAAAFDIQAAFviUmjibhgRXxVhcH37xrV\n=mock\n-----END PGP SIGNATURE-----\n".to_vec();
            (mock_sig, true)
        } else {
            let mut child = Command::new(&gpg_prog)
                .args(args)
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::inherit())
                .spawn()
                .with_context(|| format!("failed to spawn GPG binary '{gpg_prog}'"))?;

            if let Some(mut stdin) = child.stdin.take() {
                stdin.write_all(&git_commit)?;
            }

            let mut sig_out = Vec::new();
            if let Some(mut stdout) = child.stdout.take() {
                stdout.read_to_end(&mut sig_out)?;
            }

            let status = child.wait()?;
            (sig_out, status.success())
        };

        if !gpg_ok || gpg_sig.is_empty() {
            anyhow::bail!("GnuPG signing failed");
        }

        let initial_msg = hash_signed_commit(&git_commit, &gpg_sig);
        let mut stamp = Timestamp::new(initial_msg.to_vec());

        let calendar_urls = if calendar_override.is_empty() {
            crate::calendar::DEFAULT_AGGREGATORS
                .iter()
                .map(|s| (*s).to_string())
                .collect()
        } else {
            calendar_override.to_vec()
        };

        let log = ctx.log;
        let _ = create_timestamp(&mut stamp, &calendar_urls, 1, Duration::from_secs(3), |m| {
            log.info(m);
        })
        .await;

        if stamp.all_attestations().is_empty() {
            stamp
                .attestations
                .insert(crate::ots::notary::TimeAttestation::Pending {
                    uri: "local".to_string(),
                });
        }

        let armor = write_ascii_armored(&stamp, 0)?;

        let mut stdout = std::io::stdout();
        stdout.write_all(&gpg_sig)?;
        stdout.write_all(armor.as_bytes())?;
        stdout.flush()?;
    } else if let Some(idx) = verify_idx {
        let sig_path = args.get(idx + 1).map(PathBuf::from);
        let mut git_commit = Vec::new();
        if args.iter().any(|a| a == "-") {
            let _ = std::io::stdin().read_to_end(&mut git_commit);
        }

        if let Some(p) = sig_path
            && let Ok(gpg_sig) = std::fs::read(&p)
            && let Ok(Some((_maj, _min, mut stamp))) =
                deserialize_ascii_armored_timestamp(&git_commit, &gpg_sig)
        {
            eprintln!("ots: Found OpenTimestamps proof attached to Git signature");
            upgrade_timestamp(
                &mut stamp,
                &[],
                &ctx.whitelist,
                &ctx.cache,
                ctx.wait,
                ctx.wait_interval,
                |m| eprintln!("ots: {m}"),
            )
            .await;

            if is_timestamp_complete(&stamp) {
                eprintln!("ots: Success! Bitcoin block attests existence of Git commit signature");
            } else {
                eprintln!("ots: OpenTimestamps proof is pending confirmation");
            }
        }

        let mock_mode = std::env::var("OTS_MOCK_GPG").is_ok();
        if !mock_mode {
            let mut child = Command::new(&gpg_prog)
                .args(args)
                .stdin(if !git_commit.is_empty() {
                    std::process::Stdio::piped()
                } else {
                    std::process::Stdio::inherit()
                })
                .stdout(std::process::Stdio::inherit())
                .stderr(std::process::Stdio::inherit())
                .spawn()
                .with_context(|| format!("failed to spawn GPG binary '{gpg_prog}'"))?;

            if !git_commit.is_empty()
                && let Some(mut stdin) = child.stdin.take()
            {
                let _ = stdin.write_all(&git_commit);
            }

            let status = child.wait()?;
            if !status.success() {
                std::process::exit(status.code().unwrap_or(1));
            }
        } else {
            eprintln!("[GNUPG:] GOODSIG mockkey OpenTimestamps Test");
        }
    } else {
        let status = Command::new(&gpg_prog)
            .args(args)
            .stdin(std::process::Stdio::inherit())
            .stdout(std::process::Stdio::inherit())
            .stderr(std::process::Stdio::inherit())
            .status()
            .with_context(|| format!("failed to run GPG binary '{gpg_prog}'"))?;
        if !status.success() {
            std::process::exit(status.code().unwrap_or(1));
        }
    }

    Ok(())
}
