use ots_client::git::{
    ASCII_ARMOR_FOOTER, ASCII_ARMOR_HEADER, GitTreeTimestamper,
    deserialize_ascii_armored_timestamp, extract_sig_from_git_commit, extract_sig_from_git_tag,
    hash_signed_commit, write_ascii_armored,
};
use ots_client::ots::notary::TimeAttestation;
use ots_client::ots::op::Op;
use ots_client::ots::timestamp::Timestamp;
use std::collections::BTreeMap;
use std::process::Command;

#[test]
fn test_hash_signed_commit_computation() {
    let commit = b"tree d8329fc1cc938780ffdd9f94e0d364e0ea74f579\nauthor Test <test@test.com> 12345 +0000\ncommitter Test <test@test.com> 12345 +0000\n\nInitial commit\n";
    let sig = b"-----BEGIN PGP SIGNATURE-----\nVersion: GnuPG\n\niEYEARECAAYFAltest==\n-----END PGP SIGNATURE-----\n";

    let hash1 = hash_signed_commit(commit, sig);
    let hash2 = hash_signed_commit(commit, sig);
    assert_eq!(hash1, hash2);

    // Empty inputs test
    let hash_empty = hash_signed_commit(b"", b"");
    assert_eq!(hash_empty.len(), 32);

    // Changing either commit or signature must change the resulting hash
    let hash_diff_commit = hash_signed_commit(b"different commit", sig);
    let hash_diff_sig = hash_signed_commit(commit, b"different sig");
    assert_ne!(hash1, hash_diff_commit);
    assert_ne!(hash1, hash_diff_sig);
}

#[test]
fn test_extract_sig_from_git_commit() {
    let raw_commit = b"tree 47cf6325e99c9731fae3bfda9b5fb2c3e19b79bc
parent ee7614edfaf257bcc42e659c51d3c363bc016fb0
author Xinyu Yang <pana.yang@hotmail.com> 1783740981 +0800
committer GitHub <noreply@github.com> 1783740981 +0800
gpgsig -----BEGIN PGP SIGNATURE-----
 wsFcBAABCAAQBQJqUbo1CRC1aQ7uu5UhlAAAFDIQAAFviUmjibhgRXxVhcH37xrV
 Nu+p7lf6X7jUnfioapj9s8QIjvvPkd7cvo5lKBUyybaCtQMPheFmuAr5lF51ZMnq
 =7nKq
 -----END PGP SIGNATURE-----

Update licensing information in README

Clarified licensing terms.";

    let (unsigned, sig) = extract_sig_from_git_commit(raw_commit);

    // Verify gpgsig header is completely absent from unsigned commit
    assert!(!unsigned.windows(b"gpgsig".len()).any(|w| w == b"gpgsig"));
    assert!(
        unsigned
            .windows(b"tree 47cf6325e99c9731fae3bfda9b5fb2c3e19b79bc".len())
            .any(|w| w == b"tree 47cf6325e99c9731fae3bfda9b5fb2c3e19b79bc")
    );
    assert!(
        unsigned
            .windows(b"Update licensing information in README".len())
            .any(|w| w == b"Update licensing information in README")
    );

    // Verify signature begins with PGP header and has leading continuation space stripped
    assert!(sig.starts_with(b"-----BEGIN PGP SIGNATURE-----\n"));
    assert!(
        sig.windows(b"\nwsFcBAABCAAQBQJqUbo1CRC1aQ7uu5UhlAAAFDIQAAFviUmjibhgRXxVhcH37xrV\n".len())
            .any(|w| w == b"\nwsFcBAABCAAQBQJqUbo1CRC1aQ7uu5UhlAAAFDIQAAFviUmjibhgRXxVhcH37xrV\n")
    );
    assert!(sig.ends_with(b"-----END PGP SIGNATURE-----\n"));

    // Test commit with no signature
    let unsigned_raw = b"tree 47cf6325e99c9731fae3bfda9b5fb2c3e19b79bc\nauthor Test\n\nNo sig\n";
    let (u2, s2) = extract_sig_from_git_commit(unsigned_raw);
    assert_eq!(&u2[..], &unsigned_raw[..]);
    assert!(s2.is_empty());
}

#[test]
fn test_extract_sig_from_git_tag() {
    let raw_tag = b"object 7b83077600c4fc88b2e519d4bc0a0dea6d3d6396
type commit
tag v1.0.0
tagger Author <author@test.com> 12345 +0000

Release version 1.0.0
-----BEGIN PGP SIGNATURE-----
Version: GnuPG
iEYEARECAAYFAltest==
-----END PGP SIGNATURE-----
";

    let (unsigned, sig) = extract_sig_from_git_tag(raw_tag);
    assert!(unsigned.starts_with(b"object 7b83077600c4fc88b2e519d4bc0a0dea6d3d6396"));
    assert!(unsigned.ends_with(b"Release version 1.0.0\n"));
    assert!(sig.starts_with(b"-----BEGIN PGP SIGNATURE-----"));
    assert!(sig.ends_with(b"-----END PGP SIGNATURE-----\n"));
}

#[test]
fn test_ascii_armored_timestamp_roundtrip() {
    let commit = b"commit payload without gpg signature";
    let prior_sig = b"-----BEGIN PGP SIGNATURE-----\nVersion: GnuPG\n\niEYEARECAAYFAltest==\n-----END PGP SIGNATURE-----\n";

    let initial_msg = hash_signed_commit(commit, prior_sig);
    let mut stamp = Timestamp::new(initial_msg.to_vec());
    let leaf = stamp
        .add_op(Op::Append(vec![1, 2, 3]))
        .unwrap()
        .add_op(Op::Sha256)
        .unwrap();
    leaf.attestations
        .insert(TimeAttestation::Bitcoin { height: 700000 });

    let armor = write_ascii_armored(&stamp, 1).unwrap();
    assert!(armor.starts_with(ASCII_ARMOR_HEADER));
    assert!(armor.ends_with(ASCII_ARMOR_FOOTER));

    // Combine signature with OpenTimestamps armor
    let mut combined_sig = prior_sig.to_vec();
    combined_sig.extend_from_slice(armor.as_bytes());

    let (maj, min, deserialized) = deserialize_ascii_armored_timestamp(commit, &combined_sig)
        .unwrap()
        .expect("should find and deserialize ascii armored timestamp");

    assert_eq!(maj, 1);
    assert_eq!(min, 1);
    assert_eq!(deserialized.msg, initial_msg.to_vec());
    assert_eq!(deserialized.all_attestations().len(), 1);
}

#[test]
fn test_git_tree_timestamper() {
    let mut files = BTreeMap::new();
    files.insert("README.md".to_string(), vec![0x11; 32]);
    files.insert("src/main.rs".to_string(), vec![0x22; 32]);
    files.insert("Cargo.toml".to_string(), vec![0x33; 32]);

    let timestamper = GitTreeTimestamper::new(files.clone()).unwrap();

    for (path, digest) in &files {
        let detached = timestamper
            .extract_timestamp_for_file(path, digest)
            .unwrap();
        assert_eq!(detached.file_digest(), digest);
        assert_eq!(detached.file_hash_op, Op::Sha256);
    }

    // Asking for nonexistent file should fail
    assert!(
        timestamper
            .extract_timestamp_for_file("nonexistent.txt", &[0u8; 32])
            .is_err()
    );
}

#[test]
fn test_git_repository_e2e_workflow() {
    let temp_dir = std::env::temp_dir().join(format!("ots_git_test_{}", rand::random::<u64>()));
    std::fs::create_dir_all(&temp_dir).unwrap();

    // 1. Initialize git repo
    let run = |args: &[&str]| {
        let out = Command::new("git")
            .current_dir(&temp_dir)
            .args(args)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "git {:?} failed: {:?}",
            args,
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    };

    run(&["init"]);
    run(&["config", "commit.gpgsign", "false"]);
    run(&["config", "user.name", "OTS Tester"]);
    run(&["config", "user.email", "tester@opentimestamps.org"]);

    let test_file = temp_dir.join("hello.txt");
    std::fs::write(&test_file, b"Hello OpenTimestamps VCS Integration!\n").unwrap();
    run(&["add", "hello.txt"]);
    run(&["commit", "-m", "Initial commit for VCS test"]);

    let head_commit = run(&["rev-parse", "HEAD"]);
    assert_eq!(head_commit.len(), 40);

    // 2. Run ots git stamp HEAD using compiled binary
    let ots_bin = env!("CARGO_BIN_EXE_ots");
    let stamp_out = Command::new(ots_bin)
        .current_dir(&temp_dir)
        .args(["git", "stamp", "HEAD", "-m", "0", "--timeout", "1"])
        .output()
        .unwrap();

    assert!(
        stamp_out.status.success(),
        "ots git stamp failed: {:?}",
        String::from_utf8_lossy(&stamp_out.stderr)
    );

    // Check that .git/ots/<commit>.ots exists
    let ots_file = temp_dir
        .join(".git")
        .join("ots")
        .join(format!("{head_commit}.ots"));
    assert!(
        ots_file.exists(),
        "timestamp proof file should be created in .git/ots/"
    );

    // 3. Run ots git verify HEAD --json on the freshly stamped pending commit
    let json_pending_out = Command::new(ots_bin)
        .current_dir(&temp_dir)
        .args(["--no-bitcoin", "git", "verify", "HEAD", "--json"])
        .output()
        .unwrap();
    let json_pending_str = String::from_utf8(json_pending_out.stdout).unwrap();
    let pending_parsed: serde_json::Value =
        serde_json::from_str(&json_pending_str).expect("output must be valid JSON");
    assert_eq!(pending_parsed["commit"], head_commit);
    assert_eq!(pending_parsed["object_type"], "commit");
    assert_eq!(pending_parsed["pending"], true);
    assert_eq!(pending_parsed["verified"], false);

    // 4. Upgrade the commit's proof with a confirmed Bitcoin block attestation
    {
        use ots_client::ots::serialize::{Reader, Writer};
        use ots_client::ots::timestamp::DetachedTimestampFile;

        let bytes = std::fs::read(&ots_file).unwrap();
        let mut r = Reader::new(&bytes);
        let mut detached = DetachedTimestampFile::deserialize(&mut r).unwrap();
        detached
            .timestamp
            .attestations
            .insert(TimeAttestation::Bitcoin { height: 750000 });

        let mut w = Writer::new();
        detached.serialize(&mut w).unwrap();
        std::fs::write(&ots_file, w.into_bytes()).unwrap();
    }

    // 5. Run ots git verify HEAD with --no-bitcoin (offline verification)
    let verify_out = Command::new(ots_bin)
        .current_dir(&temp_dir)
        .args(["--no-bitcoin", "git", "verify", "HEAD"])
        .output()
        .unwrap();
    assert!(
        verify_out.status.success(),
        "ots git verify failed: {:?}",
        String::from_utf8_lossy(&verify_out.stderr)
    );

    // 6. Run ots git verify HEAD --json and verify verified=true
    let json_out = Command::new(ots_bin)
        .current_dir(&temp_dir)
        .args(["--no-bitcoin", "git", "verify", "HEAD", "--json"])
        .output()
        .unwrap();
    assert!(json_out.status.success());
    let json_str = String::from_utf8(json_out.stdout).unwrap();
    let parsed: serde_json::Value =
        serde_json::from_str(&json_str).expect("output must be valid JSON");
    assert_eq!(parsed["commit"], head_commit);
    assert_eq!(parsed["verified"], true);
    assert_eq!(parsed["bitcoin_block"], 750000);

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_ots_git_gpg_wrapper_execution() {
    let wrapper_bin = env!("CARGO_BIN_EXE_ots-git-gpg-wrapper");
    let ots_bin = env!("CARGO_BIN_EXE_ots");

    let git_commit_data = b"tree 47cf6325e99c9731fae3bfda9b5fb2c3e19b79bc\nauthor Developer <dev@test.org> 1234567890 +0000\ncommitter Developer <dev@test.org> 1234567890 +0000\n\nAdd critical security fix\n";

    // 1. Test signing via standalone binary ots-git-gpg-wrapper
    use std::io::Write;
    let mut child = Command::new(wrapper_bin)
        .env("OTS_MOCK_GPG", "1")
        .args(["-bsau", "key123"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::inherit())
        .spawn()
        .unwrap();

    child
        .stdin
        .take()
        .unwrap()
        .write_all(git_commit_data)
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());

    let combined_sig = output.stdout;
    assert!(
        combined_sig
            .windows(b"-----BEGIN PGP SIGNATURE-----".len())
            .any(|w| w == b"-----BEGIN PGP SIGNATURE-----")
    );
    assert!(
        combined_sig
            .windows(ASCII_ARMOR_HEADER.len())
            .any(|w| w == ASCII_ARMOR_HEADER.as_bytes())
    );
    assert!(
        combined_sig
            .windows(ASCII_ARMOR_FOOTER.len())
            .any(|w| w == ASCII_ARMOR_FOOTER.as_bytes())
    );

    // Verify deserialize_ascii_armored_timestamp parses the wrapper's output
    let (maj, min, stamp) = deserialize_ascii_armored_timestamp(git_commit_data, &combined_sig)
        .unwrap()
        .expect("wrapper output must be parseable");
    assert_eq!(maj, 1);
    assert_eq!(min, 0);
    assert!(!stamp.msg.is_empty());

    // 2. Test verifying via wrapper
    let temp_sig = std::env::temp_dir().join(format!("ots_sig_test_{}", rand::random::<u64>()));
    std::fs::write(&temp_sig, &combined_sig).unwrap();

    let mut verify_child = Command::new(wrapper_bin)
        .env("OTS_MOCK_GPG", "1")
        .args(["--verify", temp_sig.to_str().unwrap(), "-"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();

    verify_child
        .stdin
        .take()
        .unwrap()
        .write_all(git_commit_data)
        .unwrap();
    let verify_output = verify_child.wait_with_output().unwrap();
    assert!(verify_output.status.success());

    // 3. Test wrapper invocation through ots CLI subcommand: ots git gpg-wrapper
    let mut cli_child = Command::new(ots_bin)
        .env("OTS_MOCK_GPG", "1")
        .args(["git", "gpg-wrapper", "--", "-bsau", "key123"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::inherit())
        .spawn()
        .unwrap();

    cli_child
        .stdin
        .take()
        .unwrap()
        .write_all(git_commit_data)
        .unwrap();
    let cli_output = cli_child.wait_with_output().unwrap();
    assert!(cli_output.status.success());
    assert!(
        cli_output
            .stdout
            .windows(ASCII_ARMOR_HEADER.len())
            .any(|w| w == ASCII_ARMOR_HEADER.as_bytes())
    );

    let _ = std::fs::remove_file(&temp_sig);
}

#[test]
fn test_git_commit_and_tag_signing_with_real_gpg_program() {
    let gpg_check = Command::new("gpg").arg("--version").output();
    let git_check = Command::new("git").arg("--version").output();
    if gpg_check.is_err() || git_check.is_err() {
        eprintln!(
            "Skipping test_git_commit_and_tag_signing_with_real_gpg_program: git or gpg not found"
        );
        return;
    }

    let wrapper_bin = env!("CARGO_BIN_EXE_ots-git-gpg-wrapper");
    let ots_bin = env!("CARGO_BIN_EXE_ots");

    let temp_base = std::env::temp_dir().join(format!("ots_real_gpg_{}", rand::random::<u64>()));
    std::fs::create_dir_all(&temp_base).unwrap();

    let gnupg_home = temp_base.join("gnupg");
    std::fs::create_dir_all(&gnupg_home).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&gnupg_home, std::fs::Permissions::from_mode(0o700));
    }

    // Generate ephemeral gpg key
    let keygen_out = Command::new("gpg")
        .env("GNUPGHOME", &gnupg_home)
        .args([
            "--batch",
            "--passphrase",
            "",
            "--quick-generate-key",
            "OTS Test <ots@example.com>",
            "ed25519",
            "cert,sign",
            "never",
        ])
        .output()
        .expect("failed to generate ephemeral gpg key");
    assert!(
        keygen_out.status.success(),
        "gpg keygen failed: {}",
        String::from_utf8_lossy(&keygen_out.stderr)
    );

    let key_list = Command::new("gpg")
        .env("GNUPGHOME", &gnupg_home)
        .args(["--list-secret-keys", "--with-colons"])
        .output()
        .unwrap();
    let key_stdout = String::from_utf8_lossy(&key_list.stdout);
    let key_id = key_stdout
        .lines()
        .find(|l| l.starts_with("fpr:"))
        .and_then(|l| l.split(':').nth(9))
        .expect("must find fingerprint");

    let repo_dir = temp_base.join("repo");
    std::fs::create_dir_all(&repo_dir).unwrap();

    // Init git repo
    let init_out = Command::new("git")
        .args(["init", "-b", "main", repo_dir.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(init_out.status.success());

    let git_cmd = |args: &[&str]| {
        Command::new("git")
            .current_dir(&repo_dir)
            .env("GNUPGHOME", &gnupg_home)
            .args(args)
            .output()
            .unwrap()
    };

    git_cmd(&["config", "user.name", "OTS Test"]);
    git_cmd(&["config", "user.email", "ots@example.com"]);
    git_cmd(&["config", "user.signingkey", key_id]);
    git_cmd(&["config", "gpg.program", wrapper_bin]);

    // Create and sign commit with ots-git-gpg-wrapper
    std::fs::write(
        repo_dir.join("hello.txt"),
        b"Hello OpenTimestamps Git Wrapper!\n",
    )
    .unwrap();
    git_cmd(&["add", "hello.txt"]);
    let commit_out = git_cmd(&[
        "commit",
        "-S",
        "-m",
        "Signed commit via ots-git-gpg-wrapper",
    ]);
    assert!(
        commit_out.status.success(),
        "git commit -S failed: {}",
        String::from_utf8_lossy(&commit_out.stderr)
    );

    // Verify commit with git verify-commit
    let verify_commit_out = git_cmd(&["verify-commit", "HEAD"]);
    let verify_stderr = String::from_utf8_lossy(&verify_commit_out.stderr);
    assert!(
        verify_commit_out.status.success(),
        "git verify-commit failed: {verify_stderr}"
    );
    assert!(verify_stderr.contains("Good signature"));
    assert!(verify_stderr.contains("Found OpenTimestamps proof attached to Git signature"));

    // Verify git log --show-signature
    let log_out = git_cmd(&["log", "--show-signature", "-n", "1"]);
    let log_stdout = String::from_utf8_lossy(&log_out.stdout);
    let log_stderr = String::from_utf8_lossy(&log_out.stderr);
    let combined_log = format!("{log_stdout}\n{log_stderr}");
    assert!(log_out.status.success());
    assert!(combined_log.contains("Good signature"));
    assert!(combined_log.contains("Found OpenTimestamps proof attached to Git signature"));

    // Create and sign tag with ots-git-gpg-wrapper
    let tag_out = git_cmd(&["tag", "-s", "v1.0.0", "-m", "Release v1.0.0"]);
    assert!(
        tag_out.status.success(),
        "git tag -s failed: {}",
        String::from_utf8_lossy(&tag_out.stderr)
    );

    // Verify tag with git verify-tag
    let verify_tag_out = git_cmd(&["verify-tag", "v1.0.0"]);
    let tag_stderr = String::from_utf8_lossy(&verify_tag_out.stderr);
    assert!(
        verify_tag_out.status.success(),
        "git verify-tag failed: {tag_stderr}"
    );
    assert!(tag_stderr.contains("Good signature"));
    assert!(tag_stderr.contains("Found OpenTimestamps proof attached to Git signature"));

    // Verify ots git verify subcommand detects the embedded proof and reports calendar status
    let ots_verify_out = Command::new(ots_bin)
        .current_dir(&repo_dir)
        .args(["git", "verify", "--json", "HEAD"])
        .output()
        .unwrap();
    let ots_stdout = String::from_utf8_lossy(&ots_verify_out.stdout);
    let ots_stderr = String::from_utf8_lossy(&ots_verify_out.stderr);
    let combined_ots = format!("{ots_stdout}\n{ots_stderr}");
    assert!(
        combined_ots.contains("embedded OpenTimestamps git signature")
            || combined_ots.contains("\"object_type\": \"commit\"")
            || combined_ots.contains("Pending confirmation"),
        "expected embedded proof detection, got: {combined_ots}"
    );

    let _ = std::fs::remove_dir_all(&temp_base);
}
