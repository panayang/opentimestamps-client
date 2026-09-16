use std::io::Write;
use std::process::Command;

#[test]
fn test_stamp_single_and_batch_files() {
    let temp_dir = std::env::temp_dir().join(format!("ots_stamp_test_{}", rand::random::<u64>()));
    std::fs::create_dir_all(&temp_dir).unwrap();
    let ots_bin = env!("CARGO_BIN_EXE_ots");

    let f1 = temp_dir.join("doc1.txt");
    let f2 = temp_dir.join("doc2.txt");
    let f3 = temp_dir.join("doc3.txt");

    std::fs::write(&f1, b"Document 1 contents").unwrap();
    std::fs::write(&f2, b"Document 2 contents").unwrap();
    std::fs::write(&f3, b"Document 3 contents").unwrap();

    // Stamp batch of 3 files
    let stamp_out = Command::new(ots_bin)
        .current_dir(&temp_dir)
        .args([
            "stamp",
            "-m",
            "0",
            "--timeout",
            "1",
            "doc1.txt",
            "doc2.txt",
            "doc3.txt",
        ])
        .output()
        .unwrap();

    assert!(
        stamp_out.status.success(),
        "ots stamp failed: {:?}",
        String::from_utf8_lossy(&stamp_out.stderr)
    );

    let ots1 = temp_dir.join("doc1.txt.ots");
    let ots2 = temp_dir.join("doc2.txt.ots");
    let ots3 = temp_dir.join("doc3.txt.ots");

    assert!(ots1.exists());
    assert!(ots2.exists());
    assert!(ots3.exists());

    // Run info on each
    for ots in [&ots1, &ots2, &ots3] {
        let info_out = Command::new(ots_bin)
            .args(["info", ots.to_str().unwrap()])
            .output()
            .unwrap();
        assert!(info_out.status.success());
        let info_str = String::from_utf8_lossy(&info_out.stdout);
        assert!(info_str.contains("File sha256 hash:"));
        assert!(info_str.contains("Timestamp:"));
    }

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_stamp_stdin_pipe_to_stdout() {
    let ots_bin = env!("CARGO_BIN_EXE_ots");
    let data = b"Arbitrary streaming binary or text data for stdin timestamping";

    // 1. Pipe into ots stamp - -m 0
    let mut stamp_child = Command::new(ots_bin)
        .args(["stamp", "-", "-m", "0", "--timeout", "1"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::inherit())
        .spawn()
        .unwrap();

    stamp_child.stdin.take().unwrap().write_all(data).unwrap();
    let stamp_res = stamp_child.wait_with_output().unwrap();
    assert!(stamp_res.status.success());
    let ots_bytes = stamp_res.stdout;
    assert!(!ots_bytes.is_empty());

    // 2. Pipe ots_bytes into ots info -
    let mut info_child = Command::new(ots_bin)
        .args(["info", "-"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::inherit())
        .spawn()
        .unwrap();

    info_child
        .stdin
        .take()
        .unwrap()
        .write_all(&ots_bytes)
        .unwrap();
    let info_res = info_child.wait_with_output().unwrap();
    assert!(info_res.status.success());
    let info_text = String::from_utf8_lossy(&info_res.stdout);
    assert!(info_text.contains("File sha256 hash:"));

    // 3. Pipe ots_bytes into ots info --json -
    let mut json_child = Command::new(ots_bin)
        .args(["info", "--json", "-"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::inherit())
        .spawn()
        .unwrap();

    json_child
        .stdin
        .take()
        .unwrap()
        .write_all(&ots_bytes)
        .unwrap();
    let json_res = json_child.wait_with_output().unwrap();
    assert!(json_res.status.success());
    let parsed: serde_json::Value =
        serde_json::from_slice(&json_res.stdout).expect("must be valid json");
    assert_eq!(parsed["hash_algorithm"], "sha256");
    assert_eq!(parsed["file"], "stdin");
}

#[test]
fn test_verify_raw_digest_and_json() {
    let ots_bin = env!("CARGO_BIN_EXE_ots");
    let fixture_ots = "tests/fixtures/merkle3.txt.ots";
    let fixture_digest = "3966a69fc344107bb4f30c574305d9b4508df2cb8e65dd46007a2cfb116b9579";

    // 1. Verify with -d <digest>
    let out = Command::new(ots_bin)
        .args(["--no-bitcoin", "verify", "-d", fixture_digest, fixture_ots])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "verify failed: {:?}",
        String::from_utf8_lossy(&out.stderr)
    );

    // 2. Verify with wrong digest should fail
    let bad_out = Command::new(ots_bin)
        .args([
            "--no-bitcoin",
            "verify",
            "-d",
            "0000000000000000000000000000000000000000000000000000000000000000",
            fixture_ots,
        ])
        .output()
        .unwrap();
    assert!(!bad_out.status.success());

    // 3. Verify with --json output
    let json_out = Command::new(ots_bin)
        .args([
            "--no-bitcoin",
            "verify",
            "-d",
            fixture_digest,
            "--json",
            fixture_ots,
        ])
        .output()
        .unwrap();
    assert!(json_out.status.success());
    let parsed: serde_json::Value =
        serde_json::from_slice(&json_out.stdout).expect("must produce valid json");
    assert_eq!(parsed["verified"], true);
    assert_eq!(parsed["bitcoin_block"], 429808);
    assert_eq!(parsed["digest"], fixture_digest);
}

#[test]
fn test_prune_command_e2e() {
    let temp_dir = std::env::temp_dir().join(format!("ots_prune_test_{}", rand::random::<u64>()));
    std::fs::create_dir_all(&temp_dir).unwrap();
    let ots_bin = env!("CARGO_BIN_EXE_ots");

    let fixture_ots = "tests/fixtures/merkle3.txt.ots";
    let test_ots = temp_dir.join("test_prune.txt.ots");
    std::fs::copy(fixture_ots, &test_ots).unwrap();

    // Attach a bitcoin attestation so pruning pending:* leaves the bitcoin attestation
    {
        use ots_client::ots::notary::TimeAttestation;
        use ots_client::ots::serialize::{Reader, Writer};
        use ots_client::ots::timestamp::DetachedTimestampFile;

        let bytes = std::fs::read(&test_ots).unwrap();
        let mut r = Reader::new(&bytes);
        let mut detached = DetachedTimestampFile::deserialize(&mut r).unwrap();
        detached
            .timestamp
            .attestations
            .insert(TimeAttestation::Bitcoin { height: 429808 });

        let mut w = Writer::new();
        detached.serialize(&mut w).unwrap();
        std::fs::write(&test_ots, w.into_bytes()).unwrap();
    }

    let prune_out = Command::new(ots_bin)
        .args([
            "prune",
            "--no-verify",
            "--discard",
            "pending:*",
            test_ots.to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert!(
        prune_out.status.success(),
        "prune failed: {:?}",
        String::from_utf8_lossy(&prune_out.stderr)
    );

    // Verify backup .bak file was created
    let backup_file = temp_dir.join("test_prune.txt.ots.bak");
    assert!(backup_file.exists());

    // Verify pruned file still has bitcoin attestation
    let info_out = Command::new(ots_bin)
        .args(["info", "--json", test_ots.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(info_out.status.success());
    let parsed: serde_json::Value = serde_json::from_slice(&info_out.stdout).expect("json parsed");
    let attestations = parsed["attestations"].as_array().unwrap();
    // Only bitcoin attestation remains, pending attestations were discarded
    assert!(!attestations.is_empty());
    for a in attestations {
        assert_ne!(a["type"], "pending");
    }

    let _ = std::fs::remove_dir_all(&temp_dir);
}
