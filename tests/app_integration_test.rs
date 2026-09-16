use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::Command;

#[test]
fn test_mock_calendar_http_server_integration() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let port = addr.port();
    let calendar_url = format!("http://127.0.0.1:{port}");

    // Spawn mock calendar server on an independent OS thread
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let mut socket = match stream {
                Ok(s) => s,
                Err(_) => break,
            };

            let mut request_bytes = Vec::new();
            let mut body_start = 0;
            let mut content_len = 0;

            loop {
                let mut chunk = [0u8; 1024];
                let n = match socket.read(&mut chunk) {
                    Ok(n) if n > 0 => n,
                    _ => break,
                };
                request_bytes.extend_from_slice(&chunk[..n]);

                if let Some(pos) = request_bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                    body_start = pos + 4;
                    let header_str = String::from_utf8_lossy(&request_bytes[..pos]);
                    content_len = header_str
                        .lines()
                        .find(|l| l.to_ascii_lowercase().starts_with("content-length:"))
                        .and_then(|l| l.split(':').nth(1))
                        .and_then(|v| v.trim().parse().ok())
                        .unwrap_or(0);

                    if request_bytes.len() >= body_start + content_len {
                        break;
                    }
                }
            }

            let req_header =
                String::from_utf8_lossy(&request_bytes[..body_start.min(request_bytes.len())]);

            if req_header.starts_with("POST /digest") {
                let body = &request_bytes[body_start..body_start + content_len];

                // Create calendar response proof
                let mut ts = ots_client::ots::timestamp::Timestamp::new(body.to_vec());
                let leaf = ts
                    .add_op(ots_client::ots::op::Op::Append(vec![0xca, 0xfe]))
                    .unwrap();
                leaf.attestations
                    .insert(ots_client::ots::notary::TimeAttestation::Pending {
                        uri: "http://127.0.0.1".to_string(),
                    });

                let mut w = ots_client::ots::serialize::Writer::new();
                ts.serialize(&mut w).unwrap();
                let payload = w.into_bytes();

                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/vnd.opentimestamps.v1\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    payload.len()
                );
                let _ = socket.write_all(response.as_bytes());
                let _ = socket.write_all(&payload);
                let _ = socket.flush();
            } else {
                let not_found =
                    "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                let _ = socket.write_all(not_found.as_bytes());
            }
        }
    });

    let ots_bin = env!("CARGO_BIN_EXE_ots");
    let temp_dir = std::env::temp_dir().join(format!("ots_mock_cal_{}", rand::random::<u64>()));
    std::fs::create_dir_all(&temp_dir).unwrap();

    let sample_file = temp_dir.join("sample.txt");
    std::fs::write(&sample_file, b"Test data for local calendar server").unwrap();

    // Stamp against our mock calendar server!
    let stamp_out = Command::new(ots_bin)
        .current_dir(&temp_dir)
        .args([
            "stamp",
            "-c",
            &calendar_url,
            "-m",
            "1",
            "--timeout",
            "5",
            "sample.txt",
        ])
        .output()
        .unwrap();

    assert!(
        stamp_out.status.success(),
        "ots stamp against mock calendar failed: {:?}",
        String::from_utf8_lossy(&stamp_out.stderr)
    );

    let ots_file = temp_dir.join("sample.txt.ots");
    assert!(ots_file.exists());

    let info_out = Command::new(ots_bin)
        .args(["info", "--json", ots_file.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(info_out.status.success());
    let parsed: serde_json::Value =
        serde_json::from_slice(&info_out.stdout).expect("must parse json");
    let attestations = parsed["attestations"].as_array().unwrap();
    assert_eq!(attestations.len(), 1);
    assert_eq!(attestations[0]["type"], "pending");
    assert_eq!(attestations[0]["uri"], "http://127.0.0.1");

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_tarball_archive_pipeline_integration() {
    let temp_dir = std::env::temp_dir().join(format!("ots_tar_test_{}", rand::random::<u64>()));
    std::fs::create_dir_all(&temp_dir).unwrap();
    let ots_bin = env!("CARGO_BIN_EXE_ots");

    // 1. Create files and package into a tarball
    let src_dir = temp_dir.join("release");
    std::fs::create_dir_all(&src_dir).unwrap();
    std::fs::write(src_dir.join("app.bin"), b"\x7fELFbinarycontents").unwrap();
    std::fs::write(src_dir.join("config.yaml"), b"version: 1.0.0\n").unwrap();

    let tar_file = temp_dir.join("release-1.0.0.tar.gz");
    let tar_status = Command::new("tar")
        .current_dir(&temp_dir)
        .args([
            "-czf",
            tar_file.to_str().unwrap(),
            "-C",
            temp_dir.to_str().unwrap(),
            "release",
        ])
        .status()
        .unwrap();
    assert!(tar_status.success());

    // 2. Compute SHA256 of tarball
    let tar_bytes = std::fs::read(&tar_file).unwrap();
    use sha2::{Digest, Sha256};
    let tar_digest = hex::encode(Sha256::digest(&tar_bytes));

    // 3. Stamp tarball via pipe to ots stamp -
    let mut stamp_child = Command::new(ots_bin)
        .args(["stamp", "-", "-m", "0", "--timeout", "1"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::inherit())
        .spawn()
        .unwrap();

    stamp_child
        .stdin
        .take()
        .unwrap()
        .write_all(&tar_bytes)
        .unwrap();
    let stamp_res = stamp_child.wait_with_output().unwrap();
    assert!(stamp_res.status.success());
    let ots_proof_bytes = stamp_res.stdout;

    let ots_file = temp_dir.join("release-1.0.0.tar.gz.ots");
    std::fs::write(&ots_file, &ots_proof_bytes).unwrap();

    // 4. Verify tarball with ots info -d <digest>
    let info_out = Command::new(ots_bin)
        .args(["info", "--json", ots_file.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(info_out.status.success());
    let parsed: serde_json::Value = serde_json::from_slice(&info_out.stdout).unwrap();
    assert_eq!(parsed["digest"], tar_digest);

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_checksums_manifest_workflow() {
    let temp_dir =
        std::env::temp_dir().join(format!("ots_manifest_test_{}", rand::random::<u64>()));
    std::fs::create_dir_all(&temp_dir).unwrap();
    let ots_bin = env!("CARGO_BIN_EXE_ots");

    // Create release files
    let bin_file = temp_dir.join("my-app-linux-amd64");
    let doc_file = temp_dir.join("DOCUMENTATION.pdf");
    std::fs::write(&bin_file, b"Executable release payload v2.0").unwrap();
    std::fs::write(&doc_file, b"%PDF-1.4 sample PDF user manual").unwrap();

    use sha2::{Digest, Sha256};
    let bin_digest = hex::encode(Sha256::digest(b"Executable release payload v2.0"));
    let doc_digest = hex::encode(Sha256::digest(b"%PDF-1.4 sample PDF user manual"));

    // Generate SHA256SUMS file
    let manifest_content = format!(
        "{}  my-app-linux-amd64\n{}  DOCUMENTATION.pdf\n",
        bin_digest, doc_digest
    );
    let manifest_file = temp_dir.join("SHA256SUMS");
    std::fs::write(&manifest_file, manifest_content).unwrap();

    // Stamp manifest file
    let stamp_out = Command::new(ots_bin)
        .current_dir(&temp_dir)
        .args(["stamp", "-m", "0", "--timeout", "1", "SHA256SUMS"])
        .output()
        .unwrap();
    assert!(stamp_out.status.success());

    let manifest_ots = temp_dir.join("SHA256SUMS.ots");
    assert!(manifest_ots.exists());

    // Verify manifest proof against manifest file
    let info_out = Command::new(ots_bin)
        .args(["info", "--json", manifest_ots.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(info_out.status.success());
    let parsed: serde_json::Value = serde_json::from_slice(&info_out.stdout).unwrap();
    assert_eq!(parsed["hash_algorithm"], "sha256");

    let _ = std::fs::remove_dir_all(&temp_dir);
}
