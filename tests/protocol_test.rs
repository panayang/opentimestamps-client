use ots_client::cache::TimestampCache;
use ots_client::ots::merkle::merkle_paths;
use ots_client::ots::notary::TimeAttestation;
use ots_client::ots::op::Op;
use ots_client::ots::serialize::{Reader, Writer};
use ots_client::ots::timestamp::{DetachedTimestampFile, Timestamp};

#[test]
fn test_all_crypto_ops_and_test_vectors() {
    let input = b"hello";

    // Sha1
    let op_sha1 = Op::Sha1;
    let res = op_sha1.apply(input).unwrap();
    assert_eq!(
        hex::encode(&res),
        "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"
    );

    // Sha256
    let op_sha256 = Op::Sha256;
    let res = op_sha256.apply(input).unwrap();
    assert_eq!(
        hex::encode(&res),
        "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
    );

    // Ripemd160
    let op_ripemd160 = Op::Ripemd160;
    let res = op_ripemd160.apply(input).unwrap();
    assert_eq!(
        hex::encode(&res),
        "108f07b8382412612c048d07d13f814118445acd"
    );

    // Keccak256
    let op_keccak = Op::Keccak256;
    let res = op_keccak.apply(input).unwrap();
    assert_eq!(
        hex::encode(&res),
        "1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8"
    );

    // Reverse
    let op_rev = Op::Reverse;
    let res = op_rev.apply(b"abcd").unwrap();
    assert_eq!(&res, b"dcba");

    // Hexlify
    let op_hex = Op::Hexlify;
    let res = op_hex.apply(b"abc").unwrap();
    assert_eq!(&res, b"616263");

    // Append and Prepend
    let op_app = Op::Append(b" world".to_vec());
    let res = op_app.apply(input).unwrap();
    assert_eq!(&res, b"hello world");

    let op_prep = Op::Prepend(b"say ".to_vec());
    let res = op_prep.apply(input).unwrap();
    assert_eq!(&res, b"say hello");
}

#[test]
fn test_op_serialization_roundtrip() {
    let ops = vec![
        Op::Sha1,
        Op::Sha256,
        Op::Ripemd160,
        Op::Keccak256,
        Op::Reverse,
        Op::Hexlify,
        Op::Append(vec![1, 2, 3, 4, 5]),
        Op::Prepend(vec![9, 8, 7]),
    ];

    for op in ops {
        let mut w = Writer::new();
        op.serialize(&mut w);
        let bytes = w.into_bytes();

        let mut r = Reader::new(&bytes);
        let deserialized = Op::deserialize(&mut r).unwrap();
        assert_eq!(op, deserialized);
        assert_eq!(r.remaining(), 0);
    }
}

#[test]
fn test_leb128_and_varbytes_primitives() {
    let test_vals: Vec<u64> = vec![
        0,
        1,
        42,
        127,
        128,
        255,
        300,
        16384,
        65535,
        1_000_000,
        4_000_000_000,
        u64::MAX,
    ];

    for val in test_vals {
        let mut w = Writer::new();
        w.write_varuint(val);
        let bytes = w.into_bytes();

        let mut r = Reader::new(&bytes);
        let decoded = r.read_varuint().unwrap();
        assert_eq!(val, decoded);
        assert_eq!(r.remaining(), 0);
    }

    // Varbytes roundtrip
    let data = b"test arbitrary byte string with special \x00\xff characters";
    let mut w = Writer::new();
    w.write_varbytes(data);
    let bytes = w.into_bytes();

    let mut r = Reader::new(&bytes);
    let decoded = r.read_varbytes(1000).unwrap();
    assert_eq!(data, decoded);
}

#[test]
fn test_merkle_tree_paths() {
    for num_leaves in [1, 2, 3, 4, 7, 10, 16] {
        let leaves: Vec<Vec<u8>> = (0..num_leaves)
            .map(|i| format!("leaf_{i}").into_bytes())
            .collect();

        let (root, paths) = merkle_paths(leaves.clone());
        assert_eq!(paths.len(), num_leaves);

        for (i, leaf) in leaves.iter().enumerate() {
            let mut current = leaf.clone();
            for op in &paths[i] {
                current = op.apply(&current).unwrap();
            }
            assert_eq!(
                current, root,
                "path verification failed for leaf {i} out of {num_leaves}"
            );
        }
    }
}

#[test]
fn test_detached_timestamp_file_roundtrip() {
    let file_digest = vec![42u8; 32];
    let mut ts = Timestamp::new(file_digest.clone());
    let leaf = ts
        .add_op(Op::Append(vec![1, 2, 3]))
        .unwrap()
        .add_op(Op::Sha256)
        .unwrap();
    leaf.attestations
        .insert(TimeAttestation::Bitcoin { height: 100 });

    let detached = DetachedTimestampFile::new(Op::Sha256, ts);

    let mut w = Writer::new();
    detached.serialize(&mut w).unwrap();
    let bytes = w.into_bytes();

    let mut r = Reader::new(&bytes);
    let deserialized = DetachedTimestampFile::deserialize(&mut r).unwrap();

    assert_eq!(deserialized.file_hash_op, Op::Sha256);
    assert_eq!(deserialized.file_digest(), &file_digest[..]);
    assert_eq!(deserialized.timestamp.msg, file_digest);
}

#[test]
fn test_notary_attestation_types() {
    let attestations = vec![
        TimeAttestation::Bitcoin { height: 750000 },
        TimeAttestation::Litecoin { height: 2100000 },
        TimeAttestation::Pending {
            uri: "https://alice.btc.calendar.opentimestamps.org".to_string(),
        },
        TimeAttestation::Unknown {
            tag: [1, 2, 3, 4, 5, 6, 7, 8],
            payload: vec![0xaa, 0xbb, 0xcc],
        },
    ];

    for a in attestations {
        let mut w = Writer::new();
        a.serialize(&mut w);
        let bytes = w.into_bytes();

        let mut r = Reader::new(&bytes);
        let deserialized = TimeAttestation::deserialize(&mut r).unwrap();
        assert_eq!(a, deserialized);
    }
}

#[test]
fn test_official_test_fixtures() {
    let fixtures = [
        "tests/fixtures/two-calendars.txt.ots",
        "tests/fixtures/merkle3.txt.ots",
        "tests/fixtures/unknown-notary.txt.ots",
    ];

    for path in fixtures {
        let bytes = std::fs::read(path).unwrap_or_else(|_| panic!("failed to read fixture {path}"));
        let mut r = Reader::new(&bytes);
        let detached = DetachedTimestampFile::deserialize(&mut r).unwrap();

        assert_eq!(detached.file_hash_op, Op::Sha256);
        assert!(!detached.file_digest().is_empty());
        assert!(!detached.timestamp.all_attestations().is_empty());

        let mut w = Writer::new();
        detached.serialize(&mut w).unwrap();
        let reserialized = w.into_bytes();

        let mut r2 = Reader::new(&reserialized);
        let re_detached = DetachedTimestampFile::deserialize(&mut r2).unwrap();
        assert_eq!(detached.file_digest(), re_detached.file_digest());
    }
}

#[test]
fn test_cache_storage_and_retrieval() {
    let temp_dir = std::env::temp_dir().join(format!("ots_test_cache_{}", rand::random::<u64>()));
    let _ = std::fs::create_dir_all(&temp_dir);

    let cache = TimestampCache::new(Some(temp_dir.clone())).unwrap();

    let key = vec![0x55; 32];
    let mut ts = Timestamp::new(key.clone());
    let leaf = ts.add_op(Op::Append(vec![1, 2, 3])).unwrap();
    leaf.attestations
        .insert(TimeAttestation::Bitcoin { height: 12345 });

    cache.merge(&ts).unwrap();

    let retrieved = cache.get(&key).expect("cached timestamp should exist");
    assert_eq!(retrieved.msg, key);
    assert_eq!(retrieved.all_attestations().len(), 1);

    let _ = std::fs::remove_dir_all(&temp_dir);
}
