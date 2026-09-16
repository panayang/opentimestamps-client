# ots-client (Rust)

A modern, fast, dependency-light reimplementation of the [OpenTimestamps](https://opentimestamps.org)
client, ported from the reference Python `opentimestamps-client` /
`python-opentimestamps`. Wire-format compatible: it interoperates with the
real calendar servers and with `.ots` files produced by the original client
(verified against the bundled `opentimestamps-client/examples/*.ots`
fixtures and against live calendar servers).

## Why a rewrite

The Python client depends on `python-bitcoinlib`, `python-bitcoin-rpc`,
`GitPython`, `PySocks`, etc., and needs a fully-synced local `bitcoind` with
RPC access just to verify a Bitcoin attestation. This client:

- Ships as a single static binary, no Python/pip environment.
- Verifies Bitcoin attestations against a public Esplora-compatible REST API
  (mempool.space by default) instead of requiring a local Bitcoin node.
- Batches many files into **one** calendar commitment by default (a single
  merkle tree covering all inputs), so stamping a directory of files costs
  one round trip per calendar, not one per file.
- Hashes files and submits to calendars concurrently (`tokio` + `rayon`).
- Full Git / VCS integration: timestamp signed and unsigned commits and tags, extract per-file timestamps from commit Merkle trees, and drop-in `ots-git-gpg-wrapper` for automatic commit timestamping on `git commit -S`.
- Integration for external applications: structured `--json` output for CI/CD, webhooks, and GUIs, checksums manifest workflows, and Unix stdin/stdout streaming pipelines.

## Build

```
cargo build --release
```

Binaries are at `target/release/ots` and `target/release/ots-git-gpg-wrapper`.

## Usage

```
ots stamp file1.pdf file2.txt ...      # batch-timestamp files (one commitment)
ots stamp -                            # timestamp stdin, prints proof to stdout
ots upgrade file.txt.ots               # pull a Bitcoin attestation once pending
ots verify file.txt.ots                # verify against file.txt
ots verify -d <hex digest> file.ots    # verify a raw digest instead of a file
ots verify --json file.txt.ots         # machine-readable JSON output for applications
ots info file.txt.ots                  # show the proof tree
ots info --json file.txt.ots           # show proof details as JSON
ots prune file.txt.ots                 # discard pending attestations once complete

# Git / VCS Integration
ots git stamp HEAD                     # timestamp git commit or tag
ots git verify HEAD                    # verify timestamp of git commit or tag
ots git extract path/to/file HEAD      # extract timestamp for a file from a commit
ots-git-gpg-wrapper ...                # drop-in wrapper for git's gpg.program
```

### Git GPG Integration

Configure git to use `ots-git-gpg-wrapper` as the GPG program:

```bash
git config --global gpg.program ots-git-gpg-wrapper
```

When you create signed commits (`git commit -S`) or tags (`git tag -s`), OpenTimestamps automatically appends an ASCII-armored proof directly to the signature, maintaining full backward compatibility with standard Git and GnuPG clients.

Global flags: `-w/--wait` to block until Bitcoin-confirmed, `--no-bitcoin` to
skip block verification, `--bitcoin-explorer <url>` to point at a different
Esplora instance (e.g. a self-hosted one), `--cache`/`--no-cache` for the
local upgrade cache, `-v`/`-q` for verbosity.

## Layout

- `src/ots/` - consensus-critical protocol: LEB128/varbytes serialization,
  ops (append/prepend/reverse/hexlify/sha1/ripemd160/sha256/keccak256),
  attestations, the timestamp proof tree, and the `.ots` file format.
- `src/calendar.rs` - remote calendar HTTP client (submit/upgrade).
- `src/bitcoin.rs` - Esplora-based block header verification.
- `src/cache.rs` - local on-disk upgrade cache.
- `src/upgrade.rs` - shared submit/upgrade orchestration (concurrent,
  cache-aware, with `--wait` polling).
- `src/commands/` - the five subcommands.

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
