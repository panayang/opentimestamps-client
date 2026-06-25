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
- Intentionally drops the local-wallet stamping path (`-b`/`--btc-wallet`)
  and the git-commit integration — niche features that pulled in most of the
  original dependency tree for little benefit in a general-purpose client.

## Build

```
cargo build --release
```

Binary is at `target/release/ots`.

## Usage

```
ots stamp file1.pdf file2.txt ...      # batch-timestamp files (one commitment)
ots stamp -                            # timestamp stdin, prints proof to stdout
ots upgrade file.txt.ots               # pull a Bitcoin attestation once pending
ots verify file.txt.ots                # verify against file.txt
ots verify -d <hex digest> file.ots    # verify a raw digest instead of a file
ots info file.txt.ots                  # show the proof tree
ots prune file.txt.ots                 # discard pending attestations once complete
```

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
