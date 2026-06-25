use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "ots",
    version,
    about = "OpenTimestamps client - create and verify blockchain timestamp proofs",
    long_about = "A fast, dependency-light Rust reimplementation of the OpenTimestamps client.\n\
                  Supports batch stamping of many files in a single commitment, concurrent\n\
                  calendar requests, and Bitcoin verification via a public block explorer API\n\
                  (no local bitcoind required)."
)]
pub struct Cli {
    #[command(flatten)]
    pub common: CommonOpts,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Args, Debug)]
pub struct CommonOpts {
    /// Be more quiet (repeatable)
    #[arg(short = 'q', long, action = clap::ArgAction::Count, global = true)]
    pub quiet: u8,

    /// Be more verbose (repeatable)
    #[arg(short = 'v', long, action = clap::ArgAction::Count, global = true)]
    pub verbose: u8,

    /// Add a calendar URL to the upgrade whitelist (repeatable)
    #[arg(short = 'l', long = "whitelist", value_name = "URL", global = true)]
    pub whitelist: Vec<String>,

    /// Do not load the default remote calendar whitelist
    #[arg(long, global = true)]
    pub no_default_whitelist: bool,

    /// Location of the local timestamp cache directory
    #[arg(long, value_name = "PATH", global = true)]
    pub cache: Option<PathBuf>,

    /// Disable the local timestamp cache
    #[arg(long, global = true, conflicts_with = "cache")]
    pub no_cache: bool,

    /// Block explorer (Esplora-compatible) API base URL used for Bitcoin verification
    #[arg(
        long,
        value_name = "URL",
        global = true,
        default_value = "https://mempool.space/api"
    )]
    pub bitcoin_explorer: String,

    /// Disable Bitcoin attestation verification entirely
    #[arg(long, global = true)]
    pub no_bitcoin: bool,

    /// Wait until a complete (Bitcoin-attested) timestamp is available instead of returning immediately
    #[arg(short = 'w', long, global = true)]
    pub wait: bool,

    /// Seconds to wait between polling attempts when --wait is set
    #[arg(long, global = true, default_value_t = 30, hide = true)]
    pub wait_interval: u64,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Timestamp one or more files (batched into a single commitment)
    #[command(alias = "s")]
    Stamp(StampArgs),

    /// Upgrade pending timestamps to be independently verifiable
    #[command(alias = "u")]
    Upgrade(UpgradeArgs),

    /// Verify a timestamp
    #[command(alias = "v")]
    Verify(VerifyArgs),

    /// Show information about a timestamp file
    #[command(alias = "i")]
    Info(InfoArgs),

    /// Prune a timestamp (discard data not needed for verification)
    #[command(alias = "p")]
    Prune(PruneArgs),
}

#[derive(Args, Debug)]
pub struct StampArgs {
    /// Files to timestamp (reads stdin if none given). Glob patterns are expanded.
    pub files: Vec<PathBuf>,

    /// Remote calendar URL to use (repeatable). Defaults to the public OpenTimestamps pool.
    #[arg(short = 'c', long = "calendar", value_name = "URL")]
    pub calendars: Vec<String>,

    /// Seconds to wait for each calendar to respond
    #[arg(long, default_value_t = 5)]
    pub timeout: u64,

    /// Hash algorithm to use for the file digest
    #[arg(long, default_value = "sha256")]
    pub hash: String,

    /// Consider the timestamp complete once at least M calendars reply
    #[arg(short = 'm', default_value_t = 2)]
    pub m: usize,
}

#[derive(Args, Debug)]
pub struct UpgradeArgs {
    /// Existing .ots timestamp file(s); each is replaced in place (old version backed up as FILE.bak)
    #[arg(required = true)]
    pub files: Vec<PathBuf>,

    /// Override the calendar URL(s) recorded in the timestamp
    #[arg(short = 'c', long = "calendar", value_name = "URL")]
    pub calendars: Vec<String>,

    /// Check for upgrades without modifying the file
    #[arg(short = 'n', long)]
    pub dry_run: bool,
}

#[derive(Args, Debug)]
pub struct VerifyArgs {
    /// Timestamp file (.ots)
    pub timestamp: PathBuf,

    /// Target file to verify against (default: TIMESTAMP without the .ots suffix)
    #[arg(short = 'f', value_name = "FILE", conflicts_with = "digest")]
    pub target: Option<PathBuf>,

    /// Verify a hex-encoded digest instead of a file
    #[arg(short = 'd', value_name = "DIGEST", conflicts_with = "target")]
    pub digest: Option<String>,
}

#[derive(Args, Debug)]
pub struct InfoArgs {
    /// Timestamp file (.ots)
    pub file: PathBuf,
}

#[derive(Args, Debug)]
pub struct PruneArgs {
    /// Timestamp file (.ots); replaced in place (old version backed up as FILE.bak)
    pub file: PathBuf,

    /// Verify attestations from a specified notary before discarding the rest (repeatable). Default: btc.
    #[arg(long = "verify", value_name = "NOTARY")]
    pub attestations_to_verify: Vec<String>,

    /// Do not verify any attestation before pruning
    #[arg(long, conflicts_with = "attestations_to_verify")]
    pub no_verify: bool,

    /// Discard attestations from a specified notary (repeatable: btc, ltc, unknown, pending:*, pending:URI). Default: pending:*.
    #[arg(long = "discard", value_name = "NOTARY")]
    pub attestations_to_discard: Vec<String>,
}
