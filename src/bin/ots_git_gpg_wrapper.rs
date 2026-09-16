use ots_client::cli::CommonOpts;
use ots_client::context::Context;

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();

    // Default common opts for git wrapper
    let common = CommonOpts {
        quiet: 0,
        verbose: 0,
        whitelist: Vec::new(),
        no_default_whitelist: false,
        cache: None,
        no_cache: false,
        bitcoin_explorer: "https://mempool.space/api".to_string(),
        no_bitcoin: false,
        wait: false,
        wait_interval: 30,
    };

    let ctx = match Context::new(&common) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error initializing ots context: {e}");
            std::process::exit(1);
        }
    };

    if let Err(e) = ots_client::git::run_gpg_wrapper(&args, &ctx, None, &[]).await {
        eprintln!("ots-git-gpg-wrapper error: {e}");
        std::process::exit(1);
    }
}
