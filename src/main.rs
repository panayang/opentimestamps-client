mod bitcoin;
mod cache;
mod calendar;
mod cli;
mod commands;
mod context;
mod hashing;
mod log;
mod ots;
mod upgrade;
mod util;

use clap::Parser;
use cli::{Cli, Command};
use context::Context;

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let ctx = match Context::new(&cli.common) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error: {e}");
            std::process::exit(1);
        }
    };

    let result = match cli.command {
        Command::Stamp(args) => commands::stamp::run(args, &ctx).await,
        Command::Upgrade(args) => commands::upgrade::run(args, &ctx).await,
        Command::Verify(args) => commands::verify::run(args, &ctx).await,
        Command::Info(args) => commands::info::run(args, &ctx).await,
        Command::Prune(args) => commands::prune::run(args, &ctx).await,
    };

    if let Err(e) = result {
        ctx.log.error(&e.to_string());
        std::process::exit(1);
    }
}
