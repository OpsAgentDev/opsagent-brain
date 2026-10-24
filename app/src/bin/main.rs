use std::process::ExitCode;

use clap::Parser;
use opsagent_brain::cli::{self, Cli};

#[tokio::main]
async fn main() -> ExitCode {
    let args = Cli::parse();
    cli::install_tracing();
    cli::main(args).await
}
