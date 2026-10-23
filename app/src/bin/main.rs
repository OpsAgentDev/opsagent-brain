use clap::Parser;
use opsagent_brain::{
    cli::{run, Cli},
    error::AppError,
};

#[tokio::main]
async fn main() -> Result<(), AppError> {
    run(Cli::parse()).await
}
