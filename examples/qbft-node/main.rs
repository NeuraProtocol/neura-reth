mod config;

use reth_node_builder::NodeBuilder;
use reth_qbft_consensus::{QBFTChainSpec, QBFTNodeBuilder, QBFTEngineValidatorBuilder};
use reth_chainspec::ChainSpec;
use std::sync::Arc;
use std::path::PathBuf;
use clap::Parser;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Path to the configuration file
    #[arg(short, long, default_value = "config.toml")]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    // Parse command line arguments
    let cli = Cli::parse();

    // Load configuration
    let config = config::Config::load(&cli.config)?;
    let qbft_config = config.into_qbft_config()?;

    // Create base chain specification
    let base_chain_spec = ChainSpec::mainnet();

    // Create QBFT chain specification
    let chain_spec = Arc::new(QBFTChainSpec::new(base_chain_spec, qbft_config));

    // Build and start the node
    let node = NodeBuilder::default()
        .with_consensus_builder(QBFTNodeBuilder)
        .with_engine_validator_builder(QBFTEngineValidatorBuilder)
        .with_chain_spec(chain_spec)
        .build()
        .await?;

    // Start the node
    node.start().await?;

    // Keep the node running
    tokio::signal::ctrl_c().await?;
    Ok(())
} 