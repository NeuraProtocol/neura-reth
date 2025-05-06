use alloy_primitives::Address;
use eyre::Result;
use reth_chainspec::ChainSpec;
use reth_node_builder::NodeBuilder;
use reth_qbft_consensus::{
    QBFTChainSpec, QBFTConfig, QBFTEngineValidatorBuilder, QBFTNodeBuilder, RewardConfig,
};
use std::str::FromStr;

#[tokio::main]
async fn main() -> Result<()> {
    // Create the base chain specification
    let base_chain_spec = ChainSpec::mainnet();

    // Create QBFT configuration
    let qbft_config = QBFTConfig {
        block_period: 5, // 5 seconds
        validators: vec![
            Address::from_str("0x0101010101010101010101010101010101010101")?,
            Address::from_str("0x0202020202020202020202020202020202020202")?,
            Address::from_str("0x0303030303030303030303030303030303030303")?,
        ],
        epoch_length: 30000, // 30000 blocks
        min_validators: 3,
        max_validators: 10,
        reward_config: RewardConfig {
            base_reward: 2_000_000_000_000_000_000u128.into(), // 2 ETH
            proposer_multiplier: 2,
            validator_multiplier: 1,
        },
    };

    // Create the QBFT chain specification
    let chain_spec = QBFTChainSpec::new(base_chain_spec, qbft_config);

    // Build and start the node
    let node = NodeBuilder::default()
        .with_consensus_builder(QBFTNodeBuilder)
        .with_engine_validator_builder(QBFTEngineValidatorBuilder)
        .with_chain_spec(chain_spec)
        .build()
        .await?;

    node.start().await?;
    Ok(())
} 