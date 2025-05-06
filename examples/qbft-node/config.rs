use alloy_primitives::{Address, U256};
use serde::Deserialize;
use std::path::Path;
use eyre::Result;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub qbft: QBFTConfig,
}

#[derive(Debug, Deserialize)]
pub struct QBFTConfig {
    pub block_period: u64,
    pub epoch_length: u64,
    pub min_validators: usize,
    pub max_validators: usize,
    pub validators: Vec<String>,
    pub rewards: RewardConfig,
}

#[derive(Debug, Deserialize)]
pub struct RewardConfig {
    #[serde(with = "serde_with::rust::display_fromstr")]
    pub base_reward: U256,
    pub proposer_multiplier: u64,
    pub validator_multiplier: u64,
}

impl Config {
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let contents = std::fs::read_to_string(path)?;
        let config = toml::from_str(&contents)?;
        Ok(config)
    }

    pub fn into_qbft_config(self) -> Result<reth_qbft_consensus::QBFTConfig> {
        let validators = self.qbft.validators
            .into_iter()
            .map(|addr| {
                Address::parse_checksummed(&addr, None)
                    .map_err(|e| eyre::eyre!("Invalid validator address: {}", e))
            })
            .collect::<Result<Vec<_>>>()?;

        Ok(reth_qbft_consensus::QBFTConfig {
            block_period: self.qbft.block_period,
            validators,
            epoch_length: self.qbft.epoch_length,
            min_validators: self.qbft.min_validators,
            max_validators: self.qbft.max_validators,
            reward_config: reth_qbft_consensus::RewardConfig {
                base_reward: self.qbft.rewards.base_reward,
                proposer_multiplier: self.qbft.rewards.proposer_multiplier,
                validator_multiplier: self.qbft.rewards.validator_multiplier,
            },
        })
    }
} 