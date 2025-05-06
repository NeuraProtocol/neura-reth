use alloy_primitives::{Address, B256, U256};
use reth_chainspec::{ChainSpec, EthereumHardforks};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// QBFT-specific chain configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QBFTConfig {
    /// The block period in seconds
    pub block_period: u64,
    /// The initial validator set
    pub validators: Vec<Address>,
    /// The epoch length in blocks
    pub epoch_length: u64,
    /// The minimum number of validators required
    pub min_validators: usize,
    /// The maximum number of validators allowed
    pub max_validators: usize,
    /// The reward distribution configuration
    pub reward_config: RewardConfig,
}

/// Configuration for validator rewards
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RewardConfig {
    /// Base reward per block
    pub base_reward: U256,
    /// Reward multiplier for proposer
    pub proposer_multiplier: u64,
    /// Reward multiplier for validators
    pub validator_multiplier: u64,
}

/// QBFT chain specification
#[derive(Debug, Clone)]
pub struct QBFTChainSpec {
    /// Base chain specification
    pub base: ChainSpec,
    /// QBFT-specific configuration
    pub qbft_config: QBFTConfig,
    /// Validator set history
    pub validator_history: HashMap<u64, Vec<Address>>,
}

impl QBFTChainSpec {
    /// Creates a new QBFT chain specification
    pub fn new(base: ChainSpec, qbft_config: QBFTConfig) -> Self {
        let mut validator_history = HashMap::new();
        validator_history.insert(0, qbft_config.validators.clone());
        
        Self {
            base,
            qbft_config,
            validator_history,
        }
    }

    /// Returns the validator set for a given block number
    pub fn validators_at_block(&self, block_number: u64) -> &[Address] {
        let epoch = block_number / self.qbft_config.epoch_length;
        self.validator_history
            .get(&epoch)
            .map(|v| v.as_slice())
            .unwrap_or(&self.qbft_config.validators)
    }

    /// Updates the validator set for a new epoch
    pub fn update_validator_set(&mut self, epoch: u64, validators: Vec<Address>) {
        self.validator_history.insert(epoch, validators);
    }

    /// Returns the block period in seconds
    pub fn block_period(&self) -> u64 {
        self.qbft_config.block_period
    }

    /// Returns the minimum number of validators required
    pub fn min_validators(&self) -> usize {
        self.qbft_config.min_validators
    }

    /// Returns the maximum number of validators allowed
    pub fn max_validators(&self) -> usize {
        self.qbft_config.max_validators
    }
}

impl EthereumHardforks for QBFTChainSpec {
    fn ethereum_fork_activation(&self, fork: EthereumHardfork) -> ForkCondition {
        self.base.fork(fork)
    }
} 