// crates/neura-qbft/src/types/mod.rs

pub mod consensus_round_identifier;
pub mod block;
pub mod signed_data;
pub mod qbft_final_state;
pub mod block_creator;
pub mod block_importer;
pub mod extra_data;
pub mod header;
pub mod rlp_signature;

// In Java, NodeKey is an interface. Here, we'll assume we get a k256::ecdsa::SigningKey.
// A more abstract NodeKey trait could be used if different key types are needed.
pub type NodeKey = k256::ecdsa::SigningKey;

// Basic types like QbftBlockHeader etc.
// will go into files in this module.

// pub mod header;

// Re-export
pub use consensus_round_identifier::ConsensusRoundIdentifier;
pub use block::QbftBlock;
pub use signed_data::SignedData;
pub use qbft_final_state::{
    QbftFinalState, RoundTimer, BlockTimer, QbftBlockCreatorFactory, ValidatorMulticaster
};
pub use block_creator::QbftBlockCreator;
pub use header::QbftBlockHeader;
pub use block_importer::QbftBlockImporter;
pub use extra_data::{BftExtraData, BftExtraDataCodec, AlloyBftExtraDataCodec};
pub use rlp_signature::RlpSignature;

/// Configuration for the QBFT consensus engine.
#[derive(Debug, Clone)]
pub struct QbftConfig {
    /// Timeout for a consensus round in milliseconds.
    pub message_round_timeout_ms: u64,
    /// Maximum allowable time in the future for a block's timestamp, in seconds.
    pub max_future_block_time_seconds: u64,
    /// Block period in seconds.
    pub block_period_seconds: u64,
    /// Difficulty of the block.
    pub difficulty: alloy_primitives::U256,
    /// Nonce of the block.
    pub nonce: alloy_primitives::Bytes,
    /// Fault tolerance factor.
    pub fault_tolerance_f: usize,
    /// Gas limit bound divisor.
    pub gas_limit_bound_divisor: u64,
    /// Minimum allowed gas limit.
    pub min_gas_limit: u64,
    // TODO: Add other configuration parameters as needed, e.g.:
    // pub empty_block_period_seconds: u64, // For creating empty blocks if no transactions
    // pub request_timeout_ms: u64, // Timeout for other kinds of requests if any
}

impl Default for QbftConfig {
    fn default() -> Self {
        Self {
            message_round_timeout_ms: 10000, // Default to 10 seconds
            max_future_block_time_seconds: 15, // Default to 15 seconds
            block_period_seconds: 5, // Default to 5 seconds
            difficulty: alloy_primitives::U256::from(1), // Default to 1, QBFT standard
            nonce: alloy_primitives::Bytes::from_static(&[0x80]), // RLP encoding of numeric 0
            fault_tolerance_f: 0, // Default F. Will be overridden by actual validator count.
            gas_limit_bound_divisor: 1024,
            min_gas_limit: 5000,
        }
    }
}

// Constants
pub const EMPTY_NONCE: alloy_primitives::Bytes = alloy_primitives::Bytes::from_static(&[0u8; 8]);

// #[cfg(any(test, feature = "test-utils"))]
// ... existing code ... 