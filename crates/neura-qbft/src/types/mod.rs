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
#[derive(Clone, Debug)]
pub struct QbftConfig {
    /// Timeout for a consensus round in milliseconds.
    pub message_round_timeout_ms: u64,
    /// Maximum allowable time in the future for a block's timestamp, in seconds.
    pub max_future_block_time_seconds: u64,
    // TODO: Add other configuration parameters as needed, e.g.:
    // pub block_period_seconds: u64, // If QBFT variant supports fixed block period
    // pub empty_block_period_seconds: u64, // For creating empty blocks if no transactions
    // pub request_timeout_ms: u64, // Timeout for other kinds of requests if any
}

impl Default for QbftConfig {
    fn default() -> Self {
        Self {
            message_round_timeout_ms: 10000, // Default to 10 seconds
            max_future_block_time_seconds: 15, // Default to 15 seconds
        }
    }
} 