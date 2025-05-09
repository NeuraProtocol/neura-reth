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