use crate::types::SignedData;
use crate::payload::PreparePayload;
use alloy_primitives::B256 as Hash;
use alloy_rlp::{RlpEncodable, RlpDecodable};

/// Represents metadata about a round where a block was prepared.
/// This is carried in a RoundChangePayload.
#[derive(Debug, Clone, PartialEq, Eq, RlpEncodable, RlpDecodable)]
pub struct PreparedRoundMetadata {
    pub prepared_round: u32, // The round number in which the block was prepared
    pub prepared_block_hash: Hash, // The hash of the block that was prepared
    // In Java, the RoundChange message (not its payload) carries the prepares separately.
    // However, the Proposal message which might re-propose this needs the prepares.
    // The Java RoundChangePayload's getPrepares() actually gets it from the RoundChange message wrapper.
    // For simplicity and to bundle proof, let's include prepares here, making this metadata more self-contained for validation.
    // This aligns with what a `PreparedCertificate` would conceptually hold.
    pub prepares: Vec<SignedData<PreparePayload>>,
}

impl PreparedRoundMetadata {
    pub fn new(
        prepared_round: u32,
        prepared_block_hash: Hash,
        prepares: Vec<SignedData<PreparePayload>>,
    ) -> Self {
        Self {
            prepared_round,
            prepared_block_hash,
            prepares,
        }
    }
} 