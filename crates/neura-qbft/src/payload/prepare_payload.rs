use crate::types::ConsensusRoundIdentifier;
use crate::payload::qbft_payload::QbftPayload;
use crate::messagedata::qbft_v1;
use alloy_primitives::B256 as Hash; // Using B256 for hashes (fixed-size 32-byte array)
use alloy_rlp::{RlpEncodable, RlpDecodable};

/// Represents the payload of a QBFT Prepare message.
#[derive(Debug, Clone, PartialEq, Eq, RlpEncodable, RlpDecodable)]
pub struct PreparePayload {
    pub round_identifier: ConsensusRoundIdentifier,
    pub digest: Hash, // Hash of the proposed block
}

impl PreparePayload {
    pub fn new(round_identifier: ConsensusRoundIdentifier, digest: Hash) -> Self {
        Self { round_identifier, digest }
    }
}

impl QbftPayload for PreparePayload {
    fn round_identifier(&self) -> &ConsensusRoundIdentifier {
        &self.round_identifier
    }

    fn message_type(&self) -> u8 {
        qbft_v1::PREPARE
    }
} 