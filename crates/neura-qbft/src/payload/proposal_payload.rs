use crate::types::{ConsensusRoundIdentifier, QbftBlock};
use crate::payload::qbft_payload::QbftPayload; // Corrected path
use crate::messagedata::qbft_v1; // For message type codes
use alloy_rlp::{RlpEncodable, RlpDecodable}; // Added RlpEncodable, RlpDecodable

/// Represents the payload of a QBFT Proposal message.
/// This is the actual data that gets signed by the proposer.
#[derive(Debug, Clone, PartialEq, Eq, RlpEncodable, RlpDecodable)]
pub struct ProposalPayload {
    pub round_identifier: ConsensusRoundIdentifier,
    pub proposed_block: QbftBlock,
    // The block_encoder from Java is a transient field for encoding/decoding logic,
    // not part of the RLP structure itself. In Rust, RLP logic is usually handled by traits.
}

impl ProposalPayload {
    pub fn new(round_identifier: ConsensusRoundIdentifier, proposed_block: QbftBlock) -> Self {
        Self { round_identifier, proposed_block }
    }
}

impl QbftPayload for ProposalPayload {
    fn round_identifier(&self) -> &ConsensusRoundIdentifier {
        &self.round_identifier
    }

    fn message_type(&self) -> u8 {
        qbft_v1::PROPOSAL // We'll define qbft_v1::PROPOSAL later
    }
} 