use crate::types::ConsensusRoundIdentifier;
use crate::payload::qbft_payload::QbftPayload;
use crate::payload::prepared_round_metadata::PreparedRoundMetadata; // Corrected path
use crate::messagedata::qbft_v1;
use alloy_rlp::{RlpEncodable, RlpDecodable};

/// Represents the payload of a QBFT RoundChange message.
#[derive(Debug, Clone, PartialEq, Eq, RlpEncodable, RlpDecodable)]
pub struct RoundChangePayload {
    // Target round identifier (sequence number should match current height)
    pub target_round_identifier: ConsensusRoundIdentifier,
    // Optional: If the sender had a prepared block from a previous round for this height.
    pub prepared_round_metadata: Option<PreparedRoundMetadata>,
}

impl RoundChangePayload {
    pub fn new(
        target_round_identifier: ConsensusRoundIdentifier,
        prepared_round_metadata: Option<PreparedRoundMetadata>,
    ) -> Self {
        Self { target_round_identifier, prepared_round_metadata }
    }
}

impl QbftPayload for RoundChangePayload {
    fn round_identifier(&self) -> &ConsensusRoundIdentifier {
        // A RoundChange message is *about* its target_round_identifier.
        // The QbftPayload::round_identifier typically refers to the round the message originated *from* or is *for*.
        // For RoundChange, it's what it *targets*.
        &self.target_round_identifier
    }

    fn message_type(&self) -> u8 {
        qbft_v1::ROUND_CHANGE
    }
} 