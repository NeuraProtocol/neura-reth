use crate::types::ConsensusRoundIdentifier;
use crate::payload::qbft_payload::QbftPayload;
use crate::payload::prepared_round_metadata::PreparedRoundMetadata; // Keep this import
use crate::messagedata::qbft_v1;
use crate::types::QbftBlock; // Keep this if RoundChangePayload uses it directly
use alloy_rlp::{RlpEncodable, RlpDecodable};

/// Represents the payload of a QBFT RoundChange message.
#[derive(Debug, Clone, PartialEq, Eq, RlpEncodable, RlpDecodable)]
#[rlp(trailing)]
pub struct RoundChangePayload {
    /// The round identifier this message is for (i.e., the target round).
    pub round_identifier: ConsensusRoundIdentifier,
    /// Optional: Metadata about a prepared round, if this node has one to justify the round change.
    #[rlp(default)]
    pub prepared_round_metadata: Option<PreparedRoundMetadata>,
    /// Optional: The block associated with `prepared_round_metadata`.
    /// This is included if `prepared_round_metadata` is Some.
    #[rlp(default)]
    pub prepared_block: Option<QbftBlock>,
}

impl RoundChangePayload {
    pub fn new(
        round_identifier: ConsensusRoundIdentifier,
        prepared_round_metadata: Option<PreparedRoundMetadata>,
        prepared_block: Option<QbftBlock>,
    ) -> Self {
        Self {
            round_identifier,
            prepared_round_metadata,
            prepared_block,
        }
    }
}

impl QbftPayload for RoundChangePayload {
    fn round_identifier(&self) -> &ConsensusRoundIdentifier {
        &self.round_identifier
    }

    fn message_type(&self) -> u8 {
        qbft_v1::ROUND_CHANGE
    }
} 