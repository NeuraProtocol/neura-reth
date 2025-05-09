use alloy_rlp::{RlpDecodable, RlpEncodable};

/// Uniquely identifies a specific consensus round for a specific block height.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, RlpEncodable, RlpDecodable)]
pub struct ConsensusRoundIdentifier {
    /// The block height (sequence number).
    pub sequence_number: u64,
    /// The consensus round number within that height.
    pub round_number: u32,
}

impl ConsensusRoundIdentifier {
    pub fn new(sequence_number: u64, round_number: u32) -> Self {
        Self { sequence_number, round_number }
    }
} 