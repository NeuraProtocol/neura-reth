use crate::types::{QbftBlock, ConsensusRoundIdentifier, QbftBlockHeader};
use crate::error::QbftError;

// Placeholder for QbftBlockHeader - will be defined in header.rs
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QbftBlockHeader { 
    // Simplified: real header has parent_hash, number, timestamp, extra_data etc.
    pub rlp: Bytes, // Placeholder representing encoded header
    pub number: u64, // Needed for proposer selection context at least
    pub timestamp: u64, // Needed by block timer
}

impl QbftBlockHeader { // Dummy impl for now
    pub fn new_placeholder(number: u64, timestamp: u64) -> Self {
        Self { rlp: Bytes::new(), number, timestamp }
    }
}

pub trait QbftBlockCreator: Send + Sync {
    /// Creates a new block proposal.
    /// `parent_header`: The header of the parent block.
    /// `round_identifier`: The current round for which this block is being created.
    /// `timestamp_seconds`: The desired timestamp for the new block.
    fn create_block(
        &self,
        parent_header: &QbftBlockHeader, 
        round_identifier: &ConsensusRoundIdentifier,
        timestamp_seconds: u64,
    ) -> Result<QbftBlock, QbftError>;
} 