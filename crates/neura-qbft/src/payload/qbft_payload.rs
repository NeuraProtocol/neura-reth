use crate::types::ConsensusRoundIdentifier;
use alloy_rlp::{Encodable, Decodable};

/// Trait for QBFT message payloads.
/// Payloads are the core data signed in messages.
pub trait QbftPayload: Encodable + Decodable + Send + Sync + std::fmt::Debug {
    /// Returns the consensus round identifier (height and round) this payload pertains to.
    fn round_identifier(&self) -> &ConsensusRoundIdentifier;

    /// Returns the QBFT message type code (e.g., PROPOSAL, PREPARE).
    /// These codes would be defined in a place like `messagedata::qbft_v1`.
    fn message_type(&self) -> u8; 
} 