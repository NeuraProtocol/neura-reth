use thiserror::Error;

// Forward declaration for ConsensusRoundIdentifier, assuming it will be in super::types
// This will be properly resolved once types::ConsensusRoundIdentifier is defined.
// For now, to make this file parseable, we might need a placeholder if direct super:: doesn't work
// without the type existing. However, Rust usually handles this okay if the module structure is declared.

#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum QbftError {
    #[error("RLP encoding failed: {0}")]
    RlpEncodingError(String),
    #[error("RLP decoding failed: {0}")]
    RlpDecodingError(String),
    #[error("Invalid signature in message from {sender:?}")]
    InvalidSignature {
        sender: alloy_primitives::Address,
    },
    #[error("Validation failed: {0}")]
    ValidationError(String),
    #[error("Invalid block: {0}")]
    InvalidBlock(String),
    #[error("Invalid round identifier: expected {expected:?}, got {actual:?}")]
    InvalidRoundIdentifier {
        // Ensure this path is correct once types/mod.rs and its contents are defined.
        expected: super::types::ConsensusRoundIdentifier, 
        actual: super::types::ConsensusRoundIdentifier,
    },
    #[error("Invalid proposer: expected {expected:?}, got {actual:?}")]
    InvalidProposer {
        expected: alloy_primitives::Address,
        actual: alloy_primitives::Address,
    },
    #[error("Proposal already received for this round")]
    ProposalAlreadyReceived,
    #[error("No proposal received for this round yet")]
    NoProposalReceived,
    #[error("Message intended for a past round: {message_round:?}, current round: {current_round:?}")]
    MessageForPastRound {
        message_round: super::types::ConsensusRoundIdentifier, 
        current_round: super::types::ConsensusRoundIdentifier,
    },
    #[error("Message not from a current validator: {sender:?}")]
    NotAValidator { sender: alloy_primitives::Address },
    #[error("Quorum not reached: needed {needed}, got {got} for {item}")]
    QuorumNotReached {
        needed: usize,
        got: usize,
        item: String,
    },
    #[error("Internal error: {0}")]
    InternalError(String), // For unexpected logic errors
    #[error("Node key not available for signing")]
    NodeKeyUnavailable,
    #[error("Crypto operation failed: {0}")]
    CryptoError(String),
    #[error("RLP error: {0}")]
    RlpError(#[from] alloy_rlp::Error),
    #[error("Invalid message type: {0}")]
    InvalidMessageType(u8),
    #[error("No validators available to select proposer")]
    NoValidators,
    #[error("Consensus invariant violation: {0}")]
    ConsensusInvariantViolation(String),
    #[error("Invalid state: {0}")]
    InvalidState(String),
    #[error("Block import failed: {0}")]
    BlockImportFailed(String),
    #[error("Signing error: {0}")]
    SigningError(String),
    #[error("Recovery error: {0}")]
    RecoveryError(String),
    #[error("Block creation error: {0}")]
    BlockCreationError(String),
    #[error("Block import error: {0}")]
    BlockImportError(String),
    #[error("Timeout error: {0}")]
    TimeoutError(String),
    #[error("Replica is not a validator")]
    NotValidator,
    #[error("Replica is not the proposer for the current round")]
    NotProposer,
    #[error("Message from future round")]
    MessageFromFutureRound,
    #[error("Message from past round")]
    MessageFromPastRound,
    #[error("Unknown error")]
    Unknown,
}

// Helper to convert k256::ecdsa::Error to QbftError
impl From<k256::ecdsa::Error> for QbftError {
    fn from(err: k256::ecdsa::Error) -> Self {
        QbftError::CryptoError(err.to_string())
    }
} 