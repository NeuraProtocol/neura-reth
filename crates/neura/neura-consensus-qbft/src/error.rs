use thiserror::Error;
use reth_consensus::ConsensusError as RethConsensusError;
use neura_qbft_core::error::QbftError as CoreQbftError;

/// Consensus errors for QBFT.
#[derive(Error, Debug, PartialEq, Eq, Clone)]
pub enum QbftConsensusError {
    /// An internal error from the neura-qbft-core crate.
    #[error("QBFT core error: {0}")]
    CoreError(#[from] CoreQbftError),

    /// Error from the reth_consensus crate.
    #[error("Reth consensus error: {0}")]
    RethConsensus(#[from] RethConsensusError),

    /// Header validation failed.
    #[error("Header validation failed: {0}")]
    HeaderValidationFailed(String),

    /// Block validation failed.
    #[error("Block validation failed: {0}")]
    BlockValidationFailed(String),

    /// Invalid QBFT extra data.
    #[error("Invalid QBFT extra data: {0}")]
    InvalidExtraData(String),

    // TODO: Add more specific error types as needed
}

// Note: The direct From<RethInterfacesError> was removed.
// If QbftConsensusError needs to be converted from a general Reth error,
// consider a more specific From, e.g. From<ProviderError>, or handle at call site.
// The `impl Consensus for QbftConsensus` in consensus.rs is now typed to return `reth_consensus::ConsensusError` directly. 