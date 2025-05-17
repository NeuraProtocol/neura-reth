use crate::types::QbftBlock;
use crate::error::QbftError;
use alloy_primitives::B256;

pub trait QbftBlockImporter: Send + Sync {
    /// Imports a finalized block into the blockchain.
    /// This should perform all necessary validation before import.
    fn import_block(&self, block: &QbftBlock) -> Result<(), QbftError>;
} 

// If QbftBlockImporter trait is also in this file, keep it.
// Otherwise, this file might only contain ImportResult.

/// Result of a block import attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImportResult {
    /// Block was successfully imported.
    Imported { 
        /// Hash of the imported block.
        block_hash: B256, 
        /// Indicates if this import resulted in a new canonical head.
        new_head: bool 
    },
    /// Block was already present in the chain.
    AlreadyInChain,
    /// The parent of the block is unknown.
    UnknownParent { parent_hash: B256 },
    /// The block is invalid for a reason other than consensus.
    InvalidBlock { error: QbftError }, 
    /// A consensus-related failure occurred.
    ConsensusFailure(String),
    /// Fallback for unknown import status.
    Unknown,
}

// Placeholder for the trait if it's not already defined elsewhere in this module.
// pub trait QbftBlockImporter: Send + Sync {
//     fn import_block(&self, block: crate::QbftBlock) -> Result<ImportResult, QbftError>;
// } 