use crate::types::QbftBlock;
use crate::error::QbftError;

pub trait QbftBlockImporter: Send + Sync {
    /// Imports a finalized block into the blockchain.
    /// This should perform all necessary validation before import.
    fn import_block(&self, block: &QbftBlock) -> Result<(), QbftError>;
} 