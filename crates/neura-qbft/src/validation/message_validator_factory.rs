use std::sync::Arc;
use crate::types::QbftConfig;
// Removed unused imports: QbftBlockHeader, QbftFinalState, BftExtraDataCodec
// Removed unused import: RoundChangeMessageValidatorFactory
// Removed unused import: QbftError

// Import the validator traits and impls that this factory will create.
use crate::validation::{ProposalValidator, ProposalValidatorImpl};
use crate::validation::{PrepareValidator, PrepareValidatorImpl}; 
use crate::validation::{CommitValidator, CommitValidatorImpl};     

/// A factory for creating validator instances for different message types.
pub trait MessageValidatorFactory: Send + Sync {
    /// Creates a new ProposalValidator instance.
    /// Takes Arc<Self> to allow passing the factory to the validator if needed.
    fn create_proposal_validator(self: Arc<Self>) -> Arc<dyn ProposalValidator + Send + Sync>;

    /// Creates a new PrepareValidator instance.
    fn create_prepare_validator(self: Arc<Self>) -> Arc<dyn PrepareValidator + Send + Sync>;

    /// Creates a new CommitValidator instance.
    fn create_commit_validator(self: Arc<Self>) -> Arc<dyn CommitValidator + Send + Sync>;
}

/// Concrete Implementation of MessageValidatorFactory
pub struct MessageValidatorFactoryImpl {
    #[allow(dead_code)] 
    config: Arc<QbftConfig>,
}

impl MessageValidatorFactoryImpl {
    pub fn new(config: Arc<QbftConfig>) -> Self {
        Self { config }
    }
}

impl MessageValidatorFactory for MessageValidatorFactoryImpl {
    fn create_proposal_validator(self: Arc<Self>) -> Arc<dyn ProposalValidator + Send + Sync> {
        Arc::new(ProposalValidatorImpl::new(self.clone() as Arc<dyn MessageValidatorFactory>, self.config.clone()))
    }

    fn create_prepare_validator(self: Arc<Self>) -> Arc<dyn PrepareValidator + Send + Sync> {
        Arc::new(PrepareValidatorImpl::new())
    }

    fn create_commit_validator(self: Arc<Self>) -> Arc<dyn CommitValidator + Send + Sync> {
        Arc::new(CommitValidatorImpl::new())
    }
} 