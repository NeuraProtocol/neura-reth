use std::sync::Arc;
use crate::types::{QbftBlockHeader, QbftFinalState};
use crate::validation::MessageValidator;
use crate::error::QbftError;

/// A factory for creating `MessageValidator` instances.
/// The validator needs to be configured for a specific consensus context (e.g., block height, active validators).
pub trait MessageValidatorFactory: Send + Sync {
    /// Creates a `MessageValidator` for the consensus process that will build upon `parent_header`.
    /// `final_state_view` provides access to chain state like the current validator set for the new block's height.
    fn create_message_validator(
        &self,
        parent_header: &QbftBlockHeader,
        final_state_view: Arc<dyn QbftFinalState> // Provides access to validator set, proposer logic, etc.
    ) -> Result<MessageValidator, QbftError>;
} 