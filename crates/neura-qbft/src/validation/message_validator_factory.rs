use std::sync::Arc;
use crate::types::{QbftBlockHeader, QbftFinalState, BftExtraDataCodec};
use crate::validation::{MessageValidator, RoundChangeMessageValidatorFactory};
use crate::error::QbftError;

/// A factory for creating `MessageValidator` instances.
/// The validator needs to be configured for a specific consensus context (e.g., block height, active validators).
pub trait MessageValidatorFactory: Send + Sync {
    /// Creates a `MessageValidator` for the consensus process that will build upon `parent_header`.
    /// `final_state_view` provides access to chain state like the current validator set for the new block's height.
    fn create_message_validator(
        &self,
        parent_header: &QbftBlockHeader,
        final_state_view: Arc<dyn QbftFinalState>, // Provides access to validator set, proposer logic, etc.
        extra_data_codec: Arc<dyn BftExtraDataCodec>, // Added codec
        round_change_message_validator_factory: Arc<dyn RoundChangeMessageValidatorFactory> // Added factory
    ) -> Result<MessageValidator, QbftError>;
} 