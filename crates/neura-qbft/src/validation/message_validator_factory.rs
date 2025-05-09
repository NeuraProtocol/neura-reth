use std::sync::Arc;
use crate::types::{QbftBlockHeader, QbftFinalState, BftExtraDataCodec, ConsensusRoundIdentifier};
use crate::validation::{MessageValidator, RoundChangeMessageValidatorFactory, ProposalValidator, PrepareValidator, CommitValidator, RoundChangeMessageValidator};
use crate::error::QbftError;
use alloy_primitives::Address;

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

/// Concrete Implementation of MessageValidatorFactory
#[derive(Default)] // Added default for easier instantiation if no special state
pub struct MessageValidatorFactoryImpl;

impl MessageValidatorFactory for MessageValidatorFactoryImpl {
    fn create_message_validator(
        &self,
        parent_header: &QbftBlockHeader,
        final_state_view: Arc<dyn QbftFinalState>,
        extra_data_codec: Arc<dyn BftExtraDataCodec>,
        round_change_message_validator_factory: Arc<dyn RoundChangeMessageValidatorFactory> 
    ) -> Result<MessageValidator, QbftError> {
        // Note: MessageValidator::new now takes the factory and creates validators internally or on demand.
        // The old way of creating sub-validators here is removed.
        Ok(MessageValidator::new(
            final_state_view.clone(),
            Arc::new(parent_header.clone()), // MessageValidator expects Arc<QbftBlockHeader>
            extra_data_codec.clone(),
            round_change_message_validator_factory.clone(),
        ))
    }
} 