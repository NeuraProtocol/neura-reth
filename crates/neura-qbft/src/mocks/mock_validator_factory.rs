use std::sync::Arc;
use crate::types::{QbftBlockHeader, QbftFinalState, BftExtraDataCodec, AlloyBftExtraDataCodec};
use crate::validation::{
    MessageValidator, MessageValidatorFactory, 
    RoundChangeMessageValidator, RoundChangeMessageValidatorFactory
};
use crate::error::QbftError;

// --- MockMessageValidatorFactory ---
#[derive(Default)] // Can be default if it doesn't hold specific state itself
pub struct MockMessageValidatorFactory;

impl MockMessageValidatorFactory {
    pub fn new() -> Self {
        Self
    }
}

impl MessageValidatorFactory for MockMessageValidatorFactory {
    fn create_message_validator(
        &self,
        parent_header: &QbftBlockHeader,
        final_state_view: Arc<dyn QbftFinalState>,
        extra_data_codec: Arc<dyn BftExtraDataCodec>,
        // This factory needs to provide the RCMV factory to MessageValidator
        round_change_message_validator_factory: Arc<dyn RoundChangeMessageValidatorFactory> 
    ) -> Result<MessageValidator, QbftError> {
        Ok(MessageValidator::new(
            final_state_view, 
            Arc::new(parent_header.clone()), 
            extra_data_codec,
            round_change_message_validator_factory
        ))
    }
}

// --- MockRoundChangeMessageValidatorFactory ---
#[derive(Default)]
pub struct MockRoundChangeMessageValidatorFactory;

impl MockRoundChangeMessageValidatorFactory {
    pub fn new() -> Self {
        Self
    }
}

impl RoundChangeMessageValidatorFactory for MockRoundChangeMessageValidatorFactory {
    fn create_round_change_message_validator(
        &self,
        parent_header: &QbftBlockHeader,
        final_state_view: Arc<dyn QbftFinalState>
    ) -> Result<RoundChangeMessageValidator, QbftError> {
        // If RoundChangeMessageValidator needed more complex deps (like a MessageValidatorFactory for certs),
        // this mock factory would need to provide them.
        Ok(RoundChangeMessageValidator::new(
            final_state_view, 
            Arc::new(parent_header.clone())
            // Potentially pass a MessageValidatorFactory instance here if RCMV needs to validate full proposals in certs
        ))
    }
} 