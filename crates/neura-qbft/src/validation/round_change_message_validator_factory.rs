use std::sync::Arc;
use crate::types::{QbftBlockHeader, QbftFinalState};
use crate::validation::RoundChangeMessageValidator;
use crate::error::QbftError;

/// A factory for creating `RoundChangeMessageValidator` instances.
/// This validator also needs context for the consensus process, such as the active validator set.
pub trait RoundChangeMessageValidatorFactory: Send + Sync {
    /// Creates a `RoundChangeMessageValidator` for the consensus process that will build upon `parent_header`.
    fn create_round_change_message_validator(
        &self,
        parent_header: &QbftBlockHeader,
        final_state_view: Arc<dyn QbftFinalState>
    ) -> Result<RoundChangeMessageValidator, QbftError>;
}

/// Concrete Implementation of RoundChangeMessageValidatorFactory
#[derive(Default)] // Added default for easier instantiation if no special state
pub struct RoundChangeMessageValidatorFactoryImpl;

impl RoundChangeMessageValidatorFactory for RoundChangeMessageValidatorFactoryImpl {
    fn create_round_change_message_validator(
        &self,
        parent_header: &QbftBlockHeader,
        final_state_view: Arc<dyn QbftFinalState>
    ) -> Result<RoundChangeMessageValidator, QbftError> {
        Ok(RoundChangeMessageValidator::new(
            final_state_view.clone(),
            Arc::new(parent_header.clone()), // RoundChangeMessageValidator expects Arc<QbftBlockHeader>
        ))
    }
} 