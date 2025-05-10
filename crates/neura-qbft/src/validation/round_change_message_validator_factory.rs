use std::sync::Arc;
use crate::types::{QbftBlockHeader, QbftFinalState, BftExtraDataCodec, QbftConfig};
use crate::validation::{RoundChangeMessageValidator, ProposalValidator};
use crate::error::QbftError;

/// A factory for creating `RoundChangeMessageValidator` instances.
/// This validator also needs context for the consensus process, such as the active validator set.
pub trait RoundChangeMessageValidatorFactory: Send + Sync {
    /// Creates a `RoundChangeMessageValidator` for the consensus process that will build upon `parent_header`.
    fn create_round_change_message_validator(
        &self,
        parent_header: &QbftBlockHeader,
        final_state_view: Arc<dyn QbftFinalState>,
        extra_data_codec: Arc<dyn BftExtraDataCodec>,
        // To create a ProposalValidator, we need another RCMV factory. This might seem circular,
        // but ProposalValidator needs it for *its* piggybacked RCs.
        // The RCMV created here is for top-level RCs.
        round_change_message_validator_factory: Arc<dyn RoundChangeMessageValidatorFactory>, // Renaming for clarity
        config: Arc<QbftConfig>,
    ) -> Result<RoundChangeMessageValidator, QbftError>;
}

/// Concrete Implementation of RoundChangeMessageValidatorFactory
#[derive(Default)] // Added default for easier instantiation if no special state
pub struct RoundChangeMessageValidatorFactoryImpl;

impl RoundChangeMessageValidatorFactory for RoundChangeMessageValidatorFactoryImpl {
    fn create_round_change_message_validator(
        &self,
        parent_header: &QbftBlockHeader,
        final_state_view: Arc<dyn QbftFinalState>,
        extra_data_codec: Arc<dyn BftExtraDataCodec>,
        round_change_message_validator_factory: Arc<dyn RoundChangeMessageValidatorFactory>, // Use the renamed parameter
        config: Arc<QbftConfig>,
    ) -> Result<RoundChangeMessageValidator, QbftError> {
        let proposal_validator = Arc::new(ProposalValidator::new(
            final_state_view.clone(),
            Arc::new(parent_header.clone()),
            extra_data_codec,
            round_change_message_validator_factory, // Pass it through
            config,
        ));

        Ok(RoundChangeMessageValidator::new(
            final_state_view.clone(),
            Arc::new(parent_header.clone()),
            None, // local_committed_round
            None, // local_prepared_round
            proposal_validator,
        ))
    }
} 