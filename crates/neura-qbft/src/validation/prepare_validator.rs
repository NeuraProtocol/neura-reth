use crate::messagewrappers::Prepare;
use crate::validation::ValidationContext; // Assuming ValidationContext is re-exported by validation/mod.rs
use crate::error::QbftError;
use crate::payload::QbftPayload; // Added import
// Add other necessary imports if the actual validation logic needs them (e.g., QbftConfig, specific types from crate::types)

pub trait PrepareValidator: Send + Sync {
    fn validate_prepare(&self, prepare: &Prepare, context: &ValidationContext) -> Result<(), QbftError>;
}

#[derive(Default)] // Keep Default for placeholder if new() takes no args initially
pub struct PrepareValidatorImpl;

impl PrepareValidatorImpl {
    pub fn new() -> Self {
        // TODO: This might take dependencies like QbftConfig later.
        Self::default()
    }
}

impl PrepareValidator for PrepareValidatorImpl { 
    fn validate_prepare(&self, prepare: &Prepare, context: &ValidationContext) -> Result<(), QbftError> { 
        // Check 1: Prepare message's RoundIdentifier must match the ValidationContext's current round and sequence.
        let payload_round_identifier = prepare.payload().round_identifier();
        if payload_round_identifier.sequence_number != context.current_sequence_number ||
           payload_round_identifier.round_number != context.current_round_number {
            log::warn!(
                "Invalid Prepare: Payload round identifier {:?} does not match context round identifier {:?}/{:?}",
                payload_round_identifier, context.current_sequence_number, context.current_round_number
            );
            return Err(QbftError::MessageRoundMismatch { 
                message_type: "Prepare".to_string(),
                expected_sequence: context.current_sequence_number,
                expected_round: context.current_round_number,
                actual_sequence: payload_round_identifier.sequence_number,
                actual_round: payload_round_identifier.round_number,
            });
        }

        // Check 2: Prepare message's digest must match the ValidationContext's accepted_proposal_digest.
        let prepare_digest = prepare.payload().digest;
        if context.accepted_proposal_digest.is_none() {
            log::error!("Invalid Prepare: ValidationContext has no accepted_proposal_digest for round {:?}/{:?}. This should not happen if a proposal was accepted.",
                context.current_sequence_number, context.current_round_number
            );
            // This indicates a logic error upstream or an invalid context state.
            return Err(QbftError::InternalError("Context missing accepted proposal digest for Prepare validation".to_string()));
        }
        if Some(prepare_digest) != context.accepted_proposal_digest {
            log::warn!(
                "Invalid Prepare: Digest {:?} does not match accepted proposal digest {:?} for round {:?}/{:?}",
                prepare_digest, context.accepted_proposal_digest, context.current_sequence_number, context.current_round_number
            );
            return Err(QbftError::PrepareDigestMismatch);
        }

        // Check 3: Author of the Prepare message must be one of the current_validators.
        let author = prepare.author()?;
        if !context.current_validators.contains(&author) {
            log::warn!(
                "Invalid Prepare: Author {:?} is not in the current validator set for round {:?}/{:?}. Validators: {:?}",
                author, context.current_sequence_number, context.current_round_number, context.current_validators
            );
            return Err(QbftError::NotAValidator { sender: author });
        }
        
        Ok(())
        // unimplemented!("validate_prepare not implemented yet") 
    }
} 