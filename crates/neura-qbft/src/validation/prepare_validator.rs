use crate::messagewrappers::Prepare;
use crate::validation::ValidationContext; // Assuming ValidationContext is re-exported by validation/mod.rs
use crate::error::QbftError;
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
        let payload_round_identifier = prepare.payload().round_identifier;
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

#[cfg(test)]
pub mod tests {
    use super::*; // Bring in PrepareValidatorImpl, PrepareValidator, ValidationContext, QbftError
    use crate::messagewrappers::{Prepare}; // Removed BftMessage import
    use crate::payload::{PreparePayload}; 
    use crate::types::{ConsensusRoundIdentifier, NodeKey, SignedData, QbftConfig, QbftBlockHeader, QbftFinalState, BftExtraDataCodec}; // Core types
    use crate::mocks::MockQbftFinalState; // For creating ValidationContext
    use crate::validation::proposal_validator::tests::{testing_extradata_codec, default_parent_header, address_from_key, create_node_key, default_config}; // Re-use test helpers

    use alloy_primitives::{Address, B256}; // Removed Bytes, U256
    use std::sync::Arc;
    use std::collections::HashSet;
    use rand; // Added for random B256 generation

    // --- Test Helper: Create Prepare Message ---
    fn create_prepare_message(
        round_id: ConsensusRoundIdentifier,
        digest: B256,
        signer_key: &NodeKey,
    ) -> Prepare {
        let payload = PreparePayload::new(round_id, digest);
        let signed_payload = SignedData::sign(payload, signer_key).expect("Failed to sign PreparePayload");
        // Corrected: Pass signed_payload directly to Prepare::new
        Prepare::new(signed_payload) 
    }

    // --- Test Helper: Create ValidationContext ---
    // Simplified version, assuming proposal_validator's test helpers are available and suitable.
    // We might need to refine this if PrepareValidator requires a more specific context setup.
    fn default_prepare_validation_context(
        current_sequence: u64,
        current_round: u32,
        current_validators: HashSet<Address>,
        accepted_proposal_digest: Option<B256>,
        config_opt: Option<Arc<QbftConfig>>,
        // Add other fields from ValidationContext if needed for specific tests
        // For Prepare, parent_header, final_state, extra_data_codec, expected_proposer are not directly used by current logic.
        // However, a more complete context might be good practice for future-proofing.
        parent_header_opt: Option<Arc<QbftBlockHeader>>,
        final_state_opt: Option<Arc<dyn QbftFinalState>>,
        extra_data_codec_opt: Option<Arc<dyn BftExtraDataCodec>>,
        expected_proposer_opt: Option<Address>,
        local_node_key_for_final_state: Arc<NodeKey>, // For default_final_state if final_state_opt is None

    ) -> ValidationContext {
        let config = config_opt.unwrap_or_else(default_config);
        let parent_header = parent_header_opt.unwrap_or_else(|| default_parent_header(current_sequence.saturating_sub(1), B256::ZERO, 100, 50000));
        let final_state = final_state_opt.unwrap_or_else(|| Arc::new(MockQbftFinalState::new(local_node_key_for_final_state, current_validators.clone())));
        let extra_data_codec = extra_data_codec_opt.unwrap_or_else(testing_extradata_codec);
        let expected_proposer = expected_proposer_opt.unwrap_or_else(|| current_validators.iter().next().cloned().unwrap_or_default());

        ValidationContext {
            current_sequence_number: current_sequence,
            current_round_number: current_round,
            current_validators,
            accepted_proposal_digest,
            // Fill in other fields with sensible defaults if they become necessary
            parent_header, // from proposal_validator tests
            final_state, // from proposal_validator tests
            extra_data_codec, // from proposal_validator tests
            config, // from proposal_validator tests
            expected_proposer, // from proposal_validator tests
        }
    }

    // --- Test Cases --- 

    #[test]
    fn test_validate_prepare_valid() {
        let validator_key = Arc::new(create_node_key());
        let validator_address = address_from_key(&validator_key);
        let validators = HashSet::from([validator_address]);

        let sequence = 1;
        let round = 0;
        let round_id = ConsensusRoundIdentifier::new(sequence, round);
        let digest = B256::new(rand::random()); // Corrected B256 random generation

        let context = default_prepare_validation_context(
            sequence,
            round,
            validators.clone(),
            Some(digest),
            None, None, None, None, None, validator_key.clone()
        );

        let prepare_msg = create_prepare_message(round_id, digest, &validator_key);
        let validator = PrepareValidatorImpl::new();
        let result = validator.validate_prepare(&prepare_msg, &context);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_prepare_invalid_round_mismatch_sequence() {
        let validator_key = Arc::new(create_node_key());
        let validator_address = address_from_key(&validator_key);
        let validators = HashSet::from([validator_address]);

        let context_sequence = 1;
        let message_sequence = context_sequence + 1; // Mismatch
        let round = 0;
        
        let _context_round_id = ConsensusRoundIdentifier::new(context_sequence, round); // Renamed to avoid unused warning if not used elsewhere
        let message_round_id = ConsensusRoundIdentifier::new(message_sequence, round);
        let digest = B256::new(rand::random()); // Corrected B256 random generation

        let context = default_prepare_validation_context(
            context_sequence, // Context for seq 1
            round,
            validators.clone(),
            Some(digest),
            None, None, None, None, None, validator_key.clone()
        );

        let prepare_msg = create_prepare_message(message_round_id, digest, &validator_key); // Msg for seq 2
        let validator = PrepareValidatorImpl::new();
        let result = validator.validate_prepare(&prepare_msg, &context);
        assert!(matches!(result, Err(QbftError::MessageRoundMismatch { .. })));
    }

    #[test]
    fn test_validate_prepare_invalid_round_mismatch_round_number() {
        let validator_key = Arc::new(create_node_key());
        let validator_address = address_from_key(&validator_key);
        let validators = HashSet::from([validator_address]);

        let sequence = 1;
        let context_round = 0;
        let message_round = context_round + 1; // Mismatch
        
        let _context_round_id = ConsensusRoundIdentifier::new(sequence, context_round); // Renamed
        let message_round_id = ConsensusRoundIdentifier::new(sequence, message_round);
        let digest = B256::new(rand::random()); // Corrected B256 random generation

        let context = default_prepare_validation_context(
            sequence,
            context_round, // Context for round 0
            validators.clone(),
            Some(digest),
            None, None, None, None, None, validator_key.clone()
        );

        let prepare_msg = create_prepare_message(message_round_id, digest, &validator_key); // Msg for round 1
        let validator = PrepareValidatorImpl::new();
        let result = validator.validate_prepare(&prepare_msg, &context);
        assert!(matches!(result, Err(QbftError::MessageRoundMismatch { .. })));
    }

    #[test]
    fn test_validate_prepare_invalid_digest_mismatch() {
        let validator_key = Arc::new(create_node_key());
        let validator_address = address_from_key(&validator_key);
        let validators = HashSet::from([validator_address]);

        let sequence = 1;
        let round = 0;
        let round_id = ConsensusRoundIdentifier::new(sequence, round);
        let context_digest = B256::new(rand::random()); // Corrected B256 random generation
        let message_digest = B256::new(rand::random()); // Corrected B256 random generation

        assert_ne!(context_digest, message_digest);

        let context = default_prepare_validation_context(
            sequence,
            round,
            validators.clone(),
            Some(context_digest), // Context expects context_digest
            None, None, None, None, None, validator_key.clone()
        );

        let prepare_msg = create_prepare_message(round_id, message_digest, &validator_key); // Msg has message_digest
        let validator = PrepareValidatorImpl::new();
        let result = validator.validate_prepare(&prepare_msg, &context);
        assert!(matches!(result, Err(QbftError::PrepareDigestMismatch)));
    }

    #[test]
    fn test_validate_prepare_context_missing_digest() {
        let validator_key = Arc::new(create_node_key());
        let validator_address = address_from_key(&validator_key);
        let validators = HashSet::from([validator_address]);

        let sequence = 1;
        let round = 0;
        let round_id = ConsensusRoundIdentifier::new(sequence, round);
        let message_digest = B256::new(rand::random()); // Corrected B256 random generation

        let context = default_prepare_validation_context(
            sequence,
            round,
            validators.clone(),
            None, // Context has NO accepted digest
            None, None, None, None, None, validator_key.clone()
        );

        let prepare_msg = create_prepare_message(round_id, message_digest, &validator_key);
        let validator = PrepareValidatorImpl::new();
        let result = validator.validate_prepare(&prepare_msg, &context);
        assert!(matches!(result, Err(QbftError::InternalError(_))));
    }

    #[test]
    fn test_validate_prepare_invalid_author_not_validator() {
        let validator_key = Arc::new(create_node_key());
        let validator_address = address_from_key(&validator_key);
        let current_validators = HashSet::from([validator_address]); // Only one validator in the set

        let non_validator_key = Arc::new(create_node_key()); // A different key for the message author
        let non_validator_address = address_from_key(&non_validator_key);
        assert_ne!(validator_address, non_validator_address);

        let sequence = 1;
        let round = 0;
        let round_id = ConsensusRoundIdentifier::new(sequence, round);
        let digest = B256::new(rand::random()); // Corrected B256 random generation

        let context = default_prepare_validation_context(
            sequence,
            round,
            current_validators.clone(), // Context knows only validator_address
            Some(digest),
            None, None, None, None, None, validator_key.clone()
        );

        // Prepare message signed by non_validator_key
        let prepare_msg = create_prepare_message(round_id, digest, &non_validator_key); 
        let validator = PrepareValidatorImpl::new();
        let result = validator.validate_prepare(&prepare_msg, &context);
        assert!(matches!(result, Err(QbftError::NotAValidator { sender }) if sender == non_validator_address));
    }
} 