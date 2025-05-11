use std::sync::Arc;
use crate::messagewrappers::RoundChange;
use crate::validation::proposal_validator::ValidationContext; // Corrected import path
use crate::error::QbftError;
use crate::types::QbftConfig; // Corrected import
use crate::payload::QbftPayload; // Added import
use crate::validation::MessageValidatorFactory; // For validating piggybacked messages
use std::collections::HashSet; // Added for duplicate author check

pub trait RoundChangeMessageValidator: Send + Sync {
    fn validate_round_change(&self, round_change: &RoundChange, context: &ValidationContext) -> Result<(), QbftError>;
}

// This Impl struct will hold dependencies needed to perform validation.
// For RoundChange, this often means needing to validate nested proposals or prepares,
// hence the MessageValidatorFactory.
pub struct RoundChangeMessageValidatorImpl {
    #[allow(dead_code)] // Will be used by actual validation logic
    message_validator_factory: Arc<dyn MessageValidatorFactory>,
    #[allow(dead_code)] // Will be used by actual validation logic
    config: Arc<QbftConfig>,
    // Add other dependencies if needed, e.g., access to QbftFinalState for certain checks.
}

impl RoundChangeMessageValidatorImpl {
    // Constructor takes dependencies from the factory that creates it.
    pub fn new(message_validator_factory: Arc<dyn MessageValidatorFactory>, config: Arc<QbftConfig>) -> Self {
        Self { message_validator_factory, config }
    }
}

impl RoundChangeMessageValidator for RoundChangeMessageValidatorImpl { 
    fn validate_round_change(&self, round_change: &RoundChange, context: &ValidationContext) -> Result<(), QbftError> { 
        log::trace!(
            "Validating RoundChange message for sq/rd {:?}/{:?}. Context sq/rd: {:?}/{:?}", 
            round_change.payload().round_identifier.sequence_number, 
            round_change.payload().round_identifier.round_number,
            context.current_sequence_number,
            context.current_round_number
        );

        // Check 1: Author of the RoundChange message must be one of the current_validators.
        let author = round_change.author()?;
        if !context.current_validators.contains(&author) {
            log::warn!(
                "Invalid RoundChange: Author {:?} is not in the current validator set for context round {:?}/{:?}. Validators: {:?}",
                author, context.current_sequence_number, context.current_round_number, context.current_validators
            );
            return Err(QbftError::NotAValidator { sender: author });
        }

        // Check 2: Target round validation.
        let rc_target_round_id = round_change.payload().round_identifier();
        // A RoundChange message is for the current block height (sequence number).
        if rc_target_round_id.sequence_number != context.current_sequence_number {
            log::warn!(
                "Invalid RoundChange: Targets sequence number {} but current context sequence is {}. Author: {:?}",
                rc_target_round_id.sequence_number, context.current_sequence_number, author
            );
            return Err(QbftError::MessageRoundMismatch { 
                message_type: "RoundChange".to_string(),
                expected_sequence: context.current_sequence_number,
                // For sequence mismatch, expected_round is less critical, but context.current_round_number is a sensible default.
                expected_round: context.current_round_number, 
                actual_sequence: rc_target_round_id.sequence_number,
                actual_round: rc_target_round_id.round_number,
            });
        }
        // Target round number must be greater than the context's current round number.
        if rc_target_round_id.round_number <= context.current_round_number {
            log::warn!(
                "Invalid RoundChange: Targets round number {} but current context round is {}. Must be greater. Author: {:?}",
                rc_target_round_id.round_number, context.current_round_number, author
            );
            // Re-use MessageRoundMismatch or create a more specific error like RoundChangeTargetInvalid.
            // For now, using MessageRoundMismatch indicates the round part is the issue.
            return Err(QbftError::MessageRoundMismatch { 
                message_type: "RoundChange".to_string(),
                expected_sequence: context.current_sequence_number, 
                // Indicate that expected_round should be > context.current_round_number, 
                // but the error struct takes specific values. This signals the logic violation.
                expected_round: context.current_round_number + 1, // Illustrative, the check is <= 
                actual_sequence: rc_target_round_id.sequence_number,
                actual_round: rc_target_round_id.round_number,
            });
        }

        // Check 3: Handle PreparedRoundMetadata if present.
        if let Some(prepared_metadata) = round_change.payload().prepared_round_metadata.as_ref() {
            log::trace!("RoundChange has PreparedRoundMetadata for prepared_round: {}", prepared_metadata.prepared_round);

            // 3.1. The round of the prepared certificate must be less than the target round of this RoundChange.
            if prepared_metadata.prepared_round >= rc_target_round_id.round_number {
                log::warn!(
                    "Invalid RoundChange: PreparedRoundMetadata is for round {} which is not less than RoundChange target round {}. Author: {:?}",
                    prepared_metadata.prepared_round, rc_target_round_id.round_number, author
                );
                return Err(QbftError::ValidationError(
                    "PreparedRoundMetadata round not less than RoundChange target round".to_string(),
                ));
            }

            // 3.2. If PreparedRoundMetadata is present, the RoundChange MUST also contain a prepared_block.
            let prepared_block_in_rc = round_change.payload().prepared_block.as_ref()
                .ok_or_else(|| {
                    log::warn!(
                        "Invalid RoundChange: Contains PreparedRoundMetadata but no prepared_block. Author: {:?}", author
                    );
                    QbftError::ValidationError("RoundChange with PreparedRoundMetadata must also contain prepared_block".to_string())
                })?;
            
            // 3.3. The hash of the prepared_block in RoundChange must match the prepared_block_hash in PreparedRoundMetadata.
            let prepared_block_in_rc_hash = prepared_block_in_rc.hash();
            if prepared_block_in_rc_hash != prepared_metadata.prepared_block_hash {
                log::warn!(
                    "Invalid RoundChange: Hash of prepared_block ({:?}) does not match prepared_block_hash in PreparedRoundMetadata ({:?}). Author: {:?}",
                    prepared_block_in_rc_hash, prepared_metadata.prepared_block_hash, author
                );
                return Err(QbftError::ValidationError(
                    "prepared_block hash mismatch with PreparedRoundMetadata".to_string(),
                ));
            }

            // 3.4. Validate the inner proposal from PreparedRoundMetadata.
            let proposal_validator = self.message_validator_factory.clone().create_proposal_validator();
            let inner_proposal_payload = prepared_metadata.signed_proposal_payload.payload();
            let inner_proposal_round_id = inner_proposal_payload.round_identifier();
            
            // Ensure the inner proposal's sequence number matches the current context (RoundChange is for current height).
            if inner_proposal_round_id.sequence_number != context.current_sequence_number {
                log::warn!(
                    "Invalid RoundChange: Inner proposal in PreparedRoundMetadata targets sequence {} but current context is {}. Author: {:?}",
                    inner_proposal_round_id.sequence_number, context.current_sequence_number, author
                );
                return Err(QbftError::ValidationError(
                    "Inner proposal in PreparedRoundMetadata has mismatched sequence number".to_string(),
                ));
            }
            // Ensure the inner proposal's round number matches the prepared_round from metadata.
            if inner_proposal_round_id.round_number != prepared_metadata.prepared_round {
                 log::warn!(
                    "Invalid RoundChange: Inner proposal round {} does not match PreparedRoundMetadata.prepared_round {}. Author: {:?}",
                    inner_proposal_round_id.round_number, prepared_metadata.prepared_round, author
                );
                return Err(QbftError::ValidationError(
                    "Inner proposal round mismatch with PreparedRoundMetadata.prepared_round".to_string(),
                ));
            }

            let validators_for_inner_proposal = context.final_state.get_validators_for_block(inner_proposal_round_id.sequence_number)?;
            let parent_hash_for_inner_proposal = inner_proposal_payload.proposed_block.header.parent_hash;
            let parent_header_for_inner_proposal = context.final_state.get_block_header(&parent_hash_for_inner_proposal)
                .ok_or_else(|| QbftError::InternalError(format!("Parent header not found for inner proposal's parent hash: {:?}", parent_hash_for_inner_proposal)))?;
            let expected_proposer_for_inner_proposal = context.final_state.get_proposer_for_round(&inner_proposal_round_id)?;

            let inner_proposal_context = ValidationContext::new(
                inner_proposal_round_id.sequence_number,
                inner_proposal_round_id.round_number,
                validators_for_inner_proposal.iter().cloned().collect(),
                Arc::new(parent_header_for_inner_proposal),
                context.final_state.clone(),
                context.extra_data_codec.clone(),
                self.config.clone(),
                Some(prepared_metadata.prepared_block_hash),
                expected_proposer_for_inner_proposal,
            );

            // Note: The `validate_proposal` method expects a `Proposal` wrapper, not `SignedData<ProposalPayload>` directly.
            // We need to construct a temporary `Proposal` or adjust `ProposalValidator` if this is common.
            // For now, assuming `prepared_metadata.signed_proposal_payload` is of a type that `ProposalValidator` can handle,
            // or we construct the `Proposal` message correctly from it.
            // The `signed_proposal_payload` field in `PreparedRoundMetadata` is `BftMessage<ProposalPayload>` which is what `Proposal::new` takes for its `inner` field.
            // However, `ProposalValidator::validate_proposal` takes `&Proposal` which also includes `block_header`, `round_change_proofs`, `prepared_certificate`.
            // The `signed_proposal_payload` in `PreparedRoundMetadata` *is* the core proposal that was prepared.
            // We need to ensure the block it refers to (via its digest) is the same as `prepared_block_in_rc`.
            // This was checked by `prepared_block_in_rc_hash == prepared_metadata.prepared_block_hash`.
            // And `inner_proposal_payload.proposed_block.hash()` should also match `prepared_metadata.prepared_block_hash`.
            if inner_proposal_payload.proposed_block.hash() != prepared_metadata.prepared_block_hash {
                log::warn!(
                    "Invalid RoundChange: Inner proposal block hash {:?} does not match PreparedRoundMetadata.prepared_block_hash {:?}. Author: {:?}",
                    inner_proposal_payload.proposed_block.hash(), prepared_metadata.prepared_block_hash, author
                );
                return Err(QbftError::ValidationError(
                    "Inner proposal block hash mismatch with PreparedRoundMetadata.prepared_block_hash".to_string(),
                ));
            }

            // Construct a Proposal wrapper for validation. It won't have RC proofs or a cert itself, those are part of the *outer* proposal.
            let inner_bft_message = prepared_metadata.signed_proposal_payload.clone(); // BftMessage<ProposalPayload>
            let inner_proposal_for_validation = crate::messagewrappers::Proposal::new(
                inner_bft_message,
                prepared_block_in_rc.header.clone(),
                Vec::new(),
                None,
            );

            proposal_validator.validate_proposal(&inner_proposal_for_validation, &inner_proposal_context)?;
            log::debug!("Successfully validated inner proposal from PreparedRoundMetadata for RoundChange by {:?}", author);

            // 3.5. Validate the prepares within PreparedRoundMetadata.
            let prepare_validator = self.message_validator_factory.clone().create_prepare_validator();
            let mut prepare_authors = HashSet::new();
            let num_valid_prepares = prepared_metadata.prepares.len();

            // The context for these prepares relates to the inner proposal they are certifying.
            // parent_header for this context should be the one from inner_proposal_context
            let prepare_validation_context = ValidationContext::new(
                inner_proposal_round_id.sequence_number,
                inner_proposal_round_id.round_number,
                inner_proposal_context.current_validators.clone(), 
                inner_proposal_context.parent_header.clone(), 
                context.final_state.clone(), 
                context.extra_data_codec.clone(),
                self.config.clone(),
                Some(prepared_metadata.prepared_block_hash),
                expected_proposer_for_inner_proposal, 
            );

            for signed_prepare_payload in prepared_metadata.prepares.iter() {
                // a. Validate each prepare message using the prepare_validator.
                let prepare_to_validate = crate::messagewrappers::Prepare::new(signed_prepare_payload.clone());
                
                prepare_validator.validate_prepare(&prepare_to_validate, &prepare_validation_context)?;

                // b. Check for duplicate authors in prepares.
                let prepare_author = prepare_to_validate.author()?; // Use author() on the Prepare wrapper
                if !prepare_authors.insert(prepare_author) {
                    log::warn!(
                        "Invalid RoundChange: Duplicate author {:?} in prepares of PreparedRoundMetadata. Author: {:?}",
                        prepare_author, author
                    );
                    return Err(QbftError::ValidationError(
                        "Duplicate author in prepares of PreparedRoundMetadata".to_string(),
                    ));
                }
            }
            log::debug!("Successfully validated individual prepares in PreparedRoundMetadata for RoundChange by {:?}", author);

            // c. Check for quorum of prepares.
            // Quorum size should be determined based on the validator set of the inner proposal's round.
            // prepare_validation_context.final_state should reflect the state for inner_proposal_round_id.sequence_number
            let quorum_size = prepare_validation_context.final_state.quorum_size(); 
            if num_valid_prepares < quorum_size {
                log::warn!(
                    "Invalid RoundChange: Insufficient prepares ({}) for quorum ({}) in PreparedRoundMetadata. Validators for inner proposal: {}. Author: {:?}. Quorum required: {}",
                    num_valid_prepares, quorum_size, inner_proposal_context.current_validators.len(), author, quorum_size
                );
                return Err(QbftError::QuorumNotReached { 
                    needed: quorum_size, 
                    got: num_valid_prepares, 
                    item: format!("prepares for inner proposal round {:?}, block hash {:?}", inner_proposal_round_id, prepared_metadata.prepared_block_hash),
                });
            }
            log::debug!("Successfully validated prepare quorum in PreparedRoundMetadata for RoundChange by {:?}", author);

        } else {
            // If PreparedRoundMetadata is NOT present, then prepared_block must also be None.
            if round_change.payload().prepared_block.is_some() {
                log::warn!(
                    "Invalid RoundChange: Contains prepared_block but no PreparedRoundMetadata. Author: {:?}", author
                );
                return Err(QbftError::ValidationError(
                    "RoundChange without PreparedRoundMetadata must not contain prepared_block".to_string(),
                ));
            }
        }
        
        log::trace!("RoundChange message successfully validated for round {:?}", round_change.payload().round_identifier);
        Ok(())
    }
} 