use std::sync::Arc;
use crate::error::QbftError;
use std::collections::HashSet;

use crate::validation::{CommitValidator, PrepareValidator, ProposalValidator, RoundChangeMessageValidatorFactory, RoundChangeMessageValidatorFactoryImpl,MessageValidatorFactory, MessageValidatorFactoryImpl,proposal_validator::ValidationContext};
use crate::messagewrappers::{Proposal, Prepare, Commit, PreparedCertificateWrapper, BftMessage, RoundChange};
use crate::payload::{ProposalPayload, PreparePayload, CommitPayload, RoundChangePayload, PreparedRoundMetadata};
use crate::types::{QbftBlockHeader, QbftFinalState, BftExtraDataCodec, QbftConfig, SignedData, ConsensusRoundIdentifier, BftExtraData};
use alloy_primitives::{Address, B256 as Hash}; // Keep Hash
// use crate::validation::MessageValidatorFactory; // Needed for impl block logic

/// Defines the validation logic for RoundChange messages.
pub trait RoundChangeMessageValidator: Send + Sync {
    /// Validates a RoundChange message against the current context.
    fn validate_round_change(&self, round_change: &RoundChange, context: &ValidationContext) -> Result<(), QbftError>;
}

pub struct RoundChangeMessageValidatorImpl {
    #[allow(dead_code)] // May not be used directly if validators passed in
    config: Arc<QbftConfig>,
    #[allow(dead_code)]
    proposal_validator: Arc<dyn ProposalValidator + Send + Sync>,
    #[allow(dead_code)]
    prepare_validator: Arc<dyn PrepareValidator + Send + Sync>,
    #[allow(dead_code)]
    message_validator_factory: Arc<dyn MessageValidatorFactory>, // Keep factory for internal use if needed
}

    impl RoundChangeMessageValidatorImpl {
    fn new(
        config: Arc<QbftConfig>,
        proposal_validator: Arc<dyn ProposalValidator + Send + Sync>,
        prepare_validator: Arc<dyn PrepareValidator + Send + Sync>,
        message_validator_factory: Arc<dyn MessageValidatorFactory>, // Keep factory access
    ) -> Self {
        Self { config, proposal_validator, prepare_validator, message_validator_factory }
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

        let author = round_change.author()?;
        if !context.current_validators.contains(&author) {
            log::warn!(
                "Invalid RoundChange: Author {:?} is not in the current validator set for context round {:?}/{:?}. Validators: {:?}",
                author, context.current_sequence_number, context.current_round_number, context.current_validators
            );
            return Err(QbftError::NotAValidator { sender: author });
        }

        let rc_target_round_id = round_change.payload().round_identifier;
        if rc_target_round_id.sequence_number != context.current_sequence_number {
            log::warn!(
                "Invalid RoundChange: Targets sequence number {} but current context sequence is {}. Author: {:?}",
                rc_target_round_id.sequence_number, context.current_sequence_number, author
            );
            return Err(QbftError::MessageRoundMismatch { 
                message_type: "RoundChange".to_string(),
                expected_sequence: context.current_sequence_number,
                expected_round: context.current_round_number, 
                actual_sequence: rc_target_round_id.sequence_number,
                actual_round: rc_target_round_id.round_number,
            });
        }
        if rc_target_round_id.round_number <= context.current_round_number {
            log::warn!(
                "Invalid RoundChange: Targets round number {} but current context round is {}. Must be greater. Author: {:?}",
                rc_target_round_id.round_number, context.current_round_number, author
            );
            return Err(QbftError::MessageRoundMismatch { 
                message_type: "RoundChange".to_string(),
                expected_sequence: context.current_sequence_number, 
                expected_round: context.current_round_number + 1,
                actual_sequence: rc_target_round_id.sequence_number,
                actual_round: rc_target_round_id.round_number,
            });
        }

        if let Some(prepared_metadata) = round_change.payload().prepared_round_metadata.as_ref() {
            log::trace!("RoundChange has PreparedRoundMetadata for prepared_round: {}", prepared_metadata.prepared_round);

            if prepared_metadata.prepared_round >= rc_target_round_id.round_number {
                log::warn!(
                    "Invalid RoundChange: PreparedRoundMetadata is for round {} which is not less than RoundChange target round {}. Author: {:?}",
                    prepared_metadata.prepared_round, rc_target_round_id.round_number, author
                );
                return Err(QbftError::ValidationError(
                    "PreparedRoundMetadata round not less than RoundChange target round".to_string(),
                ));
            }

            let prepared_block_in_rc = round_change.payload().prepared_block.as_ref()
                .ok_or_else(|| {
                    log::warn!(
                        "Invalid RoundChange: Contains PreparedRoundMetadata but no prepared_block. Author: {:?}", author
                    );
                    QbftError::ValidationError("RoundChange with PreparedRoundMetadata must also contain prepared_block".to_string())
                })?;
            
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

            let proposal_validator = self.proposal_validator.clone();
            let inner_proposal_payload = prepared_metadata.signed_proposal_payload.payload();
            let inner_proposal_round_id = inner_proposal_payload.round_identifier;
            
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
            let prepare_validator = self.prepare_validator.clone();
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

#[cfg(test)]
pub mod tests {
    use std::collections::HashSet;
    use std::sync::Arc;
    
    // Import necessary mocks and types for tests
    use crate::mocks::{MockQbftFinalState, MockMessageValidatorFactory};
    use crate::payload::{RoundChangePayload, ProposalPayload, PreparePayload, PreparedRoundMetadata};
    use crate::testing_helpers::{*}; // Default wildcard import is fine here
    use crate::types::{
        ConsensusRoundIdentifier, NodeKey, QbftBlockHeader, SignedData, QbftFinalState,
        BftExtraDataCodec, QbftBlock, EMPTY_NONCE, QbftConfig, BftExtraData, 
        AlloyBftExtraDataCodec
    };
    use crate::validation::proposal_validator::tests::{
        create_proposal_payload, create_signed_proposal_payload
    };
    use crate::validation::proposal_validator::ProposalValidatorImpl;
    use crate::validation::prepare_validator::{PrepareValidatorImpl, PrepareValidator}; // Added PrepareValidator trait
    use crate::messagewrappers::{BftMessage, RoundChange};
    use crate::validation::proposal_validator::ValidationContext; // Import needed ValidationContext
    // Use fully qualified path for the Impl, parent trait is brought in by pub use or definition
    use crate::validation::round_change_message_validator::RoundChangeMessageValidatorImpl;
    // Import the trait explicitly for type annotations if needed, or rely on parent module scope
    use super::RoundChangeMessageValidator;
    use crate::validation::{MessageValidatorFactoryImpl, RoundChangeMessageValidatorFactoryImpl, RoundChangeMessageValidatorFactory, MessageValidatorFactory};
    use crate::error::QbftError;
    
    use alloy_primitives::{Address, B256, Bytes, U256, Bloom};
    use alloy_consensus::constants::EMPTY_OMMER_ROOT_HASH;
    use rand::Rng;

    fn default_config_for_rc_tests() -> Arc<QbftConfig> {
        default_config()
    }

    // Helper to create a simple QbftBlockHeader for testing purposes
    #[allow(dead_code)]
    fn default_qbft_block_header_for_test(number: u64) -> QbftBlockHeader {
        QbftBlockHeader::new(
            B256::from_slice(&rand::thread_rng().gen::<[u8; 32]>()), 
            EMPTY_OMMER_ROOT_HASH,                   
            Address::from_slice(&[0xAAu8; 20]),      
            B256::from_slice(&rand::thread_rng().gen::<[u8; 32]>()), 
            B256::from_slice(&rand::thread_rng().gen::<[u8; 32]>()), 
            B256::from_slice(&rand::thread_rng().gen::<[u8; 32]>()), 
            Bloom::default(), // Correct way to get empty Bloom
            U256::from(1),                           
            number,                                  
            1_000_000,                               
            0,                                       
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(), 
            Bytes::from_static(b"default test header"), 
            B256::ZERO,                              
            EMPTY_NONCE,                             
        )
    }

    // --- Test Helper: Create RoundChange Message --- 
    fn create_round_change_message(
        round_id: ConsensusRoundIdentifier,
        signer_key: &NodeKey,
        prepared_round_metadata: Option<PreparedRoundMetadata>,
        prepared_block_for_rc: Option<QbftBlock>,
        prepares_for_rc: Option<Vec<SignedData<PreparePayload>>>
    ) -> RoundChange {
        let payload = RoundChangePayload::new(
            round_id, 
            prepared_round_metadata,
            prepared_block_for_rc.clone() 
        );
        let signed_payload = SignedData::sign(payload, signer_key).expect("Failed to sign RoundChangePayload");
        // Ensure all 3 args are passed and .expect() is used
        RoundChange::new(signed_payload, prepared_block_for_rc, prepares_for_rc).expect("Failed to create RoundChange message")
    }

    // Common setup for prepared block and its proposal (refactored from create_valid_prepared_metadata)
    fn common_prepared_block_and_proposal(
        context_sequence: u64,
        prepared_round_number: u32,
        proposer_key: Arc<NodeKey>,
        parent_header_for_prepared_block: Arc<QbftBlockHeader>,
        extra_data_codec: Arc<dyn BftExtraDataCodec>, // Use dyn trait object, KEEP THIS
        final_state_for_prepared_round: Arc<MockQbftFinalState> // Keep this argument
    ) -> (ConsensusRoundIdentifier, QbftBlock, SignedData<ProposalPayload>) {
        let prepared_block_round_id = ConsensusRoundIdentifier { 
            sequence_number: context_sequence, 
            round_number: prepared_round_number 
        };
        
        // Get min gas limit from config (available via final_state context)
        // We need the QbftConfig here. Let's assume it's accessible, maybe add as arg?
        // For now, let's use the testing_helpers default config directly, as it's likely the one used.
        // let test_config = default_config(); // from testing_helpers
        // let block_gas_limit = test_config.min_gas_limit; // Use min_gas_limit from config
        // Correction: Use parent's gas limit to satisfy delta validation rule in tests.
        let block_gas_limit = parent_header_for_prepared_block.gas_limit;

        // Create valid BftExtraData for the header
        // Use validators from the final_state provided for this specific round/block context
        let validators_for_next_block: Vec<Address> = final_state_for_prepared_round.current_validators();
        let bft_extra_data = BftExtraData {
            vanity_data: Bytes::from_static(&[0u8; 32]), // Default vanity
            validators: validators_for_next_block, // Use correct validators for *next* block
            committed_seals: vec![], // No seals for a proposed block header
            round_number: prepared_round_number, // Round number for this block
        };
        let encoded_extra_data = extra_data_codec.encode(&bft_extra_data)
            .expect("Failed to encode BFT extra data");

        let block_header = QbftBlockHeader::new(
            parent_header_for_prepared_block.hash(), // Use .hash() not .hash_slow()
            EMPTY_OMMER_ROOT_HASH,                  
            deterministic_address_from_arc_key(&proposer_key), 
            B256::from_slice(&rand::thread_rng().gen::<[u8; 32]>()), // state root - random for test
            B256::from_slice(&rand::thread_rng().gen::<[u8; 32]>()), // tx root - random for test
            B256::from_slice(&rand::thread_rng().gen::<[u8; 32]>()), // receipts root - random for test
            Bloom::default(),                     
            U256::from(1),                           
            prepared_block_round_id.sequence_number, 
            block_gas_limit, // Use gas limit from config
            0,                                       
            parent_header_for_prepared_block.timestamp + 1, // Example timestamp logic
            encoded_extra_data, // Use encoded BFT extra data
            B256::ZERO,                              
            EMPTY_NONCE,                             
        );
        let prepared_block = QbftBlock::new(block_header, Vec::new(), Vec::new());
        let proposal_payload_inner = create_proposal_payload(
            prepared_block_round_id, 
            prepared_block.clone()
            // None, // No prepared cert for this inner proposal -- REMOVED
            // Vec::new() // No RC proofs for this inner proposal -- REMOVED
        );
        let signed_proposal_payload = create_signed_proposal_payload(proposal_payload_inner, &proposer_key);
        (prepared_block_round_id, prepared_block, signed_proposal_payload)
    }

    // --- Test Helper: Create ValidationContext (similar to other validators) ---
    fn default_rc_validation_context(
        current_sequence_number: u64,
        current_round_number: u32,
        current_validators: HashSet<Address>,
        parent_header: Arc<QbftBlockHeader>,
        final_state_override: Option<Arc<dyn QbftFinalState>>,
        extra_data_codec: Arc<dyn BftExtraDataCodec>,
        config_override: Option<Arc<QbftConfig>>,
        accepted_proposal_digest: Option<Hash>,
        expected_proposer: Address,
        local_node_key_for_final_state: Arc<NodeKey>,
    ) -> ValidationContext {
        let final_state = final_state_override.unwrap_or_else(|| Arc::new(MockQbftFinalState::new(
            HashMap::new(), // initial_headers
            current_validators.clone(), // initial_validators
            B256::ZERO, // block_hash_for_validators_lookup - placeholder
            local_node_key_for_final_state, // local_node_key
        )));
        let config = config_override.unwrap_or_else(default_config_for_rc_tests);

        ValidationContext::new(
            current_sequence_number,
            current_round_number,
            current_validators,
            parent_header,
            final_state,
            extra_data_codec,
            config,
            accepted_proposal_digest,
            expected_proposer,
        )
    }

    // create_valid_prepared_metadata and other helpers updated to use common_prepared_block_and_proposal
    // and ensure B256::from_slice(&rand::thread_rng().gen()) for random B256s
    // Corrected prepare_msg.inner usage

    fn create_valid_prepared_metadata(
        context_sequence: u64, 
        prepared_round_number: u32, 
        proposer_key: Arc<NodeKey>, 
        prepare_signer_keys: Vec<Arc<NodeKey>>, 
        parent_header_for_prepared_block: Arc<QbftBlockHeader>,
        final_state_for_prepared_round: Arc<MockQbftFinalState>,
        extra_data_codec: Arc<dyn BftExtraDataCodec>,
        proposer_key_for_inner_proposal: Arc<NodeKey>,
        all_validators_set: HashSet<Address>
    ) -> (PreparedRoundMetadata, QbftBlock) {
        let (prepared_block_round_id, prepared_block, signed_proposal_payload_data) =  // Renamed var
            common_prepared_block_and_proposal(
                context_sequence, 
                prepared_round_number, 
                proposer_key.clone(), 
                parent_header_for_prepared_block.clone(), 
                extra_data_codec.clone(), // This clone might be an issue for E0277, address later
                final_state_for_prepared_round.clone()
            );

        // Wrap the SignedData<ProposalPayload> in a BftMessage
        let bft_signed_proposal = BftMessage::new(signed_proposal_payload_data);

        let mut prepares_for_metadata: Vec<SignedData<PreparePayload>> = Vec::new();
        for key in prepare_signer_keys.iter() {
            let prepare_payload = PreparePayload {
                round_identifier: prepared_block_round_id,
                digest: prepared_block.hash(),
            };
            let signed_prepare = SignedData::sign(prepare_payload, key).expect("Failed to sign prepare");
            prepares_for_metadata.push(signed_prepare); 
        }

        let prepared_metadata = PreparedRoundMetadata::new(
            prepared_round_number,
            prepared_block.hash(),
            bft_signed_proposal, // Pass the BftMessage
            prepares_for_metadata,
        );
        (prepared_metadata, prepared_block)
    }

    #[test]
    fn test_validate_rc_valid_with_prepared_data() {
        let v0_key = deterministic_node_key(0);
        let v1_key = deterministic_node_key(1);
        let v2_key = deterministic_node_key(2);
        let all_validators_set = HashSet::from([
            deterministic_address_from_arc_key(&v0_key),
            deterministic_address_from_arc_key(&v1_key),
            deterministic_address_from_arc_key(&v2_key),
        ]);

        let rc_target_round_id = ConsensusRoundIdentifier { sequence_number: 1, round_number: 2 };
        let context_round_id = ConsensusRoundIdentifier { sequence_number: 1, round_number: 0 };        
        let config = default_config_for_rc_tests();
        let extra_data_codec = testing_extradata_codec();
        let mut final_state_s1 = MockQbftFinalState::new(v0_key.clone(), all_validators_set.clone());
        let context_parent_header = default_parent_header(context_round_id.sequence_number.saturating_sub(1), B256::ZERO, 100, 50000);
        
        // Add the context parent header to the mock state for lookup
        final_state_s1.add_known_header(context_parent_header.clone());
        
        let expected_proposer_for_context_round = final_state_s1.get_proposer_for_round(&context_round_id).unwrap_or_default();
        
        // Convert final_state_s1 to Arc<dyn QbftFinalState> for use
        let final_state_s1_arc: Arc<dyn QbftFinalState> = Arc::new(final_state_s1);
        
        // Determine the expected proposer for the inner prepared round (1/1)
        let inner_prepared_round_id = ConsensusRoundIdentifier { sequence_number: 1, round_number: 1 };
        let expected_proposer_for_inner_round_addr = final_state_s1_arc.get_proposer_for_round(&inner_prepared_round_id)
            .expect("Should be able to get proposer for inner round");
        // Find the key corresponding to the expected proposer address
        let inner_proposer_key = if expected_proposer_for_inner_round_addr == deterministic_address_from_arc_key(&v0_key) { v0_key.clone() }
                             else if expected_proposer_for_inner_round_addr == deterministic_address_from_arc_key(&v1_key) { v1_key.clone() }
                             else if expected_proposer_for_inner_round_addr == deterministic_address_from_arc_key(&v2_key) { v2_key.clone() }
                             else { panic!("Expected inner proposer not found among v0, v1, v2 keys"); };

        let (prepared_metadata, prepared_block) = create_valid_prepared_metadata(
            rc_target_round_id.sequence_number, 
            inner_prepared_round_id.round_number, // Use inner round number (1)
            inner_proposer_key.clone(), // Use the key of the expected proposer
            vec![v0_key.clone(), v2_key.clone()].into_iter().filter(|k| k.verifying_key() != inner_proposer_key.verifying_key()).collect(), // Sign prepares with others
            context_parent_header.clone(),
            // Pass the mock state as Arc<MockQbftFinalState>
            Arc::new(MockQbftFinalState::new(inner_proposer_key.clone(), all_validators_set.clone())), 
            extra_data_codec.clone(),
            all_validators_set
        );
        
        let context = default_rc_validation_context(
            context_round_id.sequence_number, 
            context_round_id.round_number, 
            all_validators_set.clone(), 
            context_parent_header.clone(),
            Some(final_state_s1_arc.clone()), // Use the Arc<dyn QbftFinalState> here
            extra_data_codec, // Original Arc can be used here
            Some(config.clone()),
            None,
            expected_proposer_for_context_round,
            v0_key.clone()
        );

        let round_change_msg = create_round_change_message(
            rc_target_round_id, 
            &v0_key, 
            Some(prepared_metadata.clone()),
            Some(prepared_block.clone()),
            Some(prepared_metadata.prepares.clone())
        );

        // --- Setup Validators for the main test context --- 
        // Need factories to create the validators for RoundChangeMessageValidatorImpl::new
        // Use mock for cyclic dependency: MsgFactory needs RC Factory, RC Factory needs MsgFactory.
        // Create a mock RC Factory first.
        let mock_rc_factory_for_msg_factory = Arc::new(MockRoundChangeMessageValidatorFactoryImpl { // Mock needed for cyclic dep
            validator_to_return: Arc::new(MockRoundChangeMessageValidator { should_fail_validation: false })
        });
        // Create the real Message Validator Factory using the mock RC factory.
        let msg_factory = Arc::new(MessageValidatorFactoryImpl::new(config.clone(), mock_rc_factory_for_msg_factory));
        // Create the real RC Validator Factory using the real Message Validator Factory.
        let rc_factory = Arc::new(RoundChangeMessageValidatorFactoryImpl::new(msg_factory.clone(), config.clone()));

        // Create the actual Proposal and Prepare validators using the factories.
        let proposal_validator = msg_factory.clone().create_proposal_validator();
        let prepare_validator = msg_factory.clone().create_prepare_validator();

        // Instantiate the validator under test with the created dependencies.
        let validator = RoundChangeMessageValidatorImpl::new(
            config.clone(), 
            proposal_validator, 
            prepare_validator,
            msg_factory.clone() // Pass the message factory as well
        );
        let result = validator.validate_round_change(&round_change_msg, &context);
        assert!(result.is_ok(), "Expected valid RoundChange with prepared data, got {:?}", result.err());
    }

    #[test]
    fn test_validate_rc_invalid_insufficient_prepares_for_quorum() {
        let v0_key = deterministic_node_key(0);
        let v0_addr = deterministic_address_from_arc_key(&v0_key);
        let v1_key = deterministic_node_key(1); // Another validator for the set
        let v1_addr = deterministic_address_from_arc_key(&v1_key);

        // Validator set for the context and inner proposal
        let all_validators_set = HashSet::from([v0_addr, v1_addr]);
        let validator_set_for_inner_proposal = all_validators_set.clone();

        let rc_target_round_id = ConsensusRoundIdentifier { sequence_number: 1, round_number: 2 };
        let context_round_id = ConsensusRoundIdentifier { sequence_number: 1, round_number: 0 };

        let config = default_config_for_rc_tests();
        let extra_data_codec = testing_extradata_codec();
        
        // Create MockQbftFinalState with f_override = 1, so quorum will be 2*1+1 = 3.
        // The actual number of validators (n=2) would normally yield f=0, quorum=1.
        // This override is to test the quorum check logic specifically.
        let final_state_s1 = Arc::new(MockQbftFinalState::new_with_f_override(
            v0_key.clone(), // Local node for this final_state instance
            validator_set_for_inner_proposal.clone(),
            1 // f_override = 1 --> quorum = 3
        ));
        
        let context_parent_header = default_parent_header(context_round_id.sequence_number.saturating_sub(1), B256::ZERO, 100, 50000);
        // Add the parent header to the mutable mock state before creating the Arc for context_for_rc_sender
        let mut mutable_final_state_s1_for_context = MockQbftFinalState::new_with_f_override(
            v0_key.clone(),
            validator_set_for_inner_proposal.clone(),
            1
        );
        mutable_final_state_s1_for_context.add_known_header(context_parent_header.clone());
        let final_state_s1_for_context_arc: Arc<dyn QbftFinalState> = Arc::new(mutable_final_state_s1_for_context);

        let expected_proposer_for_context_round = final_state_s1.get_proposer_for_round(&context_round_id).unwrap_or_default();

        // Determine expected proposer for the inner round (1/1) based on final_state_s1
        let inner_prepared_round_id = ConsensusRoundIdentifier { sequence_number: 1, round_number: 1 };
        let expected_inner_proposer_addr = final_state_s1.get_proposer_for_round(&inner_prepared_round_id)
            .expect("Failed to get inner proposer");
        let inner_proposer_key = if expected_inner_proposer_addr == v0_addr { v0_key.clone() }
                               else if expected_inner_proposer_addr == v1_addr { v1_key.clone() }
                               else { panic!("Inner proposer not v0 or v1"); };
        // Select the other key for signing the prepare message
        let prepare_signer_key = if inner_proposer_key.verifying_key() == v0_key.verifying_key() { v1_key.clone() } else { v0_key.clone() };

        // Create prepared metadata with only one prepare, signed by prepare_signer_key
        let (prepared_metadata_low_prepares, prepared_block_for_low_prepares) = create_valid_prepared_metadata(
            rc_target_round_id.sequence_number, 
            inner_prepared_round_id.round_number, // prepared round is 1
            inner_proposer_key.clone(), // Use the correct proposer for the inner block
            vec![prepare_signer_key.clone()], // Only one prepare signer (the non-proposer)
            context_parent_header.clone(),
            final_state_s1.clone(), // This final_state_s1 is Arc<MockQbftFinalState>
            extra_data_codec.clone(), // Cloned here
            all_validators_set.clone()
        );

        let context_for_rc_sender = default_rc_validation_context(
            context_round_id.sequence_number, 
            context_round_id.round_number, 
            validator_set_for_inner_proposal.clone(), // RC sender (v0) is part of this set
            context_parent_header.clone(), 
            Some(final_state_s1_for_context_arc.clone()), // Use the state with added header
            extra_data_codec, // Original Arc can be used here
            Some(config.clone()), 
            None,
            v0_key.clone() // local_node_key for this context (RC sender)
        );

        let round_change_msg = create_round_change_message(
            rc_target_round_id, 
            &v0_key, // RC sender
            Some(prepared_metadata_low_prepares.clone()),
            Some(prepared_block_for_low_prepares.clone()), // Pass the block here
            Some(prepared_metadata_low_prepares.prepares.clone())
        );
        
        // --- Setup Validators (similar to the valid test) --- 
        let mock_rc_factory_for_msg_factory = Arc::new(MockRoundChangeMessageValidatorFactoryImpl { // Mock needed for cyclic dep
            validator_to_return: Arc::new(MockRoundChangeMessageValidator { should_fail_validation: false })
        });
        let msg_factory = Arc::new(MessageValidatorFactoryImpl::new(config.clone(), mock_rc_factory_for_msg_factory));
        let rc_factory = Arc::new(RoundChangeMessageValidatorFactoryImpl::new(msg_factory.clone(), config.clone()));
        let proposal_validator = msg_factory.clone().create_proposal_validator();
        let prepare_validator = msg_factory.clone().create_prepare_validator();

        // Instantiate the validator under test.
        let validator = RoundChangeMessageValidatorImpl::new(
            config.clone(), 
            proposal_validator, 
            prepare_validator,
            msg_factory.clone()
        );
        let result = validator.validate_round_change(&round_change_msg, &context_for_rc_sender);
        assert!(matches!(result, Err(QbftError::QuorumNotReached { needed, got, .. }) if needed == 3 && got == 1), "Expected QuorumNotReached {{ needed: 3, got: 1 }}, got {:?}", result);
    }

    // --- Define Mocks needed for these tests --- 
    struct MockRoundChangeMessageValidator {
        should_fail_validation: bool,
    }

    impl RoundChangeMessageValidator for MockRoundChangeMessageValidator {
        fn validate_round_change(&self, _round_change: &RoundChange, _context: &ValidationContext) -> Result<(), QbftError> {
            if self.should_fail_validation {
                Err(QbftError::ValidationError("Mock RC Validation Failed".to_string()))
            } else {
                Ok(())
            }
        }
    }

    struct MockRoundChangeMessageValidatorFactory {
        #[allow(dead_code)] // May not be used in all tests
        fail_on_create: bool,
        validator_to_return: Arc<dyn RoundChangeMessageValidator + Send + Sync>,
    }

    impl RoundChangeMessageValidatorFactory for MockRoundChangeMessageValidatorFactory {
        fn create_round_change_message_validator(&self) -> Arc<dyn RoundChangeMessageValidator + Send + Sync> {
            if self.fail_on_create { // Corrected field name if it was wrong before
                panic!("MockRoundChangeMessageValidatorFactory failed on create");
            }
            self.validator_to_return.clone()
        }
    }
    // --- End Mock Definitions --- 
} 