// This file should now ONLY contain ValidationContext, ProposalValidator trait, and ProposalValidatorImpl struct/impl.

use crate::error::QbftError;
use crate::messagewrappers::Proposal;
use crate::types::{QbftBlockHeader, QbftConfig, QbftFinalState, BftExtraDataCodec};
use alloy_primitives::{Address, B256 as Hash};
use std::collections::HashSet; // Removed HashMap
use std::sync::Arc;
// Removed unused crate::types::SignedData;
// Removed unused crate::payload::ProposalPayload;

// Bring in specific validator traits it will need
use crate::validation::{RoundChangeMessageValidatorFactory,MessageValidatorFactory};

/// Provides necessary context from the current consensus state for message validation.
#[derive(Clone)]
pub struct ValidationContext {
    pub current_sequence_number: u64, 
    pub current_round_number: u32,
    pub current_validators: HashSet<Address>,
    // Added fields based on RoundState usage
    pub parent_header: Arc<QbftBlockHeader>,
    pub final_state: Arc<dyn QbftFinalState>,
    pub extra_data_codec: Arc<dyn BftExtraDataCodec>,
    pub config: Arc<QbftConfig>,
    pub accepted_proposal_digest: Option<Hash>, // Digest of the currently accepted proposal
    pub expected_proposer: Address, // Expected proposer for the current_sequence_number and current_round_number
    // TODO: Add more fields as needed, e.g.:
    // pub latest_prepared_certificate: Option<crate::statemachine::PreparedCertificate>,
    // pub chain_head_hash: alloy_primitives::B256,
    // pub chain_id: u64, 
}

impl ValidationContext {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        current_sequence_number: u64, 
        current_round_number: u32, 
        current_validators: HashSet<Address>,
        parent_header: Arc<QbftBlockHeader>,
        final_state: Arc<dyn QbftFinalState>,
        extra_data_codec: Arc<dyn BftExtraDataCodec>,
        config: Arc<QbftConfig>,
        accepted_proposal_digest: Option<Hash>,
        expected_proposer: Address,
    ) -> Self {
        Self {
            current_sequence_number,
            current_round_number,
            current_validators,
            parent_header,
            final_state,
            extra_data_codec,
            config,
            accepted_proposal_digest,
            expected_proposer,
        }
    }
}

/// Trait for validating a Proposal message.
pub trait ProposalValidator {
    /// Validates the given QBFT Proposal.
    /// # Returns
    /// * `Ok(())` if the proposal is valid.
    /// * `Err(QbftError)` if the proposal is invalid.
    fn validate_proposal(&self, proposal: &Proposal, context: &ValidationContext) -> Result<(), QbftError>;
}

/// Concrete implementation of the ProposalValidator trait.
pub struct ProposalValidatorImpl {
    // Store the factory and config to create child validators as needed
    message_validator_factory: Arc<dyn MessageValidatorFactory>,
    // Add the round change factory
    round_change_message_validator_factory: Arc<dyn RoundChangeMessageValidatorFactory>,
    config: Arc<QbftConfig>,
    // No direct child validators stored if created on-demand by factory
}

impl ProposalValidatorImpl {
    pub fn new(
        message_validator_factory: Arc<dyn MessageValidatorFactory>,
        round_change_message_validator_factory: Arc<dyn RoundChangeMessageValidatorFactory>, // Add to constructor
        config: Arc<QbftConfig>,
    ) -> Self {
        Self { 
            message_validator_factory,
            round_change_message_validator_factory, // Store it
            config,
        }
    }

    // Helper function to mimic Java's ProposalPayloadValidator + QbftBlockValidator
    // This might be broken down further or parts moved to a separate block validator.
    fn validate_payload_and_block(
        &self,
        proposal: &Proposal,
        context: &ValidationContext,
    ) -> Result<(), QbftError> {
        // 1. Author is the expected proposer for this round/sequence.
        let author = proposal.author()?;
        if author != context.expected_proposer {
            // --- DEBUG LOGGING START ---
            let mut sorted_context_validators: Vec<Address> = context.current_validators.iter().cloned().collect();
            sorted_context_validators.sort();
            log::warn!(
                "Invalid Proposal: Author mismatch for round {:?}/{:?}. Expected Proposer: {:?}, Actual Author: {:?}. Context Validators (Sorted): {:?}", 
                context.current_sequence_number, context.current_round_number, context.expected_proposer, author, sorted_context_validators
            );
            // --- DEBUG LOGGING END ---
            return Err(QbftError::ProposalNotFromProposer);
        }

        // 2. Payload's round identifier matches context's round identifier.
        let payload_round_identifier = proposal.payload().round_identifier;
        if payload_round_identifier.sequence_number != context.current_sequence_number ||
           payload_round_identifier.round_number != context.current_round_number {
            log::warn!(
                "Invalid Proposal: Payload round identifier {:?} does not match context round identifier {:?}/{:?}",
                payload_round_identifier, context.current_sequence_number, context.current_round_number
            );
            return Err(QbftError::ProposalRoundMismatch {
                expected: context.current_round_number as u64,
                actual: payload_round_identifier.round_number as u64,
            });
        }

        // 3. QbftBlockValidator logic (Initial parts):
        //    - proposal.proposed_block_header() must match proposal.block().header (the one in payload).
        //      (This is implicitly true by our Proposal struct construction where proposed_block_header is derived from the block in payload for now)
        //      TODO: If Proposal struct changes to allow them to diverge, add explicit check.
        
        let block_header = &proposal.block().header;

        //    - Block header validation (parent_hash, number)
        if block_header.parent_hash != context.parent_header.hash() {
            log::warn!(
                "Invalid Proposal: Block parent hash {:?} does not match context parent hash {:?}",
                block_header.parent_hash, context.parent_header.hash()
            );
            return Err(QbftError::ProposalInvalidParentHash);
        }

        if block_header.number != context.current_sequence_number {
            log::warn!(
                "Invalid Proposal: Block number {} does not match context sequence number {}",
                block_header.number, context.current_sequence_number
            );
            return Err(QbftError::ProposalInvalidBlockNumber);
        }

        // Timestamp validation
        // 1. Timestamp must be greater than parent's timestamp.
        if block_header.timestamp <= context.parent_header.timestamp {
            log::warn!(
                "Invalid Proposal: Block timestamp {} is not after parent timestamp {}",
                block_header.timestamp, context.parent_header.timestamp
            );
            return Err(QbftError::ValidationError("Block timestamp not after parent".to_string()));
        }

        // 2. Timestamp must not be too far in the future (typically validated by BlockTimer or chain spec config)
        // For now, let's assume a simple check if QbftConfig has a max_future_block_time_seconds or similar.
        // This check is often handled more dynamically by the BlockTimer in Besu.
        // As a placeholder, we might skip a strict future check here if not easily available, 
        // or add a TODO if config for it is missing.
        // For example, if context.config.block_period_seconds is the *minimum* period:
        // A common check is also `block_header.timestamp <= now + allowed_clock_skew`
        // We don't have `now` directly here, this is more of a live consensus rule.
        // The QBFT spec section 4.4: "Timestamp: must be greater than its parent."
        // Besu's BlockHeaderValidator->validateTimestamp also checks against System.currentTimeMillis() + clock tolerancia
        // We don't have clock here. Let's stick to spec: must be greater than parent.
        // Additional checks (e.g. not too far in future, or adhering to block period) might be separate.
        // For now, just the parent check is implemented as per direct QBFT spec.
        
        // Extra Data Validation
        match context.extra_data_codec.decode(&block_header.extra_data) {
            Ok(decoded_extra_data) => {
                if decoded_extra_data.round_number != context.current_round_number {
                    log::warn!(
                        "Invalid Proposal: Round in block extra_data {} does not match context round {}",
                        decoded_extra_data.round_number, context.current_round_number
                    );
                    return Err(QbftError::ValidationError("Round in block extra_data mismatch".to_string()));
                }
                
                // Validate that the validators list in extra_data matches context.current_validators
                // BftExtraData.validators is Vec<Address>, context.current_validators is HashSet<Address>
                // For a robust comparison, convert both to HashSets if order doesn't strictly matter for this check,
                // or ensure a canonical ordering if it does.
                let extra_data_validators_set: HashSet<Address> = decoded_extra_data.validators.iter().cloned().collect();
                if extra_data_validators_set != context.current_validators {
                    log::warn!(
                        "Invalid Proposal: Validators in block extra_data ({:?}) do not match context current validators ({:?})", 
                        extra_data_validators_set, context.current_validators
                    );
                    return Err(QbftError::ValidationError("Validators in extra_data mismatch with context".to_string()));
                }

            }
            Err(e) => {
                log::warn!("Invalid Proposal: Failed to decode block extra_data: {:?}", e);
                return Err(QbftError::ValidationError(format!("Failed to decode block extra_data: {}", e)));
            }
        }

        // Difficulty Validation
        if block_header.difficulty != alloy_primitives::U256::from(1) {
            log::warn!(
                "Invalid Proposal: Block difficulty {} is not 1", block_header.difficulty
            );
            return Err(QbftError::ValidationError("Block difficulty not 1".to_string()));
        }

        // Nonce Validation (QBFT typically uses 0 for proposed blocks)
        // Assuming 0 is represented by an empty Bytes or a specific 8-byte zero array for eth_header.nonce (Bytes)
        // For QbftBlockHeader, if nonce is Bytes, it should be the RLP encoding of 0 (0x80) or an 8-byte 0.
        // Besu uses 0L, which rlp-encodes to 0x80 for a number, or 0x00 for a single byte 0.
        // Let's assume for now it must be an empty Bytes or specifically Bytes::from_static(&[0u8; 8]) if it represents a fixed-size field.
        // Our QbftBlockHeader has nonce: Bytes. If it's meant to be numeric 0, it would be rlp::Bytes::from_static(&[0x80]).
        // If it's meant to be a U64 nonce like PoW, then Bytes::from_static(&[0u8;8]) for 0.
        // Given prior note: `nonce` as `Bytes` for `QbftBlockHeader` was corrected. Block proposals typically have 0 nonce.
        // An RLP-encoded U64 zero is just 0x80. An RLP-encoded empty byte array is 0x80.
        // An RLP-encoded 8-byte zero array is [0x88, 0,0,0,0,0,0,0,0].
        // Let's be specific: QBFT spec often says nonce is 0x0. The `ethabi::Bytes` for this would be empty or `vec![0]`. 
        // RLP encoding of `vec![0]` is `[0x00]`. RLP encoding of `vec![]` is `0x80`.
        // RLP encoding of the number 0 is `0x80`.
        // If the `nonce` field in `QbftBlockHeader` is `Bytes` that stores an RLP-encoded *value*, this gets complex.
        // Let's assume `block_header.nonce` should represent the numeric value 0. An empty `Bytes` is RLP-encoded as `0x80`.
        // A `Bytes` containing a single zero byte (`vec![0]`) is RLP-encoded as `[0x00]`.
        // The most straightforward is to check if it's empty, which corresponds to RLP `0x80` (numeric 0).
        // UPDATED: QbftBlockHeader::new asserts nonce must be 8 bytes. So, for QBFT proposal (nonce=0), it must be Bytes::from_static(&[0u8; 8]).
        if block_header.nonce != alloy_primitives::Bytes::from_static(&[0u8; 8]) { 
            log::warn!(
                "Invalid Proposal: Block nonce {:?} is not the expected 0 (must be an 8-byte zero array)", 
                block_header.nonce
            );
            return Err(QbftError::ValidationError("Block nonce not 0".to_string()));
        }
        
        // Gas Limit Validation
        let parent_gas_limit = context.parent_header.gas_limit;
        let current_gas_limit = block_header.gas_limit;
        // Example rule: Allow delta of parent_gas_limit / gas_limit_bound_divisor (e.g., 1024)
        // This should ideally come from QbftConfig or a chain specification object.
        let gas_limit_bound_divisor = context.config.gas_limit_bound_divisor; // No unwrap_or needed, field is u64
        
        if parent_gas_limit == 0 { // Avoid division by zero if parent gas limit is 0 (should not happen for valid parent)
            if current_gas_limit != 0 { // If parent is 0, child must also be 0 or a minimum.
                 // This case is unlikely for standard Ethereum blocks after genesis.
                 log::warn!("Invalid Proposal: Parent gas limit is 0, but current block gas limit {} is not.", current_gas_limit);
                 // return Err(QbftError::ValidationError("Gas limit incompatible with zero parent gas limit".to_string()));
            }
        } else {
            let max_delta = parent_gas_limit / gas_limit_bound_divisor;
            if current_gas_limit > parent_gas_limit + max_delta || 
               (current_gas_limit < parent_gas_limit - max_delta && parent_gas_limit - max_delta > 0) { // ensure subtraction doesn't wrap if current_gas_limit is tiny
                // Also need to consider a minimum gas limit (e.g., 5000 in Ethereum)
                let min_gas_limit = context.config.min_gas_limit; // No unwrap_or needed, field is u64
                if current_gas_limit < min_gas_limit {
                log::warn!(
                        "Invalid Proposal: Block gas limit {} is below minimum {}",
                        current_gas_limit, min_gas_limit
                    );
                    return Err(QbftError::ValidationError(format!("Gas limit {} below minimum {}", current_gas_limit, min_gas_limit)));
                }

                if current_gas_limit > parent_gas_limit + max_delta || current_gas_limit < parent_gas_limit.saturating_sub(max_delta) {
                     log::warn!(
                        "Invalid Proposal: Block gas limit {} is outside allowed delta of parent gas limit {} (max_delta: {})",
                        current_gas_limit, parent_gas_limit, max_delta
                    );
                    return Err(QbftError::ValidationError("Gas limit outside allowed delta of parent".to_string()));
                }
            }
        }
        
        // Validate gas_used <= gas_limit
        if block_header.gas_used > block_header.gas_limit {
            log::warn!(
                "Invalid Proposal: Block gas_used {} exceeds gas_limit {}",
                block_header.gas_used, block_header.gas_limit
            );
            return Err(QbftError::ValidationError("Block gas_used exceeds gas_limit".to_string()));
        }
        
        // TODO: Validate other fields in decoded BftExtraData (e.g., validators list for consistency) - This was addressed by checking against context.current_validators.
        // No, this specific TODO was about other potential fields in BftExtraData beyond round and validators.
        // For now, round and validators are the most critical for basic QBFT extra_data checks.

        Ok(())
    }

    fn validate_block_coinbase_matches_author(
        &self,
        proposal: &Proposal,
        _context: &ValidationContext, // context might be needed if rules depend on it
    ) -> Result<(), QbftError> {
        let author = proposal.author()?;
        if proposal.payload().proposed_block.header.beneficiary != author { 
            log::warn!(
                "Invalid Proposal: Block beneficiary {:?} does not match proposer {:?}",
                proposal.payload().proposed_block.header.beneficiary, author
            );
            return Err(QbftError::ValidationError("Block beneficiary does not match proposer".to_string()));
        }
        Ok(())
    }

    fn validate_round_zero_conditions(
        &self,
        proposal: &Proposal,
        _context: &ValidationContext, // _context might be used later if round 0 rules depend on it
    ) -> Result<(), QbftError> {
        if !proposal.round_change_proofs().is_empty() {
            log::warn!("Invalid Proposal: Round 0 proposal contains round change proofs.");
            // Return specific error variant
            return Err(QbftError::ProposalHasRoundChangeForRoundZero);
        }
        if proposal.prepared_certificate().is_some() {
            log::warn!("Invalid Proposal: Round 0 proposal contains a prepared certificate.");
            // Return specific error variant
            return Err(QbftError::ProposalHasPreparedCertificateForRoundZero);
        }
        Ok(())
    }

    // Placeholder for now
    fn validate_prepares_for_certificate(
        &self,
        prepared_certificate: &crate::messagewrappers::PreparedCertificateWrapper, // Assuming this is our Rust equivalent
        _current_sequence_number: u64, // May be needed for context, or derived from outer_context if it was passed
        outer_context: &ValidationContext, // To access final_state, config etc for quorum and child context
    ) -> Result<(), QbftError> {
        // Based on Java:
        // - Get PrepareValidator (from factory, or construct).
        let prepare_validator = self.message_validator_factory.clone().create_prepare_validator();

        let cert_proposal_payload = prepared_certificate.proposal_message.payload();
        let cert_proposal_round_id = cert_proposal_payload.round_identifier;

        // - Check for duplicate authors in prepared_certificate.prepares().
        let mut prepare_authors = HashSet::new();
        for prepare_msg in &prepared_certificate.prepares {
            let author = prepare_msg.author()?;
            if !prepare_authors.insert(author) {
                log::warn!(
                    "Invalid PreparedCertificate: Duplicate author {:?} in prepares for proposal round {:?}", 
                    author, cert_proposal_round_id
                );
                return Err(QbftError::ValidationError("Duplicate author in certificate prepares".to_string()));
            }
        }

        // - Check for sufficient entries (quorum).
        // Validators for the certificate's proposal sequence number
        let validators_for_cert_proposal = outer_context.final_state.get_validators_for_block(cert_proposal_round_id.sequence_number)?;
        let num_validators_for_cert_proposal = validators_for_cert_proposal.len();
        if num_validators_for_cert_proposal == 0 {
                log::warn!(
               "Invalid PreparedCertificate: No validators found for the certificate's proposal sequence number {}.",
               cert_proposal_round_id.sequence_number
            );
            return Err(QbftError::NoValidators); 
        }
        // Assuming F is constant for this height context, or QbftFinalState provides it appropriately for the sequence number.
        let f = outer_context.final_state.get_byzantine_fault_tolerance(); 
        let quorum_size = num_validators_for_cert_proposal - f; // N - F

        if prepared_certificate.prepares.len() < quorum_size {
                 log::warn!(
                "Invalid PreparedCertificate: Insufficient prepares (got {}, needed {}) for proposal round {:?}", 
                prepared_certificate.prepares.len(), quorum_size, cert_proposal_round_id
            );
            return Err(QbftError::QuorumNotReached {
                needed: quorum_size,
                got: prepared_certificate.prepares.len(),
                item: format!("prepares for certificate of proposal round {:?}", cert_proposal_round_id),
            });
        }

        // - For each prepare in prepared_certificate.prepares():
        //   - Validate using PrepareValidator. Context for PrepareValidator needs:
        //     - Validators for the *prepared_certificate's proposal round*.
        //     - The *prepared_certificate's proposal round identifier*.
        //     - The *prepared_certificate's proposal block hash*.
        let cert_block_hash = cert_proposal_payload.proposed_block.hash(); // Hash of the block in the certificate

        for prepare_msg in &prepared_certificate.prepares {
            // Fetch the parent header for the block *within the certificate*.
            let parent_hash_for_cert_block = cert_proposal_payload.proposed_block.header.parent_hash;
            let parent_header_for_cert_block = outer_context.final_state.get_block_header(&parent_hash_for_cert_block)
                .ok_or_else(|| QbftError::InternalError(format!("Parent header {:?} not found for certified block's parent hash", parent_hash_for_cert_block)))?;
            
            let expected_proposer_for_cert_round = outer_context.final_state.get_proposer_for_round(&cert_proposal_round_id)?;

            let prepare_specific_context = ValidationContext::new(
                cert_proposal_round_id.sequence_number, 
                cert_proposal_round_id.round_number, 
                validators_for_cert_proposal.iter().cloned().collect(), // Validators for the cert proposal's height
                Arc::new(parent_header_for_cert_block), // Parent of the block in the certificate
                outer_context.final_state.clone(),
                outer_context.extra_data_codec.clone(),
                self.config.clone(), // Use self.config as ProposalValidatorImpl stores it
                Some(cert_block_hash), // Digest of the block proposed in the certificate
                expected_proposer_for_cert_round, // Proposer for the round of the proposal in the certificate
            );
            prepare_validator.validate_prepare(prepare_msg, &prepare_specific_context)?;
        }

        Ok(())
    }

    fn validate_round_changes_in_proposal(
        &self,
        proposal: &Proposal,
        context: &ValidationContext, // For quorum_size, validators for current round
    ) -> Result<Option<crate::payload::PreparedRoundMetadata>, QbftError> {
        log::trace!("Validating RoundChange proofs in proposal for sq/rd {:?}/{:?}", context.current_sequence_number, context.current_round_number);

        let round_change_proofs = proposal.round_change_proofs(); // Use accessor
        let num_proofs = round_change_proofs.len();
        let quorum_size = context.final_state.quorum_size();

        // It's only an error to have insufficient proofs if the proposal is NOT for round 0.
        // Round 0 proposals should not have proofs.
        if context.current_round_number > 0 && num_proofs < quorum_size {
            log::warn!(
                "Invalid Proposal: Insufficient round_change_proofs (got {}, needed {} for quorum). Proposal for sq/rd {:?}/{:?}",
                num_proofs, quorum_size, context.current_sequence_number, context.current_round_number
            );
            return Err(QbftError::QuorumNotReached {
                needed: quorum_size,
                got: num_proofs,
                item: "round change proofs".to_string(),
            });
        } else if context.current_round_number == 0 && !round_change_proofs.is_empty() {
            // This condition is also checked by validate_round_zero_conditions, but included here for completeness
            return Err(QbftError::ProposalHasRoundChangeForRoundZero);
        }

        if round_change_proofs.is_empty() {
            // Valid for round 0, or for round > 0 if no prepared cert is claimed.
            return Ok(None); 
        }

        let mut best_prepared_metadata: Option<crate::payload::PreparedRoundMetadata> = None;
        let mut distinct_authors = HashSet::new();
        let round_change_validator = self.round_change_message_validator_factory.create_round_change_message_validator();
        let mut latest_rc_round: u32 = 0; // Track highest round number from *valid* proofs

        // Iterate over the result of the accessor method
        for rc_proof in round_change_proofs.iter() { 
            let author = rc_proof.author()?;
            if !distinct_authors.insert(author) {
                log::warn!(
                    "Invalid Proposal: Duplicate author {:?} in round_change_proofs. Proposal for sq/rd {:?}/{:?}",
                    author, context.current_sequence_number, context.current_round_number
                );
                return Err(QbftError::ValidationError(
                    "Duplicate author in round_change_proofs".to_string(),
                ));
            }
            
             // Create a context specific to the round the RC message is *for*.
            let rc_validation_context = ValidationContext {
                 current_round_number: rc_proof.round_identifier().round_number,
                 // TODO: Enhance context creation for historical rounds if needed.
                 ..context.clone() 
            };

            // 1. Validate the RoundChange message itself using the dedicated validator
            match round_change_validator.validate_round_change(rc_proof, &rc_validation_context) { 
                Ok(_) => { 
                    log::trace!("RoundChange proof from {:?} for round {:?} passed validation.", author, rc_proof.round_identifier());
                    // Validation passed, update latest_rc_round and check metadata.
                    
                    // Track the latest round number seen among valid proofs.
                    if rc_proof.round_identifier().round_number > latest_rc_round {
                        latest_rc_round = rc_proof.round_identifier().round_number;
                    }

                    // Process PreparedRoundMetadata if present in this valid proof.
                    if let Some(prepared_metadata) = rc_proof.payload().prepared_round_metadata.as_ref() {
                        // Logic to update best_prepared_metadata based on prepared_round and block number
                        let mut update_best = false;
                        if let Some(best_so_far) = &best_prepared_metadata {
                            if prepared_metadata.prepared_round > best_so_far.prepared_round {
                                update_best = true;
                            } else if prepared_metadata.prepared_round == best_so_far.prepared_round {
                                let current_block_num = prepared_metadata.signed_proposal_payload.payload().proposed_block.header.number;
                                let best_block_num = best_so_far.signed_proposal_payload.payload().proposed_block.header.number;
                                if current_block_num > best_block_num {
                                    update_best = true;
                                }
                                // Add check for consistent block hashes if rounds and numbers are equal
                                else if current_block_num == best_block_num && prepared_metadata.prepared_block_hash != best_so_far.prepared_block_hash {
                                     log::warn!(
                                        "Invalid Proposal: Inconsistent PreparedRoundMetadata block hashes found across RoundChange proofs for same prepared_round {} and block number {}.",
                                        prepared_metadata.prepared_round, current_block_num
                                    );
                                    return Err(QbftError::ValidationError(
                                        "Inconsistent PreparedRoundMetadata block hashes in round change proofs".to_string(),
                                    ));
                                }
                            }
                        } else {
                            update_best = true;
                        }
                        if update_best {
                            best_prepared_metadata = Some(prepared_metadata.clone());
                        }
                    }
                }, 
                Err(e) => {
                    // If validation fails for an individual RC proof, return error immediately.
                    log::warn!(
                        "RoundChange proof from {:?} for round {:?} failed validation: {:?}. Failing proposal validation.",
                        author, rc_proof.round_identifier(), e
                    );
                    return Err(QbftError::RoundChangeValidationError(format!("RC from {:?} failed: {}", author, e))); 
                }
            }
        }
        
        // After processing all proofs:
        let proposal_round = proposal.payload().round_identifier.round_number;

        if proposal_round > 0 && proposal_round != latest_rc_round + 1 {
            log::warn!(
                "Invalid Proposal: Proposal round {} does not follow latest valid RoundChange proof round {}. Context sq/rd {:?}/{:?}",
                proposal_round, 
                latest_rc_round, 
                context.current_sequence_number, context.current_round_number,
            );
            return Err(QbftError::ProposalRoundNotFollowingRoundChanges);
        }

        log::debug!("Completed validation of RoundChange proofs. Best prepared round found: {:?}. Latest RC round from valid proofs: {}", 
            best_prepared_metadata.as_ref().map(|m| m.prepared_round), latest_rc_round);

        Ok(best_prepared_metadata) 
    }

    fn calculate_hash_for_block_with_round(
        &self,
        original_block: &crate::types::QbftBlock, // Use crate::types::QbftBlock
        target_round: u32,
        extra_data_codec: &Arc<dyn BftExtraDataCodec>, 
    ) -> Result<Hash, QbftError> {
        let mut new_header = original_block.header.clone();
        let mut bft_extra_data = extra_data_codec.decode(&new_header.extra_data)?;
        
        bft_extra_data.round_number = target_round;
        
        new_header.extra_data = extra_data_codec.encode(&bft_extra_data)?;
        
        Ok(new_header.hash()) // Use .hash() which should be available on QbftBlockHeader
    }
}

impl ProposalValidator for ProposalValidatorImpl {
    fn validate_proposal(&self, proposal: &Proposal, context: &ValidationContext) -> Result<(), QbftError> {
        // Mimic Java's ProposalValidator.validate()
        // 1. Validate payload and block (combines ProposalPayloadValidator and QbftBlockValidator logic)
        self.validate_payload_and_block(proposal, context)?;

        // 2. Mimic validateProposalAndRoundChangeAreConsistent()
        let proposal_round_identifier = proposal.payload().round_identifier;

        if proposal_round_identifier.round_number == 0 {
            self.validate_round_zero_conditions(proposal, context)?;
            // As per Java: validateBlockCoinbaseMatchesMsgAuthor is also called for round 0
            self.validate_block_coinbase_matches_author(proposal, context)?;
        } else {
            // Non-Round 0 logic
            let latest_prepared_metadata_from_rc = self.validate_round_changes_in_proposal(proposal, context)?;

            if let Some(ref prepared_metadata) = latest_prepared_metadata_from_rc {
                // There was a prepared certificate in one of the round changes.
                log::debug!(
                    "Proposal for round > 0: Found PreparedRoundMetadata from RoundChanges: {:?}",
                    prepared_metadata
                );

                // b. Hash check for re-proposal consistency
                let expected_prior_block_hash = self.calculate_hash_for_block_with_round(
                    proposal.block(), // block() returns &QbftBlock from the payload
                    prepared_metadata.prepared_round,
                    &context.extra_data_codec,
                )?;

                if prepared_metadata.prepared_block_hash != expected_prior_block_hash {
            log::warn!(
                        "Invalid Proposal: Latest PreparedRoundMetadata block hash {:?} does not align with proposed block's re-calculated hash {:?} for prepared round {}",
                        prepared_metadata.prepared_block_hash, expected_prior_block_hash, prepared_metadata.prepared_round
                    );
                    return Err(QbftError::ValidationError(
                        "PreparedRoundMetadata block hash mismatch with re-calculated proposal block hash".to_string(),
                    ));
                }

                // c. Validate prepares piggybacked in the Proposal message itself.
                //    These prepares should correspond to the prepared_metadata (same block, same round).
                if let Some(piggybacked_cert_wrapper) = proposal.prepared_certificate.as_ref() {
                    // Check consistency: the proposal within the piggybacked certificate must match
                    // the proposal described by `prepared_metadata` from the RoundChanges.
                    if piggybacked_cert_wrapper.proposal_message.payload().round_identifier != prepared_metadata.signed_proposal_payload.payload().round_identifier ||
                       piggybacked_cert_wrapper.proposal_message.payload().proposed_block.hash() != prepared_metadata.prepared_block_hash {
            log::warn!(
                            "Invalid Proposal: Piggybacked PreparedCertificateWrapper is inconsistent with the PreparedRoundMetadata from RoundChanges. RC Cert Proposal: {:?}/{:?}, Piggyback Cert Proposal: {:?}/{:?}",
                            prepared_metadata.signed_proposal_payload.payload().round_identifier,
                            prepared_metadata.prepared_block_hash,
                            piggybacked_cert_wrapper.proposal_message.payload().round_identifier,
                            piggybacked_cert_wrapper.proposal_message.payload().proposed_block.hash()
                        );
                        return Err(QbftError::ValidationError(
                            "Inconsistent PreparedCertificate in Proposal vs RoundChanges".to_string(),
                        ));
                    }
                    // If consistent, validate the prepares within the piggybacked certificate.
                    self.validate_prepares_for_certificate(piggybacked_cert_wrapper, context.current_sequence_number, context)?;
                } else {
                    // If RoundChanges indicated a prepared round (i.e., latest_prepared_metadata_from_rc is Some),
                    // then the Proposal itself MUST carry this prepared certificate.
                    log::warn!(
                        "Invalid Proposal: Missing PreparedCertificate in Proposal when RoundChanges indicated one (prepared_round: {})",
                        prepared_metadata.prepared_round
                    );
                    return Err(QbftError::ValidationError(
                        "Missing PreparedCertificate in Proposal when RoundChanges indicated one".to_string(),
                    ));
                }
            } else {
                // No RoundChange carried a (valid) PreparedCertificate, or no RCs were present.
                // In this case, the Proposal must not have a prepared certificate.
                log::debug!("Proposal for round > 0: No PreparedRoundMetadata found from RoundChanges.");
                if proposal.prepared_certificate.is_some() {
                    log::warn!(
                        "Invalid Proposal: Unexpected PreparedCertificate in Proposal when RoundChanges did not provide one or were absent."
                    );
                    return Err(QbftError::ValidationError(
                        "Unexpected PreparedCertificate in Proposal".to_string(),
                    ));
                }
                // And the coinbase must match the author, as per Java logic for this path.
                self.validate_block_coinbase_matches_author(proposal, context)?;
            }
        }
        Ok(())
    }
}