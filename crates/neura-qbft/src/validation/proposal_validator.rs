// This file should now ONLY contain ValidationContext, ProposalValidator trait, and ProposalValidatorImpl struct/impl.
// The old struct ProposalValidator and its impl block have been removed.

use crate::messagewrappers::Proposal;
use crate::types::{QbftBlockHeader, QbftFinalState, BftExtraDataCodec, QbftConfig, ConsensusRoundIdentifier};
use crate::error::QbftError;
// use crate::payload::QbftPayload; // Removed unused import
use alloy_primitives::{Address, B256 as Hash}; // Added Hash import
use std::collections::{HashSet, HashMap}; // Added HashMap for duplicate author check
use std::sync::Arc;

// Bring in specific validator traits it will need
use crate::validation::{RoundChangeMessageValidator};

// Bring in MessageValidatorFactory for storage
use crate::validation::MessageValidatorFactory;

// Note: Other imports from the old struct ProposalValidator like QbftFinalState, QbftConfig, etc. 
// will be needed here if/when ProposalValidatorImpl uses them.
// For now, keeping imports minimal for the current placeholder impl.

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
    config: Arc<QbftConfig>,
    // No direct child validators stored if created on-demand by factory
}

impl ProposalValidatorImpl {
    pub fn new(
        message_validator_factory: Arc<dyn MessageValidatorFactory>,
        config: Arc<QbftConfig>,
    ) -> Self {
        Self { 
            message_validator_factory,
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
            log::warn!(
                "Invalid Proposal: Author {:?} is not the expected proposer {:?} for round {:?}/{:?}", 
                author, context.expected_proposer, context.current_sequence_number, context.current_round_number
            );
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
            return Err(QbftError::ProposalRoundMismatch);
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
    ) -> Result<Option<crate::payload::PreparedRoundMetadata>, QbftError> { // Return type changed to Option<PreparedRoundMetadata>
        
        let round_change_proofs = proposal.round_change_proofs();
        if round_change_proofs.is_empty() {
            // If no round changes, then no prepared certificate can come from them.
            return Ok(None);
        }

        // Basic checks on proposal.round_change_proofs():
        // 1. No duplicate authors.
        let mut authors = HashSet::new();
        for rc_proof in round_change_proofs {
            let author = rc_proof.author()?;
            if !authors.insert(author) {
                log::warn!("Invalid Proposal: Duplicate author {:?} in round_change_proofs", author);
                return Err(QbftError::ValidationError("Duplicate author in round change proofs".to_string()));
            }
        }

        // 2. Sufficient entries for a quorum.
        let num_validators = context.current_validators.len();
        if num_validators == 0 {
            return Err(QbftError::NoValidators); // Cannot have quorum with no validators
        }
        // F = (N-1)/3. Quorum = N - F (or commonly 2F+1, which is N - F for N=3F+1, 3F+2; and N-F+1 for N=3F)
        // Besu's BftHelpers.calculateRequiredMessages uses (N * 2 / 3) + 1, which is ceil(2N/3) or 2F+1 for N>=1.
        // Let's use context.final_state.get_byzantine_fault_tolerance() if available, or calculate 2F+1.
        // Assuming QbftConfig provides a way to get F or quorum directly.
        // For now, placeholder: use fault_tolerance_f to calculate quorum.
        let f = context.final_state.get_byzantine_fault_tolerance(); // Use QbftFinalState for this
        let quorum_size = num_validators - f; // N - F is a common definition for QBFT/IBFT style quorum
                                          // Or, more robustly, 2*f + 1, but this requires N >= 3f+1.
                                          // Besu QuorumChecker.hasSufficientVote() uses N - F.

        if round_change_proofs.len() < quorum_size {
            log::warn!(
                "Invalid Proposal: Insufficient round_change_proofs (got {}, needed {} for quorum)", 
                round_change_proofs.len(), quorum_size
            );
            return Err(QbftError::QuorumNotReached {
                needed: quorum_size,
                got: round_change_proofs.len(),
                item: "round change proofs".to_string(),
            });
        }

        // Part 3: metadataIsConsistentAcrossRoundChanges logic
        let mut metadatas_by_prepared_round: HashMap<u32, Vec<&crate::payload::PreparedRoundMetadata>> = HashMap::new();
        for rc_proof in round_change_proofs {
            if let Some(metadata) = rc_proof.payload().prepared_round_metadata.as_ref() {
                metadatas_by_prepared_round.entry(metadata.prepared_round).or_default().push(metadata);
            }
        }

        for (_prepared_round, metadatas) in metadatas_by_prepared_round {
            if metadatas.len() > 1 {
                let first_metadata_hash = metadatas[0].prepared_block_hash;
                // Compare block hash and also the full original signed proposal if we store it that deeply.
                // For now, QBFT spec implies consistency of the prepared block, so hash is key.
                // Besu's PreparedRoundMetadata only has preparedBlockHash, preparedRound, and the signedProposalPayload.
                // So, comparing the hash and the RLP of signed_proposal_payload should be sufficient.
                if !metadatas.iter().all(|m| m.prepared_block_hash == first_metadata_hash && m.signed_proposal_payload == metadatas[0].signed_proposal_payload) {
                    log::warn!(
                        "Invalid Proposal: Inconsistent PreparedRoundMetadata across round_change_proofs for the same prepared_round"
                    );
                    return Err(QbftError::ValidationError(
                        "Inconsistent PreparedRoundMetadata in round change proofs".to_string(),
                    ));
                }
            }
        }

        // Part 2: Individual RoundChange validation & Target Round Check
        // Create RoundChangeMessageValidator instance using the factory and config stored in self.
        // Note: RoundChangeMessageValidatorImpl::new takes factory and config.
        let rc_validator = crate::validation::RoundChangeMessageValidatorImpl::new(
            self.message_validator_factory.clone(), 
            self.config.clone()
        );
        
        let mut valid_rc_prepared_metadatas: Vec<&crate::payload::PreparedRoundMetadata> = Vec::new();

        for rc_proof in round_change_proofs {
            // Ensure rc_proof targets the proposal's round
            if rc_proof.payload().round_identifier != proposal.payload().round_identifier {
            log::warn!(
                    "Invalid Proposal: RoundChangeProof targets round {:?} but proposal is for round {:?}",
                    rc_proof.payload().round_identifier,
                    proposal.payload().round_identifier
                );
                return Err(QbftError::ValidationError(
                    "RoundChangeProof targets incorrect round".to_string(),
                ));
            }

            // Perform actual validation of rc_proof using RoundChangeMessageValidator
            // Create specific ValidationContext for this rc_proof.
            // This context is for validating the RC message itself, within the scope of the current proposal's round.
            let rc_context_round_number = rc_proof.payload().round_identifier.round_number;
            let rc_context_sequence_number = rc_proof.payload().round_identifier.sequence_number;

            // Hypothesis: RoundChangeMessageValidatorImpl expects the context's round to be R-1
            // if the RC payload is for round R.
            let context_round_for_rc_validator = if rc_context_round_number > 0 { rc_context_round_number - 1 } else { 0 }; // Avoid underflow for round 0 RCs

            let round_id_for_proposer_in_rc_context = ConsensusRoundIdentifier {
                sequence_number: rc_context_sequence_number, // Sequence number of the RC itself
                round_number: context_round_for_rc_validator, // The R-1 round for the context's expected_proposer
            };

            let rc_specific_context = ValidationContext::new(
                rc_context_sequence_number, // Sequence number from the RC proof itself
                context_round_for_rc_validator, // Use R-1 for the context's current_round_number
                context.current_validators.clone(), 
                context.parent_header.clone(), 
                context.final_state.clone(),
                context.extra_data_codec.clone(),
                context.config.clone(),
                None, 
                // Expected proposer should also be for the R-1 round of the context
                context.final_state.get_proposer_for_round(&round_id_for_proposer_in_rc_context)? 
            );
            
            rc_validator.validate_round_change(rc_proof, &rc_specific_context)?;

            // If validated, collect its metadata if present.
            if let Some(metadata) = rc_proof.payload().prepared_round_metadata.as_ref() {
                valid_rc_prepared_metadatas.push(metadata);
            }
        }

        // Part 4: getRoundChangeWithLatestPreparedRound logic
        // This operates on `valid_rc_prepared_metadatas` which should ideally be populated after
        // individual RC validation passes.
        let best_prepared_metadata = valid_rc_prepared_metadatas
            .iter()
            .max_by_key(|m| m.prepared_round)
            .map(|&m| m.clone()); // Clone to get owned PreparedRoundMetadata

        // log::warn!("Partial impl: validate_round_changes_in_proposal. Basic & metadata consistency checks done. Returning None for prepared metadata.");
        // Ok(None)
        // Now return the actual best_prepared_metadata found
        if best_prepared_metadata.is_some() {
            log::debug!("Found best_prepared_metadata from round changes: {:?}", best_prepared_metadata);
        } else {
            log::debug!("No prepared_metadata found in any round change proofs.");
        }
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

#[cfg(test)]
mod tests {
    use super::*; // Bring in ProposalValidatorImpl, ValidationContext etc.
    use crate::messagewrappers::{BftMessage, Proposal, Prepare, Commit, RoundChange, PreparedCertificateWrapper};
    use crate::payload::{ProposalPayload, RoundChangePayload, PreparePayload}; // Added RoundChangePayload, PreparePayload
    use crate::types::{NodeKey, QbftBlock, QbftBlockHeader, ConsensusRoundIdentifier, QbftConfig, BftExtraData, SignedData}; // Re-added here too
    use crate::mocks::{MockQbftFinalState};
    use crate::validation::{MessageValidatorFactory, ProposalValidator, PrepareValidator, CommitValidator};
    use crate::error::QbftError;
    use alloy_primitives::{Address, Bytes, B256, U256};
    use alloy_rlp::{Error as RlpError, Encodable, Decodable};
    use std::sync::Arc;
    use std::collections::{HashSet};
    use k256::SecretKey as K256SecretKey;
    use k256::ecdsa::VerifyingKey;
    // Removed: use k256::ecdsa::signature::Signer; // No longer needed after switching to SignedData::sign

    // --- Helper Functions --- 

    fn default_config() -> Arc<QbftConfig> {
        Arc::new(QbftConfig::default())
    }

    fn create_node_key() -> NodeKey {
        let secret_key = K256SecretKey::random(&mut rand::thread_rng());
        NodeKey::from(secret_key)
    }

    fn address_from_key(key: &NodeKey) -> Address {
        let verifying_key: &VerifyingKey = key.verifying_key();
        let uncompressed_pk_bytes = verifying_key.to_encoded_point(false).as_bytes().to_vec();
        // Ethereum address is last 20 bytes of Keccak256 hash of uncompressed public key (excluding prefix byte 0x04)
        let hash = alloy_primitives::keccak256(&uncompressed_pk_bytes[1..]);
        Address::from_slice(&hash[12..])
    }

    fn default_parent_header(number: u64, _hash: B256, timestamp: u64, gas_limit: u64) -> Arc<QbftBlockHeader> { // _hash param unused for now
        Arc::new(QbftBlockHeader::new(
            B256::ZERO, // parent_hash of parent (grandparent)
            B256::ZERO,    // ommers_hash
            Address::ZERO, // beneficiary
            B256::ZERO, // state_root
            B256::ZERO, // transactions_root
            B256::ZERO, // receipts_root
            Default::default(), // logs_bloom
            U256::from(1),  // difficulty
            number,         // number
            gas_limit,      // gas_limit
            0,              // gas_used
            timestamp,      // timestamp
            Bytes::from_static(&[0x01, 0x02]), // extra_data (dummy)
            B256::ZERO,    // mix_hash
            Bytes::from_static(&[0u8; 8]), // nonce (reverted to 8-byte zero array due to header constructor assertion)
        ))
    }

    // Mock ExtraDataCodec for tests
    struct TestExtraDataCodec;
    impl BftExtraDataCodec for TestExtraDataCodec {
        fn decode(&self, data: &Bytes) -> Result<BftExtraData, RlpError> {
            // Use BftExtraData's own RlpDecodable trait
            BftExtraData::decode(&mut data.as_ref())
        }
        fn encode(&self, extra_data: &BftExtraData) -> Result<Bytes, RlpError> {
            // Use BftExtraData's own RlpEncodable trait
            let mut out_vec = Vec::new();
            extra_data.encode(&mut out_vec);
            Ok(Bytes::from(out_vec))
        }
    }
    fn testing_extradata_codec() -> Arc<dyn BftExtraDataCodec> {
        Arc::new(TestExtraDataCodec)
    }

    fn default_final_state(local_node_key: Arc<NodeKey>, validators: HashSet<Address>) -> Arc<dyn QbftFinalState> {
        // local_address is derived inside MockQbftFinalState now, or not needed for its constructor.
        // Assuming MockQbftFinalState::new takes (Arc<NodeKey>, HashSet<Address>)
        Arc::new(MockQbftFinalState::new(local_node_key, validators))
    }

    fn default_validation_context(
        sequence: u64,
        round: u32,
        validators: HashSet<Address>,
        parent_header: Arc<QbftBlockHeader>,
        expected_proposer: Address,
        config: Arc<QbftConfig>,
        extra_data_codec: Arc<dyn BftExtraDataCodec>,
        final_state_opt: Option<Arc<dyn QbftFinalState>>,
        local_node_key_for_final_state: Arc<NodeKey>, // Added for creating default_final_state
    ) -> ValidationContext {
        let final_state = final_state_opt.unwrap_or_else(|| default_final_state(local_node_key_for_final_state, validators.clone()));
        ValidationContext::new(
            sequence,
            round,
            validators,
            parent_header,
            final_state,
            extra_data_codec,
            config,
            None, // accepted_proposal_digest - set per test if needed
            expected_proposer,
        )
    }
    
    // --- Mock Validators and Factory ---
    #[derive(Clone)]
    struct MockProposalValidator { fail_on_validate: bool }
    impl ProposalValidator for MockProposalValidator {
        fn validate_proposal(&self, _proposal: &Proposal, _context: &ValidationContext) -> Result<(), QbftError> {
            if self.fail_on_validate { Err(QbftError::ValidationError("MockProposalValidator failed".to_string())) } else { Ok(()) }
        }
    }

    #[derive(Clone)]
    struct MockPrepareValidator { fail_on_validate: bool }
    impl PrepareValidator for MockPrepareValidator {
        fn validate_prepare(&self, _prepare: &Prepare, _context: &ValidationContext) -> Result<(), QbftError> {
            if self.fail_on_validate { Err(QbftError::ValidationError("MockPrepareValidator failed".to_string())) } else { Ok(()) }
        }
    }
    
    #[derive(Clone)]
    struct MockCommitValidator { fail_on_validate: bool }
    impl CommitValidator for MockCommitValidator {
        fn validate_commit(&self, _commit: &Commit, _context: &ValidationContext) -> Result<(), QbftError> {
            if self.fail_on_validate { Err(QbftError::ValidationError("MockCommitValidator failed".to_string())) } else { Ok(()) }
        }
    }

    struct MockMessageValidatorFactoryImpl {
        proposal_should_fail: bool,
        prepare_should_fail: bool,
        commit_should_fail: bool,
    }

    impl MockMessageValidatorFactoryImpl {
        fn new(p: bool, pr: bool, c: bool) -> Self {
            Self { proposal_should_fail: p, prepare_should_fail: pr, commit_should_fail: c }
        }
    }

    impl MessageValidatorFactory for MockMessageValidatorFactoryImpl {
        fn create_proposal_validator(self: Arc<Self>) -> Arc<dyn ProposalValidator + Send + Sync> {
            Arc::new(MockProposalValidator { fail_on_validate: self.proposal_should_fail })
        }
        fn create_prepare_validator(self: Arc<Self>) -> Arc<dyn PrepareValidator + Send + Sync> {
            Arc::new(MockPrepareValidator { fail_on_validate: self.prepare_should_fail })
        }
        fn create_commit_validator(self: Arc<Self>) -> Arc<dyn CommitValidator + Send + Sync> {
            Arc::new(MockCommitValidator { fail_on_validate: self.commit_should_fail })
        }
    }

    fn mock_message_validator_factory(
        prop_fail: bool, 
        prep_fail: bool, 
        commit_fail: bool
    ) -> Arc<dyn MessageValidatorFactory> {
        Arc::new(MockMessageValidatorFactoryImpl::new(prop_fail, prep_fail, commit_fail))
    }

    // --- Test Proposal Construction Helpers ---
    fn create_proposal_payload(
        round_id: ConsensusRoundIdentifier,
        block: QbftBlock
    ) -> ProposalPayload {
        ProposalPayload::new(round_id, block)
    }

    fn create_signed_proposal_payload(
        payload: ProposalPayload,
        key: &NodeKey
    ) -> SignedData<ProposalPayload> {
        SignedData::sign(payload, key).expect("Failed to sign proposal payload")
    }

    fn create_bft_message_proposal(
        signed_payload: SignedData<ProposalPayload>
    ) -> BftMessage<ProposalPayload> {
        BftMessage::new(signed_payload)
    }

    fn create_proposal(
        bft_message: BftMessage<ProposalPayload>,
        header_for_proposal_struct: QbftBlockHeader, // The header that Proposal struct itself will hold
        rc_proofs: Vec<RoundChange>,
        prep_cert: Option<PreparedCertificateWrapper>
    ) -> Proposal {
        Proposal::new(bft_message, header_for_proposal_struct, rc_proofs, prep_cert)
    }
    
    fn default_qbft_block(
        parent_hash: B256,
        number: u64,
        round: u32, // For extra data
        timestamp: u64,
        gas_limit: u64,
        beneficiary: Address,
        extra_data_codec: Arc<dyn BftExtraDataCodec>,
        validators_for_extra_data: Vec<Address>,
    ) -> QbftBlock {
        let bft_extra = BftExtraData {
            vanity_data: Bytes::from_static(b"test_vanity"),
            validators: validators_for_extra_data,
            committed_seals: vec![],
            round_number: round,
        };
        let extra_data_res = extra_data_codec.encode(&bft_extra);
        // Handle RlpError if encode fails, though for this mock it shouldn't.
        let extra_data = extra_data_res.unwrap_or_else(|e| {
            panic!("TestExtraDataCodec.encode failed: {:?}", e);
            // Fallback or default Bytes if panic is not desired
            // Bytes::from_static(&[round as u8]) 
        });


        let header = QbftBlockHeader::new(
            parent_hash,
            B256::ZERO, // ommers_hash
            beneficiary,
            B256::ZERO, // state_root
            B256::ZERO, // transactions_root
            B256::ZERO, // receipts_root
            Default::default(), // logs_bloom
            U256::from(1), // difficulty
            number,
            gas_limit,
            0, // gas_used
            timestamp,
            extra_data,
            B256::ZERO, // mix_hash
            Bytes::from_static(&[0u8; 8]), // nonce (reverted to 8-byte zero array)
        );
        QbftBlock {
            header,
            body_transactions: vec![], // Corrected field name
            body_ommers: vec![],     // Corrected field name
        }
    }

    // --- TODO: Actual test functions below ---
    #[test]
    fn test_placeholder() {
        assert_eq!(1,1);
    }

    #[test]
    fn test_validate_payload_and_block_valid_proposal() {
        let config = default_config();
        let codec = testing_extradata_codec();

        let proposer_key = create_node_key();
        let proposer_address = address_from_key(&proposer_key);
        
        let validator2_key = create_node_key();
        let validator2_address = address_from_key(&validator2_key);

        let validators: HashSet<Address> = vec![proposer_address, validator2_address].into_iter().collect();
        let validators_vec: Vec<Address> = validators.iter().cloned().collect();

        let parent_sequence: u64 = 0;
        let parent_round: u32 = 0; 
        let parent_gas_limit: u64 = 30_000_000;
        let parent_timestamp: u64 = 1_000_000;
        let parent_h = default_parent_header(parent_sequence, B256::ZERO, parent_timestamp, parent_gas_limit);

        let current_sequence = parent_sequence + 1;
        let current_round = parent_round;

        let final_state_for_context = default_final_state(Arc::new(proposer_key.clone()), validators.clone());
        // Mock QbftFinalState to return the correct proposer for the current round
        // For this test, we'll assume proposer_address is the expected one.
        // If MockQbftFinalState's get_proposer_for_round is too simple, we might need to enhance it or wrap it.
        // For now, let's ensure expected_proposer passed to context is correct.

        let context = default_validation_context(
            current_sequence,
            current_round,
            validators.clone(),
            parent_h.clone(),
            proposer_address, // Expected proposer
            config.clone(),
            codec.clone(),
            Some(final_state_for_context.clone()), // Pass the correctly created final_state
            Arc::new(proposer_key.clone()), // Pass the key for default_final_state if final_state_opt is None
        );

        let block_beneficiary = proposer_address; // For this test, proposer is also beneficiary
        let block_timestamp = parent_timestamp + 1;
        let block_gas_limit = parent_gas_limit; // Keep same for simplicity, within bounds

        let proposed_block = default_qbft_block(
            parent_h.hash(),
            current_sequence,
            current_round,
            block_timestamp,
            block_gas_limit,
            block_beneficiary,
            codec.clone(),
            validators_vec.clone(), // Extra data validators match context
        );

        let proposal_round_id = ConsensusRoundIdentifier {
            sequence_number: current_sequence,
            round_number: current_round,
        };
        let proposal_payload = create_proposal_payload(proposal_round_id, proposed_block.clone());
        let signed_payload = create_signed_proposal_payload(proposal_payload, &proposer_key);
        let bft_message = create_bft_message_proposal(signed_payload);
        
        // The header in Proposal struct should match the header of the block in the payload
        let proposal_to_validate = create_proposal(bft_message, proposed_block.header.clone(), vec![], None);

        let msg_val_factory = mock_message_validator_factory(false, false, false);
        let proposal_validator = ProposalValidatorImpl::new(msg_val_factory, config.clone());

        let result = proposal_validator.validate_payload_and_block(&proposal_to_validate, &context);
        
        if let Err(ref e) = result {
            eprintln!("Validation failed: {:?}", e);
            if let QbftError::ValidationError(ref s) = e {
                if s.contains("extra_data") { // Debugging extra data issues
                    let decoded_res = codec.decode(&proposed_block.header.extra_data);
                    eprintln!("Decoded extra data for block: {:?}", decoded_res);
                    eprintln!("Context validators: {:?}", context.current_validators);
                }
            }
        }
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_payload_and_block_invalid_author() {
        let config = default_config();
        let codec = testing_extradata_codec();

        let proposer1_key = create_node_key();
        let proposer1_address = address_from_key(&proposer1_key);
        
        let proposer2_key = create_node_key(); // Different key for the actual author
        let proposer2_address = address_from_key(&proposer2_key);

        let validators: HashSet<Address> = vec![proposer1_address, proposer2_address].into_iter().collect();
        let validators_vec: Vec<Address> = validators.iter().cloned().collect();

        let parent_sequence: u64 = 0;
        let parent_gas_limit: u64 = 30_000_000;
        let parent_timestamp: u64 = 1_000_000;
        let parent_h = default_parent_header(parent_sequence, B256::ZERO, parent_timestamp, parent_gas_limit);

        let current_sequence = parent_sequence + 1;
        let current_round = 0;

        let final_state_for_context = default_final_state(Arc::new(proposer1_key.clone()), validators.clone());

        let context = default_validation_context(
            current_sequence,
            current_round,
            validators.clone(),
            parent_h.clone(),
            proposer1_address, // Context expects proposer1
            config.clone(),
            codec.clone(),
            Some(final_state_for_context.clone()),
            Arc::new(proposer1_key.clone()),
        );

        // Block is created fine, beneficiary can be anyone for this part of the test focus
        let proposed_block = default_qbft_block(
            parent_h.hash(),
            current_sequence,
            current_round,
            parent_timestamp + 1,
            parent_gas_limit,
            proposer2_address, // Block beneficiary
            codec.clone(),
            validators_vec.clone(),
        );

        let proposal_round_id = ConsensusRoundIdentifier {
            sequence_number: current_sequence,
            round_number: current_round,
        };
        let proposal_payload = create_proposal_payload(proposal_round_id, proposed_block.clone());
        // Proposal is signed by proposer2_key, but context expects proposer1_address
        let signed_payload = create_signed_proposal_payload(proposal_payload, &proposer2_key);
        let bft_message = create_bft_message_proposal(signed_payload);
        
        let proposal_to_validate = create_proposal(bft_message, proposed_block.header.clone(), vec![], None);

        let msg_val_factory = mock_message_validator_factory(false, false, false);
        let proposal_validator = ProposalValidatorImpl::new(msg_val_factory, config.clone());

        let result = proposal_validator.validate_payload_and_block(&proposal_to_validate, &context);
        
        assert!(matches!(result, Err(QbftError::ProposalNotFromProposer)));
    }

    #[test]
    fn test_validate_payload_and_block_round_mismatch() {
        let config = default_config();
        let codec = testing_extradata_codec();

        let proposer_key = create_node_key();
        let proposer_address = address_from_key(&proposer_key);
        
        let validators: HashSet<Address> = vec![proposer_address].into_iter().collect();
        let validators_vec: Vec<Address> = validators.iter().cloned().collect();

        let parent_sequence: u64 = 0;
        let parent_gas_limit: u64 = 30_000_000;
        let parent_timestamp: u64 = 1_000_000;
        let parent_h = default_parent_header(parent_sequence, B256::ZERO, parent_timestamp, parent_gas_limit);

        let current_sequence = parent_sequence + 1;
        let context_current_round = 0;
        let payload_round = context_current_round + 1; // Mismatched round

        let final_state_for_context = default_final_state(Arc::new(proposer_key.clone()), validators.clone());

        let context = default_validation_context(
            current_sequence,
            context_current_round, // Context is for round 0
            validators.clone(),
            parent_h.clone(),
            proposer_address,
            config.clone(),
            codec.clone(),
            Some(final_state_for_context.clone()),
            Arc::new(proposer_key.clone()),
        );

        // Block is created for the payload's round
        let proposed_block = default_qbft_block(
            parent_h.hash(),
            current_sequence,
            payload_round, // Block for round 1
            parent_timestamp + 1,
            parent_gas_limit,
            proposer_address,
            codec.clone(),
            validators_vec.clone(),
        );

        let proposal_round_id = ConsensusRoundIdentifier {
            sequence_number: current_sequence,
            round_number: payload_round, // Payload for round 1
        };
        let proposal_payload = create_proposal_payload(proposal_round_id, proposed_block.clone());
        let signed_payload = create_signed_proposal_payload(proposal_payload, &proposer_key);
        let bft_message = create_bft_message_proposal(signed_payload);
        
        let proposal_to_validate = create_proposal(bft_message, proposed_block.header.clone(), vec![], None);

        let msg_val_factory = mock_message_validator_factory(false, false, false);
        let proposal_validator = ProposalValidatorImpl::new(msg_val_factory, config.clone());

        let result = proposal_validator.validate_payload_and_block(&proposal_to_validate, &context);
        
        assert!(matches!(result, Err(QbftError::ProposalRoundMismatch)));
    }

    #[test]
    fn test_validate_payload_and_block_invalid_parent_hash() {
        let config = default_config();
        let codec = testing_extradata_codec();

        let proposer_key = create_node_key();
        let proposer_address = address_from_key(&proposer_key);
        
        let validators: HashSet<Address> = vec![proposer_address].into_iter().collect();
        let validators_vec: Vec<Address> = validators.iter().cloned().collect();

        let parent_sequence: u64 = 0;
        let parent_gas_limit: u64 = 30_000_000;
        let parent_timestamp: u64 = 1_000_000;
        
        // Correct parent header for the context
        let correct_parent_h = default_parent_header(parent_sequence, B256::ZERO, parent_timestamp, parent_gas_limit);
        // Incorrect parent hash for the block
        let incorrect_parent_hash = B256::from_slice(&[0xAA; 32]);

        let current_sequence = parent_sequence + 1;
        let current_round = 0;

        let final_state_for_context = default_final_state(Arc::new(proposer_key.clone()), validators.clone());

        let context = default_validation_context(
            current_sequence,
            current_round,
            validators.clone(),
            correct_parent_h.clone(), // Context uses the correct parent header
            proposer_address,
            config.clone(),
            codec.clone(),
            Some(final_state_for_context.clone()),
            Arc::new(proposer_key.clone()),
        );

        let proposed_block = default_qbft_block(
            incorrect_parent_hash, // Block created with an incorrect parent hash
            current_sequence,
            current_round,
            parent_timestamp + 1,
            parent_gas_limit,
            proposer_address,
            codec.clone(),
            validators_vec.clone(),
        );

        let proposal_round_id = ConsensusRoundIdentifier {
            sequence_number: current_sequence,
            round_number: current_round,
        };
        let proposal_payload = create_proposal_payload(proposal_round_id, proposed_block.clone());
        let signed_payload = create_signed_proposal_payload(proposal_payload, &proposer_key);
        let bft_message = create_bft_message_proposal(signed_payload);
        
        let proposal_to_validate = create_proposal(bft_message, proposed_block.header.clone(), vec![], None);

        let msg_val_factory = mock_message_validator_factory(false, false, false);
        let proposal_validator = ProposalValidatorImpl::new(msg_val_factory, config.clone());

        let result = proposal_validator.validate_payload_and_block(&proposal_to_validate, &context);
        
        assert!(matches!(result, Err(QbftError::ProposalInvalidParentHash)));
    }

    #[test]
    fn test_validate_payload_and_block_invalid_block_number() {
        let config = default_config();
        let codec = testing_extradata_codec();

        let proposer_key = create_node_key();
        let proposer_address = address_from_key(&proposer_key);
        
        let validators: HashSet<Address> = vec![proposer_address].into_iter().collect();
        let validators_vec: Vec<Address> = validators.iter().cloned().collect();

        let parent_sequence: u64 = 0;
        let parent_gas_limit: u64 = 30_000_000;
        let parent_timestamp: u64 = 1_000_000;
        let parent_h = default_parent_header(parent_sequence, B256::ZERO, parent_timestamp, parent_gas_limit);

        let context_sequence = parent_sequence + 1;
        let block_number_for_proposal = context_sequence + 1; // Mismatched block number
        let current_round = 0;

        let final_state_for_context = default_final_state(Arc::new(proposer_key.clone()), validators.clone());

        let context = default_validation_context(
            context_sequence, // Context expects this sequence
            current_round,
            validators.clone(),
            parent_h.clone(),
            proposer_address,
            config.clone(),
            codec.clone(),
            Some(final_state_for_context.clone()),
            Arc::new(proposer_key.clone()),
        );

        let proposed_block = default_qbft_block(
            parent_h.hash(),
            block_number_for_proposal, // Block created with a mismatched number
            current_round,
            parent_timestamp + 1,
            parent_gas_limit,
            proposer_address,
            codec.clone(),
            validators_vec.clone(),
        );

        let proposal_round_id = ConsensusRoundIdentifier {
            sequence_number: context_sequence, // Proposal payload still for context's sequence for this test focus
            round_number: current_round,
        };
        let proposal_payload = create_proposal_payload(proposal_round_id, proposed_block.clone());
        let signed_payload = create_signed_proposal_payload(proposal_payload, &proposer_key);
        let bft_message = create_bft_message_proposal(signed_payload);
        
        let proposal_to_validate = create_proposal(bft_message, proposed_block.header.clone(), vec![], None);

        let msg_val_factory = mock_message_validator_factory(false, false, false);
        let proposal_validator = ProposalValidatorImpl::new(msg_val_factory, config.clone());

        let result = proposal_validator.validate_payload_and_block(&proposal_to_validate, &context);
        
        assert!(matches!(result, Err(QbftError::ProposalInvalidBlockNumber)));
    }

    #[test]
    fn test_validate_payload_and_block_invalid_timestamp_not_after_parent() {
        let config = default_config();
        let codec = testing_extradata_codec();

        let proposer_key = create_node_key();
        let proposer_address = address_from_key(&proposer_key);
        
        let validators: HashSet<Address> = vec![proposer_address].into_iter().collect();
        let validators_vec: Vec<Address> = validators.iter().cloned().collect();

        let parent_sequence: u64 = 0;
        let parent_gas_limit: u64 = 30_000_000;
        let parent_timestamp: u64 = 1_000_000;
        let parent_h = default_parent_header(parent_sequence, B256::ZERO, parent_timestamp, parent_gas_limit);

        let current_sequence = parent_sequence + 1;
        let current_round = 0;

        let final_state_for_context = default_final_state(Arc::new(proposer_key.clone()), validators.clone());

        let context = default_validation_context(
            current_sequence,
            current_round,
            validators.clone(),
            parent_h.clone(),
            proposer_address,
            config.clone(),
            codec.clone(),
            Some(final_state_for_context.clone()),
            Arc::new(proposer_key.clone()),
        );

        let proposed_block = default_qbft_block(
            parent_h.hash(),
            current_sequence,
            current_round,
            parent_timestamp, // Timestamp same as parent's, which is invalid
            parent_gas_limit,
            proposer_address,
            codec.clone(),
            validators_vec.clone(),
        );

        let proposal_round_id = ConsensusRoundIdentifier {
            sequence_number: current_sequence,
            round_number: current_round,
        };
        let proposal_payload = create_proposal_payload(proposal_round_id, proposed_block.clone());
        let signed_payload = create_signed_proposal_payload(proposal_payload, &proposer_key);
        let bft_message = create_bft_message_proposal(signed_payload);
        
        let proposal_to_validate = create_proposal(bft_message, proposed_block.header.clone(), vec![], None);

        let msg_val_factory = mock_message_validator_factory(false, false, false);
        let proposal_validator = ProposalValidatorImpl::new(msg_val_factory, config.clone());

        let result = proposal_validator.validate_payload_and_block(&proposal_to_validate, &context);
        
        assert!(matches!(result, Err(QbftError::ValidationError(s)) if s == "Block timestamp not after parent"));
    }

    #[test]
    fn test_validate_payload_and_block_extradata_round_mismatch() {
        let config = default_config();
        let codec = testing_extradata_codec();

        let proposer_key = create_node_key();
        let proposer_address = address_from_key(&proposer_key);
        
        let validators: HashSet<Address> = vec![proposer_address].into_iter().collect();
        let validators_vec: Vec<Address> = validators.iter().cloned().collect();

        let parent_sequence: u64 = 0;
        let parent_gas_limit: u64 = 30_000_000;
        let parent_timestamp: u64 = 1_000_000;
        let parent_h = default_parent_header(parent_sequence, B256::ZERO, parent_timestamp, parent_gas_limit);

        let current_sequence = parent_sequence + 1;
        let context_current_round = 0;
        let extradata_round = context_current_round + 1; // Mismatched round in extra data

        let final_state_for_context = default_final_state(Arc::new(proposer_key.clone()), validators.clone());

        let context = default_validation_context(
            current_sequence,
            context_current_round, // Context expects round 0
            validators.clone(),
            parent_h.clone(),
            proposer_address,
            config.clone(),
            codec.clone(),
            Some(final_state_for_context.clone()),
            Arc::new(proposer_key.clone()),
        );

        // Block's extra data will have round `extradata_round` (i.e., 1)
        let proposed_block = default_qbft_block(
            parent_h.hash(),
            current_sequence,
            extradata_round, // This round is for BftExtraData within the block
            parent_timestamp + 1,
            parent_gas_limit,
            proposer_address,
            codec.clone(),
            validators_vec.clone(),
        );

        // Proposal payload round matches context, but block's internal extra data round does not.
        let proposal_round_id = ConsensusRoundIdentifier {
            sequence_number: current_sequence,
            round_number: context_current_round, 
        };
        let proposal_payload = create_proposal_payload(proposal_round_id, proposed_block.clone());
        let signed_payload = create_signed_proposal_payload(proposal_payload, &proposer_key);
        let bft_message = create_bft_message_proposal(signed_payload);
        
        let proposal_to_validate = create_proposal(bft_message, proposed_block.header.clone(), vec![], None);

        let msg_val_factory = mock_message_validator_factory(false, false, false);
        let proposal_validator = ProposalValidatorImpl::new(msg_val_factory, config.clone());

        let result = proposal_validator.validate_payload_and_block(&proposal_to_validate, &context);
        
        assert!(matches!(result, Err(QbftError::ValidationError(s)) if s == "Round in block extra_data mismatch"));
    }

    #[test]
    fn test_validate_payload_and_block_extradata_validators_mismatch() {
        let config = default_config();
        let codec = testing_extradata_codec();

        let proposer_key = create_node_key();
        let proposer_address = address_from_key(&proposer_key);
        
        let validator2_key = create_node_key(); // Another key for a different validator
        let validator2_address = address_from_key(&validator2_key);

        let context_validators_set: HashSet<Address> = vec![proposer_address, validator2_address].into_iter().collect();
        // Validators for the block's extra data will be different
        let block_extradata_validators_vec: Vec<Address> = vec![proposer_address]; // Only proposer

        let parent_sequence: u64 = 0;
        let parent_gas_limit: u64 = 30_000_000;
        let parent_timestamp: u64 = 1_000_000;
        let parent_h = default_parent_header(parent_sequence, B256::ZERO, parent_timestamp, parent_gas_limit);

        let current_sequence = parent_sequence + 1;
        let current_round = 0;

        let final_state_for_context = default_final_state(Arc::new(proposer_key.clone()), context_validators_set.clone());

        let context = default_validation_context(
            current_sequence,
            current_round,
            context_validators_set.clone(), // Context expects these validators
            parent_h.clone(),
            proposer_address,
            config.clone(),
            codec.clone(),
            Some(final_state_for_context.clone()),
            Arc::new(proposer_key.clone()),
        );

        // Block's extra data will have a different validator set
        let proposed_block = default_qbft_block(
            parent_h.hash(),
            current_sequence,
            current_round, 
            parent_timestamp + 1,
            parent_gas_limit,
            proposer_address,
            codec.clone(),
            block_extradata_validators_vec.clone(), // Different validator set for extra_data
        );

        let proposal_round_id = ConsensusRoundIdentifier {
            sequence_number: current_sequence,
            round_number: current_round, 
        };
        let proposal_payload = create_proposal_payload(proposal_round_id, proposed_block.clone());
        let signed_payload = create_signed_proposal_payload(proposal_payload, &proposer_key);
        let bft_message = create_bft_message_proposal(signed_payload);
        
        let proposal_to_validate = create_proposal(bft_message, proposed_block.header.clone(), vec![], None);

        let msg_val_factory = mock_message_validator_factory(false, false, false);
        let proposal_validator = ProposalValidatorImpl::new(msg_val_factory, config.clone());

        let result = proposal_validator.validate_payload_and_block(&proposal_to_validate, &context);
        
        assert!(matches!(result, Err(QbftError::ValidationError(s)) if s == "Validators in extra_data mismatch with context"));
    }

    #[test]
    fn test_validate_payload_and_block_invalid_difficulty() {
        let config = default_config();
        let codec = testing_extradata_codec();

        let proposer_key = create_node_key();
        let proposer_address = address_from_key(&proposer_key);
        
        let validators: HashSet<Address> = vec![proposer_address].into_iter().collect();
        let validators_vec: Vec<Address> = validators.iter().cloned().collect();

        let parent_sequence: u64 = 0;
        let parent_gas_limit: u64 = 30_000_000;
        let parent_timestamp: u64 = 1_000_000;
        let parent_h = default_parent_header(parent_sequence, B256::ZERO, parent_timestamp, parent_gas_limit);

        let current_sequence = parent_sequence + 1;
        let current_round = 0;

        let final_state_for_context = default_final_state(Arc::new(proposer_key.clone()), validators.clone());

        let context = default_validation_context(
            current_sequence,
            current_round,
            validators.clone(),
            parent_h.clone(),
            proposer_address,
            config.clone(),
            codec.clone(),
            Some(final_state_for_context.clone()),
            Arc::new(proposer_key.clone()),
        );

        // Create a block with invalid difficulty (e.g., 2 instead of 1)
        let mut proposed_block = default_qbft_block(
            parent_h.hash(),
            current_sequence,
            current_round,
            parent_timestamp + 1,
            parent_gas_limit,
            proposer_address,
            codec.clone(),
            validators_vec.clone(),
        );
        proposed_block.header.difficulty = U256::from(2); // Invalid difficulty

        let proposal_round_id = ConsensusRoundIdentifier {
            sequence_number: current_sequence,
            round_number: current_round,
        };
        let proposal_payload = create_proposal_payload(proposal_round_id, proposed_block.clone());
        let signed_payload = create_signed_proposal_payload(proposal_payload, &proposer_key);
        let bft_message = create_bft_message_proposal(signed_payload);
        
        let proposal_to_validate = create_proposal(bft_message, proposed_block.header.clone(), vec![], None);

        let msg_val_factory = mock_message_validator_factory(false, false, false);
        let proposal_validator = ProposalValidatorImpl::new(msg_val_factory, config.clone());

        let result = proposal_validator.validate_payload_and_block(&proposal_to_validate, &context);
        
        assert!(matches!(result, Err(QbftError::ValidationError(s)) if s == "Block difficulty not 1"));
    }

    #[test]
    fn test_validate_payload_and_block_invalid_nonce() {
        let config = default_config();
        let codec = testing_extradata_codec();

        let proposer_key = create_node_key();
        let proposer_address = address_from_key(&proposer_key);
        
        let validators: HashSet<Address> = vec![proposer_address].into_iter().collect();
        let validators_vec: Vec<Address> = validators.iter().cloned().collect();

        let parent_sequence: u64 = 0;
        let parent_gas_limit: u64 = 30_000_000;
        let parent_timestamp: u64 = 1_000_000;
        let parent_h = default_parent_header(parent_sequence, B256::ZERO, parent_timestamp, parent_gas_limit);

        let current_sequence = parent_sequence + 1;
        let current_round = 0;

        let final_state_for_context = default_final_state(Arc::new(proposer_key.clone()), validators.clone());

        let context = default_validation_context(
            current_sequence,
            current_round,
            validators.clone(),
            parent_h.clone(),
            proposer_address,
            config.clone(),
            codec.clone(),
            Some(final_state_for_context.clone()),
            Arc::new(proposer_key.clone()),
        );

        // Base proposed_block using default_qbft_block (which has a valid 8-byte zero nonce initially)
        let mut proposed_block = default_qbft_block(
            parent_h.hash(),
            current_sequence,
            current_round,
            parent_timestamp + 1,
            parent_gas_limit,
            proposer_address,
            codec.clone(),
            validators_vec.clone(),
        );

        let proposal_round_id = ConsensusRoundIdentifier {
            sequence_number: current_sequence,
            round_number: current_round,
        };

        let msg_val_factory = mock_message_validator_factory(false, false, false);
        let proposal_validator = ProposalValidatorImpl::new(msg_val_factory, config.clone());

        // Test Case 1: Nonce is Bytes::new() (empty) - THIS IS INVALID
        proposed_block.header.nonce = Bytes::new(); // Set invalid nonce
        let proposal_payload_1 = create_proposal_payload(proposal_round_id, proposed_block.clone());
        let signed_payload_1 = create_signed_proposal_payload(proposal_payload_1, &proposer_key);
        let bft_message_1 = create_bft_message_proposal(signed_payload_1);
        let proposal_to_validate_1 = create_proposal(bft_message_1, proposed_block.header.clone(), vec![], None);
        let result_1 = proposal_validator.validate_payload_and_block(&proposal_to_validate_1, &context);
        assert!(matches!(result_1, Err(QbftError::ValidationError(s)) if s == "Block nonce not 0"));

        // Test Case 2: Nonce is Bytes::from_static(&[0x00]) (single zero byte) - THIS IS INVALID
        proposed_block.header.nonce = Bytes::from_static(&[0x00]);
        let proposal_payload_2 = create_proposal_payload(proposal_round_id, proposed_block.clone());
        let signed_payload_2 = create_signed_proposal_payload(proposal_payload_2, &proposer_key);
        let bft_message_2 = create_bft_message_proposal(signed_payload_2);
        let proposal_to_validate_2 = create_proposal(bft_message_2, proposed_block.header.clone(), vec![], None);
        let result_2 = proposal_validator.validate_payload_and_block(&proposal_to_validate_2, &context);
        assert!(matches!(result_2, Err(QbftError::ValidationError(s)) if s == "Block nonce not 0"));

        // Test Case 3: Nonce is Bytes::from_static(&[0x80]) (RLP encoding of 0, but not 8 bytes) - THIS IS INVALID
        proposed_block.header.nonce = Bytes::from_static(&[0x80]);
        let proposal_payload_3 = create_proposal_payload(proposal_round_id, proposed_block.clone());
        let signed_payload_3 = create_signed_proposal_payload(proposal_payload_3, &proposer_key);
        let bft_message_3 = create_bft_message_proposal(signed_payload_3);
        let proposal_to_validate_3 = create_proposal(bft_message_3, proposed_block.header.clone(), vec![], None);
        let result_3 = proposal_validator.validate_payload_and_block(&proposal_to_validate_3, &context);
        assert!(matches!(result_3, Err(QbftError::ValidationError(s)) if s == "Block nonce not 0"));
    }

    #[test]
    fn test_validate_payload_and_block_gas_limit_too_high() {
        let mut config = QbftConfig::default();
        config.gas_limit_bound_divisor = 1024; // Standard divisor
        let arc_config = Arc::new(config);
        let codec = testing_extradata_codec();

        let proposer_key = create_node_key();
        let proposer_address = address_from_key(&proposer_key);
        
        let validators: HashSet<Address> = vec![proposer_address].into_iter().collect();
        let validators_vec: Vec<Address> = validators.iter().cloned().collect();

        let parent_sequence: u64 = 0;
        let parent_gas_limit: u64 = 30_000_000;
        let parent_timestamp: u64 = 1_000_000;
        let parent_h = default_parent_header(parent_sequence, B256::ZERO, parent_timestamp, parent_gas_limit);

        let current_sequence = parent_sequence + 1;
        let current_round = 0;

        let final_state_for_context = default_final_state(Arc::new(proposer_key.clone()), validators.clone());

        let context = default_validation_context(
            current_sequence,
            current_round,
            validators.clone(),
            parent_h.clone(),
            proposer_address,
            arc_config.clone(), // Use the configured QbftConfig
            codec.clone(),
            Some(final_state_for_context.clone()),
            Arc::new(proposer_key.clone()),
        );

        let max_delta = parent_gas_limit / arc_config.gas_limit_bound_divisor;
        let invalid_high_gas_limit = parent_gas_limit + max_delta + 1;

        let proposed_block = default_qbft_block(
            parent_h.hash(),
            current_sequence,
            current_round,
            parent_timestamp + 1,
            invalid_high_gas_limit, // Gas limit too high
            proposer_address,
            codec.clone(),
            validators_vec.clone(),
        );

        let proposal_round_id = ConsensusRoundIdentifier {
            sequence_number: current_sequence,
            round_number: current_round,
        };
        let proposal_payload = create_proposal_payload(proposal_round_id, proposed_block.clone());
        let signed_payload = create_signed_proposal_payload(proposal_payload, &proposer_key);
        let bft_message = create_bft_message_proposal(signed_payload);
        
        let proposal_to_validate = create_proposal(bft_message, proposed_block.header.clone(), vec![], None);

        let msg_val_factory = mock_message_validator_factory(false, false, false);
        let proposal_validator = ProposalValidatorImpl::new(msg_val_factory, arc_config.clone());

        let result = proposal_validator.validate_payload_and_block(&proposal_to_validate, &context);
        
        assert!(matches!(result, Err(QbftError::ValidationError(s)) if s == "Gas limit outside allowed delta of parent"));
    }

    #[test]
    fn test_validate_payload_and_block_gas_limit_too_low_outside_delta() {
        let mut config = QbftConfig::default();
        config.gas_limit_bound_divisor = 1024;
        config.min_gas_limit = 5000; // Ensure min_gas_limit is set for the test
        let arc_config = Arc::new(config);
        let codec = testing_extradata_codec();

        let proposer_key = create_node_key();
        let proposer_address = address_from_key(&proposer_key);
        
        let validators: HashSet<Address> = vec![proposer_address].into_iter().collect();
        let validators_vec: Vec<Address> = validators.iter().cloned().collect();

        let parent_sequence: u64 = 0;
        let parent_gas_limit: u64 = 30_000_000;
        let parent_timestamp: u64 = 1_000_000;
        // Ensure parent_h is created with a gas limit that allows for a valid lower bound > min_gas_limit
        let parent_h = default_parent_header(parent_sequence, B256::ZERO, parent_timestamp, parent_gas_limit);

        let current_sequence = parent_sequence + 1;
        let current_round = 0;

        let final_state_for_context = default_final_state(Arc::new(proposer_key.clone()), validators.clone());

        let context = default_validation_context(
            current_sequence,
            current_round,
            validators.clone(),
            parent_h.clone(),
            proposer_address,
            arc_config.clone(),
            codec.clone(),
            Some(final_state_for_context.clone()),
            Arc::new(proposer_key.clone()),
        );

        let max_delta = parent_gas_limit / arc_config.gas_limit_bound_divisor;
        // Make sure (parent_gas_limit - max_delta - 1) is still >= min_gas_limit for this specific test
        // If parent_gas_limit is 30M, max_delta is ~29k. So parent_gas_limit - max_delta is very high.
        let invalid_low_gas_limit = parent_gas_limit.saturating_sub(max_delta).saturating_sub(1);
        
        // Ensure the invalid_low_gas_limit is actually above min_gas_limit to isolate the delta error
        assert!(invalid_low_gas_limit >= arc_config.min_gas_limit, "Test setup error: invalid_low_gas_limit should be >= min_gas_limit for this test case");

        let proposed_block = default_qbft_block(
            parent_h.hash(),
            current_sequence,
            current_round,
            parent_timestamp + 1,
            invalid_low_gas_limit, // Gas limit too low (outside delta but above min)
            proposer_address,
            codec.clone(),
            validators_vec.clone(),
        );

        let proposal_round_id = ConsensusRoundIdentifier {
            sequence_number: current_sequence,
            round_number: current_round,
        };
        let proposal_payload = create_proposal_payload(proposal_round_id, proposed_block.clone());
        let signed_payload = create_signed_proposal_payload(proposal_payload, &proposer_key);
        let bft_message = create_bft_message_proposal(signed_payload);
        
        let proposal_to_validate = create_proposal(bft_message, proposed_block.header.clone(), vec![], None);

        let msg_val_factory = mock_message_validator_factory(false, false, false);
        let proposal_validator = ProposalValidatorImpl::new(msg_val_factory, arc_config.clone());

        let result = proposal_validator.validate_payload_and_block(&proposal_to_validate, &context);
        
        assert!(matches!(result, Err(QbftError::ValidationError(s)) if s == "Gas limit outside allowed delta of parent"));
    }

    #[test]
    fn test_validate_payload_and_block_gas_limit_below_minimum() {
        let mut config = QbftConfig::default();
        config.min_gas_limit = 5000;
        // Ensure gas_limit_bound_divisor allows the parent_gas_limit to be valid, 
        // but we will set the block's gas limit below min_gas_limit.
        config.gas_limit_bound_divisor = 1024; 
        let arc_config = Arc::new(config);
        let codec = testing_extradata_codec();

        let proposer_key = create_node_key();
        let proposer_address = address_from_key(&proposer_key);
        
        let validators: HashSet<Address> = vec![proposer_address].into_iter().collect();
        let validators_vec: Vec<Address> = validators.iter().cloned().collect();

        let parent_sequence: u64 = 0;
        // Parent gas limit should be high enough such that parent_gas_limit - delta is still above min_gas_limit,
        // so that the min_gas_limit check is the one that primarily fails.
        let parent_gas_limit: u64 = arc_config.min_gas_limit * 2; // e.g., 10000, if min_gas_limit is 5000
        let parent_timestamp: u64 = 1_000_000;
        let parent_h = default_parent_header(parent_sequence, B256::ZERO, parent_timestamp, parent_gas_limit);

        let current_sequence = parent_sequence + 1;
        let current_round = 0;

        let final_state_for_context = default_final_state(Arc::new(proposer_key.clone()), validators.clone());

        let context = default_validation_context(
            current_sequence,
            current_round,
            validators.clone(),
            parent_h.clone(),
            proposer_address,
            arc_config.clone(),
            codec.clone(),
            Some(final_state_for_context.clone()),
            Arc::new(proposer_key.clone()),
        );

        let invalid_low_gas_limit = arc_config.min_gas_limit - 1; // e.g. 4999

        let proposed_block = default_qbft_block(
            parent_h.hash(),
            current_sequence,
            current_round,
            parent_timestamp + 1,
            invalid_low_gas_limit, // Gas limit below minimum
            proposer_address,
            codec.clone(),
            validators_vec.clone(),
        );

        let proposal_round_id = ConsensusRoundIdentifier {
            sequence_number: current_sequence,
            round_number: current_round,
        };
        let proposal_payload = create_proposal_payload(proposal_round_id, proposed_block.clone());
        let signed_payload = create_signed_proposal_payload(proposal_payload, &proposer_key);
        let bft_message = create_bft_message_proposal(signed_payload);
        
        let proposal_to_validate = create_proposal(bft_message, proposed_block.header.clone(), vec![], None);

        let msg_val_factory = mock_message_validator_factory(false, false, false);
        let proposal_validator = ProposalValidatorImpl::new(msg_val_factory, arc_config.clone());

        let result = proposal_validator.validate_payload_and_block(&proposal_to_validate, &context);
        
        let expected_error_msg = format!("Gas limit {} below minimum {}", invalid_low_gas_limit, arc_config.min_gas_limit);
        assert!(matches!(result, Err(QbftError::ValidationError(s)) if s == expected_error_msg));
    }

    #[test]
    fn test_validate_payload_and_block_gas_used_exceeds_gas_limit() {
        let config = default_config(); // Standard config is fine for this test
        let codec = testing_extradata_codec();

        let proposer_key = create_node_key();
        let proposer_address = address_from_key(&proposer_key);
        
        let validators: HashSet<Address> = vec![proposer_address].into_iter().collect();
        let validators_vec: Vec<Address> = validators.iter().cloned().collect();

        let parent_sequence: u64 = 0;
        let parent_gas_limit: u64 = 30_000_000;
        let parent_timestamp: u64 = 1_000_000;
        let parent_h = default_parent_header(parent_sequence, B256::ZERO, parent_timestamp, parent_gas_limit);

        let current_sequence = parent_sequence + 1;
        let current_round = 0;

        let final_state_for_context = default_final_state(Arc::new(proposer_key.clone()), validators.clone());

        let context = default_validation_context(
            current_sequence,
            current_round,
            validators.clone(),
            parent_h.clone(),
            proposer_address,
            config.clone(),
            codec.clone(),
            Some(final_state_for_context.clone()),
            Arc::new(proposer_key.clone()),
        );

        let block_gas_limit = parent_gas_limit; // A valid gas limit
        let invalid_gas_used = block_gas_limit + 1; // gas_used exceeds gas_limit

        let mut proposed_block = default_qbft_block(
            parent_h.hash(),
            current_sequence,
            current_round,
            parent_timestamp + 1,
            block_gas_limit, 
            proposer_address,
            codec.clone(),
            validators_vec.clone(),
        );
        proposed_block.header.gas_used = invalid_gas_used; // Set invalid gas_used

        let proposal_round_id = ConsensusRoundIdentifier {
            sequence_number: current_sequence,
            round_number: current_round,
        };
        let proposal_payload = create_proposal_payload(proposal_round_id, proposed_block.clone());
        let signed_payload = create_signed_proposal_payload(proposal_payload, &proposer_key);
        let bft_message = create_bft_message_proposal(signed_payload);
        
        let proposal_to_validate = create_proposal(bft_message, proposed_block.header.clone(), vec![], None);

        let msg_val_factory = mock_message_validator_factory(false, false, false);
        let proposal_validator = ProposalValidatorImpl::new(msg_val_factory, config.clone());

        let result = proposal_validator.validate_payload_and_block(&proposal_to_validate, &context);
        
        assert!(matches!(result, Err(QbftError::ValidationError(s)) if s == "Block gas_used exceeds gas_limit"));
    }

    #[test]
    fn test_validate_block_coinbase_matches_author_valid() {
        let config = default_config();
        let codec = testing_extradata_codec();

        let proposer_key = create_node_key();
        let proposer_address = address_from_key(&proposer_key);
        
        let validators: HashSet<Address> = vec![proposer_address].into_iter().collect();
        let validators_vec: Vec<Address> = validators.iter().cloned().collect();

        let parent_sequence: u64 = 0;
        let parent_gas_limit: u64 = 30_000_000;
        let parent_timestamp: u64 = 1_000_000;
        let parent_h = default_parent_header(parent_sequence, B256::ZERO, parent_timestamp, parent_gas_limit);

        let current_sequence = parent_sequence + 1;
        let current_round = 0;

        let final_state_for_context = default_final_state(Arc::new(proposer_key.clone()), validators.clone());

        let context = default_validation_context(
            current_sequence,
            current_round,
            validators.clone(),
            parent_h.clone(),
            proposer_address, // Expected proposer
            config.clone(),
            codec.clone(),
            Some(final_state_for_context.clone()),
            Arc::new(proposer_key.clone()),
        );

        // Block beneficiary IS the proposer_address
        let proposed_block = default_qbft_block(
            parent_h.hash(),
            current_sequence,
            current_round,
            parent_timestamp + 1,
            parent_gas_limit,
            proposer_address, // Beneficiary matches proposer
            codec.clone(),
            validators_vec.clone(),
        );

        let proposal_round_id = ConsensusRoundIdentifier {
            sequence_number: current_sequence,
            round_number: current_round,
        };
        let proposal_payload = create_proposal_payload(proposal_round_id, proposed_block.clone());
        let signed_payload = create_signed_proposal_payload(proposal_payload, &proposer_key);
        let bft_message = create_bft_message_proposal(signed_payload);
        let proposal_to_validate = create_proposal(bft_message, proposed_block.header.clone(), vec![], None);

        let msg_val_factory = mock_message_validator_factory(false, false, false);
        let proposal_validator = ProposalValidatorImpl::new(msg_val_factory, config.clone());

        let result = proposal_validator.validate_block_coinbase_matches_author(&proposal_to_validate, &context);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_block_coinbase_matches_author_invalid() {
        let config = default_config();
        let codec = testing_extradata_codec();

        let proposer_key = create_node_key();
        let proposer_address = address_from_key(&proposer_key);

        let other_address = address_from_key(&create_node_key()); // A different address for beneficiary
        
        let validators: HashSet<Address> = vec![proposer_address].into_iter().collect();
        let validators_vec: Vec<Address> = validators.iter().cloned().collect();

        let parent_sequence: u64 = 0;
        let parent_gas_limit: u64 = 30_000_000;
        let parent_timestamp: u64 = 1_000_000;
        let parent_h = default_parent_header(parent_sequence, B256::ZERO, parent_timestamp, parent_gas_limit);

        let current_sequence = parent_sequence + 1;
        let current_round = 0;

        let final_state_for_context = default_final_state(Arc::new(proposer_key.clone()), validators.clone());

        let context = default_validation_context(
            current_sequence,
            current_round,
            validators.clone(),
            parent_h.clone(),
            proposer_address, // Expected proposer
            config.clone(),
            codec.clone(),
            Some(final_state_for_context.clone()),
            Arc::new(proposer_key.clone()),
        );

        // Block beneficiary is a DIFFERENT address
        let proposed_block = default_qbft_block(
            parent_h.hash(),
            current_sequence,
            current_round,
            parent_timestamp + 1,
            parent_gas_limit,
            other_address, // Beneficiary MISMATCH
            codec.clone(),
            validators_vec.clone(),
        );

        let proposal_round_id = ConsensusRoundIdentifier {
            sequence_number: current_sequence,
            round_number: current_round,
        };
        let proposal_payload = create_proposal_payload(proposal_round_id, proposed_block.clone());
        let signed_payload = create_signed_proposal_payload(proposal_payload, &proposer_key);
        let bft_message = create_bft_message_proposal(signed_payload);
        let proposal_to_validate = create_proposal(bft_message, proposed_block.header.clone(), vec![], None);

        let msg_val_factory = mock_message_validator_factory(false, false, false);
        let proposal_validator = ProposalValidatorImpl::new(msg_val_factory, config.clone());

        let result = proposal_validator.validate_block_coinbase_matches_author(&proposal_to_validate, &context);
        assert!(matches!(result, Err(QbftError::ValidationError(s)) if s == "Block beneficiary does not match proposer"));
    }

    #[test]
    fn test_validate_round_zero_conditions_valid() {
        let config = default_config();
        let codec = testing_extradata_codec();

        let proposer_key = create_node_key();
        let proposer_address = address_from_key(&proposer_key);
        
        let validators: HashSet<Address> = vec![proposer_address].into_iter().collect();
        let validators_vec: Vec<Address> = validators.iter().cloned().collect();

        let parent_sequence: u64 = 0;
        let parent_gas_limit: u64 = 30_000_000;
        let parent_timestamp: u64 = 1_000_000;
        let parent_h = default_parent_header(parent_sequence, B256::ZERO, parent_timestamp, parent_gas_limit);

        let current_sequence = parent_sequence + 1;
        let current_round = 0; // Round 0 for this test

        let final_state_for_context = default_final_state(Arc::new(proposer_key.clone()), validators.clone());

        let context = default_validation_context(
            current_sequence,
            current_round,
            validators.clone(),
            parent_h.clone(),
            proposer_address,
            config.clone(),
            codec.clone(),
            Some(final_state_for_context.clone()),
            Arc::new(proposer_key.clone()),
        );

        let proposed_block = default_qbft_block(
            parent_h.hash(),
            current_sequence,
            current_round,
            parent_timestamp + 1,
            parent_gas_limit,
            proposer_address, 
            codec.clone(),
            validators_vec.clone(),
        );

        let proposal_round_id = ConsensusRoundIdentifier {
            sequence_number: current_sequence,
            round_number: current_round,
        };
        let proposal_payload = create_proposal_payload(proposal_round_id, proposed_block.clone());
        let signed_payload = create_signed_proposal_payload(proposal_payload, &proposer_key);
        let bft_message = create_bft_message_proposal(signed_payload);
        
        // Valid for round 0: empty rc_proofs and no prepared_certificate
        let proposal_to_validate = create_proposal(bft_message, proposed_block.header.clone(), vec![], None);

        let msg_val_factory = mock_message_validator_factory(false, false, false);
        let proposal_validator = ProposalValidatorImpl::new(msg_val_factory, config.clone());

        let result = proposal_validator.validate_round_zero_conditions(&proposal_to_validate, &context);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_round_zero_conditions_invalid_has_rc_proofs() {
        let config = default_config();
        let codec = testing_extradata_codec();

        let proposer_key = create_node_key();
        let proposer_address = address_from_key(&proposer_key);
        
        let validators: HashSet<Address> = vec![proposer_address].into_iter().collect();
        let validators_vec: Vec<Address> = validators.iter().cloned().collect();

        let parent_sequence: u64 = 0;
        let parent_gas_limit: u64 = 30_000_000;
        let parent_timestamp: u64 = 1_000_000;
        let parent_h = default_parent_header(parent_sequence, B256::ZERO, parent_timestamp, parent_gas_limit);

        let current_sequence = parent_sequence + 1;
        let current_round = 0; // Round 0

        let final_state_for_context = default_final_state(Arc::new(proposer_key.clone()), validators.clone());

        let context = default_validation_context(
            current_sequence,
            current_round,
            validators.clone(),
            parent_h.clone(),
            proposer_address,
            config.clone(),
            codec.clone(),
            Some(final_state_for_context.clone()),
            Arc::new(proposer_key.clone()),
        );

        let proposed_block = default_qbft_block(
            parent_h.hash(),
            current_sequence,
            current_round,
            parent_timestamp + 1,
            parent_gas_limit,
            proposer_address, 
            codec.clone(),
            validators_vec.clone(),
        );

        let proposal_round_id = ConsensusRoundIdentifier {
            sequence_number: current_sequence,
            round_number: current_round,
        };
        let proposal_payload = create_proposal_payload(proposal_round_id, proposed_block.clone());
        let signed_payload = create_signed_proposal_payload(proposal_payload, &proposer_key);
        let bft_message = create_bft_message_proposal(signed_payload);
        
        // Create a dummy RoundChange message to include
        let rc_key = create_node_key();
        // let rc_address = address_from_key(&rc_key);
        let rc_round_id = ConsensusRoundIdentifier { sequence_number: current_sequence, round_number: current_round };
        let rc_payload = crate::payload::RoundChangePayload::new(rc_round_id, None, None);
        let signed_rc_payload = SignedData::sign(rc_payload, &rc_key).expect("Failed to sign RC payload");
        // let bft_rc_message = BftMessage::new(signed_rc_payload.clone()); // Not needed directly for RoundChange::new
        let round_change_proof = RoundChange::new(signed_rc_payload, None, None).expect("Failed to create RoundChange proof for test");

        // Invalid for round 0: HAS round change proofs
        let proposal_to_validate = create_proposal(bft_message, proposed_block.header.clone(), vec![round_change_proof], None);

        let msg_val_factory = mock_message_validator_factory(false, false, false);
        let proposal_validator = ProposalValidatorImpl::new(msg_val_factory, config.clone());

        let result = proposal_validator.validate_round_zero_conditions(&proposal_to_validate, &context);
        assert!(matches!(result, Err(QbftError::ProposalHasRoundChangeForRoundZero)));
    }

    #[test]
    fn test_validate_round_zero_conditions_invalid_has_prepared_cert() {
        let config = default_config();
        let codec = testing_extradata_codec();

        let proposer_key = create_node_key();
        let proposer_address = address_from_key(&proposer_key);
        
        let validators: HashSet<Address> = vec![proposer_address].into_iter().collect();
        let validators_vec: Vec<Address> = validators.iter().cloned().collect();

        let parent_sequence: u64 = 0;
        let parent_gas_limit: u64 = 30_000_000;
        let parent_timestamp: u64 = 1_000_000;
        let parent_h = default_parent_header(parent_sequence, B256::ZERO, parent_timestamp, parent_gas_limit);

        let current_sequence = parent_sequence + 1;
        let current_round = 0; // Round 0

        let final_state_for_context = default_final_state(Arc::new(proposer_key.clone()), validators.clone());

        let context = default_validation_context(
            current_sequence,
            current_round,
            validators.clone(),
            parent_h.clone(),
            proposer_address,
            config.clone(),
            codec.clone(),
            Some(final_state_for_context.clone()),
            Arc::new(proposer_key.clone()),
        );

        let proposed_block = default_qbft_block(
            parent_h.hash(),
            current_sequence,
            current_round,
            parent_timestamp + 1,
            parent_gas_limit,
            proposer_address, 
            codec.clone(),
            validators_vec.clone(),
        );

        let proposal_round_id = ConsensusRoundIdentifier {
            sequence_number: current_sequence,
            round_number: current_round,
        };
        let proposal_payload = create_proposal_payload(proposal_round_id, proposed_block.clone());
        let signed_proposal_payload = create_signed_proposal_payload(proposal_payload.clone(), &proposer_key);
        let bft_proposal_message = create_bft_message_proposal(signed_proposal_payload);

        // Create a dummy PreparedCertificateWrapper
        // For simplicity, the inner proposal of the cert can be the same as the main one for this test.
        // We also need some dummy prepares.
        let prepare_key = create_node_key();
        let dummy_prepare_payload = crate::payload::PreparePayload::new(proposal_round_id, proposed_block.hash());
        let signed_dummy_prepare = SignedData::sign(dummy_prepare_payload, &prepare_key).unwrap();
        let dummy_prepare_msg = crate::messagewrappers::Prepare::new(signed_dummy_prepare);

        let prepared_certificate = PreparedCertificateWrapper {
            proposal_message: bft_proposal_message.clone(), // Use the cloned bft_proposal_message
            prepares: vec![dummy_prepare_msg],
        };
        
        // Invalid for round 0: HAS a prepared certificate
        let proposal_to_validate = create_proposal(bft_proposal_message, proposed_block.header.clone(), vec![], Some(prepared_certificate));

        let msg_val_factory = mock_message_validator_factory(false, false, false);
        let proposal_validator = ProposalValidatorImpl::new(msg_val_factory, config.clone());

        let result = proposal_validator.validate_round_zero_conditions(&proposal_to_validate, &context);
        assert!(matches!(result, Err(QbftError::ProposalHasPreparedCertificateForRoundZero)));
    }

    #[test]
    fn test_validate_prepares_for_certificate_valid() {
        // --- Setup Common Config & Keys --- 
        let config = default_config();
        let codec = testing_extradata_codec();

        // We need multiple validators for a meaningful quorum
        let validator1_key = Arc::new(create_node_key());
        let validator1_address = address_from_key(&validator1_key);
        let validator2_key = Arc::new(create_node_key());
        let validator2_address = address_from_key(&validator2_key);
        let validator3_key = Arc::new(create_node_key());
        let validator3_address = address_from_key(&validator3_key);
        // Assuming N=3, F=1. Quorum for prepares = N-F = 2.

        let current_validators_set: HashSet<Address> = 
            vec![validator1_address, validator2_address, validator3_address].into_iter().collect();
        let current_validators_vec: Vec<Address> = current_validators_set.iter().cloned().collect();

        // --- Outer Context (for the main proposal that might carry this certificate) ---
        let outer_parent_sequence: u64 = 0;
        let outer_parent_gas_limit: u64 = 30_000_000;
        let outer_parent_timestamp: u64 = 1_000_000;
        let outer_parent_h = default_parent_header(outer_parent_sequence, B256::ZERO, outer_parent_timestamp, outer_parent_gas_limit);
        
        let outer_current_sequence = outer_parent_sequence + 1;
        let outer_current_round = 1; // A round > 0, where a cert might be relevant

        // Create a FinalState that knows about our validators for F calculation and get_proposer
        // AND the necessary parent header.
        let mut final_state_instance = MockQbftFinalState::new_with_f_override(
            validator1_key.clone(), // Arbitrary local key for mock final state
            current_validators_set.clone(),
            1, // Explicitly set F=1 for N=3
        );
        final_state_instance.add_known_header(outer_parent_h.clone()); // Added line
        let final_state_for_outer_context = Arc::new(final_state_instance); // Adjusted line

        // Proposer for the *outer* round (e.g. a Proposal carrying this cert)
        let outer_expected_proposer = final_state_for_outer_context.get_proposer_for_round(
            &ConsensusRoundIdentifier::new(outer_current_sequence, outer_current_round)
        ).unwrap();

        let outer_context = ValidationContext::new(
            outer_current_sequence,
            outer_current_round,
            current_validators_set.clone(),
            outer_parent_h.clone(),
            final_state_for_outer_context.clone(),
            codec.clone(),
            config.clone(),
            None, // outer_context.accepted_proposal_digest not strictly needed for this sub-validation
            outer_expected_proposer,
        );

        // --- Certificate's Inner Proposal Details ---
        // This proposal is what the prepares are for.
        // It should be for a round *before* outer_current_round, e.g., round 0 of the same sequence.
        let cert_proposal_sequence = outer_current_sequence;
        let cert_proposal_round = 0; 
        let cert_proposal_round_id = ConsensusRoundIdentifier::new(cert_proposal_sequence, cert_proposal_round);

        // Proposer for the certificate's proposal round.
        let cert_expected_proposer_key = validator1_key.clone(); // Let validator1 be proposer for cert's proposal
        let cert_expected_proposer_address = validator1_address;
        // Ensure final_state_for_outer_context returns this proposer for (cert_proposal_sequence, cert_proposal_round)
        // MockQbftFinalState needs to be flexible enough or we assume it does for this test setup.
        // For this test, we will pass this explicitly to Prepare's ValidationContext.

        let cert_block_beneficiary = cert_expected_proposer_address;
        let cert_block_timestamp = outer_parent_h.timestamp + 1; // After outer parent
        let cert_block_gas_limit = outer_parent_gas_limit;

        let cert_proposed_block = default_qbft_block(
            outer_parent_h.hash(), // Cert block is child of outer_parent_h
            cert_proposal_sequence,
            cert_proposal_round, // Round in extra data
            cert_block_timestamp,
            cert_block_gas_limit,
            cert_block_beneficiary,
            codec.clone(),
            current_validators_vec.clone(), // Validators in extra data
        );
        let cert_block_hash = cert_proposed_block.hash();

        let cert_proposal_payload = create_proposal_payload(cert_proposal_round_id, cert_proposed_block.clone());
        let cert_signed_proposal_payload = create_signed_proposal_payload(cert_proposal_payload, &cert_expected_proposer_key);
        let cert_bft_proposal_message = create_bft_message_proposal(cert_signed_proposal_payload);

        // --- Create Prepares for the Certificate --- (Need 2 for quorum)
        let mut prepares_for_cert: Vec<Prepare> = Vec::new();

        // Prepare from validator2
        let prepare_payload_v2 = crate::payload::PreparePayload::new(cert_proposal_round_id, cert_block_hash);
        let signed_prepare_v2 = SignedData::sign(prepare_payload_v2, &validator2_key).unwrap();
        prepares_for_cert.push(Prepare::new(signed_prepare_v2));

        // Prepare from validator3
        let prepare_payload_v3 = crate::payload::PreparePayload::new(cert_proposal_round_id, cert_block_hash);
        let signed_prepare_v3 = SignedData::sign(prepare_payload_v3, &validator3_key).unwrap();
        prepares_for_cert.push(Prepare::new(signed_prepare_v3));

        // --- Construct the PreparedCertificateWrapper ---
        let prepared_certificate_to_validate = PreparedCertificateWrapper {
            proposal_message: cert_bft_proposal_message.clone(),
            prepares: prepares_for_cert,
        };

        // --- Create ProposalValidator with a real PrepareValidator (via factory) ---
        // We need the PrepareValidator to actually work, not a mock one that always passes/fails.
        // So, we use the real MessageValidatorFactoryImpl.
        let real_msg_val_factory = Arc::new(crate::validation::MessageValidatorFactoryImpl::new(config.clone()));
        let proposal_validator = ProposalValidatorImpl::new(real_msg_val_factory, config.clone());

        // --- Perform Validation ---
        let result = proposal_validator.validate_prepares_for_certificate(
            &prepared_certificate_to_validate, 
            outer_current_sequence, // This param seems unused in current impl, outer_context is preferred
            &outer_context
        );
        
        if result.is_err() {
            dbg!(result.as_ref().err());
        }
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_prepares_for_certificate_duplicate_author() {
        let config = default_config();
        let codec = testing_extradata_codec();

        let validator1_key = Arc::new(create_node_key());
        let validator1_address = address_from_key(&validator1_key);
        let validator2_key = Arc::new(create_node_key()); // Used for the duplicate prepare
        let validator2_address = address_from_key(&validator2_key);
        let validator3_key = Arc::new(create_node_key());
        let validator3_address = address_from_key(&validator3_key);

        let current_validators_set: HashSet<Address> = 
            vec![validator1_address, validator2_address, validator3_address].into_iter().collect();
        let current_validators_vec: Vec<Address> = current_validators_set.iter().cloned().collect();

        let outer_parent_sequence: u64 = 0;
        let outer_parent_h = default_parent_header(outer_parent_sequence, B256::ZERO, 1_000_000, 30_000_000);
        let outer_current_sequence = outer_parent_sequence + 1;
        let outer_current_round = 1;

        let mut final_state_instance = MockQbftFinalState::new_with_f_override( // Made mutable
            validator1_key.clone(), current_validators_set.clone(), 1);
        final_state_instance.add_known_header(outer_parent_h.clone()); // Added: outer_parent_h is parent of cert_proposed_block
        let final_state_for_outer_context = Arc::new(final_state_instance); // Adjusted
        let outer_expected_proposer = final_state_for_outer_context.get_proposer_for_round(
            &ConsensusRoundIdentifier::new(outer_current_sequence, outer_current_round)).unwrap();

        let outer_context = ValidationContext::new(
            outer_current_sequence, outer_current_round, current_validators_set.clone(),
            outer_parent_h.clone(), final_state_for_outer_context.clone(), codec.clone(), config.clone(),
            None, outer_expected_proposer);

        let cert_proposal_sequence = outer_current_sequence;
        let cert_proposal_round = 0;
        let cert_proposal_round_id = ConsensusRoundIdentifier::new(cert_proposal_sequence, cert_proposal_round);
        let cert_expected_proposer_key = validator1_key.clone();
        let cert_expected_proposer_address = validator1_address;

        let cert_proposed_block = default_qbft_block(
            outer_parent_h.hash(), cert_proposal_sequence, cert_proposal_round, 
            outer_parent_h.timestamp + 1, 30_000_000, cert_expected_proposer_address,
            codec.clone(), current_validators_vec.clone());
        let cert_block_hash = cert_proposed_block.hash();

        let cert_proposal_payload = create_proposal_payload(cert_proposal_round_id, cert_proposed_block.clone());
        let cert_signed_proposal_payload = create_signed_proposal_payload(cert_proposal_payload, &cert_expected_proposer_key);
        let cert_bft_proposal_message = create_bft_message_proposal(cert_signed_proposal_payload);

        let mut prepares_for_cert: Vec<Prepare> = Vec::new();
        // Prepare from validator2
        let prepare_payload_v2 = crate::payload::PreparePayload::new(cert_proposal_round_id, cert_block_hash);
        // Clone `prepare_payload_v2` for the first signing, so it can be reused for the duplicate.
        let signed_prepare_v2 = SignedData::sign(prepare_payload_v2.clone(), &validator2_key).unwrap();
        prepares_for_cert.push(Prepare::new(signed_prepare_v2));
        
        // DUPLICATE Prepare from validator2
        // `prepare_payload_v2` (original, now un-cloned for this call) can be moved here for the second signing.
        let signed_prepare_v2_dup = SignedData::sign(prepare_payload_v2, &validator2_key).unwrap(); 
        prepares_for_cert.push(Prepare::new(signed_prepare_v2_dup));

        let prepared_certificate_to_validate = PreparedCertificateWrapper {
            proposal_message: cert_bft_proposal_message.clone(),
            prepares: prepares_for_cert,
        };

        let real_msg_val_factory = Arc::new(crate::validation::MessageValidatorFactoryImpl::new(config.clone()));
        let proposal_validator = ProposalValidatorImpl::new(real_msg_val_factory, config.clone());

        let result = proposal_validator.validate_prepares_for_certificate(
            &prepared_certificate_to_validate, outer_current_sequence, &outer_context);
        
        assert!(matches!(result, Err(QbftError::ValidationError(s)) if s == "Duplicate author in certificate prepares"));
    }

    #[test]
    fn test_validate_prepares_for_certificate_insufficient_prepares() {
        let config = default_config();
        let codec = testing_extradata_codec();

        let validator1_key = Arc::new(create_node_key());
        let validator1_address = address_from_key(&validator1_key);
        let validator2_key = Arc::new(create_node_key()); 
        let validator2_address = address_from_key(&validator2_key);
        let validator3_key = Arc::new(create_node_key());
        let validator3_address = address_from_key(&validator3_key);

        let current_validators_set: HashSet<Address> = 
            vec![validator1_address, validator2_address, validator3_address].into_iter().collect();
        let current_validators_vec: Vec<Address> = current_validators_set.iter().cloned().collect();

        let outer_parent_sequence: u64 = 0;
        let outer_parent_h = default_parent_header(outer_parent_sequence, B256::ZERO, 1_000_000, 30_000_000);
        let outer_current_sequence = outer_parent_sequence + 1;
        let outer_current_round = 1;

        // N=3, F=1. Quorum for prepares = N-F = 2.
        let mut final_state_instance = MockQbftFinalState::new_with_f_override( // Made mutable
            validator1_key.clone(), current_validators_set.clone(), 1); 
        final_state_instance.add_known_header(outer_parent_h.clone()); // Added: outer_parent_h is parent of cert_proposed_block
        let final_state_for_outer_context = Arc::new(final_state_instance); // Adjusted
        let outer_expected_proposer = final_state_for_outer_context.get_proposer_for_round(
            &ConsensusRoundIdentifier::new(outer_current_sequence, outer_current_round)).unwrap();

        let outer_context = ValidationContext::new(
            outer_current_sequence, outer_current_round, current_validators_set.clone(),
            outer_parent_h.clone(), final_state_for_outer_context.clone(), codec.clone(), config.clone(),
            None, outer_expected_proposer);

        let cert_proposal_sequence = outer_current_sequence;
        let cert_proposal_round = 0;
        let cert_proposal_round_id = ConsensusRoundIdentifier::new(cert_proposal_sequence, cert_proposal_round);
        let cert_expected_proposer_key = validator1_key.clone();
        let cert_expected_proposer_address = validator1_address;

        let cert_proposed_block = default_qbft_block(
            outer_parent_h.hash(), cert_proposal_sequence, cert_proposal_round, 
            outer_parent_h.timestamp + 1, 30_000_000, cert_expected_proposer_address,
            codec.clone(), current_validators_vec.clone());
        let cert_block_hash = cert_proposed_block.hash();

        let cert_proposal_payload = create_proposal_payload(cert_proposal_round_id, cert_proposed_block.clone());
        let cert_signed_proposal_payload = create_signed_proposal_payload(cert_proposal_payload, &cert_expected_proposer_key);
        let cert_bft_proposal_message = create_bft_message_proposal(cert_signed_proposal_payload);

        let mut prepares_for_cert: Vec<Prepare> = Vec::new();
        // ONLY ONE Prepare from validator2 (Quorum is 2)
        let prepare_payload_v2 = crate::payload::PreparePayload::new(cert_proposal_round_id, cert_block_hash);
        let signed_prepare_v2 = SignedData::sign(prepare_payload_v2.clone(), &validator2_key).unwrap();
        prepares_for_cert.push(Prepare::new(signed_prepare_v2));
        
        let prepared_certificate_to_validate = PreparedCertificateWrapper {
            proposal_message: cert_bft_proposal_message.clone(),
            prepares: prepares_for_cert,
        };

        let real_msg_val_factory = Arc::new(crate::validation::MessageValidatorFactoryImpl::new(config.clone()));
        let proposal_validator = ProposalValidatorImpl::new(real_msg_val_factory, config.clone());

        let result = proposal_validator.validate_prepares_for_certificate(
            &prepared_certificate_to_validate, outer_current_sequence, &outer_context);
        
        assert!(matches!(result, Err(QbftError::QuorumNotReached { needed, got, .. }) if needed == 2 && got == 1 ));
    }

    #[test]
    fn test_validate_prepares_for_certificate_invalid_prepare_digest_mismatch() {
        let config = default_config();
        let codec = testing_extradata_codec();

        let validator1_key = Arc::new(create_node_key());
        let validator1_address = address_from_key(&validator1_key);
        let validator2_key = Arc::new(create_node_key()); 
        let validator2_address = address_from_key(&validator2_key);
        let validator3_key = Arc::new(create_node_key());
        let validator3_address = address_from_key(&validator3_key);

        let current_validators_set: HashSet<Address> = 
            vec![validator1_address, validator2_address, validator3_address].into_iter().collect();
        let current_validators_vec: Vec<Address> = current_validators_set.iter().cloned().collect();

        let outer_parent_sequence: u64 = 0;
        let outer_parent_h = default_parent_header(outer_parent_sequence, B256::ZERO, 1_000_000, 30_000_000);
        let outer_current_sequence = outer_parent_sequence + 1;
        let outer_current_round = 1;

        let mut final_state_instance = MockQbftFinalState::new_with_f_override( // Made mutable
            validator1_key.clone(), current_validators_set.clone(), 1); 
        final_state_instance.add_known_header(outer_parent_h.clone()); // Added: outer_parent_h is parent of cert_proposed_block
        let final_state_for_outer_context = Arc::new(final_state_instance); // Adjusted
        let outer_expected_proposer = final_state_for_outer_context.get_proposer_for_round(
            &ConsensusRoundIdentifier::new(outer_current_sequence, outer_current_round)).unwrap();

        let outer_context = ValidationContext::new(
            outer_current_sequence, outer_current_round, current_validators_set.clone(),
            outer_parent_h.clone(), final_state_for_outer_context.clone(), codec.clone(), config.clone(),
            None, outer_expected_proposer);

        let cert_proposal_sequence = outer_current_sequence;
        let cert_proposal_round = 0;
        let cert_proposal_round_id = ConsensusRoundIdentifier::new(cert_proposal_sequence, cert_proposal_round);
        let cert_expected_proposer_key = validator1_key.clone();
        let cert_expected_proposer_address = validator1_address;

        let cert_proposed_block = default_qbft_block(
            outer_parent_h.hash(), cert_proposal_sequence, cert_proposal_round, 
            outer_parent_h.timestamp + 1, 30_000_000, cert_expected_proposer_address,
            codec.clone(), current_validators_vec.clone());
        let cert_block_hash = cert_proposed_block.hash(); // Correct hash
        let incorrect_block_hash = B256::from_slice(&[0xAA; 32]); // Incorrect hash for one prepare

        let cert_proposal_payload = create_proposal_payload(cert_proposal_round_id, cert_proposed_block.clone());
        let cert_signed_proposal_payload = create_signed_proposal_payload(cert_proposal_payload, &cert_expected_proposer_key);
        let cert_bft_proposal_message = create_bft_message_proposal(cert_signed_proposal_payload);

        let mut prepares_for_cert: Vec<Prepare> = Vec::new();
        // Prepare from validator2 (Correct digest)
        let prepare_payload_v2 = crate::payload::PreparePayload::new(cert_proposal_round_id, cert_block_hash);
        let signed_prepare_v2 = SignedData::sign(prepare_payload_v2, &validator2_key).unwrap();
        prepares_for_cert.push(Prepare::new(signed_prepare_v2));
        
        // Prepare from validator3 (INCORRECT digest)
        let prepare_payload_v3_invalid = crate::payload::PreparePayload::new(cert_proposal_round_id, incorrect_block_hash);
        let signed_prepare_v3_invalid = SignedData::sign(prepare_payload_v3_invalid, &validator3_key).unwrap();
        prepares_for_cert.push(Prepare::new(signed_prepare_v3_invalid));

        let prepared_certificate_to_validate = PreparedCertificateWrapper {
            proposal_message: cert_bft_proposal_message.clone(),
            prepares: prepares_for_cert,
        };

        let real_msg_val_factory = Arc::new(crate::validation::MessageValidatorFactoryImpl::new(config.clone()));
        let proposal_validator = ProposalValidatorImpl::new(real_msg_val_factory, config.clone());

        let result = proposal_validator.validate_prepares_for_certificate(
            &prepared_certificate_to_validate, outer_current_sequence, &outer_context);
        
        assert!(matches!(result, Err(QbftError::PrepareDigestMismatch { .. })));
    }

    #[test]
    fn test_validate_round_changes_empty_proofs() {
        let config = default_config();
        let codec = testing_extradata_codec();

        let proposer_key = Arc::new(create_node_key());
        let proposer_address = address_from_key(&proposer_key);
        
        let validators: HashSet<Address> = vec![proposer_address].into_iter().collect();
        let validators_vec: Vec<Address> = validators.iter().cloned().collect();

        let parent_sequence: u64 = 0;
        let parent_h = default_parent_header(parent_sequence, B256::ZERO, 1_000_000, 30_000_000);
        let current_sequence = parent_sequence + 1;
        let current_round = 1; // Non-zero round for this set of tests

        let final_state = Arc::new(MockQbftFinalState::new_with_f_override(proposer_key.clone(), validators.clone(), 0)); // F=0 for N=1
        let expected_proposer = final_state.get_proposer_for_round(
            &ConsensusRoundIdentifier::new(current_sequence, current_round)).unwrap();

        let context = ValidationContext::new(
            current_sequence, current_round, validators.clone(),
            parent_h.clone(), final_state.clone(), codec.clone(), config.clone(),
            None, expected_proposer);

        let proposed_block = default_qbft_block(
            parent_h.hash(), current_sequence, current_round, 
            parent_h.timestamp + 1, 30_000_000, proposer_address,
            codec.clone(), validators_vec.clone());

        let proposal_round_id = ConsensusRoundIdentifier::new(current_sequence, current_round);
        let proposal_payload = create_proposal_payload(proposal_round_id, proposed_block.clone());
        let signed_proposal_payload = create_signed_proposal_payload(proposal_payload, &proposer_key);
        let bft_proposal_message = create_bft_message_proposal(signed_proposal_payload);

        // Proposal with NO round change proofs
        let proposal_to_validate = create_proposal(bft_proposal_message, proposed_block.header.clone(), vec![], None);

        // Use real RoundChangeMessageValidator via MessageValidatorFactoryImpl
        let real_msg_val_factory = Arc::new(crate::validation::MessageValidatorFactoryImpl::new(config.clone()));
        let proposal_validator = ProposalValidatorImpl::new(real_msg_val_factory, config.clone());

        let result = proposal_validator.validate_round_changes_in_proposal(&proposal_to_validate, &context);
        
        assert!(result.is_ok());
        assert!(result.unwrap().is_none()); // Should return Ok(None) for best_prepared_metadata
    }

    #[test]
    fn test_validate_round_changes_duplicate_author() {
        let config = default_config();
        let codec = testing_extradata_codec();

        let validator1_key = Arc::new(create_node_key());
        let validator1_address = address_from_key(&validator1_key);
        let validator2_key = Arc::new(create_node_key()); // This key will be used for duplicate RCs
        let validator2_address = address_from_key(&validator2_key);
        // For N=2, F=0. Quorum for RCs N-F = 2. We'll provide 2 RCs, but from same author (validator2).

        let current_validators_set: HashSet<Address> = 
            vec![validator1_address, validator2_address].into_iter().collect();
        let current_validators_vec: Vec<Address> = current_validators_set.iter().cloned().collect();

        let parent_sequence: u64 = 0;
        let parent_h = default_parent_header(parent_sequence, B256::ZERO, 1_000_000, 30_000_000);
        let current_sequence = parent_sequence + 1;
        let current_round = 1; // Target round for the proposal and RCs

        let final_state = Arc::new(MockQbftFinalState::new_with_f_override(validator1_key.clone(), current_validators_set.clone(), 0));
        let expected_proposer = final_state.get_proposer_for_round(
            &ConsensusRoundIdentifier::new(current_sequence, current_round)).unwrap();

        let context = ValidationContext::new(
            current_sequence, current_round, current_validators_set.clone(),
            parent_h.clone(), final_state.clone(), codec.clone(), config.clone(),
            None, expected_proposer);

        let proposed_block = default_qbft_block(
            parent_h.hash(), current_sequence, current_round, 
            parent_h.timestamp + 1, 30_000_000, expected_proposer, // Proposer is the beneficiary for simplicity
            codec.clone(), current_validators_vec.clone());

        let proposal_round_id = ConsensusRoundIdentifier::new(current_sequence, current_round);
        let proposal_payload = create_proposal_payload(proposal_round_id, proposed_block.clone());
        // Proposal signed by expected_proposer (validator1 in this simplified F=0 setup if it rotates that way)
        let signed_proposal_payload = create_signed_proposal_payload(proposal_payload, &final_state.node_key()); // Assuming get_node_key() gives proposer's key
        let bft_proposal_message = create_bft_message_proposal(signed_proposal_payload);

        // Create RoundChange messages - two from validator2_key
        let mut rc_proofs: Vec<RoundChange> = Vec::new();
        let rc_target_round_id = ConsensusRoundIdentifier::new(current_sequence, current_round);

        let rc_payload1 = crate::payload::RoundChangePayload::new(rc_target_round_id, None, None);
        let signed_rc1 = SignedData::sign(rc_payload1.clone(), &validator2_key).unwrap();
        rc_proofs.push(RoundChange::new(signed_rc1, None, None).unwrap());

        // Duplicate RC from validator2_key
        let signed_rc2 = SignedData::sign(rc_payload1, &validator2_key).unwrap(); // Same payload, same key
        rc_proofs.push(RoundChange::new(signed_rc2, None, None).unwrap());

        let proposal_to_validate = create_proposal(bft_proposal_message, proposed_block.header.clone(), rc_proofs, None);

        let real_msg_val_factory = Arc::new(crate::validation::MessageValidatorFactoryImpl::new(config.clone()));
        let proposal_validator = ProposalValidatorImpl::new(real_msg_val_factory, config.clone());

        let result = proposal_validator.validate_round_changes_in_proposal(&proposal_to_validate, &context);
        
        assert!(matches!(result, Err(QbftError::ValidationError(s)) if s == "Duplicate author in round change proofs"));
    }

    #[test]
    fn test_validate_round_changes_insufficient_proofs() {
        let config = default_config();
        let codec = testing_extradata_codec();

        let validator1_key = Arc::new(create_node_key());
        let validator1_address = address_from_key(&validator1_key);
        let validator2_key = Arc::new(create_node_key()); 
        let validator2_address = address_from_key(&validator2_key);
        let validator3_key = Arc::new(create_node_key());
        let validator3_address = address_from_key(&validator3_key);

        let current_validators_set: HashSet<Address> = 
            vec![validator1_address, validator2_address, validator3_address].into_iter().collect();
        let current_validators_vec: Vec<Address> = current_validators_set.iter().cloned().collect();

        let parent_sequence: u64 = 0;
        let parent_h = default_parent_header(parent_sequence, B256::ZERO, 1_000_000, 30_000_000);
        let current_sequence = parent_sequence + 1;
        let current_round = 1;

        // N=3, F=1. Quorum for RCs N-F = 2.
        let final_state = Arc::new(MockQbftFinalState::new_with_f_override(validator1_key.clone(), current_validators_set.clone(), 1));
        let expected_proposer = final_state.get_proposer_for_round(
            &ConsensusRoundIdentifier::new(current_sequence, current_round)).unwrap();

        let context = ValidationContext::new(
            current_sequence, current_round, current_validators_set.clone(),
            parent_h.clone(), final_state.clone(), codec.clone(), config.clone(),
            None, expected_proposer);

        let proposed_block = default_qbft_block(
            parent_h.hash(), current_sequence, current_round, 
            parent_h.timestamp + 1, 30_000_000, expected_proposer,
            codec.clone(), current_validators_vec.clone());

        let proposal_round_id = ConsensusRoundIdentifier::new(current_sequence, current_round);
        let proposal_payload = create_proposal_payload(proposal_round_id, proposed_block.clone());
        let signed_proposal_payload = create_signed_proposal_payload(proposal_payload, &final_state.node_key());
        let bft_proposal_message = create_bft_message_proposal(signed_proposal_payload);

        // ONLY ONE RoundChange from validator2 (Quorum is 2)
        let mut rc_proofs: Vec<RoundChange> = Vec::new();
        let rc_target_round_id = ConsensusRoundIdentifier::new(current_sequence, current_round);
        let rc_payload = crate::payload::RoundChangePayload::new(rc_target_round_id, None, None);
        let signed_rc = SignedData::sign(rc_payload, &validator2_key).unwrap();
        rc_proofs.push(RoundChange::new(signed_rc, None, None).unwrap());

        let proposal_to_validate = create_proposal(bft_proposal_message, proposed_block.header.clone(), rc_proofs, None);

        let real_msg_val_factory = Arc::new(crate::validation::MessageValidatorFactoryImpl::new(config.clone()));
        let proposal_validator = ProposalValidatorImpl::new(real_msg_val_factory, config.clone());

        let result = proposal_validator.validate_round_changes_in_proposal(&proposal_to_validate, &context);
        
        assert!(matches!(result, Err(QbftError::QuorumNotReached { needed, got, item }) 
            if needed == 2 && got == 1 && item == "round change proofs"));
    }

    #[test]
    fn test_validate_round_changes_rc_targets_wrong_round() {
        let config = default_config();
        let codec = testing_extradata_codec();

        let validator1_key = Arc::new(create_node_key());
        let validator1_address = address_from_key(&validator1_key);
        let validator2_key = Arc::new(create_node_key()); 
        let validator2_address = address_from_key(&validator2_key);

        // N=2, F=0. Quorum for RCs N-F = 2 (but we'll make one RC invalid before quorum check hits)
        let current_validators_set: HashSet<Address> = 
            vec![validator1_address, validator2_address].into_iter().collect();
        let current_validators_vec: Vec<Address> = current_validators_set.iter().cloned().collect();

        let parent_sequence: u64 = 0;
        let parent_h = default_parent_header(parent_sequence, B256::ZERO, 1_000_000, 30_000_000);
        let current_sequence = parent_sequence + 1;
        let proposal_target_round = 2;
        let rc_incorrect_target_round = 1; // RC targets a different round

        let mut final_state_instance = MockQbftFinalState::new_with_f_override(validator1_key.clone(), current_validators_set.clone(), 0); // Made mutable
        final_state_instance.add_known_header(parent_h.clone()); // Added: parent_h might be needed by validate_round_change for the first valid RC if it has metadata.
        let final_state = Arc::new(final_state_instance); // Adjusted
        let expected_proposer_for_proposal_round = final_state.get_proposer_for_round(
            &ConsensusRoundIdentifier::new(current_sequence, proposal_target_round)).unwrap();

        let context = ValidationContext::new(
            current_sequence, proposal_target_round, current_validators_set.clone(),
            parent_h.clone(), final_state.clone(), codec.clone(), config.clone(),
            None, expected_proposer_for_proposal_round);

        let proposed_block = default_qbft_block(
            parent_h.hash(), current_sequence, proposal_target_round, 
            parent_h.timestamp + 1, 30_000_000, expected_proposer_for_proposal_round,
            codec.clone(), current_validators_vec.clone());

        let proposal_round_id = ConsensusRoundIdentifier::new(current_sequence, proposal_target_round);
        let proposal_payload = create_proposal_payload(proposal_round_id, proposed_block.clone());
        let signed_proposal_payload = create_signed_proposal_payload(proposal_payload, &final_state.node_key());
        let bft_proposal_message = create_bft_message_proposal(signed_proposal_payload);

        let mut rc_proofs: Vec<RoundChange> = Vec::new();
        // RC from validator1 (Correctly targets proposal_target_round)
        let rc_payload1 = crate::payload::RoundChangePayload::new(
            ConsensusRoundIdentifier::new(current_sequence, proposal_target_round), None, None);
        let signed_rc1 = SignedData::sign(rc_payload1, &validator1_key).unwrap();
        rc_proofs.push(RoundChange::new(signed_rc1, None, None).unwrap());

        // RC from validator2 (Incorrectly targets rc_incorrect_target_round)
        let rc_payload2_invalid = crate::payload::RoundChangePayload::new(
            ConsensusRoundIdentifier::new(current_sequence, rc_incorrect_target_round), None, None);
        let signed_rc2_invalid = SignedData::sign(rc_payload2_invalid, &validator2_key).unwrap();
        rc_proofs.push(RoundChange::new(signed_rc2_invalid, None, None).unwrap());

        let proposal_to_validate = create_proposal(bft_proposal_message, proposed_block.header.clone(), rc_proofs, None);

        let real_msg_val_factory = Arc::new(crate::validation::MessageValidatorFactoryImpl::new(config.clone()));
        let proposal_validator = ProposalValidatorImpl::new(real_msg_val_factory, config.clone());

        let result = proposal_validator.validate_round_changes_in_proposal(&proposal_to_validate, &context);
        
        dbg!(result.as_ref().err()); // Added dbg!
        assert!(matches!(result, Err(QbftError::ValidationError(s)) if s == "RoundChangeProof targets incorrect round"));
    }

    #[test]
    fn test_validate_round_changes_invalid_inner_rc() {
        let config = default_config();
        let codec = testing_extradata_codec();

        let validator1_key = Arc::new(create_node_key());
        let validator1_address = address_from_key(&validator1_key);
        let validator2_key = Arc::new(create_node_key()); 
        let validator2_address = address_from_key(&validator2_key);

        let current_validators_set: HashSet<Address> = 
            vec![validator1_address, validator2_address].into_iter().collect();
        let current_validators_vec: Vec<Address> = current_validators_set.iter().cloned().collect();

        let parent_sequence: u64 = 0;
        let parent_h = default_parent_header(parent_sequence, B256::ZERO, 1_000_000, 30_000_000);
        let current_sequence = parent_sequence + 1;
        let proposal_target_round = 2;

        // N=2, F=0. Quorum for RCs is 2.
        let mut final_state_instance = MockQbftFinalState::new_with_f_override(validator1_key.clone(), current_validators_set.clone(), 0); // Made mutable
        final_state_instance.add_known_header(parent_h.clone()); // Added: parent_h is parent of prepared_block_for_rc_original
        let final_state = Arc::new(final_state_instance); // Adjusted
        let expected_proposer_for_proposal_round = final_state.get_proposer_for_round(
            &ConsensusRoundIdentifier::new(current_sequence, proposal_target_round)).unwrap();

        let context = ValidationContext::new(
            current_sequence, proposal_target_round, current_validators_set.clone(),
            parent_h.clone(), final_state.clone(), codec.clone(), config.clone(),
            None, expected_proposer_for_proposal_round);

        let proposed_block_for_proposal = default_qbft_block( // Block for the main proposal
            parent_h.hash(), current_sequence, proposal_target_round, 
            parent_h.timestamp + 1, 30_000_000, expected_proposer_for_proposal_round,
            codec.clone(), current_validators_vec.clone());

        let proposal_round_id = ConsensusRoundIdentifier::new(current_sequence, proposal_target_round);
        let proposal_payload = create_proposal_payload(proposal_round_id, proposed_block_for_proposal.clone());
        let signed_proposal_payload = create_signed_proposal_payload(proposal_payload, &final_state.node_key());
        let bft_proposal_message = create_bft_message_proposal(signed_proposal_payload);

        // --- Create RCs --- 
        let mut rc_proofs: Vec<RoundChange> = Vec::new();
        let rc_target_round_id = ConsensusRoundIdentifier::new(current_sequence, proposal_target_round);

        // Valid RC from validator1 (no prepared data for simplicity here)
        let rc_payload1 = crate::payload::RoundChangePayload::new(rc_target_round_id, None, None);
        let signed_rc1 = SignedData::sign(rc_payload1, &validator1_key).unwrap();
        rc_proofs.push(RoundChange::new(signed_rc1, None, None).unwrap());

        // Invalid RC from validator2: PreparedRoundMetadata.prepared_round >= RC target round
        let prepared_block_for_rc_original = default_qbft_block( // Dummy block for prepared cert
            parent_h.hash(), current_sequence, proposal_target_round, // Incorrectly using proposal_target_round for prepared_round
            parent_h.timestamp + 1, 30_000_000, validator2_address, // Some beneficiary
            codec.clone(), current_validators_vec.clone());
        
        let inner_proposal_payload_for_rc_cert = create_proposal_payload(
            ConsensusRoundIdentifier::new(current_sequence, proposal_target_round), // prepared_round = proposal_target_round (INVALID)
            prepared_block_for_rc_original.clone() // Clone here for this use
        );
        let signed_inner_proposal_for_rc_cert = create_signed_proposal_payload(inner_proposal_payload_for_rc_cert, &validator2_key);
        let bft_inner_proposal_for_rc_cert = create_bft_message_proposal(signed_inner_proposal_for_rc_cert);

        let prepared_metadata_invalid = crate::payload::PreparedRoundMetadata {
            prepared_round: proposal_target_round, // INVALID: prepared_round must be < rc_target_round.number
            prepared_block_hash: prepared_block_for_rc_original.hash(),
            signed_proposal_payload: bft_inner_proposal_for_rc_cert,
            prepares: vec![], // Empty prepares for simplicity, validation should fail before this
        };

        let rc_payload2_invalid_metadata = crate::payload::RoundChangePayload::new(
            rc_target_round_id, 
            Some(prepared_metadata_invalid), 
            Some(prepared_block_for_rc_original.clone()) // Clone for payload
        );
        let signed_rc2_invalid_metadata = SignedData::sign(rc_payload2_invalid_metadata, &validator2_key).unwrap();

        rc_proofs.push(RoundChange::new(
            signed_rc2_invalid_metadata, 
            Some(prepared_block_for_rc_original), // Original moved here
            Some(vec![])
        ).unwrap());

        let proposal_to_validate = create_proposal(bft_proposal_message, proposed_block_for_proposal.header.clone(), rc_proofs, None);

        let real_msg_val_factory = Arc::new(crate::validation::MessageValidatorFactoryImpl::new(config.clone()));
        let proposal_validator = ProposalValidatorImpl::new(real_msg_val_factory, config.clone());

        let result = proposal_validator.validate_round_changes_in_proposal(&proposal_to_validate, &context);
        
        dbg!(result.as_ref().err()); // Added dbg!
        assert!(matches!(result, Err(QbftError::ValidationError(s)) if s == "PreparedRoundMetadata round not less than RoundChange target round"));
    }

    #[test]
    fn test_validate_round_changes_inconsistent_prepared_metadata() {
        let config = default_config();
        let codec = testing_extradata_codec();

        let validator1_key = Arc::new(create_node_key());
        let validator1_address = address_from_key(&validator1_key);
        let validator2_key = Arc::new(create_node_key()); 
        let validator2_address = address_from_key(&validator2_key);
        let validator3_key = Arc::new(create_node_key());
        let validator3_address = address_from_key(&validator3_key);

        let current_validators_set: HashSet<Address> = 
            vec![validator1_address, validator2_address, validator3_address].into_iter().collect();
        let current_validators_vec: Vec<Address> = current_validators_set.iter().cloned().collect();

        let parent_sequence: u64 = 0;
        let parent_h = default_parent_header(parent_sequence, B256::ZERO, 1_000_000, 30_000_000);
        let current_sequence = parent_sequence + 1;
        let proposal_target_round = 3; // Proposal for round 3
        let common_prepared_round = 1;   // RCs will refer to a prepared round 1

        // N=3, F=1. Quorum for RCs is 2.
        let final_state = Arc::new(MockQbftFinalState::new_with_f_override(validator1_key.clone(), current_validators_set.clone(), 1));
        let expected_proposer_for_proposal_round = final_state.get_proposer_for_round(
            &ConsensusRoundIdentifier::new(current_sequence, proposal_target_round)).unwrap();

        let context = ValidationContext::new(
            current_sequence, proposal_target_round, current_validators_set.clone(),
            parent_h.clone(), final_state.clone(), codec.clone(), config.clone(),
            None, expected_proposer_for_proposal_round);

        let proposed_block_for_main_proposal = default_qbft_block(
            parent_h.hash(), current_sequence, proposal_target_round, 
            parent_h.timestamp + 10, 30_000_000, expected_proposer_for_proposal_round,
            codec.clone(), current_validators_vec.clone());

        let proposal_round_id = ConsensusRoundIdentifier::new(current_sequence, proposal_target_round);
        let proposal_payload = create_proposal_payload(proposal_round_id, proposed_block_for_main_proposal.clone());
        let signed_proposal_payload = create_signed_proposal_payload(proposal_payload, &final_state.node_key());
        let bft_proposal_message = create_bft_message_proposal(signed_proposal_payload);

        // --- Create RCs with inconsistent PreparedRoundMetadata for the same prepared_round --- 
        let mut rc_proofs: Vec<RoundChange> = Vec::new();
        let rc_target_round_id = ConsensusRoundIdentifier::new(current_sequence, proposal_target_round);

        // Metadata A (Good)
        let prepared_block_a = default_qbft_block( // Renamed variable
            parent_h.hash(), current_sequence, common_prepared_round, 
            parent_h.timestamp + 1, 30_000_000, validator1_address, // Arbitrary proposer for this inner block
            codec.clone(), current_validators_vec.clone());
        let inner_proposal_payload_a = create_proposal_payload( // Renamed variable
            ConsensusRoundIdentifier::new(current_sequence, common_prepared_round), prepared_block_a.clone());
        let signed_inner_proposal_a = create_signed_proposal_payload(inner_proposal_payload_a, &validator1_key); // Renamed variable
        let bft_inner_proposal_a = create_bft_message_proposal(signed_inner_proposal_a); // Renamed variable
        let prepared_metadata_a = crate::payload::PreparedRoundMetadata { // Renamed variable
            prepared_round: common_prepared_round,
            prepared_block_hash: prepared_block_a.hash(),
            signed_proposal_payload: bft_inner_proposal_a.clone(),
            prepares: vec![], // For simplicity, assume these would be valid if consistency passed
        };

        // Metadata B (Inconsistent - different block hash)
        let prepared_block_b = default_qbft_block( // Slightly different block // Renamed variable
            parent_h.hash(), current_sequence, common_prepared_round, 
            parent_h.timestamp + 2, 30_000_000, validator2_address, 
            codec.clone(), current_validators_vec.clone());
        let prepared_metadata_b_inconsistent_hash = crate::payload::PreparedRoundMetadata { // Renamed variable
            prepared_round: common_prepared_round, 
            prepared_block_hash: prepared_block_b.hash(), // Different hash
            signed_proposal_payload: bft_inner_proposal_a.clone(), // Same proposal payload for now
            prepares: vec![],
        };
        
        // RC from validator1 with Metadata A
        let rc_payload1 = crate::payload::RoundChangePayload::new(
            rc_target_round_id, Some(prepared_metadata_a.clone()), Some(prepared_block_a.clone()));
        let signed_rc1 = SignedData::sign(rc_payload1, &validator1_key).unwrap();
        rc_proofs.push(RoundChange::new(signed_rc1, Some(prepared_block_a.clone()), Some(vec![])).unwrap());

        // RC from validator2 with Metadata B (inconsistent hash)
        let rc_payload2 = crate::payload::RoundChangePayload::new(
            rc_target_round_id, Some(prepared_metadata_b_inconsistent_hash), Some(prepared_block_b.clone())); // Block B also provided here
        let signed_rc2 = SignedData::sign(rc_payload2, &validator2_key).unwrap();
        rc_proofs.push(RoundChange::new(signed_rc2, Some(prepared_block_b.clone()), Some(vec![])).unwrap());
        
        // RC from validator3 (could be without metadata, or with consistent metadata A to ensure quorum for other checks if needed)
        // For this test, just ensuring we have enough RCs to pass quorum if the consistency check wasn't there.
        let rc_payload3_no_meta = crate::payload::RoundChangePayload::new(rc_target_round_id, None, None);
        let signed_rc3 = SignedData::sign(rc_payload3_no_meta, &validator3_key).unwrap();
        rc_proofs.push(RoundChange::new(signed_rc3, None, None).unwrap());


        let proposal_to_validate = create_proposal(bft_proposal_message, proposed_block_for_main_proposal.header.clone(), rc_proofs, None);

        let real_msg_val_factory = Arc::new(crate::validation::MessageValidatorFactoryImpl::new(config.clone()));
        let proposal_validator = ProposalValidatorImpl::new(real_msg_val_factory, config.clone());

        let result = proposal_validator.validate_round_changes_in_proposal(&proposal_to_validate, &context);
        
        dbg!(result.as_ref().err()); // Added dbg!
        assert!(matches!(result, Err(QbftError::ValidationError(s)) if s == "Inconsistent PreparedRoundMetadata in round change proofs"));
    }

    #[test]
    fn test_validate_round_changes_returns_best_prepared_metadata() {
        let config = default_config();
        let codec = testing_extradata_codec();

        let validator1_key = Arc::new(create_node_key());
        let validator1_address = address_from_key(&validator1_key);
        let validator2_key = Arc::new(create_node_key()); 
        let validator2_address = address_from_key(&validator2_key);
        let validator3_key = Arc::new(create_node_key());
        let validator3_address = address_from_key(&validator3_key);

        let current_validators_set: HashSet<Address> = 
            vec![validator1_address, validator2_address, validator3_address].into_iter().collect();
        let current_validators_vec: Vec<Address> = current_validators_set.iter().cloned().collect();

        let parent_sequence: u64 = 0;
        let parent_h = default_parent_header(parent_sequence, B256::ZERO, 1_000_000, 30_000_000);
        let current_sequence = parent_sequence + 1;
        let proposal_target_round = 3; 

        let mut final_state_instance = MockQbftFinalState::new_with_f_override(validator1_key.clone(), current_validators_set.clone(), 1); // Made mutable
        final_state_instance.add_known_header(parent_h.clone()); // Added: parent_h is parent of prepared_block_r1 and prepared_block_r2
        let final_state = Arc::new(final_state_instance); // Adjusted

        // --- DBG: Print proposer for round 2 ---
        let proposer_for_round_2_dbg = final_state.get_proposer_for_round(&ConsensusRoundIdentifier::new(current_sequence, 2)).unwrap();
        dbg!(&proposer_for_round_2_dbg);
        dbg!(&validator1_address);
        dbg!(&validator2_address);
        dbg!(&validator3_address);
        // --- END DBG ---

        let expected_proposer_for_proposal_round = final_state.get_proposer_for_round(
            &ConsensusRoundIdentifier::new(current_sequence, proposal_target_round)).unwrap();

        let context = ValidationContext::new(
            current_sequence, proposal_target_round, current_validators_set.clone(),
            parent_h.clone(), final_state.clone(), codec.clone(), config.clone(),
            None, expected_proposer_for_proposal_round);

        let proposed_block_for_main_proposal = default_qbft_block(
            parent_h.hash(), current_sequence, proposal_target_round, 
            parent_h.timestamp + 10, 30_000_000, expected_proposer_for_proposal_round,
            codec.clone(), current_validators_vec.clone());

        let proposal_round_id = ConsensusRoundIdentifier::new(current_sequence, proposal_target_round);
        let proposal_payload_main = create_proposal_payload(proposal_round_id, proposed_block_for_main_proposal.clone());
        let signed_proposal_payload_main = create_signed_proposal_payload(proposal_payload_main, &final_state.node_key());
        let bft_proposal_message_main = create_bft_message_proposal(signed_proposal_payload_main);

        // --- Create RCs with different PreparedRoundMetadata --- 
        let mut rc_proofs: Vec<RoundChange> = Vec::new();
        let rc_target_round_id = ConsensusRoundIdentifier::new(current_sequence, proposal_target_round);

        // Metadata for prepared_round = 1 (from validator1)
        let prepared_round_1 = 1;
        let prepared_block_r1 = default_qbft_block( 
            parent_h.hash(), current_sequence, prepared_round_1, parent_h.timestamp + 1, 
            30_000_000, validator2_address, codec.clone(), current_validators_vec.clone()); // BENEFICIARY = validator2_address (Proposer for R1)
        let inner_proposal_payload_r1 = create_proposal_payload(
            ConsensusRoundIdentifier::new(current_sequence, prepared_round_1), prepared_block_r1.clone());
        let signed_inner_proposal_r1 = create_signed_proposal_payload(inner_proposal_payload_r1.clone(), &validator2_key); // Signed by validator2_key (Proposer for R1)
        let bft_inner_proposal_r1 = create_bft_message_proposal(signed_inner_proposal_r1);

        // Create a common PreparePayload for metadata_r1
        let common_prepare_payload_r1 = PreparePayload::new(
            inner_proposal_payload_r1.round_identifier, // Use round_id from inner_proposal_payload_r1
            prepared_block_r1.hash()
        );
        // Sign it by validator3
        let signed_prepare_for_r1_by_v3 = SignedData::sign(common_prepare_payload_r1.clone(), &validator3_key).unwrap();
        // Sign it by validator2
        let signed_prepare_for_r1_by_v2 = SignedData::sign(common_prepare_payload_r1.clone(), &validator2_key).unwrap();


        let prepared_metadata_r1 = crate::payload::PreparedRoundMetadata {
            prepared_round: prepared_round_1,
            prepared_block_hash: prepared_block_r1.hash(),
            signed_proposal_payload: bft_inner_proposal_r1.clone(),
            prepares: vec![signed_prepare_for_r1_by_v3.clone(), signed_prepare_for_r1_by_v2.clone()], // Use signed data
        };
        let rc_payload_r1 = crate::payload::RoundChangePayload::new(
            rc_target_round_id, Some(prepared_metadata_r1.clone()), Some(prepared_block_r1.clone()));
        let signed_rc_r1 = SignedData::sign(rc_payload_r1, &validator1_key).unwrap();
        rc_proofs.push(RoundChange::new(signed_rc_r1, Some(prepared_block_r1.clone()), Some(vec![])).unwrap());

        // Metadata for prepared_round = 2 (from validator2) - THIS IS THE BEST
        let prepared_round_2 = 2;
        let mut prepared_block_r2 = default_qbft_block( // Made block mutable
            parent_h.hash(), current_sequence, prepared_round_2, parent_h.timestamp + 2, 
            30_000_000, validator1_address, codec.clone(), current_validators_vec.clone()); // BENEFICIARY = validator1_address (Proposer for R2)
        
        // Ensure the header's hash is computed and cached before cloning for the payload
        let _ = prepared_block_r2.header.hash(); 

        let inner_proposal_payload_r2 = create_proposal_payload(
            ConsensusRoundIdentifier::new(current_sequence, prepared_round_2), prepared_block_r2.clone());
        let signed_inner_proposal_r2 = create_signed_proposal_payload(inner_proposal_payload_r2.clone(), &validator1_key); // Signed by validator1_key (Proposer for R2)
        let bft_inner_proposal_r2 = create_bft_message_proposal(signed_inner_proposal_r2);

        // Create a common PreparePayload for metadata_r2 (best_prepared_metadata)
        let common_prepare_payload_r2 = PreparePayload::new(
            inner_proposal_payload_r2.round_identifier, // Use round_id from inner_proposal_payload_r2
            prepared_block_r2.hash()
        );
        // Sign it by validator1
        let signed_prepare_for_r2_by_v1 = SignedData::sign(common_prepare_payload_r2.clone(), &validator1_key).unwrap();
        // Sign it by validator3 (another validator, as RC is from v2)
        let signed_prepare_for_r2_by_v3 = SignedData::sign(common_prepare_payload_r2.clone(), &validator3_key).unwrap();

        let best_prepared_metadata = crate::payload::PreparedRoundMetadata {
            prepared_round: prepared_round_2,
            prepared_block_hash: prepared_block_r2.hash(),
            signed_proposal_payload: bft_inner_proposal_r2.clone(),
            prepares: vec![signed_prepare_for_r2_by_v1.clone(), signed_prepare_for_r2_by_v3.clone()], // Use signed data
        };
        let rc_payload_r2 = crate::payload::RoundChangePayload::new(
            rc_target_round_id, Some(best_prepared_metadata.clone()), Some(prepared_block_r2.clone()));
        let signed_rc_r2 = SignedData::sign(rc_payload_r2, &validator2_key).unwrap(); // REVERTED to validator2_key
        rc_proofs.push(RoundChange::new(signed_rc_r2, Some(prepared_block_r2.clone()), Some(vec![])).unwrap());

        // RC from validator3 (no metadata, to ensure quorum)
        let rc_payload_no_meta = crate::payload::RoundChangePayload::new(rc_target_round_id, None, None);
        let signed_rc_no_meta = SignedData::sign(rc_payload_no_meta, &validator3_key).unwrap();
        rc_proofs.push(RoundChange::new(signed_rc_no_meta, None, None).unwrap());

        let proposal_to_validate = create_proposal(bft_proposal_message_main, proposed_block_for_main_proposal.header.clone(), rc_proofs, None);

        let real_msg_val_factory = Arc::new(crate::validation::MessageValidatorFactoryImpl::new(config.clone()));
        let proposal_validator = ProposalValidatorImpl::new(real_msg_val_factory, config.clone());

        let result = proposal_validator.validate_round_changes_in_proposal(&proposal_to_validate, &context);
        
        dbg!(result.as_ref().err()); // Added dbg!
        assert!(result.is_ok());
        let unwrapped_metadata = result.unwrap();
        assert!(unwrapped_metadata.is_some());
        assert_eq!(unwrapped_metadata.unwrap(), best_prepared_metadata);
    }

    // --- Tests for the main validate_proposal method --- 

    #[test]
    fn test_validate_proposal_round_0_valid() {
        let config = default_config();
        let codec = testing_extradata_codec();

        let proposer_key = Arc::new(create_node_key());
        let proposer_address = address_from_key(&proposer_key);
        
        let validators: HashSet<Address> = vec![proposer_address].into_iter().collect();
        let validators_vec: Vec<Address> = validators.iter().cloned().collect();

        let parent_sequence: u64 = 0;
        let parent_h = default_parent_header(parent_sequence, B256::ZERO, 1_000_000, 30_000_000);
        let current_sequence = parent_sequence + 1;
        let current_round = 0; // ROUND 0

        let final_state = Arc::new(MockQbftFinalState::new_with_f_override(proposer_key.clone(), validators.clone(), 0));
        let expected_proposer = final_state.get_proposer_for_round(
            &ConsensusRoundIdentifier::new(current_sequence, current_round)).unwrap();

        let context = ValidationContext::new(
            current_sequence, current_round, validators.clone(),
            parent_h.clone(), final_state.clone(), codec.clone(), config.clone(),
            None, // accepted_proposal_digest for round 0 might be None
            expected_proposer);

        // Valid block for round 0 proposal
        let proposed_block = default_qbft_block(
            parent_h.hash(), current_sequence, current_round, 
            parent_h.timestamp + 1, // Valid timestamp
            30_000_000, // Valid gas limit
            proposer_address, // Coinbase matches author
            codec.clone(), validators_vec.clone());

        let proposal_round_id = ConsensusRoundIdentifier::new(current_sequence, current_round);
        let proposal_payload = create_proposal_payload(proposal_round_id, proposed_block.clone());
        let signed_proposal_payload = create_signed_proposal_payload(proposal_payload, &proposer_key);
        let bft_proposal_message = create_bft_message_proposal(signed_proposal_payload);

        // Valid Round 0 proposal: No RCs, No Prepared Cert
        let proposal_to_validate = create_proposal(
            bft_proposal_message, 
            proposed_block.header.clone(), 
            vec![], // No RC proofs
            None    // No prepared certificate
        );

        // Use real factory to ensure sub-validators are also real if not mocked at a lower level
        let real_msg_val_factory = Arc::new(crate::validation::MessageValidatorFactoryImpl::new(config.clone()));
        let proposal_validator = ProposalValidatorImpl::new(real_msg_val_factory, config.clone());

        let result = proposal_validator.validate_proposal(&proposal_to_validate, &context);
        
        if result.is_err() {
            dbg!(result.as_ref().err()); // Print error for debugging if it fails
        }
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_proposal_round_0_invalid_payload_block() {
        // SETUP: Similar to round 0 valid, but we\'ll make the block\'s author invalid
        let config = default_config();
        let node_key = create_node_key(); // Proposer\'s key
        let another_key = create_node_key(); // A different key for an invalid author

        let proposer_address = address_from_key(&node_key);
        let validators: HashSet<Address> = vec![proposer_address, address_from_key(&create_node_key()), address_from_key(&create_node_key())].into_iter().collect();
        
        let parent_header = default_parent_header(0, B256::ZERO, 100, 5000);
        let sequence = parent_header.number + 1;
        let round: u32 = 0;

        let extra_data_codec = testing_extradata_codec();
        
        // Create a block with an invalid author (not the expected proposer)
        let invalid_author_address = address_from_key(&another_key);
        let block_for_proposal = default_qbft_block(
            parent_header.hash(), 
            sequence, 
            round, 
            parent_header.timestamp + 1, 
            parent_header.gas_limit, 
            invalid_author_address, // Invalid author
            extra_data_codec.clone(),
            validators.iter().cloned().collect()
        );

        let proposal_payload = create_proposal_payload(
            ConsensusRoundIdentifier { sequence_number: sequence, round_number: round },
            block_for_proposal.clone()
        );

        // Sign the payload with the *expected* proposer\'s key, even though block author is different
        // The proposal signer being correct but the block author being wrong is a specific test for ProposalNotFromProposer.
        // If we signed with `another_key`, the `proposal.author()` check would fail earlier.
        let signed_proposal_payload = create_signed_proposal_payload(proposal_payload, &node_key); 
        let bft_message = create_bft_message_proposal(signed_proposal_payload);
        
        let proposal = create_proposal(
            bft_message, 
            block_for_proposal.header.clone(), 
            Vec::new(), // No RC proofs for round 0
            None        // No prepared cert for round 0
        );

        let final_state = default_final_state(Arc::new(node_key.clone()), validators.clone()); // Use proposer_address\'s key for final_state context
        let context = default_validation_context(
            sequence, 
            round, 
            validators.clone(), 
            parent_header.clone(),
            proposer_address, // Expected proposer is proposer_address
            config.clone(),
            extra_data_codec.clone(),
            Some(final_state),
            Arc::new(node_key) // local_node_key for default_final_state creation if needed by it
        );
        
        let message_validator_factory = mock_message_validator_factory(false, false, false);
        let proposal_validator = ProposalValidatorImpl::new(message_validator_factory, config.clone());

        // ACTION
        let result = proposal_validator.validate_proposal(&proposal, &context);

        // ASSERT
        assert!(matches!(result, Err(QbftError::ValidationError(s)) if s == "Block beneficiary does not match proposer"));
    }

    #[test]
    fn test_validate_proposal_round_0_invalid_round_zero_conditions() {
        // SETUP: Base setup for a round 0 proposal.
        // We will test two sub-cases: 
        // 1. Proposal has round change proofs.
        // 2. Proposal has a prepared certificate.
        let config = default_config();
        let node_key_proposer = create_node_key();
        let proposer_address = address_from_key(&node_key_proposer);
        
        let validator_keys: Vec<NodeKey> = (0..3).map(|_| create_node_key()).collect();
        let mut validators_set: HashSet<Address> = validator_keys.iter().map(address_from_key).collect();
        validators_set.insert(proposer_address); // Ensure proposer is a validator

        let parent_header = default_parent_header(0, B256::ZERO, 100, 5000);
        let sequence = parent_header.number + 1;
        let round: u32 = 0;

        let extra_data_codec = testing_extradata_codec();
        let final_state = default_final_state(Arc::new(node_key_proposer.clone()), validators_set.clone());
        
        let context = default_validation_context(
            sequence, 
            round, 
            validators_set.clone(), 
            parent_header.clone(),
            proposer_address, 
            config.clone(),
            extra_data_codec.clone(),
            Some(final_state.clone()),
            Arc::new(node_key_proposer.clone())
        );

        let block_for_proposal = default_qbft_block(
            parent_header.hash(), 
            sequence, 
            round, 
            parent_header.timestamp + 1, 
            parent_header.gas_limit, 
            proposer_address, 
            extra_data_codec.clone(),
            validators_set.iter().cloned().collect()
        );

        let proposal_payload = create_proposal_payload(
            ConsensusRoundIdentifier { sequence_number: sequence, round_number: round },
            block_for_proposal.clone()
        );
        let signed_proposal_payload = create_signed_proposal_payload(proposal_payload, &node_key_proposer);
        let bft_message = create_bft_message_proposal(signed_proposal_payload);

        let message_validator_factory = mock_message_validator_factory(false, false, false); // No inner validation failures expected
        let proposal_validator = ProposalValidatorImpl::new(message_validator_factory, config.clone());

        // SUB-CASE 1: Proposal has round change proofs (should fail)
        let round_change_payload = RoundChangePayload::new(
            ConsensusRoundIdentifier { sequence_number: sequence, round_number: round + 1 }, // Target next round
            None, // No best prepared certificate
            None // No block
        );
        // Correctly sign the actual payload using SignedData::sign, not by manual hash signing.
        let signed_rc_payload = SignedData::sign(round_change_payload, &validator_keys[0]).unwrap();
        // RoundChange::new takes SignedData<RoundChangePayload>, and the None args are correct.
        let round_change_proofs = vec![RoundChange::new(signed_rc_payload.clone(), None, None).unwrap()]; 

        let proposal_with_rcs = create_proposal(
            bft_message.clone(), 
            block_for_proposal.header.clone(), 
            round_change_proofs, // Invalid for round 0
            None
        );

        let result_rcs = proposal_validator.validate_proposal(&proposal_with_rcs, &context);
        assert!(matches!(result_rcs, Err(QbftError::ProposalHasRoundChangeForRoundZero)), "Expected ProposalHasRoundChangeForRoundZero, got {:?}", result_rcs);

        // SUB-CASE 2: Proposal has a prepared certificate (should fail)
        // Create a mock Prepare for the certificate
        let prepare_payload = PreparePayload::new(
            ConsensusRoundIdentifier { sequence_number: sequence, round_number: round }, // Same round as proposal
            block_for_proposal.header.hash() // Digest of the proposed block
        );
        // Correctly sign the actual payload using SignedData::sign.
        let signed_prepare_payload = SignedData::sign(prepare_payload.clone(), &validator_keys[0]).unwrap();
        // Corrected Prepare::new call (single argument, no unwrap needed as it returns Self)
        let prepare_wrapper = Prepare::new(signed_prepare_payload); 

        // Correctly construct BftMessage for the PreparedCertificateWrapper
        let dummy_proposal_payload_for_cert = ProposalPayload::new(
             ConsensusRoundIdentifier { sequence_number: sequence, round_number: round }, 
             block_for_proposal.clone()
        );
        // Correctly sign the payload using SignedData::sign
        let signed_dummy_proposal_payload_for_cert = SignedData::sign(dummy_proposal_payload_for_cert, &node_key_proposer).unwrap();
        let bft_dummy_proposal_for_cert = BftMessage::new(signed_dummy_proposal_payload_for_cert);

        // Corrected PreparedCertificateWrapper initialization
        let prepared_certificate = PreparedCertificateWrapper {
            proposal_message: bft_dummy_proposal_for_cert, 
            prepares: vec![prepare_wrapper], 
        };
        
        let proposal_with_cert = create_proposal(
            bft_message.clone(), 
            block_for_proposal.header.clone(), 
            Vec::new(), 
            Some(prepared_certificate) 
        );

        let result_cert = proposal_validator.validate_proposal(&proposal_with_cert, &context);
        assert!(matches!(result_cert, Err(QbftError::ProposalHasPreparedCertificateForRoundZero)), "Expected ProposalHasPreparedCertificateForRoundZero, got {:?}", result_cert);
    }
} 