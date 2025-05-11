use crate::messagewrappers::Commit;
use crate::validation::ValidationContext; // Assuming ValidationContext is re-exported by validation/mod.rs
use crate::error::QbftError;
use crate::payload::QbftPayload; // Added import
use alloy_primitives::B256;
// Add other necessary imports if the actual validation logic needs them

pub trait CommitValidator: Send + Sync {
    fn validate_commit(&self, commit: &Commit, context: &ValidationContext) -> Result<(), QbftError>;
}

#[derive(Default)] 
pub struct CommitValidatorImpl;

impl CommitValidatorImpl {
    pub fn new() -> Self {
        // TODO: This might take dependencies like QbftConfig later.
        Self::default()
    }
}

impl CommitValidator for CommitValidatorImpl { 
    fn validate_commit(&self, commit: &Commit, context: &ValidationContext) -> Result<(), QbftError> { 
        // Check 1: Commit message's RoundIdentifier must match the ValidationContext's current round and sequence.
        let payload_round_identifier = commit.payload().round_identifier();
        if payload_round_identifier.sequence_number != context.current_sequence_number ||
           payload_round_identifier.round_number != context.current_round_number {
            log::warn!(
                "Invalid Commit: Payload round identifier {:?} does not match context round identifier {:?}/{:?}",
                payload_round_identifier, context.current_sequence_number, context.current_round_number
            );
            return Err(QbftError::MessageRoundMismatch { 
                message_type: "Commit".to_string(),
                expected_sequence: context.current_sequence_number,
                expected_round: context.current_round_number,
                actual_sequence: payload_round_identifier.sequence_number,
                actual_round: payload_round_identifier.round_number,
            });
        }

        // Check 2: Commit message's digest must match the ValidationContext's accepted_proposal_digest.
        let commit_digest = commit.payload().digest; // This is a B256 Hash
        if context.accepted_proposal_digest.is_none() {
            log::error!("Invalid Commit: ValidationContext has no accepted_proposal_digest for round {:?}/{:?}. This should not happen if a proposal was accepted.",
                context.current_sequence_number, context.current_round_number
            );
            return Err(QbftError::InternalError("Context missing accepted proposal digest for Commit validation".to_string()));
        }
        if Some(commit_digest) != context.accepted_proposal_digest {
            log::warn!(
                "Invalid Commit: Digest {:?} does not match accepted proposal digest {:?} for round {:?}/{:?}",
                commit_digest, context.accepted_proposal_digest, context.current_sequence_number, context.current_round_number
            );
            return Err(QbftError::CommitDigestMismatch);
        }

        // Check 3: Author of the Commit message must be one of the current_validators.
        let author = commit.author()?; // This is an Address
        if !context.current_validators.contains(&author) {
            log::warn!(
                "Invalid Commit: Author {:?} is not in the current validator set for round {:?}/{:?}. Validators: {:?}",
                author, context.current_sequence_number, context.current_round_number, context.current_validators
            );
            return Err(QbftError::NotAValidator { sender: author });
        }

        // Check 4: Validate the committed_seal signature.
        // `committed_seal` is `RlpSignature` which wraps `alloy_primitives::Signature`.
        // `RlpSignature` implements `Deref<Target = alloy_primitives::Signature>`.
        let committed_seal_ref = &commit.payload().committed_seal; 
        let digest_b256: B256 = commit_digest; // commit_digest is already B256

        match committed_seal_ref.recover_address_from_prehash(&digest_b256) {
            Ok(recovered_address_for_seal) => {
                if recovered_address_for_seal != author {
                    log::warn!(
                        "Invalid Commit: Commit seal signature recovery produced address {:?} which does not match author {:?} for round {:?}/{:?}",
                        recovered_address_for_seal,
                        author,
                        context.current_sequence_number, 
                        context.current_round_number
                    );
                    return Err(QbftError::InvalidSignature { sender: author }); 
                }
                // If recovery matches author, the signature is valid for that author over the digest.
            }
            Err(e) => {
                log::warn!(
                    "Invalid Commit: Failed to recover address from commit seal signature for claimed author {:?} and digest {:?}: {}. Round {:?}/{:?}", 
                    author, digest_b256, e, context.current_sequence_number, context.current_round_number
                );
                return Err(QbftError::CryptoError(format!("Commit seal signature recovery failed: {}", e)));
            }
        }
        
        Ok(())
    }
} 

#[cfg(test)]
pub mod tests {
    use super::*; // Bring in CommitValidatorImpl, CommitValidator, ValidationContext, QbftError
    use crate::messagewrappers::Commit; // BftMessage for constructing Commit
    use crate::payload::{CommitPayload}; 
    use crate::types::{ConsensusRoundIdentifier, NodeKey, SignedData, QbftConfig, QbftBlockHeader, QbftFinalState, BftExtraDataCodec, RlpSignature}; // Core types, RlpSignature for commit_seal
    use crate::mocks::MockQbftFinalState; // For creating ValidationContext
    use crate::validation::proposal_validator::tests::{testing_extradata_codec, default_parent_header, default_config, deterministic_node_key, deterministic_address_from_arc_key}; // Re-use test helpers
    use k256::ecdsa::{Signature as K256Signature, RecoveryId}; // Use new k256 API for recoverable signatures

    use alloy_primitives::{Address, B256, Signature as AlloySignature}; // Removed Parity
    use std::sync::Arc;
    use std::collections::HashSet;
    use rand::RngCore; // For random B256 generation

    // --- Test Helper: Create Commit Message ---
    fn create_commit_message(
        round_id: ConsensusRoundIdentifier,
        digest: B256,
        signer_key: &NodeKey, // Key for signing the BftMessage<CommitPayload>
        seal_signer_key: &NodeKey, // Key for creating the committed_seal over the digest
    ) -> Commit {
        // The committed_seal is a signature over the digest by the seal_signer_key
        let (k256_sig, recovery_id): (K256Signature, RecoveryId) = seal_signer_key.sign_prehash_recoverable(digest.as_slice()).expect("Failed to sign digest recoverably");
        
        // Normalize s part of k256 signature to be low, this is common practice.
        let normalized_k256_sig = k256_sig.normalize_s().unwrap_or(k256_sig);
        
        let r_bytes = normalized_k256_sig.r().to_bytes();
        let s_bytes = normalized_k256_sig.s().to_bytes();
        let recovery_id_byte = recovery_id.to_byte(); // Use the separate RecoveryId

        let r_uint = alloy_primitives::U256::from_be_slice(&r_bytes);
        let s_uint = alloy_primitives::U256::from_be_slice(&s_bytes);
        let y_parity_bool = recovery_id_byte % 2 == 1; 

        // Corrected: Use AlloySignature::new constructor, passing the bool directly. No .expect() as it returns Signature not Result.
        let alloy_sig = AlloySignature::new(r_uint, s_uint, y_parity_bool);

        let rlp_seal = RlpSignature(alloy_sig);

        let payload = CommitPayload::new(round_id, digest, rlp_seal);
        let signed_payload = SignedData::sign(payload, signer_key).expect("Failed to sign CommitPayload");
        Commit::new(signed_payload)
    }

    // --- Test Helper: Create ValidationContext (can reuse/adapt from prepare_validator) ---
    fn default_commit_validation_context(
        current_sequence: u64,
        current_round: u32,
        current_validators: HashSet<Address>,
        accepted_proposal_digest: Option<B256>,
        config_opt: Option<Arc<QbftConfig>>,
        parent_header_opt: Option<Arc<QbftBlockHeader>>,
        final_state_opt: Option<Arc<dyn QbftFinalState>>,
        extra_data_codec_opt: Option<Arc<dyn BftExtraDataCodec>>,
        expected_proposer_opt: Option<Address>,
        local_node_key_for_final_state: Arc<NodeKey>,
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
            parent_header,
            final_state,
            extra_data_codec,
            config,
            expected_proposer,
        }
    }

    // --- TODO: Test Cases ---
    #[test]
    fn test_validate_commit_valid() {
        let validator_key = deterministic_node_key(1); // Corrected: No extra Arc::new
        let validator_address = deterministic_address_from_arc_key(&validator_key);
        let validators = HashSet::from([validator_address]);

        let sequence = 1;
        let round = 0;
        let round_id = ConsensusRoundIdentifier::new(sequence, round);
        
        // Generate a random digest for the proposal
        let mut digest_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut digest_bytes);
        let digest = B256::from(digest_bytes);

        let context = default_commit_validation_context(
            sequence,
            round,
            validators.clone(),
            Some(digest), // Context has this digest as the accepted proposal
            None, None, None, None, None, validator_key.clone()
        );

        // Commit message is signed by validator_key, and its seal is also by validator_key over the same digest
        let commit_msg = create_commit_message(round_id, digest, &validator_key, &validator_key);
        
        let validator_impl = CommitValidatorImpl::new();
        let result = validator_impl.validate_commit(&commit_msg, &context);

        if result.is_err() {
            dbg!(result.as_ref().err()); // Print error for debugging
        }
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_commit_invalid_round_mismatch_sequence() {
        let validator_key = deterministic_node_key(1); // Corrected
        let validator_address = deterministic_address_from_arc_key(&validator_key);
        let validators = HashSet::from([validator_address]);

        let context_sequence = 1;
        let message_sequence = context_sequence + 1; // Mismatch
        let round = 0;

        let mut digest_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut digest_bytes);
        let digest = B256::from(digest_bytes);

        let context = default_commit_validation_context(
            context_sequence, // Context for seq 1
            round,
            validators.clone(),
            Some(digest),
            None, None, None, None, None, validator_key.clone()
        );

        let message_round_id = ConsensusRoundIdentifier::new(message_sequence, round);
        let commit_msg = create_commit_message(message_round_id, digest, &validator_key, &validator_key); // Msg for seq 2
        
        let validator_impl = CommitValidatorImpl::new();
        let result = validator_impl.validate_commit(&commit_msg, &context);
        assert!(matches!(result, Err(QbftError::MessageRoundMismatch { .. })));
    }

    #[test]
    fn test_validate_commit_invalid_round_mismatch_round_number() {
        let validator_key = deterministic_node_key(1); // Corrected
        let validator_address = deterministic_address_from_arc_key(&validator_key);
        let validators = HashSet::from([validator_address]);

        let sequence = 1;
        let context_round = 0;
        let message_round = context_round + 1; // Mismatch
        
        let mut digest_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut digest_bytes);
        let digest = B256::from(digest_bytes);

        let context = default_commit_validation_context(
            sequence,
            context_round, // Context for round 0
            validators.clone(),
            Some(digest),
            None, None, None, None, None, validator_key.clone()
        );

        let message_round_id = ConsensusRoundIdentifier::new(sequence, message_round);
        let commit_msg = create_commit_message(message_round_id, digest, &validator_key, &validator_key); // Msg for round 1
        
        let validator_impl = CommitValidatorImpl::new();
        let result = validator_impl.validate_commit(&commit_msg, &context);
        assert!(matches!(result, Err(QbftError::MessageRoundMismatch { .. })));
    }

    #[test]
    fn test_validate_commit_invalid_digest_mismatch() {
        let validator_key = deterministic_node_key(1); // Corrected
        let validator_address = deterministic_address_from_arc_key(&validator_key);
        let validators = HashSet::from([validator_address]);

        let sequence = 1;
        let round = 0;
        let round_id = ConsensusRoundIdentifier::new(sequence, round);

        let mut context_digest_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut context_digest_bytes);
        let context_digest = B256::from(context_digest_bytes);
        
        let mut message_digest_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut message_digest_bytes);
        let message_digest = B256::from(message_digest_bytes);
        assert_ne!(context_digest, message_digest, "Context and message digests should differ for this test");

        let context = default_commit_validation_context(
            sequence,
            round,
            validators.clone(),
            Some(context_digest), // Context expects context_digest
            None, None, None, None, None, validator_key.clone()
        );

        let commit_msg = create_commit_message(round_id, message_digest, &validator_key, &validator_key); // Msg has message_digest
        
        let validator_impl = CommitValidatorImpl::new();
        let result = validator_impl.validate_commit(&commit_msg, &context);
        assert!(matches!(result, Err(QbftError::CommitDigestMismatch)));
    }

    #[test]
    fn test_validate_commit_context_missing_digest() {
        let validator_key = deterministic_node_key(1); // Corrected
        let validator_address = deterministic_address_from_arc_key(&validator_key);
        let validators = HashSet::from([validator_address]);

        let sequence = 1;
        let round = 0;
        let round_id = ConsensusRoundIdentifier::new(sequence, round);

        let mut message_digest_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut message_digest_bytes);
        let message_digest = B256::from(message_digest_bytes);

        let context = default_commit_validation_context(
            sequence,
            round,
            validators.clone(),
            None, // Context has NO accepted digest
            None, None, None, None, None, validator_key.clone()
        );

        let commit_msg = create_commit_message(round_id, message_digest, &validator_key, &validator_key);
        
        let validator_impl = CommitValidatorImpl::new();
        let result = validator_impl.validate_commit(&commit_msg, &context);
        assert!(matches!(result, Err(QbftError::InternalError(_))));
    }

    #[test]
    fn test_validate_commit_invalid_author_not_validator() {
        let validator_in_set_key = deterministic_node_key(1); // Corrected
        let validator_in_set_address = deterministic_address_from_arc_key(&validator_in_set_key);
        let current_validators = HashSet::from([validator_in_set_address]);

        let non_validator_key = deterministic_node_key(2); // Corrected
        let non_validator_address = deterministic_address_from_arc_key(&non_validator_key);
        assert_ne!(validator_in_set_address, non_validator_address, "Validator and non-validator addresses should differ");

        let sequence = 1;
        let round = 0;
        let round_id = ConsensusRoundIdentifier::new(sequence, round);

        let mut digest_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut digest_bytes);
        let digest = B256::from(digest_bytes);

        let context = default_commit_validation_context(
            sequence,
            round,
            current_validators.clone(), // Context knows only validator_in_set_address
            Some(digest),
            None, None, None, None, None, validator_in_set_key.clone() // local_node_key for final state
        );

        // Commit message signed by non_validator_key (who is also the seal signer for simplicity here)
        let commit_msg = create_commit_message(round_id, digest, &non_validator_key, &non_validator_key); 
        
        let validator_impl = CommitValidatorImpl::new();
        let result = validator_impl.validate_commit(&commit_msg, &context);
        assert!(matches!(result, Err(QbftError::NotAValidator { sender }) if sender == non_validator_address));
    }

    #[test]
    fn test_validate_commit_invalid_seal_signature_wrong_signer() {
        let author_key = deterministic_node_key(1); // Corrected
        let author_address = deterministic_address_from_arc_key(&author_key);
        let validators = HashSet::from([author_address]);

        let seal_signer_key = deterministic_node_key(2); // Corrected
        let seal_signer_address = deterministic_address_from_arc_key(&seal_signer_key);
        assert_ne!(author_address, seal_signer_address, "Author and seal signer addresses should differ");

        let sequence = 1;
        let round = 0;
        let round_id = ConsensusRoundIdentifier::new(sequence, round);

        let mut digest_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut digest_bytes);
        let digest = B256::from(digest_bytes);

        let context = default_commit_validation_context(
            sequence,
            round,
            validators.clone(),
            Some(digest),
            None, None, None, None, None, author_key.clone()
        );

        // Commit BftMessage is signed by author_key, but the inner seal is signed by seal_signer_key
        let commit_msg = create_commit_message(round_id, digest, &author_key, &seal_signer_key); 
        
        let validator_impl = CommitValidatorImpl::new();
        let result = validator_impl.validate_commit(&commit_msg, &context);
        // Expecting InvalidSignature because the seal recovery won't match the BftMessage author
        assert!(matches!(result, Err(QbftError::InvalidSignature { sender }) if sender == author_address));
    }

    #[test]
    fn test_validate_commit_invalid_seal_signature_wrong_digest() {
        let author_key = deterministic_node_key(1);  // Corrected
        let author_address = deterministic_address_from_arc_key(&author_key);
        let validators = HashSet::from([author_address]);

        let sequence = 1;
        let round = 0;
        let round_id = ConsensusRoundIdentifier::new(sequence, round);

        let mut correct_digest_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut correct_digest_bytes);
        let correct_digest = B256::from(correct_digest_bytes); // This is the digest in the CommitPayload and context

        let mut different_digest_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut different_digest_bytes);
        let different_digest_for_seal = B256::from(different_digest_bytes); // Seal will be over this different digest
        assert_ne!(correct_digest, different_digest_for_seal, "Digests should differ for this test");

        let context = default_commit_validation_context(
            sequence,
            round,
            validators.clone(),
            Some(correct_digest), // Context expects the correct_digest
            None, None, None, None, None, author_key.clone()
        );
        
        // Create a CommitPayload with the correct_digest
        let (k256_sig_over_different_digest, recovery_id_for_different_digest): (K256Signature, RecoveryId) = author_key.as_ref().sign_prehash_recoverable(different_digest_for_seal.as_slice()).expect("Failed to sign different digest recoverably"); 
        let normalized_k256_sig = k256_sig_over_different_digest.normalize_s().unwrap_or(k256_sig_over_different_digest);
        let r_bytes = normalized_k256_sig.r().to_bytes();
        let s_bytes = normalized_k256_sig.s().to_bytes();
        let recovery_id_byte = recovery_id_for_different_digest.to_byte(); // Use the separate RecoveryId
        let r_uint = alloy_primitives::U256::from_be_slice(&r_bytes);
        let s_uint = alloy_primitives::U256::from_be_slice(&s_bytes);
        let y_parity_bool = recovery_id_byte % 2 == 1;
        let alloy_sig_over_different_digest = AlloySignature::new(r_uint, s_uint, y_parity_bool); 
        let rlp_seal_over_different_digest = RlpSignature(alloy_sig_over_different_digest);

        let payload_with_correct_digest = CommitPayload::new(round_id, correct_digest, rlp_seal_over_different_digest);
        let signed_payload = SignedData::sign(payload_with_correct_digest, &author_key).expect("Failed to sign CommitPayload");
        let commit_msg = Commit::new(signed_payload);
        
        let validator_impl = CommitValidatorImpl::new();
        let result = validator_impl.validate_commit(&commit_msg, &context);
        // Expecting InvalidSignature because the seal (over different_digest_for_seal) recovery 
        // will produce author_address, but when validate_commit re-checks this seal against payload.digest (correct_digest),
        // the recovery will fail or produce a different address.
        // The error QbftError::InvalidSignature is correct as the author of BftMessage is `author_key`
        // but the seal, when verified against `correct_digest` (from payload) will not match `author_key`'s address.
        assert!(matches!(result, Err(QbftError::InvalidSignature { sender }) if sender == author_address));
    }
} 