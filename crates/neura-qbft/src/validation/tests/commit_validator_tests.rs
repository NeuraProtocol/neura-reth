//! Tests for the CommitValidator implementation.

use super::common_helpers::*; // Import all common helpers, including sign_digest
use crate::validation::{CommitValidator, CommitValidatorImpl, ValidationContext};
use crate::types::{ConsensusRoundIdentifier, NodeKey, RlpSignature, QbftFinalState, SignedData}; // Added NodeKey, RlpSignature, QbftFinalState
use crate::messagewrappers::Commit;
use crate::payload::CommitPayload; // Removed QbftPayloadType
use crate::error::QbftError;
use std::sync::Arc;
use std::collections::HashSet;
use alloy_primitives::{Address, B256}; // Removed Signature, FixedBytes.
// Remove secp256k1::SecretKey, use NodeKey from common_helpers

fn create_signed_commit_for_test(
    sequence_number: u64,
    round_number: u64, // Round numbers in messages are u64
    proposal_digest: B256,
    signer_key: &NodeKey, // Use NodeKey
    seal_signer_key: &NodeKey, // Key for signing the committed_seal
) -> Commit {
    let round_id = ConsensusRoundIdentifier {
        sequence_number,
        round_number: round_number.try_into().unwrap(),
    };
    
    // The committed_seal is a signature over this proposal_digest by the seal_signer_key.
    let committed_seal_signature: RlpSignature = sign_digest(seal_signer_key, proposal_digest);

    let commit_payload = CommitPayload::new(
        round_id,
        proposal_digest,
        committed_seal_signature, // Directly use RlpSignature
    );

    // Sign the CommitPayload directly
    let signed_commit_payload: SignedData<CommitPayload> = SignedData::sign(commit_payload, signer_key)
        .expect("Failed to sign commit payload");
    
    // Commit::new expects SignedData<CommitPayload>
    Commit::new(signed_commit_payload)
}

#[test]
fn test_validate_commit_valid() {
    let config = default_config();
    let codec = testing_extradata_codec();

    let validator_key = deterministic_node_key(1);
    let validator_address = address_from_key(&validator_key);

    let proposer_key = deterministic_node_key(2); // Renamed for clarity
    let proposer_address = address_from_key(&proposer_key);

    let validators: HashSet<Address> = vec![validator_address, proposer_address].into_iter().collect();

    let parent_sequence: u64 = 0;
    let parent_gas_limit: u64 = 30_000_000;
    let parent_timestamp: u64 = 1_000_000;
    let parent_h = default_parent_header(parent_sequence, B256::ZERO, parent_timestamp, parent_gas_limit);

    let current_sequence = parent_sequence + 1;
    let current_round = 0u64; // Use u64 for consistency

    let accepted_proposal_digest = B256::from_slice(&[0xAB; 32]);

    let final_state_for_context: Arc<dyn QbftFinalState> = default_final_state(validator_key.clone(), validators.clone());

    let context = ValidationContext::new(
        current_sequence,
        current_round as u32, // Context expects u32 round
        validators.clone(),
        parent_h.clone(), 
        final_state_for_context.clone(), // Pass the trait object
        codec.clone(),
        config.clone(),
        Some(accepted_proposal_digest), // Context has an accepted proposal digest
        proposer_address,      
    );

    let commit_message = create_signed_commit_for_test(
        current_sequence, 
        current_round, 
        accepted_proposal_digest, 
        &validator_key, // Signer of the commit message
        &validator_key  // Signer of the committed_seal (same validator)
    );

    let commit_validator = CommitValidatorImpl::new();
    let result = commit_validator.validate_commit(&commit_message, &context);
    
    assert!(result.is_ok(), "Validation failed: {:?}", result.err());
}

#[test]
fn test_validate_commit_invalid_author_not_validator() {
    let config = default_config();
    let codec = testing_extradata_codec();

    let validator_key = deterministic_node_key(1);
    let validator_address = address_from_key(&validator_key);
    let proposer_key = deterministic_node_key(2);
    let proposer_address = address_from_key(&proposer_key);
    let validators: HashSet<Address> = vec![validator_address, proposer_address].into_iter().collect();

    let non_validator_key = deterministic_node_key(99); // Key not in validator set
    let non_validator_address = address_from_key(&non_validator_key);

    let parent_sequence: u64 = 0;
    let parent_h = default_parent_header(parent_sequence, B256::ZERO, 1_000_000, 30_000_000);
    let current_sequence = parent_sequence + 1;
    let current_round = 0u64;
    let accepted_proposal_digest = B256::from_slice(&[0xAB; 32]);

    let final_state_for_context: Arc<dyn QbftFinalState> = default_final_state(validator_key.clone(), validators.clone()); // Base state on a valid validator

    let context = ValidationContext::new(
        current_sequence, current_round as u32, validators.clone(), parent_h.clone(), 
        final_state_for_context.clone(), codec.clone(), config.clone(),
        Some(accepted_proposal_digest), proposer_address,
    );

    // Create commit signed by the non-validator
    let commit_message = create_signed_commit_for_test(
        current_sequence, 
        current_round, 
        accepted_proposal_digest, 
        &non_validator_key, // Signed by non-validator
        &non_validator_key  // Seal also signed by non-validator
    );

    let commit_validator = CommitValidatorImpl::new();
    let result = commit_validator.validate_commit(&commit_message, &context);

    // Expect ValidationAuthorNotValidator error, comparing against the non-validator's address
    assert!(matches!(result, Err(QbftError::ValidationAuthorNotValidator { author }) if author == non_validator_address),
            "Expected ValidationAuthorNotValidator with author {}, got {:?}", non_validator_address, result);
}

#[test]
fn test_validate_commit_round_mismatch() {
    let config = default_config();
    let codec = testing_extradata_codec();
    let validator_key = deterministic_node_key(1);
    let validator_address = address_from_key(&validator_key);
    let proposer_key = deterministic_node_key(2);
    let proposer_address = address_from_key(&proposer_key);
    let validators: HashSet<Address> = vec![validator_address, proposer_address].into_iter().collect();

    let parent_sequence: u64 = 0;
    let parent_h = default_parent_header(parent_sequence, B256::ZERO, 1_000_000, 30_000_000);
    let current_sequence = parent_sequence + 1;
    let context_round = 0u64;
    let commit_round = context_round + 1; // Mismatched round
    let accepted_proposal_digest = B256::from_slice(&[0xAB; 32]);

    let final_state_for_context: Arc<dyn QbftFinalState> = default_final_state(validator_key.clone(), validators.clone());

    // Context is for round 0
    let context = ValidationContext::new(
        current_sequence, context_round as u32, validators.clone(), parent_h.clone(), 
        final_state_for_context.clone(), codec.clone(), config.clone(),
        Some(accepted_proposal_digest), proposer_address,
    );

    // Commit message is for round 1
    let commit_message = create_signed_commit_for_test(
        current_sequence, 
        commit_round, // Use mismatched round
        accepted_proposal_digest, 
        &validator_key,
        &validator_key
    );

    let commit_validator = CommitValidatorImpl::new();
    let result = commit_validator.validate_commit(&commit_message, &context);

    // Expect MessageRoundMismatch when the round is incorrect
    assert!(matches!(result, Err(QbftError::MessageRoundMismatch { message_type, expected_sequence, expected_round, actual_sequence, actual_round })
        if message_type == "Commit" &&
           expected_sequence == current_sequence && expected_round == context_round as u32 &&
           actual_sequence == current_sequence && actual_round == commit_round as u32));
}

#[test]
fn test_validate_commit_sequence_mismatch() {
    let config = default_config();
    let codec = testing_extradata_codec();
    let validator_key = deterministic_node_key(1);
    let validator_address = address_from_key(&validator_key);
    let proposer_key = deterministic_node_key(2);
    let proposer_address = address_from_key(&proposer_key);
    let validators: HashSet<Address> = vec![validator_address, proposer_address].into_iter().collect();

    let parent_sequence: u64 = 0;
    let parent_h = default_parent_header(parent_sequence, B256::ZERO, 1_000_000, 30_000_000);
    let context_sequence = parent_sequence + 1;
    let commit_sequence = context_sequence + 1; // Mismatched sequence
    let current_round = 0u64;
    let accepted_proposal_digest = B256::from_slice(&[0xAB; 32]);

    let final_state_for_context: Arc<dyn QbftFinalState> = default_final_state(validator_key.clone(), validators.clone());

    // Context is for sequence context_sequence (1)
    let context = ValidationContext::new(
        context_sequence, current_round as u32, validators.clone(), parent_h.clone(), 
        final_state_for_context.clone(), codec.clone(), config.clone(),
        Some(accepted_proposal_digest), proposer_address,
    );

    // Commit message is for sequence commit_sequence (2)
    let commit_message = create_signed_commit_for_test(
        commit_sequence, // Use mismatched sequence
        current_round, 
        accepted_proposal_digest, 
        &validator_key,
        &validator_key
    );

    let commit_validator = CommitValidatorImpl::new();
    let result = commit_validator.validate_commit(&commit_message, &context);

    // Expect MessageRoundMismatch when the sequence is incorrect
    assert!(matches!(result, Err(QbftError::MessageRoundMismatch { message_type, expected_sequence, expected_round, actual_sequence, actual_round })
        if message_type == "Commit" &&
           expected_sequence == context_sequence && expected_round == current_round as u32 &&
           actual_sequence == commit_sequence && actual_round == current_round as u32));
}

#[test]
fn test_validate_commit_digest_mismatch() {
    let config = default_config();
    let codec = testing_extradata_codec();
    let validator_key = deterministic_node_key(1);
    let validator_address = address_from_key(&validator_key);
    let proposer_key = deterministic_node_key(2);
    let proposer_address = address_from_key(&proposer_key);
    let validators: HashSet<Address> = vec![validator_address, proposer_address].into_iter().collect();

    let parent_sequence: u64 = 0;
    let parent_h = default_parent_header(parent_sequence, B256::ZERO, 1_000_000, 30_000_000);
    let current_sequence = parent_sequence + 1;
    let current_round = 0u64;

    let context_proposal_digest = B256::from_slice(&[0xAA; 32]); // Digest expected by context
    let commit_digest = B256::from_slice(&[0xBB; 32]); // Different digest in commit message

    let final_state_for_context: Arc<dyn QbftFinalState> = default_final_state(validator_key.clone(), validators.clone());

    let context = ValidationContext::new(
        current_sequence, current_round as u32, validators.clone(), parent_h.clone(), 
        final_state_for_context.clone(), codec.clone(), config.clone(),
        Some(context_proposal_digest), // Context expects digest AA
        proposer_address,
    );

    // Create commit message with the incorrect digest (BB)
    // Seal is signed over commit_digest (BB)
    let commit_message = create_signed_commit_for_test(
        current_sequence, 
        current_round, 
        commit_digest, // Use mismatched digest
        &validator_key,
        &validator_key // Seal also signed over wrong digest
    );

    let commit_validator = CommitValidatorImpl::new();
    let result = commit_validator.validate_commit(&commit_message, &context);

    // Expect CommitDigestMismatch
    assert!(matches!(result, Err(QbftError::CommitDigestMismatch)));
}

#[test]
fn test_validate_commit_invalid_seal_signature_mismatched_author() {
    let config = default_config();
    let codec = testing_extradata_codec();

    let validator1_key = deterministic_node_key(1);
    let validator1_address = address_from_key(&validator1_key);
    let validator2_key = deterministic_node_key(2); // Second validator key
    let validator2_address = address_from_key(&validator2_key);
    let proposer_key = deterministic_node_key(3);
    let proposer_address = address_from_key(&proposer_key);
    let validators: HashSet<Address> = vec![validator1_address, validator2_address, proposer_address].into_iter().collect();

    let parent_sequence: u64 = 0;
    let parent_h = default_parent_header(parent_sequence, B256::ZERO, 1_000_000, 30_000_000);
    let current_sequence = parent_sequence + 1;
    let current_round = 0u64;
    let accepted_proposal_digest = B256::from_slice(&[0xAB; 32]);

    let final_state_for_context: Arc<dyn QbftFinalState> = default_final_state(validator1_key.clone(), validators.clone());

    let context = ValidationContext::new(
        current_sequence, current_round as u32, validators.clone(), parent_h.clone(), 
        final_state_for_context.clone(), codec.clone(), config.clone(),
        Some(accepted_proposal_digest), proposer_address,
    );

    // Create commit signed by validator1, but with seal signed by validator2
    let commit_message = create_signed_commit_for_test(
        current_sequence, 
        current_round, 
        accepted_proposal_digest, 
        &validator1_key,     // Commit message signed by validator1 (author)
        &validator2_key      // Seal signed by validator2
    );

    let commit_validator = CommitValidatorImpl::new();
    let result = commit_validator.validate_commit(&commit_message, &context);

    // The error should be InvalidSignature because the seal signature doesn't match the commit author
    assert!(matches!(result, Err(QbftError::InvalidSignature { sender }) if sender == validator1_address));
}

#[test]
fn test_validate_commit_invalid_seal_signature_recovery_fails() {
    let config = default_config();
    let codec = testing_extradata_codec();
    let validator_key = deterministic_node_key(1);
    let validator_address = address_from_key(&validator_key);
    let proposer_key = deterministic_node_key(2);
    let proposer_address = address_from_key(&proposer_key);
    let validators: HashSet<Address> = vec![validator_address, proposer_address].into_iter().collect();

    let parent_sequence: u64 = 0;
    let parent_h = default_parent_header(parent_sequence, B256::ZERO, 1_000_000, 30_000_000);
    let current_sequence = parent_sequence + 1;
    let current_round = 0u32;
    let accepted_proposal_digest = B256::from_slice(&[0xAB; 32]);

    let final_state_for_context: Arc<dyn QbftFinalState> = default_final_state(validator_key.clone(), validators.clone());

    let context = ValidationContext::new(
        current_sequence, current_round, validators.clone(), parent_h.clone(), 
        final_state_for_context.clone(), codec.clone(), config.clone(),
        Some(accepted_proposal_digest), proposer_address,
    );

    // Create the commit payload but with a deliberately invalid seal signature
    let round_id = ConsensusRoundIdentifier { sequence_number: current_sequence, round_number: current_round };
    
    // Create an invalid RlpSignature (e.g., by modifying a valid one)
    let valid_seal_signature = sign_digest(&validator_key, accepted_proposal_digest);
    let corrupted_sig = valid_seal_signature.into_inner(); // Get alloy_primitives::Signature
    // Flip some bits (example corruption)
    let mut corrupted_bytes = corrupted_sig.as_bytes();
    corrupted_bytes[0] ^= 0xff;
    let truly_corrupted_sig = alloy_primitives::Signature::from_raw(&corrupted_bytes)
        .expect("Failed to create corrupted signature from bytes");
    let corrupted_seal_signature = RlpSignature::from(truly_corrupted_sig);

    let commit_payload = CommitPayload::new(
        round_id,
        accepted_proposal_digest,
        corrupted_seal_signature, // Use the corrupted RlpSignature
    );

    // Sign the outer CommitPayload with the validator's key
    let signed_commit_payload: SignedData<CommitPayload> = SignedData::sign(commit_payload, &validator_key)
        .expect("Failed to sign commit payload");
    
    let commit_message = Commit::new(signed_commit_payload); 

    let commit_validator = CommitValidatorImpl::new();
    let result = commit_validator.validate_commit(&commit_message, &context);

    // Expecting InvalidSignature because signature recovery should fail or yield wrong key
    assert!(matches!(result, Err(QbftError::InvalidSignature { .. })));
} 