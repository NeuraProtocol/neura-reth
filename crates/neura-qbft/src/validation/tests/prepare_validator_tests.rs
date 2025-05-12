//! Tests for the PrepareValidator implementation.

use super::common_helpers::*; // Import all common helpers
use crate::validation::{PrepareValidator, PrepareValidatorImpl, ValidationContext}; // Import items under test
use crate::types::{ConsensusRoundIdentifier, QbftConfig, SignedData};
use crate::messagewrappers::Prepare;  // Import necessary types
use crate::error::QbftError;
use crate::payload::{PreparePayload};
use std::collections::HashSet;
use alloy_primitives::{Address, B256}; // Import primitives

#[test]
fn test_validate_prepare_valid() {
    let config = default_config();
    let codec = testing_extradata_codec();

    let validator_key = deterministic_node_key(1);
    let validator_address = deterministic_address_from_arc_key(&validator_key);

    let proposer_key = deterministic_node_key(2); // Different proposer
    let proposer_address = deterministic_address_from_arc_key(&proposer_key);

    let validators: HashSet<Address> = vec![validator_address, proposer_address].into_iter().collect();

    let parent_sequence: u64 = 0;
    let parent_gas_limit: u64 = 30_000_000;
    let parent_timestamp: u64 = 1_000_000;
    let parent_h = default_parent_header(parent_sequence, B256::ZERO, parent_timestamp, parent_gas_limit);

    let current_sequence = parent_sequence + 1;
    let current_round = 0;

    // Create a dummy proposal digest that the Prepare message will refer to
    let proposal_digest = B256::from_slice(&[0xAB; 32]);

    let final_state_for_context = default_final_state(validator_key.clone(), validators.clone());

    let context = ValidationContext::new(
        current_sequence,
        current_round,
        validators.clone(),
        parent_h.clone(), 
        final_state_for_context,
        codec.clone(),
        config.clone(),
        Some(proposal_digest), // Context has an accepted proposal digest
        proposer_address,      // Expected proposer for the round
    );

    // Create the Prepare message
    let prepare_round_id = ConsensusRoundIdentifier {
        sequence_number: current_sequence,
        round_number: current_round,
    };
    // Use helper functions from common_helpers if available, otherwise define inline
    let prepare_payload = PreparePayload::new(prepare_round_id, proposal_digest);
    let signed_prepare_payload = SignedData::sign(prepare_payload, validator_key.as_ref())
        .expect("Failed to sign prepare payload");
    let prepare_message = Prepare::new(signed_prepare_payload);

    // Create the validator instance
    let prepare_validator = PrepareValidatorImpl::new(); // Assuming PrepareValidatorImpl only needs config

    // Validate
    let result = prepare_validator.validate_prepare(&prepare_message, &context);
    
    if let Err(ref e) = result {
        eprintln!("Validation failed in test_validate_prepare_valid: {:?}", e);
    }
    assert!(result.is_ok());
}

#[test]
fn test_validate_prepare_invalid_author_not_validator() {
    let config = default_config();
    let codec = testing_extradata_codec();

    let validator_key = deterministic_node_key(1);
    let validator_address = deterministic_address_from_arc_key(&validator_key);
    
    let non_validator_key = deterministic_node_key(99); // Key not in the validator set
    let non_validator_address = deterministic_address_from_arc_key(&non_validator_key);

    let proposer_key = deterministic_node_key(2); 
    let proposer_address = deterministic_address_from_arc_key(&proposer_key);

    // Context's validator set only includes validator_address and proposer_address
    let validators: HashSet<Address> = vec![validator_address, proposer_address].into_iter().collect();

    let parent_sequence: u64 = 0;
    let parent_gas_limit: u64 = 30_000_000;
    let parent_timestamp: u64 = 1_000_000;
    let parent_h = default_parent_header(parent_sequence, B256::ZERO, parent_timestamp, parent_gas_limit);

    let current_sequence = parent_sequence + 1;
    let current_round = 0;
    let proposal_digest = B256::from_slice(&[0xAB; 32]);

    let final_state_for_context = default_final_state(validator_key.clone(), validators.clone()); // Context uses a valid validator key

    let context = ValidationContext::new(
        current_sequence, current_round, validators.clone(), parent_h.clone(), 
        final_state_for_context, codec.clone(), config.clone(),
        Some(proposal_digest), proposer_address,
    );

    // Create the Prepare message signed by the non-validator
    let prepare_round_id = ConsensusRoundIdentifier { sequence_number: current_sequence, round_number: current_round };
    let prepare_payload = PreparePayload::new(prepare_round_id, proposal_digest);
    let signed_prepare_payload = SignedData::sign(prepare_payload, non_validator_key.as_ref())
        .expect("Failed to sign prepare payload");
    let prepare_message = Prepare::new(signed_prepare_payload);

    let prepare_validator = PrepareValidatorImpl::new();
    let result = prepare_validator.validate_prepare(&prepare_message, &context);
    
    assert!(matches!(result, Err(QbftError::NotAValidator { sender }) if sender == non_validator_address));
}

#[test]
fn test_validate_prepare_round_mismatch() {
    let config = default_config();
    let codec = testing_extradata_codec();

    let validator_key = deterministic_node_key(1);
    let validator_address = deterministic_address_from_arc_key(&validator_key);
    let proposer_address = deterministic_address_from_arc_key(&deterministic_node_key(2));
    let validators: HashSet<Address> = vec![validator_address, proposer_address].into_iter().collect();

    let parent_sequence: u64 = 0;
    let parent_h = default_parent_header(parent_sequence, B256::ZERO, 1_000_000, 30_000_000);

    let current_sequence = parent_sequence + 1;
    let context_round = 0;
    let prepare_round = context_round + 1; // Mismatched round
    let proposal_digest = B256::from_slice(&[0xAB; 32]);

    let final_state_for_context = default_final_state(validator_key.clone(), validators.clone());

    // Context is for round 0
    let context = ValidationContext::new(
        current_sequence, context_round, validators.clone(), parent_h.clone(), 
        final_state_for_context, codec.clone(), config.clone(),
        Some(proposal_digest), proposer_address,
    );

    // Prepare message is for round 1
    let prepare_round_id = ConsensusRoundIdentifier { sequence_number: current_sequence, round_number: prepare_round };
    let prepare_payload = PreparePayload::new(prepare_round_id, proposal_digest);
    let signed_prepare_payload = SignedData::sign(prepare_payload, validator_key.as_ref()).unwrap();
    let prepare_message = Prepare::new(signed_prepare_payload);

    let prepare_validator = PrepareValidatorImpl::new();
    let result = prepare_validator.validate_prepare(&prepare_message, &context);
    
    assert!(matches!(result, Err(QbftError::MessageRoundMismatch { .. })));
    // We can be more specific if needed: check expected/actual rounds
}

#[test]
fn test_validate_prepare_sequence_mismatch() {
    let config = default_config();
    let codec = testing_extradata_codec();
    let validator_key = deterministic_node_key(1);
    let validator_address = deterministic_address_from_arc_key(&validator_key);
    let proposer_address = deterministic_address_from_arc_key(&deterministic_node_key(2));
    let validators: HashSet<Address> = vec![validator_address, proposer_address].into_iter().collect();

    let parent_sequence: u64 = 0;
    let parent_h = default_parent_header(parent_sequence, B256::ZERO, 1_000_000, 30_000_000);

    let context_sequence = parent_sequence + 1;
    let prepare_sequence = context_sequence + 1; // Mismatched sequence
    let current_round = 0;
    let proposal_digest = B256::from_slice(&[0xAB; 32]);

    let final_state_for_context = default_final_state(validator_key.clone(), validators.clone());

    // Context is for sequence context_sequence (1)
    let context = ValidationContext::new(
        context_sequence, current_round, validators.clone(), parent_h.clone(), 
        final_state_for_context, codec.clone(), config.clone(),
        Some(proposal_digest), proposer_address,
    );

    // Prepare message is for sequence prepare_sequence (2)
    let prepare_round_id = ConsensusRoundIdentifier { sequence_number: prepare_sequence, round_number: current_round };
    let prepare_payload = PreparePayload::new(prepare_round_id, proposal_digest);
    let signed_prepare_payload = SignedData::sign(prepare_payload, validator_key.as_ref()).unwrap();
    let prepare_message = Prepare::new(signed_prepare_payload);

    let prepare_validator = PrepareValidatorImpl::new();
    let result = prepare_validator.validate_prepare(&prepare_message, &context);
    
    assert!(matches!(result, Err(QbftError::MessageRoundMismatch { .. })));
    // We can be more specific if needed: check expected/actual sequences
}

#[test]
fn test_validate_prepare_digest_mismatch() {
    let config = default_config();
    let codec = testing_extradata_codec();
    let validator_key = deterministic_node_key(1);
    let validator_address = deterministic_address_from_arc_key(&validator_key);
    let proposer_address = deterministic_address_from_arc_key(&deterministic_node_key(2));
    let validators: HashSet<Address> = vec![validator_address, proposer_address].into_iter().collect();

    let parent_sequence: u64 = 0;
    let parent_h = default_parent_header(parent_sequence, B256::ZERO, 1_000_000, 30_000_000);

    let current_sequence = parent_sequence + 1;
    let current_round = 0;
    
    let context_proposal_digest = B256::from_slice(&[0xAA; 32]); // Digest expected by context
    let prepare_digest = B256::from_slice(&[0xBB; 32]); // Different digest in prepare message

    let final_state_for_context = default_final_state(validator_key.clone(), validators.clone());

    let context = ValidationContext::new(
        current_sequence, current_round, validators.clone(), parent_h.clone(), 
        final_state_for_context, codec.clone(), config.clone(),
        Some(context_proposal_digest), // Context expects digest AA
        proposer_address,
    );

    // Prepare message has digest BB
    let prepare_round_id = ConsensusRoundIdentifier { sequence_number: current_sequence, round_number: current_round };
    let prepare_payload = PreparePayload::new(prepare_round_id, prepare_digest);
    let signed_prepare_payload = SignedData::sign(prepare_payload, validator_key.as_ref()).unwrap();
    let prepare_message = Prepare::new(signed_prepare_payload);

    let prepare_validator = PrepareValidatorImpl::new();
    let result = prepare_validator.validate_prepare(&prepare_message, &context);
    
    assert!(matches!(result, Err(QbftError::PrepareDigestMismatch)));
}

// Remove the placeholder test if it exists
// #[test]
// fn test_placeholder_prepare_validator() {
//     assert!(true);
// } 