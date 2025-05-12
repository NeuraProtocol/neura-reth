//! Tests for the ProposalValidator implementation.

use super::common_helpers::*; // Import all common helpers
use crate::validation::{ProposalValidator, ProposalValidatorImpl, ValidationContext}; // Import items under test
use crate::types::{ConsensusRoundIdentifier, QbftConfig, QbftBlockHeader}; // Import necessary types, added QbftBlockHeader
use crate::error::QbftError;
use std::sync::Arc;
use std::collections::HashSet;
use alloy_primitives::{Address, B256, U256}; // Import primitives

#[test]
fn test_placeholder_proposal_validator() {
    // TODO: Move/implement actual proposal validation tests here.
    assert!(true);
}

#[test]
fn test_validate_payload_and_block_valid_proposal() {
    let config = default_config();
    let codec = testing_extradata_codec();

    let proposer_key = deterministic_node_key(1); // Using common_helpers
    let proposer_address = deterministic_address_from_arc_key(&proposer_key);

    let validator2_key = deterministic_node_key(2); // Using common_helpers
    let validator2_address = deterministic_address_from_arc_key(&validator2_key);

    let validators: HashSet<Address> = vec![proposer_address, validator2_address].into_iter().collect();
    let validators_vec: Vec<Address> = validators.iter().cloned().collect();

    let parent_sequence: u64 = 0;
    let parent_gas_limit: u64 = 30_000_000;
    let parent_timestamp: u64 = 1_000_000;
    let parent_h: Arc<QbftBlockHeader> = default_parent_header(parent_sequence, B256::ZERO, parent_timestamp, parent_gas_limit); // Using common_helpers

    let current_sequence = parent_sequence + 1;
    let current_round = 0;

    let expected_proposer = proposer_address;
    let final_state_for_context = default_final_state(proposer_key.clone(), validators.clone()); // Using common_helpers

    let context = default_validation_context( // Using common_helpers
        current_sequence,
        current_round,
        validators.clone(),
        parent_h.clone(),
        expected_proposer,
        config.clone(),
        codec.clone(),
        Some(final_state_for_context.clone()),
        proposer_key.clone(),
    );

    let block_beneficiary = proposer_address;
    let block_timestamp = parent_timestamp + 1;
    let block_gas_limit = parent_gas_limit;

    let proposed_block = default_qbft_block( // Using common_helpers
        parent_h.hash(),
        current_sequence,
        current_round,
        block_timestamp,
        block_gas_limit,
        block_beneficiary,
        codec.clone(),
        validators_vec.clone(),
    );

    let proposal_round_id = ConsensusRoundIdentifier {
        sequence_number: current_sequence,
        round_number: current_round,
    };
    let proposal_payload = create_proposal_payload(proposal_round_id, proposed_block.clone()); // Using common_helpers
    let signed_payload = create_signed_proposal_payload(proposal_payload, proposer_key.as_ref()); // Using common_helpers
    let bft_message = create_bft_message_proposal(signed_payload); // Using common_helpers
    
    let proposal_to_validate = create_proposal(bft_message, proposed_block.header.clone(), vec![], None); // Using common_helpers

    let proposal_validator = ProposalValidatorImpl::new(
        mock_message_validator_factory(false, false, false), // Mocks for other validators are OK
        mock_round_change_message_validator_factory(false),
        config.clone()
    );

    let result = proposal_validator.validate_proposal(&proposal_to_validate, &context);
    
    if let Err(ref e) = result {
        eprintln!("Validation failed in test_validate_payload_and_block_valid_proposal: {:?}", e);
    }
    assert!(result.is_ok());
}

#[test]
fn test_validate_proposal_invalid_author() {
    let config = default_config();
    let codec = testing_extradata_codec();

    let expected_proposer_key = deterministic_node_key(1);
    let expected_proposer_address = deterministic_address_from_arc_key(&expected_proposer_key);
    
    let actual_author_key = deterministic_node_key(2); // Different key for the actual author
    let actual_author_address = deterministic_address_from_arc_key(&actual_author_key);

    let validators: HashSet<Address> = vec![expected_proposer_address, actual_author_address].into_iter().collect();
    let validators_vec: Vec<Address> = validators.iter().cloned().collect();

    let parent_sequence: u64 = 0;
    let parent_gas_limit: u64 = 30_000_000;
    let parent_timestamp: u64 = 1_000_000;
    let parent_h = default_parent_header(parent_sequence, B256::ZERO, parent_timestamp, parent_gas_limit);

    let current_sequence = parent_sequence + 1;
    let current_round = 0;

    let final_state_for_context = default_final_state(expected_proposer_key.clone(), validators.clone());

    let context = default_validation_context(
        current_sequence,
        current_round,
        validators.clone(),
        parent_h.clone(),
        expected_proposer_address, // Context expects proposer 1
        config.clone(),
        codec.clone(),
        Some(final_state_for_context.clone()),
        expected_proposer_key.clone(),
    );

    // Block can be created fine, beneficiary doesn't matter for this specific check
    let proposed_block = default_qbft_block(
        parent_h.hash(),
        current_sequence,
        current_round,
        parent_timestamp + 1,
        parent_gas_limit,
        actual_author_address, // Block beneficiary can be the actual author
        codec.clone(),
        validators_vec.clone(),
    );

    let proposal_round_id = ConsensusRoundIdentifier {
        sequence_number: current_sequence,
        round_number: current_round,
    };
    let proposal_payload = create_proposal_payload(proposal_round_id, proposed_block.clone());
    // Proposal is signed by actual_author_key, but context expects expected_proposer_address
    let signed_payload = create_signed_proposal_payload(proposal_payload, actual_author_key.as_ref());
    let bft_message = create_bft_message_proposal(signed_payload);
    
    let proposal_to_validate = create_proposal(bft_message, proposed_block.header.clone(), vec![], None);

    let proposal_validator = ProposalValidatorImpl::new(
        mock_message_validator_factory(false, false, false),
        mock_round_change_message_validator_factory(false),
        config.clone()
    );

    // validate_proposal calls validate_payload_and_block internally, which checks the author
    let result = proposal_validator.validate_proposal(&proposal_to_validate, &context);
    
    assert!(matches!(result, Err(QbftError::ProposalNotFromProposer)));
}

#[test]
fn test_validate_proposal_round_mismatch() {
    let config = default_config();
    let codec = testing_extradata_codec();

    let proposer_key = deterministic_node_key(1);
    let proposer_address = deterministic_address_from_arc_key(&proposer_key);
    
    let validators: HashSet<Address> = vec![proposer_address].into_iter().collect();
    let validators_vec: Vec<Address> = validators.iter().cloned().collect();

    let parent_sequence: u64 = 0;
    let parent_gas_limit: u64 = 30_000_000;
    let parent_timestamp: u64 = 1_000_000;
    let parent_h = default_parent_header(parent_sequence, B256::ZERO, parent_timestamp, parent_gas_limit);

    let current_sequence = parent_sequence + 1;
    let context_current_round = 0;
    let payload_round = context_current_round + 1; // Mismatched round

    let final_state_for_context = default_final_state(proposer_key.clone(), validators.clone());

    let context = default_validation_context(
        current_sequence,
        context_current_round, // Context is for round 0
        validators.clone(),
        parent_h.clone(),
        proposer_address,
        config.clone(),
        codec.clone(),
        Some(final_state_for_context.clone()),
        proposer_key.clone(),
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
    let signed_payload = create_signed_proposal_payload(proposal_payload, proposer_key.as_ref());
    let bft_message = create_bft_message_proposal(signed_payload);
    
    let proposal_to_validate = create_proposal(bft_message, proposed_block.header.clone(), vec![], None);

    let proposal_validator = ProposalValidatorImpl::new(
        mock_message_validator_factory(false, false, false),
        mock_round_change_message_validator_factory(false),
        config.clone()
    );

    let result = proposal_validator.validate_proposal(&proposal_to_validate, &context);
    
    assert!(matches!(result, Err(QbftError::ProposalRoundMismatch { .. })));
}

#[test]
fn test_validate_proposal_invalid_parent_hash() {
    let config = default_config();
    let codec = testing_extradata_codec();

    let proposer_key = deterministic_node_key(1);
    let proposer_address = deterministic_address_from_arc_key(&proposer_key);
    
    let validators: HashSet<Address> = vec![proposer_address].into_iter().collect();
    let validators_vec: Vec<Address> = validators.iter().cloned().collect();

    let parent_sequence: u64 = 0;
    let parent_gas_limit: u64 = 30_000_000;
    let parent_timestamp: u64 = 1_000_000;
    
    let correct_parent_h = default_parent_header(parent_sequence, B256::ZERO, parent_timestamp, parent_gas_limit);
    // Incorrect parent hash for the block
    let incorrect_parent_hash = B256::from_slice(&[0xAA; 32]);

    let current_sequence = parent_sequence + 1;
    let current_round = 0;

    let final_state_for_context = default_final_state(proposer_key.clone(), validators.clone());

    let context = default_validation_context(
        current_sequence,
        current_round,
        validators.clone(),
        correct_parent_h.clone(), // Context uses the correct parent header
        proposer_address,
        config.clone(),
        codec.clone(),
        Some(final_state_for_context.clone()),
        proposer_key.clone(),
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
    let signed_payload = create_signed_proposal_payload(proposal_payload, proposer_key.as_ref());
    let bft_message = create_bft_message_proposal(signed_payload);
    
    let proposal_to_validate = create_proposal(bft_message, proposed_block.header.clone(), vec![], None);

    let proposal_validator = ProposalValidatorImpl::new(
        mock_message_validator_factory(false, false, false),
        mock_round_change_message_validator_factory(false),
        config.clone()
    );

    let result = proposal_validator.validate_proposal(&proposal_to_validate, &context);
    
    assert!(matches!(result, Err(QbftError::ProposalInvalidParentHash)));
}

#[test]
fn test_validate_proposal_invalid_block_number() {
    let config = default_config();
    let codec = testing_extradata_codec();

    let proposer_key = deterministic_node_key(1);
    let proposer_address = deterministic_address_from_arc_key(&proposer_key);
    
    let validators: HashSet<Address> = vec![proposer_address].into_iter().collect();
    let validators_vec: Vec<Address> = validators.iter().cloned().collect();

    let parent_sequence: u64 = 0;
    let parent_gas_limit: u64 = 30_000_000;
    let parent_timestamp: u64 = 1_000_000;
    let parent_h = default_parent_header(parent_sequence, B256::ZERO, parent_timestamp, parent_gas_limit);

    let context_sequence = parent_sequence + 1;
    let block_number_for_proposal = context_sequence + 1; // Mismatched block number
    let current_round = 0;

    let final_state_for_context = default_final_state(proposer_key.clone(), validators.clone());

    let context = default_validation_context(
        context_sequence, // Context expects this sequence
        current_round,
        validators.clone(),
        parent_h.clone(),
        proposer_address,
        config.clone(),
        codec.clone(),
        Some(final_state_for_context.clone()),
        proposer_key.clone(),
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

    // Proposal payload still for context's sequence/round for this test focus
    let proposal_round_id = ConsensusRoundIdentifier {
        sequence_number: context_sequence,
        round_number: current_round,
    };
    let proposal_payload = create_proposal_payload(proposal_round_id, proposed_block.clone());
    let signed_payload = create_signed_proposal_payload(proposal_payload, proposer_key.as_ref());
    let bft_message = create_bft_message_proposal(signed_payload);
    
    let proposal_to_validate = create_proposal(bft_message, proposed_block.header.clone(), vec![], None);

    let proposal_validator = ProposalValidatorImpl::new(
        mock_message_validator_factory(false, false, false),
        mock_round_change_message_validator_factory(false),
        config.clone()
    );

    let result = proposal_validator.validate_proposal(&proposal_to_validate, &context);
    
    assert!(matches!(result, Err(QbftError::ProposalInvalidBlockNumber)));
}

#[test]
fn test_validate_proposal_invalid_timestamp_not_after_parent() {
    let config = default_config();
    let codec = testing_extradata_codec();

    let proposer_key = deterministic_node_key(1);
    let proposer_address = deterministic_address_from_arc_key(&proposer_key);
    
    let validators: HashSet<Address> = vec![proposer_address].into_iter().collect();
    let validators_vec: Vec<Address> = validators.iter().cloned().collect();

    let parent_sequence: u64 = 0;
    let parent_gas_limit: u64 = 30_000_000;
    let parent_timestamp: u64 = 1_000_000;
    let parent_h = default_parent_header(parent_sequence, B256::ZERO, parent_timestamp, parent_gas_limit);

    let current_sequence = parent_sequence + 1;
    let current_round = 0;

    let final_state_for_context = default_final_state(proposer_key.clone(), validators.clone());

    let context = default_validation_context(
        current_sequence,
        current_round,
        validators.clone(),
        parent_h.clone(),
        proposer_address,
        config.clone(),
        codec.clone(),
        Some(final_state_for_context.clone()),
        proposer_key.clone(),
    );

    let proposed_block = default_qbft_block(
        parent_h.hash(),
        current_sequence,
        current_round,
        parent_timestamp, // Timestamp SAME as parent's, which is invalid
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
    let signed_payload = create_signed_proposal_payload(proposal_payload, proposer_key.as_ref());
    let bft_message = create_bft_message_proposal(signed_payload);
    
    let proposal_to_validate = create_proposal(bft_message, proposed_block.header.clone(), vec![], None);

    let proposal_validator = ProposalValidatorImpl::new(
        mock_message_validator_factory(false, false, false),
        mock_round_change_message_validator_factory(false),
        config.clone()
    );

    let result = proposal_validator.validate_proposal(&proposal_to_validate, &context);
    
    // Note: The error comes from the internal validate_payload_and_block function.
    assert!(matches!(result, Err(QbftError::ValidationError(s)) if s == "Block timestamp not after parent"));
}

#[test]
fn test_validate_proposal_extradata_round_mismatch() {
    let config = default_config();
    let codec = testing_extradata_codec();

    let proposer_key = deterministic_node_key(1);
    let proposer_address = deterministic_address_from_arc_key(&proposer_key);
    
    let validators: HashSet<Address> = vec![proposer_address].into_iter().collect();
    let validators_vec: Vec<Address> = validators.iter().cloned().collect();

    let parent_sequence: u64 = 0;
    let parent_gas_limit: u64 = 30_000_000;
    let parent_timestamp: u64 = 1_000_000;
    let parent_h = default_parent_header(parent_sequence, B256::ZERO, parent_timestamp, parent_gas_limit);

    let current_sequence = parent_sequence + 1;
    let context_current_round = 0;
    let extradata_round = context_current_round + 1; // Mismatched round in extra data

    let final_state_for_context = default_final_state(proposer_key.clone(), validators.clone());

    let context = default_validation_context(
        current_sequence,
        context_current_round, // Context expects round 0
        validators.clone(),
        parent_h.clone(),
        proposer_address,
        config.clone(),
        codec.clone(),
        Some(final_state_for_context.clone()),
        proposer_key.clone(),
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
    let signed_payload = create_signed_proposal_payload(proposal_payload, proposer_key.as_ref());
    let bft_message = create_bft_message_proposal(signed_payload);
    
    let proposal_to_validate = create_proposal(bft_message, proposed_block.header.clone(), vec![], None);

    let proposal_validator = ProposalValidatorImpl::new(
        mock_message_validator_factory(false, false, false),
        mock_round_change_message_validator_factory(false),
        config.clone()
    );

    let result = proposal_validator.validate_proposal(&proposal_to_validate, &context);
    
    assert!(matches!(result, Err(QbftError::ValidationError(s)) if s == "Round in block extra_data mismatch"));
}

#[test]
fn test_validate_proposal_extradata_validators_mismatch() {
    let config = default_config();
    let codec = testing_extradata_codec();

    let proposer_key = deterministic_node_key(1);
    let proposer_address = deterministic_address_from_arc_key(&proposer_key);
    
    let validator2_key = deterministic_node_key(2); // Another key for a different validator
    let validator2_address = deterministic_address_from_arc_key(&validator2_key);

    let context_validators_set: HashSet<Address> = vec![proposer_address, validator2_address].into_iter().collect();
    // Validators for the block's extra data will be different
    let block_extradata_validators_vec: Vec<Address> = vec![proposer_address]; // Only proposer

    let parent_sequence: u64 = 0;
    let parent_gas_limit: u64 = 30_000_000;
    let parent_timestamp: u64 = 1_000_000;
    let parent_h = default_parent_header(parent_sequence, B256::ZERO, parent_timestamp, parent_gas_limit);

    let current_sequence = parent_sequence + 1;
    let current_round = 0;

    let final_state_for_context = default_final_state(proposer_key.clone(), context_validators_set.clone());

    let context = default_validation_context(
        current_sequence,
        current_round,
        context_validators_set.clone(), // Context expects these validators
        parent_h.clone(),
        proposer_address,
        config.clone(),
        codec.clone(),
        Some(final_state_for_context.clone()),
        proposer_key.clone(),
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
    let signed_payload = create_signed_proposal_payload(proposal_payload, proposer_key.as_ref());
    let bft_message = create_bft_message_proposal(signed_payload);
    
    let proposal_to_validate = create_proposal(bft_message, proposed_block.header.clone(), vec![], None);

    let proposal_validator = ProposalValidatorImpl::new(
        mock_message_validator_factory(false, false, false),
        mock_round_change_message_validator_factory(false),
        config.clone()
    );

    let result = proposal_validator.validate_proposal(&proposal_to_validate, &context);
    
    assert!(matches!(result, Err(QbftError::ValidationError(s)) if s == "Validators in extra_data mismatch with context"));
}

#[test]
fn test_validate_proposal_invalid_difficulty() {
    let config = default_config();
    let codec = testing_extradata_codec();

    let proposer_key = deterministic_node_key(1);
    let proposer_address = deterministic_address_from_arc_key(&proposer_key);
    
    let validators: HashSet<Address> = vec![proposer_address].into_iter().collect();
    let validators_vec: Vec<Address> = validators.iter().cloned().collect();

    let parent_sequence: u64 = 0;
    let parent_gas_limit: u64 = 30_000_000;
    let parent_timestamp: u64 = 1_000_000;
    let parent_h = default_parent_header(parent_sequence, B256::ZERO, parent_timestamp, parent_gas_limit);

    let current_sequence = parent_sequence + 1;
    let current_round = 0;

    let final_state_for_context = default_final_state(proposer_key.clone(), validators.clone());

    let context = default_validation_context(
        current_sequence,
        current_round,
        validators.clone(),
        parent_h.clone(),
        proposer_address,
        config.clone(),
        codec.clone(),
        Some(final_state_for_context.clone()),
        proposer_key.clone(),
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
    let signed_payload = create_signed_proposal_payload(proposal_payload, proposer_key.as_ref());
    let bft_message = create_bft_message_proposal(signed_payload);
    
    let proposal_to_validate = create_proposal(bft_message, proposed_block.header.clone(), vec![], None);

    let proposal_validator = ProposalValidatorImpl::new(
        mock_message_validator_factory(false, false, false),
        mock_round_change_message_validator_factory(false),
        config.clone()
    );

    let result = proposal_validator.validate_proposal(&proposal_to_validate, &context);
    
    assert!(matches!(result, Err(QbftError::ValidationError(s)) if s == "Block difficulty not 1"));
}

#[test]
fn test_validate_proposal_invalid_nonce() {
    let config = default_config();
    let codec = testing_extradata_codec();

    let proposer_key = deterministic_node_key(1);
    let proposer_address = deterministic_address_from_arc_key(&proposer_key);
    
    let validators: HashSet<Address> = vec![proposer_address].into_iter().collect();
    let validators_vec: Vec<Address> = validators.iter().cloned().collect();

    let parent_sequence: u64 = 0;
    let parent_gas_limit: u64 = 30_000_000;
    let parent_timestamp: u64 = 1_000_000;
    let parent_h = default_parent_header(parent_sequence, B256::ZERO, parent_timestamp, parent_gas_limit);

    let current_sequence = parent_sequence + 1;
    let current_round = 0;

    let final_state_for_context = default_final_state(proposer_key.clone(), validators.clone());

    let context = default_validation_context(
        current_sequence,
        current_round,
        validators.clone(),
        parent_h.clone(),
        proposer_address,
        config.clone(),
        codec.clone(),
        Some(final_state_for_context.clone()),
        proposer_key.clone(),
    );

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
    // QbftBlockHeader requires 8-byte nonce, default_qbft_block provides this.
    // To make it invalid, we set it to something else, e.g., non-zero.
    proposed_block.header.nonce = alloy_primitives::Bytes::from_static(&[0u8; 7]); // Invalid length

    let proposal_round_id = ConsensusRoundIdentifier {
        sequence_number: current_sequence,
        round_number: current_round,
    };
    let proposal_payload = create_proposal_payload(proposal_round_id, proposed_block.clone());
    let signed_payload = create_signed_proposal_payload(proposal_payload, proposer_key.as_ref());
    let bft_message = create_bft_message_proposal(signed_payload);
    let proposal_to_validate = create_proposal(bft_message, proposed_block.header.clone(), vec![], None);

    let proposal_validator = ProposalValidatorImpl::new(
        mock_message_validator_factory(false, false, false),
        mock_round_change_message_validator_factory(false),
        config.clone()
    );
    let result = proposal_validator.validate_proposal(&proposal_to_validate, &context);
    assert!(matches!(result, Err(QbftError::ValidationError(s)) if s == "Block nonce not 0"));

    // Test with non-zero 8-byte nonce
    proposed_block.header.nonce = alloy_primitives::Bytes::from_static(&[0, 0, 0, 0, 0, 0, 0, 1]); 
    let proposal_payload_2 = create_proposal_payload(proposal_round_id, proposed_block.clone());
    let signed_payload_2 = create_signed_proposal_payload(proposal_payload_2, proposer_key.as_ref());
    let bft_message_2 = create_bft_message_proposal(signed_payload_2);
    let proposal_to_validate_2 = create_proposal(bft_message_2, proposed_block.header.clone(), vec![], None);
    let result_2 = proposal_validator.validate_proposal(&proposal_to_validate_2, &context);
    assert!(matches!(result_2, Err(QbftError::ValidationError(s)) if s == "Block nonce not 0"));
}

#[test]
fn test_validate_proposal_gas_limit_too_high() {
    let mut config = QbftConfig::default();
    config.gas_limit_bound_divisor = 1024; // Standard divisor
    let arc_config = Arc::new(config);
    let codec = testing_extradata_codec();

    let proposer_key = deterministic_node_key(1);
    let proposer_address = deterministic_address_from_arc_key(&proposer_key);
    
    let validators: HashSet<Address> = vec![proposer_address].into_iter().collect();
    let validators_vec: Vec<Address> = validators.iter().cloned().collect();

    let parent_sequence: u64 = 0;
    let parent_gas_limit: u64 = 30_000_000;
    let parent_timestamp: u64 = 1_000_000;
    let parent_h = default_parent_header(parent_sequence, B256::ZERO, parent_timestamp, parent_gas_limit);

    let current_sequence = parent_sequence + 1;
    let current_round = 0;

    let final_state_for_context = default_final_state(proposer_key.clone(), validators.clone());

    let context = default_validation_context(
        current_sequence,
        current_round,
        validators.clone(),
        parent_h.clone(),
        proposer_address,
        arc_config.clone(), // Use the configured QbftConfig
        codec.clone(),
        Some(final_state_for_context.clone()),
        proposer_key.clone(),
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
    let signed_payload = create_signed_proposal_payload(proposal_payload, proposer_key.as_ref());
    let bft_message = create_bft_message_proposal(signed_payload);
    
    let proposal_to_validate = create_proposal(bft_message, proposed_block.header.clone(), vec![], None);

    let proposal_validator = ProposalValidatorImpl::new(
        mock_message_validator_factory(false, false, false),
        mock_round_change_message_validator_factory(false),
        arc_config.clone()
    );

    let result = proposal_validator.validate_proposal(&proposal_to_validate, &context);
    
    assert!(matches!(result, Err(QbftError::ValidationError(s)) if s == "Gas limit outside allowed delta of parent"));
}

#[test]
fn test_validate_proposal_gas_limit_too_low_outside_delta() {
    let mut config = QbftConfig::default();
    config.gas_limit_bound_divisor = 1024;
    config.min_gas_limit = 5000; // Ensure min_gas_limit is set for the test
    let arc_config = Arc::new(config);
    let codec = testing_extradata_codec();

    let proposer_key = deterministic_node_key(1);
    let proposer_address = deterministic_address_from_arc_key(&proposer_key);
    
    let validators: HashSet<Address> = vec![proposer_address].into_iter().collect();
    let validators_vec: Vec<Address> = validators.iter().cloned().collect();

    let parent_sequence: u64 = 0;
    let parent_gas_limit: u64 = 30_000_000;
    let parent_timestamp: u64 = 1_000_000;
    let parent_h = default_parent_header(parent_sequence, B256::ZERO, parent_timestamp, parent_gas_limit);

    let current_sequence = parent_sequence + 1;
    let current_round = 0;

    let final_state_for_context = default_final_state(proposer_key.clone(), validators.clone());

    let context = default_validation_context(
        current_sequence,
        current_round,
        validators.clone(),
        parent_h.clone(),
        proposer_address,
        arc_config.clone(),
        codec.clone(),
        Some(final_state_for_context.clone()),
        proposer_key.clone(),
    );

    let max_delta = parent_gas_limit / arc_config.gas_limit_bound_divisor;
    let invalid_low_gas_limit = parent_gas_limit.saturating_sub(max_delta).saturating_sub(1);
    
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
    let signed_payload = create_signed_proposal_payload(proposal_payload, proposer_key.as_ref());
    let bft_message = create_bft_message_proposal(signed_payload);
    
    let proposal_to_validate = create_proposal(bft_message, proposed_block.header.clone(), vec![], None);

    let proposal_validator = ProposalValidatorImpl::new(
        mock_message_validator_factory(false, false, false),
        mock_round_change_message_validator_factory(false),
        arc_config.clone()
    );

    let result = proposal_validator.validate_proposal(&proposal_to_validate, &context);
    
    assert!(matches!(result, Err(QbftError::ValidationError(s)) if s == "Gas limit outside allowed delta of parent"));
}

#[test]
fn test_validate_proposal_gas_limit_below_minimum() {
    let mut config = QbftConfig::default();
    config.min_gas_limit = 5000;
    config.gas_limit_bound_divisor = 1024; 
    let arc_config = Arc::new(config);
    let codec = testing_extradata_codec();

    let proposer_key = deterministic_node_key(1);
    let proposer_address = deterministic_address_from_arc_key(&proposer_key);
    
    let validators: HashSet<Address> = vec![proposer_address].into_iter().collect();
    let validators_vec: Vec<Address> = validators.iter().cloned().collect();

    let parent_sequence: u64 = 0;
    let parent_gas_limit: u64 = arc_config.min_gas_limit * 2;
    let parent_timestamp: u64 = 1_000_000;
    let parent_h = default_parent_header(parent_sequence, B256::ZERO, parent_timestamp, parent_gas_limit);

    let current_sequence = parent_sequence + 1;
    let current_round = 0;

    let final_state_for_context = default_final_state(proposer_key.clone(), validators.clone());

    let context = default_validation_context(
        current_sequence,
        current_round,
        validators.clone(),
        parent_h.clone(),
        proposer_address,
        arc_config.clone(),
        codec.clone(),
        Some(final_state_for_context.clone()),
        proposer_key.clone(),
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
    let signed_payload = create_signed_proposal_payload(proposal_payload, proposer_key.as_ref());
    let bft_message = create_bft_message_proposal(signed_payload);
    
    let proposal_to_validate = create_proposal(bft_message, proposed_block.header.clone(), vec![], None);

    let proposal_validator = ProposalValidatorImpl::new(
        mock_message_validator_factory(false, false, false),
        mock_round_change_message_validator_factory(false),
        arc_config.clone()
    );

    let result = proposal_validator.validate_proposal(&proposal_to_validate, &context);
    
    let expected_error_msg = format!("Gas limit {} below minimum {}", invalid_low_gas_limit, arc_config.min_gas_limit);
    assert!(matches!(result, Err(QbftError::ValidationError(s)) if s == expected_error_msg));
}

#[test]
fn test_validate_proposal_gas_used_exceeds_gas_limit() {
    let config = default_config(); // Standard config is fine for this test
    let arc_config = config.clone(); // Use Arc for consistency
    let codec = testing_extradata_codec();

    let proposer_key = deterministic_node_key(1);
    let proposer_address = deterministic_address_from_arc_key(&proposer_key);
    
    let validators: HashSet<Address> = vec![proposer_address].into_iter().collect();
    let validators_vec: Vec<Address> = validators.iter().cloned().collect();

    let parent_sequence: u64 = 0;
    let parent_gas_limit: u64 = 30_000_000;
    let parent_timestamp: u64 = 1_000_000;
    let parent_h = default_parent_header(parent_sequence, B256::ZERO, parent_timestamp, parent_gas_limit);

    let current_sequence = parent_sequence + 1;
    let current_round = 0;

    let final_state_for_context = default_final_state(proposer_key.clone(), validators.clone());

    let context = default_validation_context(
        current_sequence,
        current_round,
        validators.clone(),
        parent_h.clone(),
        proposer_address,
        arc_config.clone(),
        codec.clone(),
        Some(final_state_for_context.clone()),
        proposer_key.clone(),
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
    let signed_payload = create_signed_proposal_payload(proposal_payload, proposer_key.as_ref());
    let bft_message = create_bft_message_proposal(signed_payload);
    
    let proposal_to_validate = create_proposal(bft_message, proposed_block.header.clone(), vec![], None);

    let proposal_validator = ProposalValidatorImpl::new(
        mock_message_validator_factory(false, false, false),
        mock_round_change_message_validator_factory(false),
        arc_config.clone()
    );

    let result = proposal_validator.validate_proposal(&proposal_to_validate, &context);
    
    assert!(matches!(result, Err(QbftError::ValidationError(s)) if s == "Block gas_used exceeds gas_limit"));
}

#[test]
fn test_validate_proposal_with_invalid_round_changes() {
    let config = default_config();
    let codec = testing_extradata_codec();

    let proposer_key = deterministic_node_key(1);
    let proposer_address = deterministic_address_from_arc_key(&proposer_key);
    
    let validator2_key = deterministic_node_key(2);
    let validator2_address = deterministic_address_from_arc_key(&validator2_key);

    let validators: HashSet<Address> = vec![proposer_address, validator2_address].into_iter().collect();
    let validators_vec: Vec<Address> = validators.iter().cloned().collect();

    let parent_sequence: u64 = 0;
    let parent_gas_limit: u64 = 30_000_000;
    let parent_timestamp: u64 = 1_000_000;
    let parent_h = default_parent_header(parent_sequence, B256::ZERO, parent_timestamp, parent_gas_limit);

    let current_sequence = parent_sequence + 1;
    let current_round = 1; // Proposal in a later round, suggesting round changes might exist

    let final_state_for_context = default_final_state(proposer_key.clone(), validators.clone());

    let context = default_validation_context(
        current_sequence,
        current_round,
        validators.clone(),
        parent_h.clone(),
        proposer_address,
        config.clone(),
        codec.clone(),
        Some(final_state_for_context.clone()),
        proposer_key.clone(),
    );

    let block_beneficiary = proposer_address;
    let block_timestamp = parent_timestamp + 1;
    let block_gas_limit = parent_gas_limit;

    let proposed_block = default_qbft_block(
        parent_h.hash(),
        current_sequence,
        current_round,
        block_timestamp,
        block_gas_limit,
        block_beneficiary,
        codec.clone(),
        validators_vec.clone(),
    );

    // Create some round change messages for a previous round (e.g., round 0)
    let rc_round_id = ConsensusRoundIdentifier { sequence_number: current_sequence, round_number: 0 };
    let rc_payload = create_round_change_payload(rc_round_id, None, None); // No prepared metadata or block
    let signed_rc_payload1 = create_signed_round_change_payload(rc_payload.clone(), proposer_key.as_ref());
    let round_change1 = create_round_change(signed_rc_payload1.clone(), None, None); // Pass signed payload, no block/prepares

    let signed_rc_payload2 = create_signed_round_change_payload(rc_payload, validator2_key.as_ref());
    let round_change2 = create_round_change(signed_rc_payload2.clone(), None, None); // Pass signed payload, no block/prepares

    let proposal_round_id = ConsensusRoundIdentifier {
        sequence_number: current_sequence,
        round_number: current_round,
    };
    let proposal_payload = create_proposal_payload(proposal_round_id, proposed_block.clone());
    let signed_proposal_payload = create_signed_proposal_payload(proposal_payload, proposer_key.as_ref());
    let bft_proposal_message = create_bft_message_proposal(signed_proposal_payload);
    
    // Include the round changes in the proposal
    let proposal_to_validate = create_proposal(bft_proposal_message, proposed_block.header.clone(), vec![round_change1, round_change2], None);

    // Mock the RoundChangeMessageValidatorFactory to return a validator that *fails*
    let failing_rc_validator_factory = mock_round_change_message_validator_factory(true); // true means it will error

    let proposal_validator = ProposalValidatorImpl::new(
        mock_message_validator_factory(false, false, false), // Other validators are OK
        failing_rc_validator_factory, // Use the failing one here
        config.clone()
    );

    let result = proposal_validator.validate_proposal(&proposal_to_validate, &context);
    
    assert!(matches!(result, Err(QbftError::RoundChangeValidationError(_))));
}

#[test]
fn test_validate_proposal_with_valid_round_changes() {
    let config = default_config();
    let codec = testing_extradata_codec();

    let proposer_key = deterministic_node_key(1);
    let proposer_address = deterministic_address_from_arc_key(&proposer_key);
    
    let validator2_key = deterministic_node_key(2);
    let validator2_address = deterministic_address_from_arc_key(&validator2_key);

    let validators: HashSet<Address> = vec![proposer_address, validator2_address].into_iter().collect();
    let validators_vec: Vec<Address> = validators.iter().cloned().collect();

    let parent_sequence: u64 = 0;
    let parent_gas_limit: u64 = 30_000_000;
    let parent_timestamp: u64 = 1_000_000;
    let parent_h = default_parent_header(parent_sequence, B256::ZERO, parent_timestamp, parent_gas_limit);

    let current_sequence = parent_sequence + 1;
    let current_round = 1; // Proposal in round 1

    let final_state_for_context = default_final_state(proposer_key.clone(), validators.clone());

    let context = default_validation_context(
        current_sequence,
        current_round,
        validators.clone(),
        parent_h.clone(),
        proposer_address,
        config.clone(),
        codec.clone(),
        Some(final_state_for_context.clone()),
        proposer_key.clone(),
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

    // Round changes for round 0
    let rc_round_id = ConsensusRoundIdentifier { sequence_number: current_sequence, round_number: 0 };
    let rc_payload = create_round_change_payload(rc_round_id, None, None); // No prepared metadata or block
    let signed_rc_payload1 = create_signed_round_change_payload(rc_payload.clone(), proposer_key.as_ref());
    let round_change1 = create_round_change(signed_rc_payload1.clone(), None, None); // Pass signed payload, no block/prepares

    let signed_rc_payload2 = create_signed_round_change_payload(rc_payload, validator2_key.as_ref());
    let round_change2 = create_round_change(signed_rc_payload2.clone(), None, None); // Pass signed payload, no block/prepares

    let proposal_round_id = ConsensusRoundIdentifier {
        sequence_number: current_sequence,
        round_number: current_round,
    };
    let proposal_payload = create_proposal_payload(proposal_round_id, proposed_block.clone());
    let signed_proposal_payload = create_signed_proposal_payload(proposal_payload, proposer_key.as_ref());
    let bft_proposal_message = create_bft_message_proposal(signed_proposal_payload);
    
    let proposal_to_validate = create_proposal(bft_proposal_message, proposed_block.header.clone(), vec![round_change1, round_change2], None);

    // Mock the RoundChangeMessageValidatorFactory to return a validator that *succeeds*
    let succeeding_rc_validator_factory = mock_round_change_message_validator_factory(false); // false means it will succeed

    let proposal_validator = ProposalValidatorImpl::new(
        mock_message_validator_factory(false, false, false),
        succeeding_rc_validator_factory, // Use the succeeding one
        config.clone()
    );

    let result = proposal_validator.validate_proposal(&proposal_to_validate, &context);
    if let Err(e) = &result {
        eprintln!("Validation failed in test_validate_proposal_with_valid_round_changes: {:?}", e);
    }
    assert!(result.is_ok());
}

#[test]
fn test_validate_proposal_round_higher_than_latest_rc_message() {
    let config = default_config();
    let codec = testing_extradata_codec();

    let proposer_key = deterministic_node_key(1);
    let proposer_address = deterministic_address_from_arc_key(&proposer_key);
    
    let validator2_key = deterministic_node_key(2);
    let validator2_address = deterministic_address_from_arc_key(&validator2_key);

    let validators: HashSet<Address> = vec![proposer_address, validator2_address].into_iter().collect();
    let validators_vec: Vec<Address> = validators.iter().cloned().collect();

    let parent_sequence: u64 = 0;
    let parent_gas_limit: u64 = 30_000_000;
    let parent_timestamp: u64 = 1_000_000;
    let parent_h = default_parent_header(parent_sequence, B256::ZERO, parent_timestamp, parent_gas_limit);

    let current_sequence = parent_sequence + 1;
    let proposal_round = 2; // Proposal in round 2
    let latest_rc_round = 0; // Latest RC message is for round 0

    let final_state_for_context = default_final_state(proposer_key.clone(), validators.clone());

    // Context is for the proposal_round
    let context = default_validation_context(
        current_sequence,
        proposal_round, 
        validators.clone(),
        parent_h.clone(),
        proposer_address,
        config.clone(),
        codec.clone(),
        Some(final_state_for_context.clone()),
        proposer_key.clone(),
    );

    let proposed_block = default_qbft_block(
        parent_h.hash(),
        current_sequence,
        proposal_round, // Block matches proposal round
        parent_timestamp + 1,
        parent_gas_limit,
        proposer_address,
        codec.clone(),
        validators_vec.clone(),
    );

    // Round changes only for `latest_rc_round` (e.g. round 0)
    let rc_round_id = ConsensusRoundIdentifier { sequence_number: current_sequence, round_number: latest_rc_round };
    let rc_payload = create_round_change_payload(rc_round_id, None, None); // No prepared metadata or block
    let signed_rc_payload1 = create_signed_round_change_payload(rc_payload.clone(), proposer_key.as_ref());
    let round_change1 = create_round_change(signed_rc_payload1.clone(), None, None); // Pass signed payload, no block/prepares

    let signed_rc_payload2 = create_signed_round_change_payload(rc_payload, validator2_key.as_ref());
    let round_change2 = create_round_change(signed_rc_payload2.clone(), None, None); // Pass signed payload, no block/prepares

    let proposal_round_id_for_payload = ConsensusRoundIdentifier {
        sequence_number: current_sequence,
        round_number: proposal_round, // Payload for round 2
    };
    let proposal_payload = create_proposal_payload(proposal_round_id_for_payload, proposed_block.clone());
    let signed_proposal_payload = create_signed_proposal_payload(proposal_payload, proposer_key.as_ref());
    let bft_proposal_message = create_bft_message_proposal(signed_proposal_payload);
    
    // Proposal includes RCs from round 0, but proposal itself is for round 2.
    // The check is proposal_round == latest_rc_round + 1
    // So, 2 != 0 + 1, which is an error.
    let proposal_to_validate = create_proposal(bft_proposal_message, proposed_block.header.clone(), vec![round_change1, round_change2], None);

    // RCs themselves are considered valid for this test
    let succeeding_rc_validator_factory = mock_round_change_message_validator_factory(false); 

    let proposal_validator = ProposalValidatorImpl::new(
        mock_message_validator_factory(false, false, false),
        succeeding_rc_validator_factory,
        config.clone()
    );

    let result = proposal_validator.validate_proposal(&proposal_to_validate, &context);
    
    assert!(matches!(result, Err(QbftError::ProposalRoundNotFollowingRoundChanges)));
}

// End of ProposalValidator tests