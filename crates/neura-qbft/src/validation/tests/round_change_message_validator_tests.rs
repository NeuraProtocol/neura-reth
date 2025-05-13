//! Tests for RoundChangeMessageValidatorImpl.

use super::common_helpers::*;
use crate::messagewrappers::{RoundChange,BftMessage};
use crate::payload::{RoundChangePayload, PreparePayload, ProposalPayload, PreparedRoundMetadata};
use crate::types::{ConsensusRoundIdentifier, SignedData, QbftConfig, QbftBlockHeader, NodeKey, QbftBlock, BftExtraDataCodec, QbftFinalState};
use crate::validation::{RoundChangeMessageValidator, ValidationContext, MessageValidatorFactoryImpl, MessageValidatorFactory, ProposalValidatorImpl, RoundChangeMessageValidatorFactory, RoundChangeMessageValidatorFactoryImpl};
use crate::error::QbftError;
use crate::mocks::MockQbftFinalState;
use alloy_primitives::{Address, B256};
use std::collections::HashSet;
use std::sync::Arc;

// Helper to create the validator with mocks
fn create_rc_validator(
    config: Arc<QbftConfig>,
    local_node_key: Arc<NodeKey>,
    validators: HashSet<Address>,
    parent_header_to_add: Option<Arc<QbftBlockHeader>>, // Add optional parent header
) -> (Arc<dyn RoundChangeMessageValidator + Send + Sync>, Arc<dyn QbftFinalState + Send + Sync>) {
    let _codec = testing_extradata_codec();
    let mut final_state = MockQbftFinalState::new(local_node_key.clone(), validators); // Make mutable
    
    // Add the header if provided
    if let Some(header) = parent_header_to_add {
        final_state.add_known_header(header);
    }

    let final_state_arc: Arc<dyn QbftFinalState + Send + Sync> = Arc::new(final_state);

    // Create real dependencies for RoundChangeMessageValidatorFactory
    let mock_rc_factory_for_mvf = mock_round_change_message_validator_factory(false); // Mock for MessageValidatorFactoryImpl
    let message_validator_factory: Arc<dyn MessageValidatorFactory> = Arc::new(MessageValidatorFactoryImpl::new(config.clone(), mock_rc_factory_for_mvf.clone()));

    // Create a ProposalValidator instance.
    // It needs a RoundChangeMessageValidatorFactory. We provide a mock one here to break the cycle,
    let mock_rc_factory_for_proposal_validator = mock_round_change_message_validator_factory(false); // false = not failing
    let _proposal_validator = Arc::new(ProposalValidatorImpl::new(
        message_validator_factory.clone(),
        mock_rc_factory_for_proposal_validator,
        config.clone()
    ));

    // Create the real factory that produces the validator we want to test
    // This RoundChangeMessageValidatorFactoryImpl will use the proposal_validator created above.
    let rc_validator_factory = RoundChangeMessageValidatorFactoryImpl::new(
        message_validator_factory.clone(),
        config.clone(),
    );

    // Use the factory to create the validator
    let rc_validator = rc_validator_factory.create_round_change_message_validator();

    (rc_validator, final_state_arc) // Return Arc
}

// Helper to create a basic signed RoundChange message
fn create_basic_signed_rc(
    sequence: u64,
    round: u32, // Use u64
    target_round: u32, // Use u64
    signer_key: &NodeKey,
) -> RoundChange {
    let _round_id = ConsensusRoundIdentifier { sequence_number: sequence, round_number: round };
    let target_round_id = ConsensusRoundIdentifier { sequence_number: sequence, round_number: target_round };
    let payload = RoundChangePayload::new(target_round_id, None, None);
    let signed_payload = SignedData::sign(payload, signer_key).expect("Signing failed"); // Use signer_key directly
    RoundChange::new(signed_payload, None, None).expect("RC creation failed")
}

// Helper to create valid PreparedRoundMetadata
fn create_valid_prepared_round_metadata(
    sequence: u64,
    prepared_round: u64, // Use u64
    proposer_key: &NodeKey,
    validator_keys: &[Arc<NodeKey>],
    validators: &HashSet<Address>,
    parent_header: &QbftBlockHeader,
    _config: &QbftConfig,
    codec: Arc<dyn BftExtraDataCodec>,
    timestamp: u64,
    gas_limit: u64,
) -> (PreparedRoundMetadata, QbftBlock) {
    let proposer_address = address_from_key(proposer_key);
    let round_id = ConsensusRoundIdentifier { sequence_number: sequence, round_number: prepared_round.try_into().unwrap() };
    let block = default_qbft_block(
        parent_header.hash(),
        sequence,
        prepared_round as u32, // BftExtraData likely still uses u32
        timestamp,
        gas_limit,
        proposer_address,
        codec.clone(),
        validators.iter().cloned().collect(),
    );
    let block_hash = block.hash();

    let proposal_payload = ProposalPayload::new(round_id.clone(), block.clone());
    let signed_proposal = SignedData::sign(proposal_payload, proposer_key).expect("Proposal signing failed"); // Use proposer_key directly
    let bft_proposal = BftMessage::new(signed_proposal); // Wrap in BftMessage

    let prepare_payload = PreparePayload::new(round_id.clone(), block_hash);
    let prepares: Vec<SignedData<PreparePayload>> = validator_keys
        .iter()
        .map(|key| {
            SignedData::sign(prepare_payload.clone(), key.as_ref()).expect("Prepare signing failed") // Use key.as_ref() directly
        })
        .collect();

    let metadata = PreparedRoundMetadata::new(
        round_id.round_number,
        block_hash,
        bft_proposal, // Pass BftMessage
        prepares,
    );
    (metadata, block)
}

// Helper to create a signed RoundChange with prepared data
fn create_signed_rc_with_prepared(
    sequence: u64,
    _round: u64, // Use u64 - Prefixed with underscore
    target_round: u64, // Use u64
    prepared_metadata: PreparedRoundMetadata,
    prepared_block: QbftBlock,
    signer_key: &NodeKey,
) -> RoundChange {
    let target_round_id = ConsensusRoundIdentifier { sequence_number: sequence, round_number: target_round.try_into().unwrap() };
    // RoundChangePayload::new expects Option<PreparedRoundMetadata> and Option<QbftBlock>
    let payload = RoundChangePayload::new(target_round_id, Some(prepared_metadata.clone()), Some(prepared_block.clone()));
    let signed_payload = SignedData::sign(payload, signer_key).expect("Signing failed"); // Use signer_key directly
    // Extract prepares from metadata for the RoundChange struct
    let prepares = Some(prepared_metadata.prepares.to_vec());
    // RoundChange::new expects SignedData<RoundChangePayload>, Option<QbftBlock>, Option<Vec<SignedData<PreparePayload>>>
    RoundChange::new(signed_payload, Some(prepared_block), prepares).expect("RC creation failed")
}

#[test]
fn test_validate_rc_valid() {
    let config = default_config();
    let key1 = deterministic_node_key(1);
    let key2 = deterministic_node_key(2);
    let addr1 = address_from_key(&key1);
    let addr2 = address_from_key(&key2);
    let validators: HashSet<Address> = [addr1, addr2].iter().cloned().collect();
    let (validator, final_state) = create_rc_validator(config.clone(), key1.clone(), validators.clone(), None);

    let sequence = 10;
    let current_round = 1u64; // Use u64
    let target_round = 2u64; // Use u64
    let parent_num = sequence - 1;
    let parent_hash = B256::from_slice(&[1; 32]);
    let parent_header = default_parent_header(parent_num, parent_hash, 100, 5000);
    let proposer = addr1; // Proposer for round 1 doesn't matter here

    let context = ValidationContext::new(
        sequence,
        current_round as u32, // Context still expects u32 for current round
        validators.clone(),
        parent_header.clone(),
        final_state.clone(),
        testing_extradata_codec(),
        config.clone(),
        None,
        proposer,
    );

    let rc = create_basic_signed_rc(sequence, current_round.try_into().unwrap(), target_round.try_into().unwrap(), &key1);

    assert!(validator.validate_round_change(&rc, &context).is_ok());

    // Check with other validator's key
    let rc_key2 = create_basic_signed_rc(sequence, current_round.try_into().unwrap(), target_round.try_into().unwrap(), &key2);
    assert!(validator.validate_round_change(&rc_key2, &context).is_ok());
}

#[test]
fn test_validate_rc_invalid_author() {
    let config = default_config();
    let key1 = deterministic_node_key(1);
    let key_non_validator = deterministic_node_key(3);
    let addr1 = address_from_key(&key1);
    let validators: HashSet<Address> = [addr1].iter().cloned().collect();
    let (validator, final_state) = create_rc_validator(config.clone(), key1.clone(), validators.clone(), None);

    let sequence = 10;
    let current_round = 1u64; // Use u64
    let target_round = 2u64; // Use u64
    let parent_num = sequence - 1;
    let parent_hash = B256::from_slice(&[1; 32]);
    let parent_header = default_parent_header(parent_num, parent_hash, 100, 5000);
    let proposer = addr1;

    let context = ValidationContext::new(
        sequence,
        current_round as u32, // Context expects u32
        validators.clone(),
        parent_header.clone(),
        final_state.clone(),
        testing_extradata_codec(),
        config.clone(),
        None,
        proposer,
    );

    // Sign with a key not in the validator set
    let non_validator_addr = address_from_key(&key_non_validator);
    let rc = create_basic_signed_rc(sequence, current_round.try_into().unwrap(), target_round.try_into().unwrap(), &key_non_validator);

    // Expect ValidationAuthorNotValidator error
    assert_eq!(
        validator.validate_round_change(&rc, &context),
        Err(QbftError::ValidationAuthorNotValidator { author: non_validator_addr })
    );
}

#[test]
fn test_validate_rc_sequence_mismatch() {
    let config = default_config();
    let key1 = deterministic_node_key(1);
    let addr1 = address_from_key(&key1);
    let validators: HashSet<Address> = [addr1].iter().cloned().collect();
    let (validator, final_state) = create_rc_validator(config.clone(), key1.clone(), validators.clone(), None);

    let sequence_context = 10;
    let sequence_rc = 11; // Mismatch
    let current_round = 1u64; // Use u64
    let target_round = 2u64; // Use u64
    let parent_num = sequence_context - 1;
    let parent_hash = B256::from_slice(&[1; 32]);
    let parent_header = default_parent_header(parent_num, parent_hash, 100, 5000);
    let proposer = addr1;

    let context = ValidationContext::new(
        sequence_context,
        current_round as u32, // Context expects u32
        validators.clone(),
        parent_header.clone(),
        final_state.clone(),
        testing_extradata_codec(),
        config.clone(),
        None,
        proposer,
    );

    // Create RC with different sequence
    let rc = create_basic_signed_rc(sequence_rc, current_round.try_into().unwrap(), target_round.try_into().unwrap(), &key1);

    // Expect MessageRoundMismatch when the sequence is incorrect
    assert_eq!(
        validator.validate_round_change(&rc, &context),
        Err(QbftError::MessageRoundMismatch {
            message_type: "RoundChange".to_string(),
            expected_sequence: sequence_context,
            expected_round: current_round as u32, // Context round is u32
            actual_sequence: sequence_rc,
            actual_round: target_round as u32, // RC payload round is u32
        })
    );
}

#[test]
fn test_validate_rc_target_round_not_greater() {
    let config = default_config();
    let key1 = deterministic_node_key(1);
    let addr1 = address_from_key(&key1);
    let validators: HashSet<Address> = [addr1].iter().cloned().collect();
    let (validator, final_state) = create_rc_validator(config.clone(), key1.clone(), validators.clone(), None);

    let sequence = 10;
    let current_round = 1u64; // Use u64
    let target_round_equal = 1u64; // Equal - invalid
    let target_round_less = 0u64;  // Less - invalid
    let parent_num = sequence - 1;
    let parent_hash = B256::from_slice(&[1; 32]);
    let parent_header = default_parent_header(parent_num, parent_hash, 100, 5000);
    let proposer = addr1;

    let context = ValidationContext::new(
        sequence,
        current_round as u32, // Context expects u32
        validators.clone(),
        parent_header.clone(),
        final_state.clone(),
        testing_extradata_codec(),
        config.clone(),
        None,
        proposer,
    );

    // Target round == current round
    let rc_equal = create_basic_signed_rc(sequence, current_round.try_into().unwrap(), target_round_equal.try_into().unwrap(), &key1);
    assert_eq!(
        validator.validate_round_change(&rc_equal, &context),
        Err(QbftError::RoundChangeTargetRoundNotGreater { target: target_round_equal, current: current_round })
    );

    // Target round < current round
    let rc_less = create_basic_signed_rc(sequence, current_round.try_into().unwrap(), target_round_less.try_into().unwrap(), &key1);
    assert_eq!(
        validator.validate_round_change(&rc_less, &context),
        Err(QbftError::RoundChangeTargetRoundNotGreater { target: target_round_less, current: current_round })
    );
}

#[test]
fn test_validate_rc_valid_with_prepared() {
    let config = default_config();
    let key_proposer = deterministic_node_key(1);
    let key_v2 = deterministic_node_key(2);
    let key_v3 = deterministic_node_key(3);
    let addr_proposer = address_from_key(&key_proposer);
    let addr_v2 = address_from_key(&key_v2);
    let addr_v3 = address_from_key(&key_v3);
    let validators: HashSet<Address> = [addr_proposer, addr_v2, addr_v3].iter().cloned().collect();
    let validator_keys = vec![key_proposer.clone(), key_v2.clone(), key_v3.clone()];

    let sequence = 10;
    let parent_num = sequence - 1;
    let parent_hash = B256::from_slice(&[1; 32]);
    let timestamp = 100;
    let gas_limit = 5000;
    let parent_header = default_parent_header(parent_num, parent_hash, timestamp - 5, gas_limit);

    // Assume key_v2 is the local node sending the RC
    let (rc_validator, final_state) = create_rc_validator(config.clone(), key_v2.clone(), validators.clone(), Some(parent_header.clone()));
    let codec = testing_extradata_codec();

    let current_round = 1u64; // Use u64
    let prepared_round = 0u64; // Use u64
    let target_round = 2u64; // Use u64

    // Proposer for prepared_round (round 0) based on (seq+round) % num_validators = (10+0)%3 = 1
    // sorted_validators = [addr_proposer (key1), addr_v2 (key2), addr_v3 (key3)]
    // So, expected proposer for inner proposal (seq 10, round 0) is sorted_validators[1] == addr_v2 (key_v2)
    let expected_proposer_for_inner_round = &key_v2; 
    let context_round = current_round as u32; // context expects u32

    // Create valid prepared metadata from round 0, proposed by expected_proposer_for_inner_round (key_v2)
    let (prepared_metadata, prepared_block) = create_valid_prepared_round_metadata(
        sequence,
        prepared_round,
        expected_proposer_for_inner_round, // Use key_v2 as proposer for inner proposal
        &validator_keys[0..2], // Need F+1 = 1+1=2 prepares (N=3, F=1). Using proposer + one other.
        &validators,
        &parent_header,
        &config,
        codec.clone(),
        timestamp,
        gas_limit,
    );

    // Context for validating the RC message (node is in round 1)
    let context = ValidationContext::new(
        sequence,
        context_round,
        validators.clone(),
        parent_header.clone(),
        final_state.clone(),
        codec.clone(),
        config.clone(),
        None, // No prior round state needed for basic RC validation
        addr_v2, // Proposer for current_round (round 1), not relevant for RC itself
    );

    // Create RC signed by key_v2, containing proof for round 0
    let rc = create_signed_rc_with_prepared(
        sequence,
        current_round, // RC is sent *during* current_round
        target_round,
        prepared_metadata,
        prepared_block,
        &key_v2, // Signed by the sender
    );

    // Validation should pass
    let result = rc_validator.validate_round_change(&rc, &context);
    assert!(result.is_ok(), "Validation of valid RC with prepared failed: {:?}", result.err());
}

#[test]
fn test_validate_rc_prepared_round_ge_target_round() {
    let config = default_config();
    let key_proposer = deterministic_node_key(1);
    let key_v2 = deterministic_node_key(2);
    let addr_proposer = address_from_key(&key_proposer);
    let addr_v2 = address_from_key(&key_v2);
    let validators: HashSet<Address> = [addr_proposer, addr_v2].iter().cloned().collect();
    let validator_keys = vec![key_proposer.clone(), key_v2.clone()];
    let (rc_validator, final_state) = create_rc_validator(config.clone(), key_v2.clone(), validators.clone(), None);
    let codec = testing_extradata_codec();

    let sequence = 10;
    let current_round = 1u64; // Use u64
    let prepared_round = 3u64; // Use u64 - INVALID (>= target)
    let target_round = 3u64; // Use u64
    let parent_num = sequence - 1;
    let parent_hash = B256::from_slice(&[1; 32]);
    let timestamp = 100;
    let gas_limit = 5000;
    let parent_header = default_parent_header(parent_num, parent_hash, timestamp - 5, gas_limit);

    let (prepared_metadata, prepared_block) = create_valid_prepared_round_metadata(
        sequence,
        prepared_round,
        &key_proposer,
        &validator_keys,
        &validators,
        &parent_header,
        &config,
        codec.clone(),
        timestamp,
        gas_limit,
    );

    let context = ValidationContext::new(
        sequence,
        current_round as u32,
        validators.clone(),
        parent_header.clone(),
        final_state.clone(),
        codec.clone(),
        config.clone(),
        None,
        addr_v2,
    );

    let rc = create_signed_rc_with_prepared(
        sequence,
        current_round,
        target_round,
        prepared_metadata,
        prepared_block,
        &key_v2,
    );

    // Expect specific RoundChangeValidationError string
    assert_eq!(
        rc_validator.validate_round_change(&rc, &context).unwrap_err(),
        QbftError::RoundChangeValidationError("Prepared round must be less than target round".to_string()) // Updated expected error string if validator returns this directly
    );
}

#[test]
fn test_validate_rc_prepared_metadata_without_block() {
    let config = default_config();
    let key_proposer = deterministic_node_key(1);
    let key_v2 = deterministic_node_key(2);
    let addr_proposer = address_from_key(&key_proposer);
    let addr_v2 = address_from_key(&key_v2);
    let validators: HashSet<Address> = [addr_proposer, addr_v2].iter().cloned().collect();
    let validator_keys = vec![key_proposer.clone(), key_v2.clone()];
    let (rc_validator, final_state) = create_rc_validator(config.clone(), key_v2.clone(), validators.clone(), None);
    let codec = testing_extradata_codec();

    let sequence = 10;
    let current_round = 1u64; // Use u64
    let prepared_round = 0u64; // Use u64
    let target_round = 2u32; // Use u64
    let parent_num = sequence - 1;
    let parent_hash = B256::from_slice(&[1; 32]);
    let timestamp = 100;
    let gas_limit = 5000;
    let parent_header = default_parent_header(parent_num, parent_hash, timestamp - 5, gas_limit);

    let (prepared_metadata, _prepared_block) = create_valid_prepared_round_metadata(
        sequence,
        prepared_round,
        &key_proposer,
        &validator_keys,
        &validators,
        &parent_header,
        &config,
        codec.clone(),
        timestamp,
        gas_limit,
    );

    let context = ValidationContext::new(
        sequence,
        current_round as u32,
        validators.clone(),
        parent_header.clone(),
        final_state.clone(),
        codec.clone(),
        config.clone(),
        None,
        addr_v2,
    );

    // Create RC payload with metadata but NO block
    let target_round_id = ConsensusRoundIdentifier { sequence_number: sequence, round_number: target_round };
    let payload = RoundChangePayload::new(target_round_id, Some(prepared_metadata.clone()), None); // No block here
    let signed_payload = SignedData::sign(payload, &key_v2).expect("Signing failed"); // Use key directly
    // Create RC struct with NO prepared_block, but use prepares from metadata
    let rc = RoundChange::new(signed_payload, None, Some(prepared_metadata.prepares.to_vec())).expect("RC creation failed"); // Access as field

    // Expect specific RoundChangeValidationError from the validator
    assert_eq!(
        rc_validator.validate_round_change(&rc, &context).unwrap_err(),
        QbftError::RoundChangeValidationError("RoundChange with PreparedRoundMetadata must also contain prepared_block".to_string()) // Error comes from validator now
    );
}

#[test]
fn test_validate_rc_prepared_metadata_block_hash_mismatch() {
    let config = default_config();
    let key_proposer = deterministic_node_key(1);
    let key_v2 = deterministic_node_key(2);
    let addr_proposer = address_from_key(&key_proposer);
    let addr_v2 = address_from_key(&key_v2);
    let validators: HashSet<Address> = [addr_proposer, addr_v2].iter().cloned().collect();
    let validator_keys = vec![key_proposer.clone(), key_v2.clone()];
    // Define parent_header *before* calling create_rc_validator
    let sequence = 10;
    let parent_num = sequence - 1;
    let parent_hash = B256::from_slice(&[1; 32]);
    let timestamp = 100;
    let gas_limit = 5000;
    let parent_header = default_parent_header(parent_num, parent_hash, timestamp - 5, gas_limit);
    // Pass the parent_header Arc directly
    let (rc_validator, final_state) = create_rc_validator(config.clone(), key_v2.clone(), validators.clone(), Some(parent_header.clone()));
    let codec = testing_extradata_codec();

    let current_round = 1u64; // Use u64
    let prepared_round = 0u64; // Use u64
    let target_round = 2u64; // Use u64

    let (prepared_metadata, prepared_block) = create_valid_prepared_round_metadata(
        sequence,
        prepared_round,
        &key_v2,
        &validator_keys,
        &validators,
        &parent_header,
        &config,
        codec.clone(),
        timestamp,
        gas_limit,
    );

    // Create a *different* block
    let wrong_block = default_qbft_block(
        parent_header.hash(),
        sequence,
        prepared_round as u32,
        timestamp + 10, // Different timestamp -> different hash
        gas_limit,
        addr_proposer,
        codec.clone(),
        validators.iter().cloned().collect(),
    );
    assert_ne!(wrong_block.hash(), prepared_block.hash());
    assert_eq!(prepared_metadata.prepared_block_hash, prepared_block.hash());

    let context = ValidationContext::new(
        sequence,
        current_round as u32,
        validators.clone(),
        parent_header.clone(),
        final_state.clone(),
        codec.clone(),
        config.clone(),
        None,
        addr_v2,
    );

    // Create RC using metadata for block A, but providing block B
    let target_round_id = ConsensusRoundIdentifier { sequence_number: sequence, round_number: target_round.try_into().unwrap() };
    let payload = RoundChangePayload::new(target_round_id, Some(prepared_metadata.clone()), Some(wrong_block.clone())); // Include wrong block in payload
    let signed_payload = SignedData::sign(payload, &key_v2).expect("Signing failed"); // Use key directly
    // Create RC struct providing wrong block, using prepares from metadata
    let rc = RoundChange::new(signed_payload, Some(wrong_block.clone()), Some(prepared_metadata.prepares.to_vec())).expect("RC creation failed"); // Access as field

    // Expect error during inner proposal validation due to block hash mismatch
    match rc_validator.validate_round_change(&rc, &context) {
        Err(QbftError::RoundChangeValidationError(msg)) => {
            // Expect the direct error from the RoundChange validator itself
            let expected_err = "Hash of block in RoundChangePayload does not match hash in PreparedRoundMetadata".to_string();
            assert_eq!(msg, expected_err, "Error message mismatch.");
        }
        res => panic!("Expected RoundChangeValidationError with specific hash mismatch message, got {:?}", res),
    }
}

#[test]
fn test_validate_rc_prepared_proposal_invalid_sequence() {
    let config = default_config();
    let key_proposer = deterministic_node_key(1);
    let key_v2 = deterministic_node_key(2);
    let addr_proposer = address_from_key(&key_proposer);
    let addr_v2 = address_from_key(&key_v2);
    let validators: HashSet<Address> = [addr_proposer, addr_v2].iter().cloned().collect();
    let validator_keys = vec![key_proposer.clone(), key_v2.clone()];
    let (rc_validator, final_state) = create_rc_validator(config.clone(), key_v2.clone(), validators.clone(), None);
    let codec = testing_extradata_codec();

    let sequence_context = 10;
    let sequence_prepared = 11; // Mismatch with context
    let current_round = 1u64; // Use u64
    let prepared_round = 0u64; // Use u64
    let target_round = 2u64; // Use u64
    let parent_num = sequence_context - 1;
    let parent_hash = B256::from_slice(&[1; 32]);
    let timestamp = 100;
    let gas_limit = 5000;
    let parent_header = default_parent_header(parent_num, parent_hash, timestamp - 5, gas_limit);

    // Create metadata with wrong sequence
    let (prepared_metadata, prepared_block) = create_valid_prepared_round_metadata(
        sequence_prepared,
        prepared_round,
        &key_proposer,
        &validator_keys,
        &validators,
        &parent_header, // Parent still based on context sequence's parent
        &config,
        codec.clone(),
        timestamp,
        gas_limit,
    );

    let context = ValidationContext::new(
        sequence_context,
        current_round as u32,
        validators.clone(),
        parent_header.clone(),
        final_state.clone(),
        codec.clone(),
        config.clone(),
        None,
        addr_v2,
    );

    let rc = create_signed_rc_with_prepared(
        sequence_context, // RC itself uses context sequence
        current_round,
        target_round,
        prepared_metadata,
        prepared_block,
        &key_v2,
    );

    // Expect error during inner proposal validation
    match rc_validator.validate_round_change(&rc, &context) {
        Err(QbftError::RoundChangeValidationError(msg)) => {
            // Revert to original check for ProposalBlockSequenceInvalid
            let expected_err_fragment = format!("Inner Proposal Error: ProposalBlockSequenceInvalid {{ expected: {}, actual: {} }}", sequence_context, sequence_prepared);
            assert!(msg.contains(&expected_err_fragment), "Error message mismatch. Expected fragment: '{}', Got: '{}'", expected_err_fragment, msg);
        }
        res => panic!("Expected RoundChangeValidationError containing ProposalBlockSequenceInvalid, got {:?}", res),
    }
}

#[test]
fn test_validate_rc_prepared_proposal_invalid_round() {
    let config = default_config();
    let key_proposer = deterministic_node_key(1);
    let key_v2 = deterministic_node_key(2);
    let addr_proposer = address_from_key(&key_proposer);
    let addr_v2 = address_from_key(&key_v2);
    let validators: HashSet<Address> = [addr_proposer, addr_v2].iter().cloned().collect();
    let validator_keys = vec![key_proposer.clone(), key_v2.clone()];
    let (rc_validator, final_state) = create_rc_validator(config.clone(), key_v2.clone(), validators.clone(), None);
    let codec = testing_extradata_codec();

    let sequence = 10;
    let current_round = 1u64; // Use u64
    let prepared_round_metadata = 0u64; // Metadata says round 0
    let prepared_round_proposal = 1u64; // But inner proposal is for round 1 - Mismatch
    let target_round = 2u64; // Use u64
    let parent_num = sequence - 1;
    let parent_hash = B256::from_slice(&[1; 32]);
    let timestamp = 100;
    let gas_limit = 5000;
    let parent_header = default_parent_header(parent_num, parent_hash, timestamp - 5, gas_limit);

    // Create block for proposal round
    let block = default_qbft_block(
        parent_header.hash(), sequence, prepared_round_proposal as u32,
        timestamp, gas_limit, addr_proposer, codec.clone(), validators.iter().cloned().collect(),
    );
    let block_hash = block.hash();

    // Create proposal payload for the *wrong* round
    let proposal_payload = ProposalPayload::new(
        ConsensusRoundIdentifier { sequence_number: sequence, round_number: prepared_round_proposal.try_into().unwrap() },
        block.clone()
    );
    let signed_proposal = SignedData::sign(proposal_payload, &key_proposer).expect("Sign failed"); // Use key directly

    // Create prepares for the *metadata* round
    let prepare_payload = PreparePayload::new(
        ConsensusRoundIdentifier { sequence_number: sequence, round_number: prepared_round_metadata.try_into().unwrap() },
        block_hash // Hash still matches block
    );
    let prepares: Vec<SignedData<PreparePayload>> = validator_keys
        .iter()
        .map(|key| SignedData::sign(prepare_payload.clone(), key.as_ref()).expect("Sign failed")) // Use key directly
        .collect();

    // Create metadata for the metadata round, but using the proposal for the wrong round
    let bft_proposal_wrong_round = BftMessage::new(signed_proposal); // Wrap in BftMessage
    let prepared_metadata = PreparedRoundMetadata::new(
        prepared_round_metadata.try_into().unwrap(),
        block_hash,
        bft_proposal_wrong_round, // Pass BftMessage
        prepares,
    );

    let context = ValidationContext::new(
        sequence,
        current_round as u32,
        validators.clone(),
        parent_header.clone(),
        final_state.clone(),
        codec.clone(),
        config.clone(),
        None,
        addr_v2,
    );

    let rc = create_signed_rc_with_prepared(
        sequence,
        current_round,
        target_round,
        prepared_metadata,
        block,
        &key_v2,
    );

    // Expect error during inner proposal validation
    match rc_validator.validate_round_change(&rc, &context) {
        Err(QbftError::RoundChangeValidationError(msg)) => {
            // Revert to original check for ProposalRoundMismatch
            let expected_err_fragment = format!("Inner Proposal Error: ProposalRoundMismatch {{ expected: {}, actual: {} }}", prepared_round_metadata, prepared_round_proposal);
            assert!(msg.contains(&expected_err_fragment), "Error message mismatch. Expected fragment: '{}', Got: '{}'", expected_err_fragment, msg);
        }
        res => panic!("Expected RoundChangeValidationError containing ProposalRoundMismatch, got {:?}", res),
    }
}

#[test]
fn test_validate_rc_prepared_proposal_block_hash_mismatch() {
    let config = default_config();
    let key_proposer = deterministic_node_key(1);
    let key_v2 = deterministic_node_key(2);
    let addr_proposer = address_from_key(&key_proposer);
    let addr_v2 = address_from_key(&key_v2);
    let validators: HashSet<Address> = [addr_proposer, addr_v2].iter().cloned().collect();
    let validator_keys = vec![key_proposer.clone(), key_v2.clone()];
    // Define parent_header *before* calling create_rc_validator
    let sequence = 10;
    let parent_num = sequence - 1;
    let parent_hash = B256::from_slice(&[1; 32]);
    let timestamp = 100;
    let gas_limit = 5000;
    let parent_header = default_parent_header(parent_num, parent_hash, timestamp - 5, gas_limit);
    // Pass the parent_header Arc directly
    let (rc_validator, final_state) = create_rc_validator(config.clone(), key_v2.clone(), validators.clone(), Some(parent_header.clone()));
    let codec = testing_extradata_codec();

    let current_round = 1u64; // Use u64
    let prepared_round = 0u64; // Use u64
    let target_round = 2u64; // Use u64

    // Create block A
    let block_a = default_qbft_block(
        parent_header.hash(), sequence, prepared_round as u32,
        timestamp, gas_limit, addr_proposer, codec.clone(), validators.iter().cloned().collect(),
    );
    let block_a_hash = block_a.hash();

    // Create block B (different timestamp)
    let block_b = default_qbft_block(
        parent_header.hash(), sequence, prepared_round as u32,
        timestamp + 10, gas_limit,
        addr_v2, // Use addr_v2 as beneficiary to match the proposer key_v2
        codec.clone(), validators.iter().cloned().collect(),
    );
    let block_b_hash = block_b.hash();
    assert_ne!(block_a_hash, block_b_hash);

    // Create proposal payload for block B
    let proposal_payload = ProposalPayload::new(
        ConsensusRoundIdentifier { sequence_number: sequence, round_number: prepared_round.try_into().unwrap() },
        block_b.clone() // Use block B
    );
    let signed_proposal = SignedData::sign(proposal_payload, &key_v2).expect("Sign failed"); // Use key directly

    // Create prepares for block A hash
    let prepare_payload = PreparePayload::new(
        ConsensusRoundIdentifier { sequence_number: sequence, round_number: prepared_round.try_into().unwrap() },
        block_a_hash // Use hash of block A
    );
    let prepares: Vec<SignedData<PreparePayload>> = validator_keys
        .iter()
        .map(|key| SignedData::sign(prepare_payload.clone(), key.as_ref()).expect("Sign failed")) // Use key directly
        .collect();

    // Create metadata for block A hash, but using proposal for block B
    let bft_proposal_block_b = BftMessage::new(signed_proposal); // Wrap in BftMessage
    let prepared_metadata = PreparedRoundMetadata::new(
        prepare_payload.round_identifier.round_number,
        block_a_hash, // Metadata claims hash is A
        bft_proposal_block_b, // Pass BftMessage
        prepares,
    );

    let context = ValidationContext::new(
        sequence,
        current_round as u32,
        validators.clone(),
        parent_header.clone(),
        final_state.clone(),
        codec.clone(),
        config.clone(),
        None,
        addr_v2,
    );

    // Provide block B with the RC message
    let rc = create_signed_rc_with_prepared(
        sequence,
        current_round,
        target_round,
        prepared_metadata,
        block_b, // Use block B
        &key_v2,
    );

    // Expect error during inner proposal validation
    match rc_validator.validate_round_change(&rc, &context) {
        Err(QbftError::RoundChangeValidationError(msg)) => {
            // Expect the direct error from the RoundChange validator itself
            let expected_err = "Hash of block in RoundChangePayload does not match hash in PreparedRoundMetadata".to_string();
            assert_eq!(msg, expected_err, "Error message mismatch.");
        }
        res => panic!("Expected RoundChangeValidationError with specific hash mismatch message, got {:?}", res),
    }
}

#[test]
fn test_validate_rc_prepared_proposal_invalid_author() {
    let config = default_config();
    let key_proposer_actual = deterministic_node_key(1);
    let key_v2 = deterministic_node_key(2);
    let key_wrong_proposer = deterministic_node_key(3); // Not the expected proposer
    let addr_proposer_actual = address_from_key(&key_proposer_actual);
    let addr_v2 = address_from_key(&key_v2);
    let addr_wrong_proposer = address_from_key(&key_wrong_proposer);
    let validators: HashSet<Address> = [addr_proposer_actual, addr_v2, addr_wrong_proposer].iter().cloned().collect(); // Ensure wrong proposer is a validator
    let validator_keys = vec![key_proposer_actual.clone(), key_v2.clone(), key_wrong_proposer.clone()];
    
    let sequence = 10;
    let parent_num = sequence - 1;
    let parent_hash = B256::from_slice(&[1; 32]);
    let timestamp = 100;
    let gas_limit = 5000;
    let parent_header = default_parent_header(parent_num, parent_hash, timestamp - 5, gas_limit);
    // Ensure parent_header is passed
    let (rc_validator, final_state) = create_rc_validator(config.clone(), key_v2.clone(), validators.clone(), Some(parent_header.clone()));
    let codec = testing_extradata_codec();

    let current_round = 1u64; // Use u64
    let prepared_round = 0u64; // Use u64
    let target_round = 2u64; // Use u64

    // Expected proposer for prepared_round (round 0) based on simple logic
    let expected_proposer = addr_proposer_actual; // Assume key 1 should propose round 0

    // Create block with the *actual* proposer's address as beneficiary (common but not required)
    let block = default_qbft_block(
        parent_header.hash(), sequence, prepared_round as u32,
        timestamp, gas_limit, expected_proposer, codec.clone(), validators.iter().cloned().collect(),
    );
    let block_hash = block.hash();

    // Create proposal payload, but sign it with the *wrong* proposer key
    let proposal_payload = ProposalPayload::new(
        ConsensusRoundIdentifier { sequence_number: sequence, round_number: prepared_round.try_into().unwrap() },
        block.clone()
    );
    let signed_proposal = SignedData::sign(proposal_payload, &key_wrong_proposer).expect("Sign failed"); // Signed by wrong key
    assert_ne!(signed_proposal.recover_author().expect("Author recovery failed"), expected_proposer);
    assert_eq!(signed_proposal.recover_author().expect("Author recovery failed"), addr_wrong_proposer);

    // Create prepares using correct keys
    let prepare_payload = PreparePayload::new(
        ConsensusRoundIdentifier { sequence_number: sequence, round_number: prepared_round.try_into().unwrap() },
        block_hash
    );
    let prepares: Vec<SignedData<PreparePayload>> = validator_keys[0..2] // Use key 1 and 2 for prepares
        .iter()
        .map(|key| SignedData::sign(prepare_payload.clone(), key.as_ref()).expect("Sign failed")) // Use key directly
        .collect();

    // Create metadata
    let bft_proposal_invalid_author = BftMessage::new(signed_proposal); // Wrap in BftMessage
    let prepared_metadata = PreparedRoundMetadata::new(
        prepare_payload.round_identifier.round_number,
        block_hash,
        bft_proposal_invalid_author, // Pass BftMessage
        prepares,
    );

    let context = ValidationContext::new(
        sequence,
        current_round as u32,
        validators.clone(),
        parent_header.clone(),
        final_state.clone(),
        codec.clone(),
        config.clone(),
        None,
        addr_v2, // Proposer for current round (doesn't affect inner validation logic directly here)
    );

    let rc = create_signed_rc_with_prepared(
        sequence,
        current_round,
        target_round,
        prepared_metadata,
        block,
        &key_v2,
    );

    // Expect error during inner proposal validation because author != expected_proposer
    match rc_validator.validate_round_change(&rc, &context) {
        Err(QbftError::ProposalNotFromProposer) => {
            // Correct: Validation fails because the author is not the expected proposer
            // for the inner round, even before checking if the signature itself is valid
            // for that author.
        }
        res => panic!("Expected ProposalNotFromProposer, got {:?}", res),
    }
}

#[test]
fn test_validate_rc_prepared_invalid_prepare_author() {
    let config = default_config();
    let key_proposer = deterministic_node_key(1);
    let key_v2 = deterministic_node_key(2);
    let key_non_validator = deterministic_node_key(99);
    let addr_proposer = address_from_key(&key_proposer);
    let addr_v2 = address_from_key(&key_v2);
    let validators: HashSet<Address> = [addr_proposer, addr_v2].iter().cloned().collect();
    let validator_keys = vec![key_proposer.clone(), key_v2.clone()];
    let sequence = 10;
    let current_round = 1u64; // Use u64
    let prepared_round = 0u64; // Use u64
    let target_round = 2u64; // Use u64
    let parent_num = sequence - 1;
    let parent_hash = B256::from_slice(&[1; 32]);
    let timestamp = 100;
    let gas_limit = 5000;
    let parent_header = default_parent_header(parent_num, parent_hash, timestamp - 5, gas_limit);
    let (rc_validator, final_state) = create_rc_validator(config.clone(), key_v2.clone(), validators.clone(), Some(parent_header.clone()));
    let codec = testing_extradata_codec();

    // Create valid block and proposal
    let (prepared_metadata_base, prepared_block) = create_valid_prepared_round_metadata(
        sequence, prepared_round,
        &key_v2, // Use key_v2 as proposer for inner proposal (expected by mock)
        &validator_keys[0..1], // Only proposer's prepare initially (key_v2's prepare)
        &validators, &parent_header, &config, codec.clone(), timestamp, gas_limit,
    );

    // Create an invalid prepare signed by a non-validator
    let prepare_payload = PreparePayload::new(
        prepared_metadata_base.signed_proposal_payload.payload().round_identifier.clone(), // Access via payload
        prepared_metadata_base.prepared_block_hash // Direct field access
    );
    let invalid_prepare = SignedData::sign(prepare_payload.clone(), &key_non_validator).expect("Sign failed"); // Use key directly

    // Create metadata with the invalid prepare
    let mut prepares_with_invalid = prepared_metadata_base.prepares.to_vec();
    prepares_with_invalid.push(invalid_prepare);
    let bft_proposal_for_invalid_prepare = prepared_metadata_base.signed_proposal_payload.clone(); 
    let prepared_metadata = PreparedRoundMetadata::new(
        prepared_metadata_base.signed_proposal_payload.payload().round_identifier.round_number, // Access via payload
        prepared_metadata_base.prepared_block_hash, // Direct field access
        bft_proposal_for_invalid_prepare,
        prepares_with_invalid,
    );

    let context = ValidationContext::new(
        sequence,
        current_round as u32,
        validators.clone(),
        parent_header.clone(),
        final_state.clone(),
        codec.clone(),
        config.clone(),
        None,
        addr_v2,
    );

    let rc = create_signed_rc_with_prepared(
        sequence,
        current_round,
        target_round,
        prepared_metadata,
        prepared_block,
        &key_v2,
    );

    // Restore original assertion block
    match rc_validator.validate_round_change(&rc, &context) {
        Err(QbftError::RoundChangeValidationError(msg)) => {
            let non_validator_addr = address_from_key(&key_non_validator);
            // This error should come from the PrepareValidator, wrapped by RoundChangeValidator
            let expected_err_fragment = format!("Inner Prepare Error: NotAValidator {{ sender: {:?} }}", non_validator_addr);
            assert!(msg.contains(&expected_err_fragment), "Error message mismatch. Expected fragment: '{}', Got: '{}'", expected_err_fragment, msg);
        }
        res => panic!("Expected RoundChangeValidationError containing NotAValidator for prepare, got {:?}", res),
    }
}

#[test]
fn test_validate_rc_prepared_duplicate_prepare_author() {
    let config = default_config();
    let key_proposer = deterministic_node_key(1);
    let key_v2 = deterministic_node_key(2);
    let addr_proposer = address_from_key(&key_proposer);
    let addr_v2 = address_from_key(&key_v2);
    let validators: HashSet<Address> = [addr_proposer, addr_v2].iter().cloned().collect();
    // Define parent_header vars *before* calling create_rc_validator
    let sequence = 10;
    let parent_num = sequence - 1;
    let parent_hash = B256::from_slice(&[1; 32]);
    let timestamp = 100;
    let gas_limit = 5000;
    // Note: default_parent_header returns Arc<QbftBlockHeader>
    let parent_header = default_parent_header(parent_num, parent_hash, timestamp - 5, gas_limit);
    // Pass the parent_header (which is already an Arc) to the final state mock
    let (rc_validator, final_state) = create_rc_validator(config.clone(), key_v2.clone(), validators.clone(), Some(parent_header.clone()));
    let codec = testing_extradata_codec();

    let current_round = 1u64; // Use u64
    let prepared_round = 0u64; // Use u64
    let target_round = 2u64; // Use u64

    // Create valid block and proposal
    let (prepared_metadata_base, prepared_block) = create_valid_prepared_round_metadata(
        sequence, prepared_round,
        &key_v2, // Use key_v2 as proposer for inner proposal (expected by mock)
        &[key_v2.clone()], // Only proposer's prepare initially
        &validators, &parent_header, &config, codec.clone(), timestamp, gas_limit,
    );

    // Create another prepare signed by the *same* author (key_proposer)
    let prepare_payload = PreparePayload::new(
        prepared_metadata_base.signed_proposal_payload.payload().round_identifier.clone(), // Access via payload
        prepared_metadata_base.prepared_block_hash // Direct field access
    );
    let duplicate_prepare = SignedData::sign(prepare_payload.clone(), &key_v2).expect("Sign failed"); // Use key directly

    // Create metadata with the duplicate prepare
    let mut prepares_with_duplicate = prepared_metadata_base.prepares.to_vec();
    prepares_with_duplicate.push(duplicate_prepare);
    assert_eq!(prepares_with_duplicate.len(), 2);
    assert_eq!(prepares_with_duplicate[0].recover_author().expect("Author recovery failed"), prepares_with_duplicate[1].recover_author().expect("Author recovery failed"));

    let bft_proposal_for_duplicate = prepared_metadata_base.signed_proposal_payload.clone(); 
    let prepared_metadata = PreparedRoundMetadata::new(
        prepared_metadata_base.prepared_round,
        prepared_metadata_base.prepared_block_hash,
        bft_proposal_for_duplicate,
        prepares_with_duplicate,
    );

    let context = ValidationContext::new(
        sequence,
        current_round as u32,
        validators.clone(),
        parent_header.clone(),
        final_state.clone(),
        codec.clone(),
        config.clone(),
        None,
        addr_v2,
    );

    let rc = create_signed_rc_with_prepared(
        sequence,
        current_round,
        target_round,
        prepared_metadata,
        prepared_block,
        &key_v2,
    );

    // Expect error due to duplicate author
    match rc_validator.validate_round_change(&rc, &context) {
        Err(QbftError::RoundChangeValidationError(msg)) => {
            let expected_err = "Duplicate author in prepares of PreparedRoundMetadata".to_string();
            assert_eq!(msg, expected_err, "Error message mismatch.");
        }
        res => panic!("Expected RoundChangeValidationError containing duplicate author, got {:?}", res),
    }
}

#[test]
fn test_validate_rc_prepared_insufficient_prepares() {
    // Need F+1 prepares. F=1, so need 2. Provide only 1.
    let mut config = QbftConfig::default();
    config.fault_tolerance_f = 1; // Need F+1 = 2 prepares
    let config = Arc::new(config);

    let key_proposer = deterministic_node_key(1);
    let key_v2 = deterministic_node_key(2);
    let key_v3 = deterministic_node_key(3); // Total 3 validators
    let key_v4 = deterministic_node_key(4);
    let addr_proposer = address_from_key(&key_proposer);
    let addr_v2 = address_from_key(&key_v2);
    let addr_v3 = address_from_key(&key_v3);
    let addr_v4 = address_from_key(&key_v4);
    // N = 4 validators, F = floor((N-1)/3) = floor(3/3) = 1.
    let validators: HashSet<Address> = [addr_proposer, addr_v2, addr_v3, addr_v4].iter().cloned().collect();
    let validator_keys = vec![key_proposer.clone()]; // Only provide proposer's key for prepare creation
    // Define parent header vars *before* calling create_rc_validator
    let sequence = 10;
    let parent_num = sequence - 1;
    let parent_hash = B256::from_slice(&[1; 32]);
    let timestamp = 100;
    let gas_limit = 5000;
    // Note: default_parent_header returns Arc<QbftBlockHeader>
    let parent_header = default_parent_header(parent_num, parent_hash, timestamp - 5, gas_limit);
    // Pass the parent_header (which is already an Arc) to the final state mock
    let (rc_validator, final_state) = create_rc_validator(config.clone(), key_v2.clone(), validators.clone(), Some(parent_header.clone()));
    let codec = testing_extradata_codec();

    let current_round = 1u64; // Use u64
    let prepared_round = 0u64; // Use u64
    let target_round = 2u64; // Use u64

    // Create metadata with only ONE prepare (from the proposer)
    let (prepared_metadata, prepared_block) = create_valid_prepared_round_metadata(
        sequence,
        prepared_round,
        &key_proposer,
        &validator_keys, // Only key_proposer -> 1 prepare
        &validators,
        &parent_header,
        &config,
        codec.clone(),
        timestamp,
        gas_limit,
    );
    assert_eq!(prepared_metadata.prepares.len(), 1); // Verify only 1 prepare

    let context = ValidationContext::new(
        sequence,
        current_round as u32,
        validators.clone(),
        parent_header.clone(),
        final_state.clone(),
        codec.clone(),
        config.clone(),
        None,
        addr_v2,
    );

    let rc = create_signed_rc_with_prepared(
        sequence,
        current_round,
        target_round,
        prepared_metadata,
        prepared_block,
        &key_v2,
    );

    // Expect error due to insufficient prepares
    match rc_validator.validate_round_change(&rc, &context) {
        Err(QbftError::QuorumNotReached { needed, got, item }) => {
            let n = validators.len();
            let f = (n - 1) / 3;
            let expected_quorum = 2 * f + 1;
            assert_eq!(needed, expected_quorum, "Incorrect needed quorum reported");
            assert_eq!(got, 1, "Incorrect got count reported");
            assert!(item.contains("prepares for inner proposal round"), "Incorrect item description");
        }
        res => panic!("Expected QuorumNotReached error for insufficient prepares, got {:?}", res),
    }
}

#[test]
fn test_validate_rc_no_prepared_metadata_with_block() {
    let config = default_config();
    let key1 = deterministic_node_key(1);
    let addr1 = address_from_key(&key1);
    let validators: HashSet<Address> = [addr1].iter().cloned().collect();
    let (validator, final_state) = create_rc_validator(config.clone(), key1.clone(), validators.clone(), None);
    let codec = testing_extradata_codec();

    let sequence = 10;
    let current_round = 1u64; // Use u64
    let target_round = 2u64; // Use u64
    let parent_num = sequence - 1;
    let parent_hash = B256::from_slice(&[1; 32]);
    let parent_header = default_parent_header(parent_num, parent_hash, 100, 5000);
    let proposer = addr1;

    let context = ValidationContext::new(
        sequence,
        current_round as u32,
        validators.clone(),
        parent_header.clone(),
        final_state.clone(),
        codec.clone(),
        config.clone(),
        None,
        proposer,
    );

    // Create a dummy block
    let block = default_qbft_block(
        parent_header.hash(), sequence, current_round as u32, 105, 5000,
        addr1, codec.clone(), validators.iter().cloned().collect(),
    );

    // Create RC payload with NO metadata, but WITH a block
    let target_round_id = ConsensusRoundIdentifier { sequence_number: sequence, round_number: target_round.try_into().unwrap() };
    let payload = RoundChangePayload::new(target_round_id, None, Some(block.clone())); // Block present, metadata None
    let signed_payload = SignedData::sign(payload, &key1).expect("Signing failed"); // Use key directly
    // Create RC struct
    let rc = RoundChange::new(signed_payload, Some(block), None).expect("RC creation failed");

    // Expect specific RoundChangeValidationError from the validator
    assert_eq!(
        validator.validate_round_change(&rc, &context).unwrap_err(),
        QbftError::RoundChangeValidationError("RoundChangePayload must not contain block if prepared round metadata is absent".to_string()) // Error comes from validator now
    );
} 