#![cfg(test)] // Ensure this module is only compiled for tests

// Standard library imports
use std::sync::Arc;
use std::iter;
use std::collections::HashSet;

// External crate imports
use k256::SecretKey;
use rand_08::thread_rng;
use alloy_primitives::{Address as RethAddress, keccak256, U256, B256, Bytes, BlockNumber, FixedBytes};
use alloy_consensus::{
    Header as AlloyConsensusHeader, Sealable, EMPTY_OMMER_ROOT_HASH,
    constants::{EMPTY_RECEIPTS, EMPTY_TRANSACTIONS},
};
use alloy_eips::eip4895::{Withdrawals}; // REMOVED: Withdrawal (unused)
use tokio::sync::mpsc;
use neura_qbft_core::types::QbftFinalState;
use neura_qbft_core::types::BftExtraDataCodec;

// Reth crate imports
use reth_primitives::{
    Header as RethPrimitivesHeader, BlockBody as RethBlockBody, TransactionSigned, 
    SealedBlock as RethSealedBlock, SealedHeader
};
use reth_provider::{
    test_utils::MockNodeTypesWithDB,
};
use reth_stages::test_utils::{TestStageDB, StorageKind};
use reth_chainspec::{MAINNET}; // REMOVED: ChainSpec (unused)

// Neura QBFT core imports
use neura_qbft_core::{
    types::{NodeKey, QbftConfig, AlloyBftExtraDataCodec, BftExtraData}, // REMOVED: ConsensusRoundIdentifier, QbftBlockHeader, QbftBlock
    mocks::{
        MockQbftFinalState, MockQbftBlockCreatorFactory, MockQbftBlockImporter,
        MockValidatorMulticaster, MockBlockTimer, MockMessageValidatorFactory,
        MockRoundChangeMessageValidatorFactory,
    },
    statemachine::QbftController,
    payload::MessageFactory as CoreMessageFactory,
};

// Local crate imports (from neura-consensus-qbft itself)
use crate::{
    RethQbftFinalState, QbftConsensus, RethRoundTimer, 
};


// Helper to generate a unique NodeKey and corresponding RethAddress for testing
pub fn generate_unique_node_key_and_address() -> (Arc<NodeKey>, RethAddress) {
    let mut rng = thread_rng();
    let secret_key = SecretKey::random(&mut rng);
    let node_key = Arc::new(NodeKey::from(secret_key));
    let verifying_key = node_key.verifying_key();
    let uncompressed_pk_bytes = verifying_key.to_encoded_point(false).as_bytes().to_vec();
    let hash = keccak256(&uncompressed_pk_bytes[1..]);
    let local_address = RethAddress::from_slice(&hash[12..]);
    (node_key, local_address)
}

pub fn default_qbft_config_for_test() -> Arc<QbftConfig> {
    Arc::new(QbftConfig {
        difficulty: U256::from(1), // Default difficulty for QBFT blocks
        block_period_seconds: 1,
        message_round_timeout_ms: 2000,
        ..Default::default()
    })
}

pub fn default_extra_data_codec_for_test() -> Arc<AlloyBftExtraDataCodec> {
    Arc::new(AlloyBftExtraDataCodec::default())
}

// Corrected setup_test_final_state_components
pub fn setup_test_final_state_components(
    num_initial_validators: usize,
) -> (
    RethQbftFinalState<MockNodeTypesWithDB>,
    Vec<RethAddress>, // initial_validators (these will be in the custom genesis)
    Arc<QbftConfig>,
    Arc<AlloyBftExtraDataCodec>,
    TestStageDB,
) {
    let test_db = TestStageDB::default();
    let config = default_qbft_config_for_test();
    let extra_data_codec = default_extra_data_codec_for_test();
    let (node_key, local_address) = generate_unique_node_key_and_address();

    let mut qbft_genesis_validators: Vec<RethAddress> = iter::repeat_with(|| generate_unique_node_key_and_address().1)
        .take(num_initial_validators.saturating_sub(1))
        .collect();
    qbft_genesis_validators.push(local_address);

    let bft_extra_data_for_genesis = BftExtraData {
        vanity_data: Bytes::from_static(&[0u8; 32]),
        validators: qbft_genesis_validators.clone(),
        committed_seals: Vec::new(),
        round_number: 0u32,
    };
    let qbft_genesis_extra_data_bytes = extra_data_codec.encode(&bft_extra_data_for_genesis).unwrap();

    let qbft_genesis_alloy_header = AlloyConsensusHeader {
        number: 0,
        parent_hash: B256::ZERO,
        ommers_hash: EMPTY_OMMER_ROOT_HASH,
        beneficiary: RethAddress::random(),
        state_root: B256::random(),
        transactions_root: EMPTY_TRANSACTIONS,
        receipts_root: EMPTY_RECEIPTS,
        logs_bloom: Default::default(),
        difficulty: config.difficulty,
        gas_limit: MAINNET.genesis_header().gas_limit,
        gas_used: 0,
        timestamp: 0,
        extra_data: qbft_genesis_extra_data_bytes,
        mix_hash: Default::default(),
        nonce: FixedBytes::ZERO,
        base_fee_per_gas: Some(MAINNET.genesis_header().base_fee_per_gas.unwrap_or(1_000_000_000)),
        withdrawals_root: None, // Default for genesis
        blob_gas_used: None,
        excess_blob_gas: None,
        parent_beacon_block_root: None,
        requests_hash: None,
    };

    let alloy_sealed_qbft_genesis = qbft_genesis_alloy_header.seal_slow();
    let (header_part, _hash_part) = alloy_sealed_qbft_genesis.into_parts(); // MODIFIED: _hash_part
    
    let qbft_genesis_body = RethBlockBody {
        transactions: Vec::<TransactionSigned>::new(),
        ommers: Vec::<RethPrimitivesHeader>::new(),
        withdrawals: Some(Withdrawals::default()), // Assuming default() is Vec::new()
    };

    let qbft_genesis_sealed_block = RethSealedBlock::seal_parts(header_part, qbft_genesis_body);

    test_db.insert_blocks(
        std::iter::once(&qbft_genesis_sealed_block),
        StorageKind::Database(None)
    )
        .expect("Failed to insert QBFT genesis block into test_db");

    let provider_factory_from_test_db = test_db.factory.clone();

    let final_state = RethQbftFinalState::new(
        provider_factory_from_test_db,
        node_key.clone(),
        local_address,
        extra_data_codec.clone(),
        config.clone(),
    );
    (final_state, qbft_genesis_validators, config, extra_data_codec, test_db)
}

// Corrected create_sealed_header_with_validators
pub fn create_sealed_header_with_validators(
    block_number: BlockNumber,
    parent_hash: B256,
    validators_slice: &[RethAddress],
    extra_data_codec: &AlloyBftExtraDataCodec,
    _qbft_config: &QbftConfig, 
    difficulty: U256,
) -> SealedHeader {
    let bft_extra_data = BftExtraData {
        vanity_data: Bytes::from_static(&[0u8; 32]),
        validators: validators_slice.to_vec(),
        committed_seals: Vec::new(),
        round_number: 0u32,
    };
    let extra_data_bytes = extra_data_codec.encode(&bft_extra_data).unwrap();

    let alloy_header = AlloyConsensusHeader {
        number: block_number,
        extra_data: extra_data_bytes,
        parent_hash,
        ommers_hash: EMPTY_OMMER_ROOT_HASH,
        beneficiary: RethAddress::from_slice(&[0x01; 20]),
        state_root: B256::from_slice(&[0x02; 32]),
        transactions_root: EMPTY_TRANSACTIONS,
        receipts_root: EMPTY_RECEIPTS,
        logs_bloom: Default::default(),
        difficulty,
        gas_limit: 30_000_000,
        gas_used: 0,
        timestamp: block_number * 1,
        mix_hash: B256::ZERO,
        nonce: FixedBytes::ZERO,
        base_fee_per_gas: Some(1_000_000_000),
        withdrawals_root: None,
        blob_gas_used: None,
        excess_blob_gas: None,
        parent_beacon_block_root: None,
        requests_hash: None,
    };

    let sealed_alloy_header = alloy_header.seal_slow(); // Uses alloy_consensus::Sealable
    let (header_part, hash_part) = sealed_alloy_header.into_parts();
    // Use reth_primitives::SealedHeader::new for consistency with Reth types
    SealedHeader::new(header_part, hash_part)
}

// Helper to set up QbftConsensus for testing
pub fn setup_qbft_consensus_for_test() -> (
    QbftConsensus<MockNodeTypesWithDB>,
    Arc<NodeKey>,
    RethAddress,
    Arc<QbftConfig>,
    TestStageDB,
    Arc<RethQbftFinalState<MockNodeTypesWithDB>>
) {
    let chainspec = MAINNET.clone();
    // Use setup_test_final_state_components to create the TestStageDB and initial QBFT genesis
    // We request 1 initial validator for the genesis block created by setup_test_final_state_components
    // This will also give us a node_key and local_address that is part of that genesis.
    let (final_state_adapter_for_consensus, initial_validators, config, _codec, test_db) =
        setup_test_final_state_components(1); 
    
    // The local_address and node_key for the QbftConsensus instance should be the one
    // that was made a validator in the genesis block by setup_test_final_state_components.
    // We can get this from the final_state_adapter_for_consensus.
    let node_key = final_state_adapter_for_consensus.node_key();
    let local_address = final_state_adapter_for_consensus.local_address();

    // Ensure the local_address is indeed in the initial_validators (it should be by design of setup_test_final_state_components)
    assert!(initial_validators.contains(&local_address));

    let provider_factory = test_db.factory.clone();

    // Setup for QbftController (can be mostly mocks for these tests)
    let (round_event_tx, _round_event_rx) = mpsc::channel(10);
    let round_timer_for_controller = Arc::new(RethRoundTimer::new(round_event_tx.clone()));
    
    let mut mock_validators_for_controller = HashSet::new();
    mock_validators_for_controller.insert(local_address);

    let final_state_for_controller = Arc::new(MockQbftFinalState::new(
        node_key.clone(),
        mock_validators_for_controller,
    ));
    let block_creator_factory = Arc::new(MockQbftBlockCreatorFactory::new());
    let block_importer = Arc::new(MockQbftBlockImporter::new());
    let controller_extra_data_codec = Arc::new(AlloyBftExtraDataCodec::default());
    let message_factory_for_controller = Arc::new(CoreMessageFactory::new(node_key.clone()).unwrap());
    let validator_multicaster = Arc::new(MockValidatorMulticaster::new());
    let block_timer = Arc::new(MockBlockTimer::new(config.block_period_seconds));
    let message_validator_factory = Arc::new(MockMessageValidatorFactory::new());
    let rc_message_validator_factory = Arc::new(MockRoundChangeMessageValidatorFactory::new());

    let controller = Arc::new(QbftController::new(
        final_state_for_controller,
        block_creator_factory,
        block_importer,
        message_factory_for_controller,
        validator_multicaster,
        block_timer,
        round_timer_for_controller,
        controller_extra_data_codec,
        message_validator_factory,
        rc_message_validator_factory,
        Vec::new(), 
        config.clone(),
    ));
    
    // QbftConsensus uses the real RethQbftFinalState adapter
    let qbft_consensus = QbftConsensus::new(
        chainspec,
        provider_factory, // Use the factory from the TestStageDB that has the QBFT genesis
        controller, 
        config.clone(),
        node_key.clone(),
        local_address,
    );

    // The RethQbftFinalState returned by setup_test_final_state_components is the one
    // that QbftConsensus will create internally. We can return it for direct assertions if needed,
    // but it's important that QbftConsensus itself instantiates its own.
    // For clarity, let's return the one created by setup_test_final_state_components for now,
    // although QbftConsensus::new() will create its own instance.
    // We could instead return `qbft_consensus.final_state_adapter.clone()`
    let final_state_adapter_for_test_return = Arc::new(RethQbftFinalState::new(
        test_db.factory.clone(), // Use the same factory
        node_key.clone(),
        local_address,
        default_extra_data_codec_for_test(), // Use a fresh codec instance
        config.clone(),
    ));


    (qbft_consensus, node_key, local_address, config, test_db, final_state_adapter_for_test_return)
}

pub fn create_valid_bft_extra_data_bytes(
    validators: &[RethAddress],
    codec: &AlloyBftExtraDataCodec,
    round_number: u32,
) -> Bytes {
    let bft_extra_data = BftExtraData {
        vanity_data: Bytes::from_static(&[0u8; 32]),
        validators: validators.to_vec(),
        committed_seals: Vec::new(),
        round_number,
    };
    codec.encode(&bft_extra_data).unwrap()
} 