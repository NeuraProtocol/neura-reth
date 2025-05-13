//! Common helper functions, structs, and mocks for validation tests.

use crate::messagewrappers::{Proposal, RoundChange, BftMessage, PreparedCertificateWrapper, Prepare, Commit};
use crate::payload::{ProposalPayload, RoundChangePayload, PreparePayload, CommitPayload,PreparedRoundMetadata}; // Added CommitPayload, SignedData, and RoundChangePayload
use crate::types::{NodeKey, QbftBlock, QbftBlockHeader, ConsensusRoundIdentifier, QbftConfig, BftExtraData, QbftFinalState, BftExtraDataCodec, RlpSignature, SignedData}; // Removed SignedData, Added RlpSignature
use crate::mocks::MockQbftFinalState;
use crate::validation::{ValidationContext, MessageValidatorFactory, ProposalValidator, PrepareValidator, CommitValidator,  RoundChangeMessageValidator}; // Added RoundChangeMessageValidator
use crate::error::QbftError;
use alloy_primitives::{Address, Bytes, B256, U256};
use alloy_rlp::{Error as RlpError, Encodable, Decodable};
use std::sync::Arc;
use std::collections::{HashSet};
use k256::ecdsa::VerifyingKey;
use alloy_primitives::Signature as AlloySignature;

// --- Basic Config and Keys ---

pub fn default_config() -> Arc<QbftConfig> {
    Arc::new(QbftConfig::default())
}

pub fn deterministic_node_key(seed: u8) -> Arc<NodeKey> {
    let mut bytes = [0u8; 32];
    bytes[0] = seed;
    let secret_key = k256::SecretKey::from_slice(&bytes).expect("Failed to create secret_key from slice");
    Arc::new(NodeKey::from(secret_key))
}

// Keep original address_from_key if needed anywhere
pub fn address_from_key(key: &NodeKey) -> Address {
    let verifying_key: &VerifyingKey = key.verifying_key();
    let uncompressed_pk_bytes = verifying_key.to_encoded_point(false).as_bytes().to_vec();
    let hash = alloy_primitives::keccak256(&uncompressed_pk_bytes[1..]);
    Address::from_slice(&hash[12..])
}

pub fn deterministic_address_from_arc_key(key: &Arc<NodeKey>) -> Address {
    address_from_key(key.as_ref())
}

// Optional: keep the random key generator if needed for specific scenarios
pub fn create_node_key() -> NodeKey {
    let secret_key = k256::SecretKey::random(&mut rand::thread_rng());
    NodeKey::from(secret_key)
}

// --- Block and Header Helpers ---

pub fn default_parent_header(number: u64, _hash: B256, timestamp: u64, gas_limit: u64) -> Arc<QbftBlockHeader> {
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
        Bytes::from_static(&[0u8; 8]), // nonce (8-byte zero array)
    ))
}

pub fn default_qbft_block(
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
    let extra_data = extra_data_codec.encode(&bft_extra).unwrap_or_else(|e| {
        panic!("TestExtraDataCodec.encode failed: {:?}", e);
    });

    let header = QbftBlockHeader::new(
        parent_hash, B256::ZERO, beneficiary, B256::ZERO, B256::ZERO,
        B256::ZERO, Default::default(), U256::from(1), number, gas_limit,
        0, timestamp, extra_data, B256::ZERO, Bytes::from_static(&[0u8; 8]),
    );
    QbftBlock {
        header,
        body_transactions: vec![],
        body_ommers: vec![],
    }
}

// --- Extra Data Codec Mock ---

#[derive(Debug, Clone)] // Added Debug and Clone
pub struct TestExtraDataCodec;
impl BftExtraDataCodec for TestExtraDataCodec {
    fn decode(&self, data: &Bytes) -> Result<BftExtraData, RlpError> {
        BftExtraData::decode(&mut data.as_ref())
    }
    fn encode(&self, extra_data: &BftExtraData) -> Result<Bytes, RlpError> {
        let mut out_vec = Vec::new();
        extra_data.encode(&mut out_vec);
        Ok(Bytes::from(out_vec))
    }
}
pub fn testing_extradata_codec() -> Arc<dyn BftExtraDataCodec> {
    Arc::new(TestExtraDataCodec)
}

// --- Final State and Context Helpers ---

pub fn default_final_state(local_node_key: Arc<NodeKey>, validators: HashSet<Address>) -> Arc<dyn QbftFinalState> {
    // Use the specific constructor from MockQbftFinalState
    Arc::new(MockQbftFinalState::new(local_node_key, validators))
}

// Consider enhancing MockQbftFinalState or adding specific mock setup functions if more complex state is needed.
pub fn default_validation_context(
    sequence: u64,
    round: u32,
    validators: HashSet<Address>,
    parent_header: Arc<QbftBlockHeader>,
    expected_proposer: Address,
    config: Arc<QbftConfig>,
    extra_data_codec: Arc<dyn BftExtraDataCodec>,
    final_state_opt: Option<Arc<dyn QbftFinalState>>,
    local_node_key_for_final_state: Arc<NodeKey>, // Used if final_state_opt is None
) -> ValidationContext {
    let final_state = final_state_opt.unwrap_or_else(|| default_final_state(local_node_key_for_final_state, validators.clone()));
    ValidationContext::new(
        sequence, round, validators, parent_header, final_state,
        extra_data_codec, config, None, expected_proposer,
    )
}

// --- Mock Validators ---

#[derive(Clone)]
pub struct MockProposalValidator { pub fail_on_validate: bool }
impl ProposalValidator for MockProposalValidator {
    fn validate_proposal(&self, _proposal: &Proposal, _context: &ValidationContext) -> Result<(), QbftError> {
        if self.fail_on_validate { Err(QbftError::ValidationError("MockProposalValidator failed".to_string())) } else { Ok(()) }
    }
}

#[derive(Clone)]
pub struct MockPrepareValidator { pub fail_on_validate: bool }
impl PrepareValidator for MockPrepareValidator {
    fn validate_prepare(&self, _prepare: &Prepare, _context: &ValidationContext) -> Result<(), QbftError> {
        if self.fail_on_validate { Err(QbftError::ValidationError("MockPrepareValidator failed".to_string())) } else { Ok(()) }
    }
}

#[derive(Clone)]
pub struct MockCommitValidator { pub fail_on_validate: bool }
impl CommitValidator for MockCommitValidator {
    fn validate_commit(&self, _commit: &Commit, _context: &ValidationContext) -> Result<(), QbftError> {
        if self.fail_on_validate { Err(QbftError::ValidationError("MockCommitValidator failed".to_string())) } else { Ok(()) }
    }
}

#[derive(Clone)]
pub struct MockRoundChangeMessageValidator { pub fail_on_validate: bool } // Added Mock for RoundChange
impl RoundChangeMessageValidator for MockRoundChangeMessageValidator {
    fn validate_round_change(&self, _round_change: &RoundChange, _context: &ValidationContext) -> Result<(), QbftError> {
        if self.fail_on_validate { Err(QbftError::ValidationError("MockRoundChangeMessageValidator failed".to_string())) } else { Ok(()) }
    }
}

// --- Mock Validator Factory ---

pub struct MockMessageValidatorFactoryImpl {
    pub proposal_should_fail: bool,
    pub prepare_should_fail: bool,
    pub commit_should_fail: bool,
    // Add field for round change mock behavior if needed by this factory
    // pub round_change_should_fail: bool, // Example
}

impl MockMessageValidatorFactoryImpl {
    // Update constructor if adding more fields
    pub fn new(p: bool, pr: bool, c: bool) -> Self {
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
    // Note: create_round_change_message_validator is NOT part of MessageValidatorFactory trait.
    // If a mock factory needs to provide a mock RoundChangeMessageValidator, it would need to be
    // a mock of RoundChangeMessageValidatorFactory trait, not MessageValidatorFactory.
}

// Helper function to easily create the mock MessageValidatorFactory
pub fn mock_message_validator_factory(
    prop_fail: bool,
    prep_fail: bool,
    commit_fail: bool
) -> Arc<dyn MessageValidatorFactory> {
    Arc::new(MockMessageValidatorFactoryImpl::new(prop_fail, prep_fail, commit_fail))
}

// Added Mock for RoundChangeMessageValidatorFactory
pub struct MockRoundChangeMessageValidatorFactoryImpl {
    pub round_change_should_fail: bool,
}

impl MockRoundChangeMessageValidatorFactoryImpl {
     pub fn new(rc_fail: bool) -> Self {
        Self { round_change_should_fail: rc_fail }
    }
}

impl crate::validation::RoundChangeMessageValidatorFactory for MockRoundChangeMessageValidatorFactoryImpl { // Use full trait path
    fn create_round_change_message_validator(self: &Self) -> Arc<dyn RoundChangeMessageValidator + Send + Sync> {
        Arc::new(MockRoundChangeMessageValidator { fail_on_validate: self.round_change_should_fail })
    }
}

// Helper function to easily create the mock RoundChangeMessageValidatorFactory
pub fn mock_round_change_message_validator_factory(
    rc_fail: bool
) -> Arc<dyn crate::validation::RoundChangeMessageValidatorFactory> { // Use full trait path
    Arc::new(MockRoundChangeMessageValidatorFactoryImpl::new(rc_fail))
}

// Helper to sign a digest (B256) with a NodeKey, returning RlpSignature
pub fn sign_digest(key: &NodeKey, digest: B256) -> RlpSignature {
    // NodeKey is an alias for k256::ecdsa::SigningKey, so use `key` directly.
    
    // Corrected: sign_prehash_recoverable returns (Signature, RecoveryId)
    let (secp_signature, recovery_id): (k256::ecdsa::Signature, k256::ecdsa::RecoveryId) = key // Use key directly
        .sign_prehash_recoverable(digest.as_slice())
        .expect("ECDSA recoverable signing failed");

    // The recovery_id is now obtained directly from the signing call
    let v_parity_bool = recovery_id.is_y_odd();

    let (r, s) = secp_signature.split_bytes(); // Use split_bytes for raw components

    // Convert r and s FieldBytes directly to U256
    let r_u256 = U256::from_be_slice(r.as_slice());
    let s_u256 = U256::from_be_slice(s.as_slice());

    // Create the alloy signature
    let alloy_sig = AlloySignature::new(r_u256, s_u256, v_parity_bool);

    RlpSignature(alloy_sig)
}

// --- Message Construction Helpers ---

pub fn create_proposal_payload(
    round_id: ConsensusRoundIdentifier,
    block: QbftBlock
) -> ProposalPayload {
    ProposalPayload::new(round_id, block)
}

pub fn create_signed_proposal_payload(
    payload: ProposalPayload,
    key: &NodeKey
) -> SignedData<ProposalPayload> {
    SignedData::sign(payload, key).expect("Failed to sign proposal payload")
}

pub fn create_bft_message_proposal(
    signed_payload: SignedData<ProposalPayload>
) -> BftMessage<ProposalPayload> {
    BftMessage::new(signed_payload)
}

pub fn create_proposal(
    bft_message: BftMessage<ProposalPayload>,
    header_for_proposal_struct: QbftBlockHeader, // Match field name if changed
    rc_proofs: Vec<RoundChange>,
    prep_cert: Option<PreparedCertificateWrapper>
) -> Proposal {
    Proposal::new(bft_message, header_for_proposal_struct, rc_proofs, prep_cert)
}

// Added helpers for other message types

pub fn create_prepare_payload(
    round_id: ConsensusRoundIdentifier,
    digest: B256
) -> PreparePayload {
    PreparePayload::new(round_id, digest)
}

pub fn create_signed_prepare_payload(
    payload: PreparePayload,
    key: &NodeKey
) -> SignedData<PreparePayload> {
    SignedData::sign(payload, key).expect("Failed to sign prepare payload")
}

pub fn create_prepare(
    signed_payload: SignedData<PreparePayload>
) -> Prepare {
    Prepare::new(signed_payload)
}


pub fn create_commit_payload(
    round_id: ConsensusRoundIdentifier,
    digest: B256,
    committed_seal: RlpSignature // Assuming commit needs the seal directly as Bytes
) -> CommitPayload {
    CommitPayload::new(round_id, digest, committed_seal)
}

pub fn create_signed_commit_payload(
    payload: CommitPayload,
    key: &NodeKey
) -> SignedData<CommitPayload> {
    SignedData::sign(payload, key).expect("Failed to sign commit payload")
}

pub fn create_commit(
    signed_payload: SignedData<CommitPayload>
) -> Commit {
    Commit::new(signed_payload)
}

// --- Round Change Message Helpers ---

pub fn create_round_change_payload(
    round_id: ConsensusRoundIdentifier,
    prepared_round_metadata: Option<PreparedRoundMetadata>,
    prepared_block: Option<QbftBlock>,
) -> RoundChangePayload {
    RoundChangePayload::new(round_id, prepared_round_metadata, prepared_block)
}

pub fn create_signed_round_change_payload(
    payload: RoundChangePayload,
    key: &NodeKey
) -> SignedData<RoundChangePayload> {
    SignedData::sign(payload, key).expect("Failed to sign round change payload")
}

pub fn create_bft_message_round_change(
    signed_payload: SignedData<RoundChangePayload>
) -> BftMessage<RoundChangePayload> {
    BftMessage::new(signed_payload)
}

pub fn create_round_change(
    signed_payload_data: SignedData<RoundChangePayload>,
    prepared_block: Option<QbftBlock>,
    prepares: Option<Vec<SignedData<PreparePayload>>>,
) -> RoundChange {
    RoundChange::new(signed_payload_data, prepared_block, prepares)
        .expect("Failed to create RoundChange in test helper") // Use expect for test helpers
}

// Note: RoundChange creation is more complex due to optional fields,
// ensure consistency between payload metadata and provided block/prepares.