// crates/neura-qbft/src/payload/message_factory.rs
use crate::types::{ConsensusRoundIdentifier, SignedData, QbftBlock, NodeKey, RlpSignature};
use crate::payload::{
    ProposalPayload, PreparePayload, CommitPayload, RoundChangePayload, PreparedRoundMetadata
};
use crate::messagewrappers::{Proposal, Prepare, Commit, RoundChange, PreparedCertificateWrapper, BftMessage};
use crate::error::QbftError;

use alloy_primitives::{Address, B256 as Hash, Signature, U256, keccak256};
use k256::ecdsa::VerifyingKey as K256VerifyingKey;
use std::sync::Arc;

pub struct MessageFactory {
    node_key: Arc<NodeKey>, 
    local_address: Address, 
}

impl MessageFactory {
    pub fn new(node_key: Arc<NodeKey>) -> Result<Self, QbftError> {
        let verifying_key: &K256VerifyingKey = node_key.verifying_key();
        let encoded_point = verifying_key.to_encoded_point(false); // Bind to a variable
        let uncompressed_pk_bytes = encoded_point.as_bytes();
        
        if uncompressed_pk_bytes.is_empty() || uncompressed_pk_bytes[0] != 0x04 {
            return Err(QbftError::InternalError("Invalid uncompressed public key format".to_string()));
        }
        let hashed_pk = keccak256(&uncompressed_pk_bytes[1..]);
        let local_address = Address::from_slice(&hashed_pk[12..]); // Last 20 bytes

        Ok(Self { node_key, local_address })
    }

    pub fn local_address(&self) -> Address {
        self.local_address
    }

    // --- Proposal --- 
    pub fn create_proposal(
        &self,
        round_identifier: ConsensusRoundIdentifier,
        proposed_block: QbftBlock,
        round_change_proofs: Vec<RoundChange>,
        prepared_certificate: Option<PreparedCertificateWrapper>,
    ) -> Result<Proposal, QbftError> {
        let payload = ProposalPayload::new(round_identifier, proposed_block.clone());
        let signed_payload_data = SignedData::sign(payload, &self.node_key)?;
        let bft_message = BftMessage::new(signed_payload_data);
        let block_header = proposed_block.header.clone(); 
        Ok(Proposal::new(bft_message, block_header, round_change_proofs, prepared_certificate))
    }

    // --- Prepare --- 
    pub fn create_prepare(
        &self,
        round_identifier: ConsensusRoundIdentifier,
        digest: Hash, // Hash of the proposed block
    ) -> Result<Prepare, QbftError> {
        let payload = PreparePayload::new(round_identifier, digest);
        let signed_payload = SignedData::sign(payload, &self.node_key)?;
        Ok(Prepare::new(signed_payload))
    }

    // --- Commit --- 
    pub fn create_commit(
        &self,
        round_identifier: ConsensusRoundIdentifier,
        digest: Hash,            
        commit_seal: Signature, 
    ) -> Result<Commit, QbftError> {
        let payload = CommitPayload::new(round_identifier, digest, RlpSignature(commit_seal));
        let signed_payload = SignedData::sign(payload, &self.node_key)?;
        Ok(Commit::new(signed_payload))
    }

    pub fn create_commit_seal(
        &self,
        block_digest: Hash, 
    ) -> Result<Signature, QbftError> {
        let (k256_rec_sig, recovery_id) = self.node_key.sign_prehash_recoverable(block_digest.as_slice())?;
        
        let r_bytes = k256_rec_sig.r().to_bytes();
        let s_bytes = k256_rec_sig.s().to_bytes();
        let r_u256 = U256::from_be_slice(&r_bytes);
        let s_u256 = U256::from_be_slice(&s_bytes);
        let parity_bool = recovery_id.is_y_odd();

        let r_b256 = Hash::from(r_u256.to_be_bytes());
        let s_b256 = Hash::from(s_u256.to_be_bytes());

        Ok(Signature::from_scalars_and_parity(r_b256, s_b256, parity_bool))
    }

    // --- RoundChange --- 
    pub fn create_round_change(
        &self,
        target_round_identifier: ConsensusRoundIdentifier,
        prepared_round_metadata: Option<PreparedRoundMetadata>,
        prepared_block: Option<QbftBlock>,
        prepares_for_wrapper: Vec<SignedData<PreparePayload>>,
    ) -> Result<RoundChange, QbftError> {
        let is_metadata_none = prepared_round_metadata.is_none();
        
        let payload = RoundChangePayload::new(target_round_identifier, prepared_round_metadata);
        let signed_payload = SignedData::sign(payload, &self.node_key)?;
        
        let prepares_option = if prepares_for_wrapper.is_empty() && is_metadata_none {
            None 
        } else {
            Some(prepares_for_wrapper)
        };
        RoundChange::new(signed_payload, prepared_block, prepares_option)
    }
} 