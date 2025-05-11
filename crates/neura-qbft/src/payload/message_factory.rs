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
        // This prepared_round_metadata (if Some) is now expected to contain the 
        // original signed_proposal_payload and the Vec<SignedData<PreparePayload>>.
        prepared_round_metadata_opt: Option<PreparedRoundMetadata>, 
        prepared_block_opt: Option<QbftBlock>,
        // prepares_for_wrapper: Vec<SignedData<PreparePayload>>, // This argument is removed
    ) -> Result<RoundChange, QbftError> {
        
        let rc_payload = RoundChangePayload::new(
            target_round_identifier, 
            prepared_round_metadata_opt.clone(), 
            prepared_block_opt.clone()
        );
        let signed_rc_payload = SignedData::sign(rc_payload, &self.node_key)?;
        
        // Extract Vec<SignedData<PreparePayload>> for RoundChange::new
        let prepares_for_rc_new_method: Option<Vec<SignedData<PreparePayload>>> = 
            if let Some(ref metadata) = prepared_round_metadata_opt {
                if metadata.prepares.is_empty() {
                    None 
                } else {
                    Some(metadata.prepares.clone()) // Clone the Vec<SignedData<PreparePayload>>
                }
            } else {
                None
            };
            
        RoundChange::new(signed_rc_payload, prepared_block_opt, prepares_for_rc_new_method)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{
        ConsensusRoundIdentifier, QbftBlock, QbftBlockHeader, RlpSignature, 
    };
    use crate::messagewrappers::BftMessage;
    use crate::payload::{ProposalPayload, PreparePayload, PreparedRoundMetadata};

    use alloy_primitives::{Address, Bytes, B256, U256, Bloom};
    use k256::ecdsa::{SigningKey as K256SigningKey, VerifyingKey as K256VerifyingKey, signature::hazmat::PrehashVerifier};
    use std::sync::Arc;

    // --- Test Utility Functions (redefined for self-containment, consider a shared test_utils.rs later) ---
    fn dummy_node_key() -> Arc<NodeKey> {
        Arc::new(K256SigningKey::from_bytes(&[4u8; 32].into()).unwrap())
    }

    fn address_from_node_key(node_key: &NodeKey) -> Address {
        let verifying_key: &K256VerifyingKey = node_key.verifying_key();
        let encoded_point = verifying_key.to_encoded_point(false); 
        let uncompressed_pk_bytes = encoded_point.as_bytes();
        if uncompressed_pk_bytes.is_empty() || uncompressed_pk_bytes[0] != 0x04 {
            panic!("Invalid uncompressed public key format");
        }
        let hashed_pk = keccak256(&uncompressed_pk_bytes[1..]);
        Address::from_slice(&hashed_pk[12..])
    }

    fn dummy_round_identifier(sequence: u64, round: u32) -> ConsensusRoundIdentifier {
        ConsensusRoundIdentifier { sequence_number: sequence, round_number: round }
    }
    
    fn dummy_block_header(block_number: u64, parent_hash_val: B256) -> QbftBlockHeader {
        QbftBlockHeader::new(
            parent_hash_val, B256::from([1; 32]), Address::ZERO,
            B256::from([2; 32]), B256::from([3; 32]), B256::from([4; 32]),
            Bloom::default(), U256::from(1), block_number, 1_000_000, 0,
            1_000_000_000 + block_number, Bytes::from_static(&[0u8; 32]),
            B256::from([5; 32]), Bytes::from_static(&[0u8; 8]),
        )
    }

    fn dummy_qbft_block(block_number: u64, parent_hash_val: B256) -> QbftBlock {
        let header = dummy_block_header(block_number, parent_hash_val);
        QbftBlock::new(header, Vec::new(), Vec::new())
    }
    
    // --- MessageFactory Tests ---
    #[test]
    fn test_message_factory_new_and_local_address() {
        let node_key_arc = dummy_node_key();
        let factory = MessageFactory::new(node_key_arc.clone()).expect("Failed to create MessageFactory");
        let expected_address = address_from_node_key(&node_key_arc);
        assert_eq!(factory.local_address(), expected_address, "MessageFactory local_address mismatch");
    }

    #[test]
    fn test_create_commit_seal_and_commit() {
        let node_key_arc = dummy_node_key();
        let factory = MessageFactory::new(node_key_arc.clone()).unwrap();
        let round_id = dummy_round_identifier(1, 0);
        let block_digest = B256::from([0xAB; 32]);

        let commit_seal = factory.create_commit_seal(block_digest).expect("Failed to create commit seal");
        
        let pk = node_key_arc.verifying_key();
        // For k256::Signature (which is AlloyPrimitiveSignature), we need to convert it to k256::ecdsa::Signature for verify_prehash
        let k256_commit_sig = k256::ecdsa::Signature::from_scalars(commit_seal.r().to_be_bytes(), commit_seal.s().to_be_bytes()).unwrap();
        assert!(pk.verify_prehash(block_digest.as_slice(), &k256_commit_sig).is_ok(), "Commit seal verification failed");

        let commit_msg = factory.create_commit(round_id, block_digest, commit_seal).expect("Failed to create commit message");

        assert_eq!(commit_msg.author().unwrap(), factory.local_address(), "Commit author mismatch");
        assert_eq!(commit_msg.payload().round_identifier, round_id);
        assert_eq!(commit_msg.payload().digest, block_digest);
        assert_eq!(commit_msg.payload().committed_seal, RlpSignature(commit_seal));
    }

    // Placeholder for Proposal test
    #[test]
    fn test_create_proposal() {
        let node_key_arc = dummy_node_key();
        let factory = MessageFactory::new(node_key_arc.clone()).unwrap();
        let round_id = dummy_round_identifier(2, 1);
        let block = dummy_qbft_block(2, B256::from([0xAA; 32]));
        
        let proposal_msg = factory.create_proposal(round_id, block.clone(), Vec::new(), None).expect("Failed to create proposal");
        
        assert_eq!(proposal_msg.author().unwrap(), factory.local_address(), "Proposal author mismatch");
        assert_eq!(proposal_msg.payload().round_identifier, round_id);
        assert_eq!(proposal_msg.payload().proposed_block.hash(), block.hash());
        assert_eq!(proposal_msg.proposed_block_header(), &block.header);
    }

    // Placeholder for Prepare test
    #[test]
    fn test_create_prepare() {
        let node_key_arc = dummy_node_key();
        let factory = MessageFactory::new(node_key_arc.clone()).unwrap();
        let round_id = dummy_round_identifier(3, 2);
        let digest = B256::from([0xBB; 32]);

        let prepare_msg = factory.create_prepare(round_id, digest).expect("Failed to create prepare message");

        assert_eq!(prepare_msg.author().unwrap(), factory.local_address(), "Prepare author mismatch");
        assert_eq!(prepare_msg.payload().round_identifier, round_id);
        assert_eq!(prepare_msg.payload().digest, digest);
    }
    
    // --- Dummy helpers for RoundChange and PreparedCertificate --- 
    // (Copied and adapted from proposal.rs tests for now)
    fn dummy_prepare_payload_for_mf(round_id: ConsensusRoundIdentifier, digest: B256) -> PreparePayload {
        PreparePayload::new(round_id, digest)
    }

    fn dummy_signed_prepare_payload_for_mf(payload: PreparePayload, key: &NodeKey) -> SignedData<PreparePayload> {
        SignedData::sign(payload, key).unwrap()
    }
    
    fn dummy_bft_message_proposal_payload_for_mf(block_number: u64, round_number: u32, key: &NodeKey) -> BftMessage<ProposalPayload> {
        let payload = ProposalPayload::new(
            dummy_round_identifier(block_number, round_number), 
            dummy_qbft_block(block_number, B256::from([0u8; 32]))
        );
        let signed_payload = SignedData::sign(payload, key).unwrap();
        BftMessage::new(signed_payload)
    }

    fn dummy_prepared_round_metadata_for_mf(key: &NodeKey, round_id_seq: u64, round_id_num: u32) -> PreparedRoundMetadata {
        let proposal_bft_msg = dummy_bft_message_proposal_payload_for_mf(round_id_seq, round_id_num, key);
        let block_hash = proposal_bft_msg.payload().proposed_block.hash();
        
        let prepare_payload = dummy_prepare_payload_for_mf(dummy_round_identifier(round_id_seq, round_id_num), block_hash);
        let signed_prepare = dummy_signed_prepare_payload_for_mf(prepare_payload, key);

        PreparedRoundMetadata::new(
            round_id_num, // prepared_round
            block_hash, // prepared_block_hash
            proposal_bft_msg, // signed_proposal_payload
            vec![signed_prepare], // prepares
        )
    }
    
    // Placeholder for RoundChange test
    #[test]
    fn test_create_round_change() {
        let node_key_arc = dummy_node_key();
        let factory = MessageFactory::new(node_key_arc.clone()).unwrap();
        let target_round_id = dummy_round_identifier(4, 3);

        // Case 1: No prepared data
        let rc_msg_none = factory.create_round_change(target_round_id, None, None)
            .expect("Failed to create RoundChange (no prepared data)");
        assert_eq!(rc_msg_none.author().unwrap(), factory.local_address());
        assert_eq!(rc_msg_none.payload().round_identifier, target_round_id);
        assert!(rc_msg_none.payload().prepared_round_metadata.is_none());
        assert!(rc_msg_none.prepared_block().is_none());
        assert!(rc_msg_none.prepares().is_none());

        // Case 2: With prepared data
        let prepared_block = dummy_qbft_block(4, B256::from([0xCC; 32]));
        let prepared_metadata = dummy_prepared_round_metadata_for_mf(&node_key_arc, 4, 2); // Prepared in round 2 for block 4
        
        let rc_msg_some = factory.create_round_change(target_round_id, Some(prepared_metadata.clone()), Some(prepared_block.clone()))
            .expect("Failed to create RoundChange (with prepared data)");
        
        assert_eq!(rc_msg_some.author().unwrap(), factory.local_address());
        assert_eq!(rc_msg_some.payload().round_identifier, target_round_id);
        assert_eq!(rc_msg_some.payload().prepared_round_metadata, Some(prepared_metadata.clone()));
        assert_eq!(rc_msg_some.prepared_block(), Some(&prepared_block));
        assert_eq!(rc_msg_some.prepares().unwrap().len(), prepared_metadata.prepares.len());
    }
} 