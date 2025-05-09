// crates/neura-qbft/src/payload/message_factory.rs
use crate::types::{ConsensusRoundIdentifier, SignedData, QbftBlock, NodeKey};
use crate::payload::{
    ProposalPayload, PreparePayload, CommitPayload, RoundChangePayload, PreparedRoundMetadata
};
use crate::messagewrappers::{Proposal, Prepare, Commit, RoundChange};
use crate::error::QbftError;

use alloy_primitives::{Address, B256 as Hash, Signature};
use k256::ecdsa::SigningKey;
use std::sync::Arc; // For NodeKey, assuming it might be shared

// In Java, NodeKey is an interface. Here, we'll assume we get a k256::ecdsa::SigningKey.
// A more abstract NodeKey trait could be used if different key types are needed.
pub type NodeKey = K256SigningKey;

pub struct MessageFactory {
    node_key: Arc<NodeKey>, // Use Arc for shared ownership if MessageFactory is cloned
    local_address: Address, // Recovered from node_key or passed in
}

impl MessageFactory {
    pub fn new(node_key: Arc<NodeKey>) -> Result<Self, QbftError> {
        let verifying_key = node_key.verifying_key();
        let local_address = Address::from_public_key(&verifying_key);
        Ok(Self { node_key, local_address })
    }

    pub fn local_address(&self) -> Address {
        self.local_address
    }

    // --- Proposal --- 
    pub fn create_proposal(
        &self,
        round_identifier: ConsensusRoundIdentifier,
        block: QbftBlock,
        round_changes: Vec<SignedData<RoundChangePayload>>,
        prepares: Vec<SignedData<PreparePayload>>,
    ) -> Result<Proposal, QbftError> {
        let payload = ProposalPayload::new(round_identifier, block);
        let signed_payload = SignedData::sign(payload, &self.node_key)?;
        Ok(Proposal::new(signed_payload, round_changes, prepares))
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
        digest: Hash,             // Hash of the proposed block
        commit_seal: Signature, // This seal is created by signing the block's hash with node_key
                                // The QbftRound logic in Java does this separately.
                                // Let's assume commit_seal is pre-calculated and passed in for now.
                                // Alternatively, MessageFactory could create it if it has the block hash.
    ) -> Result<Commit, QbftError> {
        // In Besu, the commitSeal is a signature over RLP(blockHeader.getHashFor όλα(), roundIdentifier)
        // For now, we assume it's passed in after being calculated by the consensus logic.
        let payload = CommitPayload::new(round_identifier, digest, commit_seal);
        let signed_payload = SignedData::sign(payload, &self.node_key)?;
        Ok(Commit::new(signed_payload))
    }

    // Method to create the commit seal itself, which is part of CommitPayload
    // This should sign the block_digest (hash of the proposed block).
    pub fn create_commit_seal(
        &self,
        block_digest: Hash, // Only the block digest is signed for the seal, as per Besu's CommitValidator
        // round_identifier: &ConsensusRoundIdentifier // Not part of the data signed for the seal itself
    ) -> Result<Signature, QbftError> {
        // In Besu's CommitValidator, the seal is a signature over the commitPayload.getDigest(),
        // which is the block hash.
        // final Hash committerEmbeddedBlockHash = commitPayload.getDigest();
        // final Signature committerSignature = Signature.decode(commitPayload.getCommittedSeal());
        // final Address committer = nodeKey.recoverPublicKey(committerEmbeddedBlockHash, committerSignature);
        
        // The block_digest itself is the message to be signed for the committed_seal.
        // k256::ecdsa::SigningKey::sign_prehash_recoverable expects a pre-hashed message.
        // Since block_digest is already a hash (B256), it can be used directly if the key type expects a pre-hashed message.
        // If sign_prehash_recoverable expects the *message* itself to be hashed again, we should not re-hash it.
        // Given the name `sign_prehash_recoverable`, it implies `block_digest` is the pre-hashed message.
        let (k256_sig, recovery_id) = self.node_key.sign_prehash_recoverable(block_digest.as_slice())?;
        
        Signature::from_signature_and_parity(k256_sig, recovery_id)
            .map_err(|e| QbftError::CryptoError(format!("Failed to create commit seal signature: {}", e)))
    }

    // --- RoundChange --- 
    pub fn create_round_change(
        &self,
        target_round_identifier: ConsensusRoundIdentifier,
        prepared_round_metadata: Option<PreparedRoundMetadata>,
        // For RoundChange wrapper, we also need block and prepares if metadata is Some
        prepared_block: Option<QbftBlock>,
        prepares_for_wrapper: Vec<SignedData<PreparePayload>>,
    ) -> Result<RoundChange, QbftError> {
        let payload = RoundChangePayload::new(target_round_identifier, prepared_round_metadata);
        let signed_payload = SignedData::sign(payload, &self.node_key)?;
        RoundChange::new(signed_payload, prepared_block, prepares_for_wrapper) 
    }
} 