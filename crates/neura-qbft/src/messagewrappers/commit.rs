use crate::payload::CommitPayload;
use crate::messagewrappers::bft_message::BftMessage;
use crate::types::SignedData;
use alloy_rlp::{Encodable, Decodable, BufMut};
use std::ops::Deref;

/// Represents a QBFT Commit message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Commit {
    inner: BftMessage<CommitPayload>,
}

impl Deref for Commit {
    type Target = BftMessage<CommitPayload>;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl Commit {
    pub fn new(signed_payload: SignedData<CommitPayload>) -> Self {
        Self { inner: BftMessage::new(signed_payload) }
    }
}

// RLP encoding for Commit is just its SignedData<CommitPayload>.
impl Encodable for Commit {
    fn encode(&self, out: &mut dyn BufMut) {
        self.inner.signed_payload.encode(out);
    }
    fn length(&self) -> usize {
        self.inner.signed_payload.length()
    }
}

impl Decodable for Commit {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        let signed_payload = SignedData::<CommitPayload>::decode(buf)?;
        Ok(Self::new(signed_payload))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::payload::CommitPayload;
    use crate::types::{ConsensusRoundIdentifier, SignedData, NodeKey, RlpSignature};
    use alloy_primitives::{B256, U256, Signature as AlloyPrimitiveSignature};
    use k256::ecdsa::SigningKey;

    fn dummy_node_key() -> NodeKey {
        SigningKey::from_bytes(&[3u8; 32].into()).unwrap()
    }

    fn dummy_round_identifier(sequence: u64, round: u32) -> ConsensusRoundIdentifier {
        ConsensusRoundIdentifier { sequence_number: sequence, round_number: round }
    }

    // Re-using the mock_rlp_signature idea from commit_payload.rs tests for self-containment
    fn mock_rlp_signature_for_commit(digest: &B256, key: &NodeKey) -> RlpSignature {
        let signature: k256::ecdsa::Signature = key.sign_prehash_recoverable(digest.as_slice()).unwrap().0;
        let recovery_id = key.sign_prehash_recoverable(digest.as_slice()).unwrap().1;
        
        let r_bytes = signature.r().to_bytes();
        let s_bytes = signature.s().to_bytes();
        
        let alloy_sig = AlloyPrimitiveSignature::from_scalars_and_parity(
            B256::from(U256::from_be_slice(&r_bytes).to_be_bytes()),
            B256::from(U256::from_be_slice(&s_bytes).to_be_bytes()),
            recovery_id.is_y_odd(),
        );
        RlpSignature(alloy_sig)
    }

    fn dummy_commit_payload(key: &NodeKey) -> CommitPayload {
        let round_id = dummy_round_identifier(3, 4);
        let digest = B256::from([0xEF; 32]);
        let committed_seal = mock_rlp_signature_for_commit(&digest, key);
        CommitPayload::new(round_id, digest, committed_seal)
    }

    #[test]
    fn test_commit_message_rlp_roundtrip() {
        let node_key = dummy_node_key();
        let payload = dummy_commit_payload(&node_key);
        let signed_payload = SignedData::sign(payload, &node_key).expect("Failed to sign CommitPayload");
        
        let commit_message = Commit::new(signed_payload.clone());

        let mut encoded_commit = Vec::new();
        commit_message.encode(&mut encoded_commit);

        // The custom RLP for Commit should be identical to RLP of just SignedData<CommitPayload>
        let mut encoded_signed_payload = Vec::new();
        signed_payload.encode(&mut encoded_signed_payload);
        assert_eq!(encoded_commit, encoded_signed_payload, "Commit RLP should match SignedData<CommitPayload> RLP");

        let decoded_commit = Commit::decode(&mut encoded_commit.as_slice()).expect("Failed to decode Commit message");

        assert_eq!(commit_message.inner.signed_payload, decoded_commit.inner.signed_payload, "Decoded Commit message content mismatch");
        assert_eq!(commit_message, decoded_commit, "Full Commit message RLP roundtrip failed");
    }
} 