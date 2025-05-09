use crate::types::{ConsensusRoundIdentifier, RlpSignature, SignedData, NodeKey};
use crate::payload::qbft_payload::QbftPayload;
use crate::messagedata::qbft_v1;
use alloy_primitives::{B256 as Hash, keccak256, Bytes};
use alloy_rlp::{RlpEncodable, RlpDecodable, Encodable, Decodable};

/// Represents the payload of a COMMIT message in QBFT.
#[derive(Debug, Clone, PartialEq, Eq, RlpEncodable, RlpDecodable)]
pub struct CommitPayload {
    /// The round identifier (block number and round number).
    pub round_identifier: ConsensusRoundIdentifier,
    /// The digest of the proposed block being committed to.
    pub digest: Hash,
    /// ECDSA signature of the committer over the `digest` (hash of the proposed block).
    pub committed_seal: RlpSignature,
}

impl CommitPayload {
    pub fn new(round_identifier: ConsensusRoundIdentifier, digest: Hash, committed_seal: RlpSignature) -> Self {
        Self { round_identifier, digest, committed_seal }
    }
}

impl QbftPayload for CommitPayload {
    fn round_identifier(&self) -> &ConsensusRoundIdentifier {
        &self.round_identifier
    }

    fn message_type(&self) -> u8 {
        qbft_v1::COMMIT
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::messagedata::qbft_v1;
    use alloy_primitives::{b256, Signature as AlloyPrimitiveSignature, U256, B256 as HashB256};
    use k256::ecdsa::SigningKey;
    use rand::rngs::OsRng;

    fn MOCK_ROUND_IDENTIFIER() -> ConsensusRoundIdentifier {
        ConsensusRoundIdentifier { sequence_number: 1, round_number: 2 }
    }

    fn MOCK_DIGEST() -> Hash {
        b256!("0000000000000000000000000000000000000000000000000000000000000002")
    }

    fn MOCK_RLP_SIGNATURE() -> RlpSignature {
        let signing_key = SigningKey::random(&mut OsRng);
        let signature: k256::ecdsa::Signature = signing_key.sign_prehash_recoverable(MOCK_DIGEST().as_slice()).unwrap().0;
        
        let r_bytes = signature.r().to_bytes();
        let s_bytes = signature.s().to_bytes();
        let parity_bool = signing_key.sign_prehash_recoverable(MOCK_DIGEST().as_slice()).unwrap().1.is_y_odd();

        let alloy_sig = AlloyPrimitiveSignature::from_scalars_and_parity(
            HashB256::from(U256::from_be_slice(&r_bytes).to_be_bytes()),
            HashB256::from(U256::from_be_slice(&s_bytes).to_be_bytes()),
            parity_bool,
        );
        RlpSignature(alloy_sig)
    }

    #[test]
    fn test_commit_payload_rlp_encoding_decoding() {
        let original_payload = CommitPayload {
            round_identifier: MOCK_ROUND_IDENTIFIER(),
            digest: MOCK_DIGEST(),
            committed_seal: MOCK_RLP_SIGNATURE(),
        };

        let mut encoded_data = Vec::new();
        original_payload.encode(&mut encoded_data);

        let decoded_payload = CommitPayload::decode(&mut encoded_data.as_slice()).unwrap();

        assert_eq!(original_payload, decoded_payload);
        assert_eq!(decoded_payload.committed_seal, MOCK_RLP_SIGNATURE());
    }

    #[test]
    fn test_commit_payload_qbft_payload_methods() {
        let payload = CommitPayload {
            round_identifier: MOCK_ROUND_IDENTIFIER(),
            digest: MOCK_DIGEST(),
            committed_seal: MOCK_RLP_SIGNATURE(),
        };

        assert_eq!(*payload.round_identifier(), MOCK_ROUND_IDENTIFIER());
        assert_eq!(payload.message_type(), qbft_v1::COMMIT);
    }
} 