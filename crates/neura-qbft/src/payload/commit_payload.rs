use crate::types::ConsensusRoundIdentifier;
use crate::payload::qbft_payload::QbftPayload;
use crate::messagedata::qbft_v1;
use alloy_primitives::{B256 as Hash, Signature};
use alloy_rlp::{RlpEncodable, RlpDecodable};

/// Represents the payload of a COMMIT message in QBFT.
#[derive(Debug, Clone, PartialEq, Eq, RlpEncodable, RlpDecodable)]
pub struct CommitPayload {
    /// The round identifier (block number and round number).
    pub round_identifier: ConsensusRoundIdentifier,
    /// The digest of the proposed block being committed to.
    pub digest: Hash,
    /// ECDSA signature of the committer over the `digest` (hash of the proposed block).
    pub committed_seal: Signature,
}

impl CommitPayload {
    pub fn new(round_identifier: ConsensusRoundIdentifier, digest: Hash, committed_seal: Signature) -> Self {
        Self { round_identifier, digest, committed_seal }
    }
}

impl QbftPayload for CommitPayload {
    fn round_identifier(&self) -> ConsensusRoundIdentifier {
        self.round_identifier
    }

    fn message_type(&self) -> u8 {
        qbft_v1::COMMIT
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::messagedata::qbft_v1::COMMIT_MESSAGE_CODE;
    use alloy_primitives::{b256, fixed_bytes};
    use k256::ecdsa::SigningKey; // For creating a dummy signature
    use rand::rngs::OsRng; // For key generation

    // Helper to create a mock ConsensusRoundIdentifier for tests
    fn MOCK_ROUND_IDENTIFIER() -> ConsensusRoundIdentifier {
        ConsensusRoundIdentifier { sequence_number: 1, round_number: 2 }
    }

    fn MOCK_DIGEST() -> Hash {
        b256!("0000000000000000000000000000000000000000000000000000000000000002")
    }

    fn MOCK_SIGNATURE() -> Signature {
        // Create a dummy signature for testing.
        // This doesn't need to be a valid signature over MOCK_DIGEST for RLP tests,
        // but for actual crypto tests it would.
        let signing_key = SigningKey::random(&mut OsRng);
        let signature: k256::ecdsa::Signature = signing_key.sign_prehash_recoverable(&MOCK_DIGEST()).unwrap().0;
        
        let r_bytes = signature.r().to_bytes();
        let s_bytes = signature.s().to_bytes();
        let v = signature.recovery_id().to_byte() as u64;

        Signature {
            r: alloy_primitives::U256::from_be_slice(&r_bytes),
            s: alloy_primitives::U256::from_be_slice(&s_bytes),
            v: alloy_primitives::U256::from(v), // Parity. In k256, it's 0 or 1. Alloy's v can be 0,1 or 27,28.
                                           // For RLP, just need values. Actual crypto compatibility needs care.
                                           // Let's assume simple 0 or 1 for RLP encoding tests.
        }
    }

    #[test]
    fn test_commit_payload_rlp_encoding_decoding() {
        let original_payload = CommitPayload {
            round_identifier: MOCK_ROUND_IDENTIFIER(),
            digest: MOCK_DIGEST(),
            committed_seal: MOCK_SIGNATURE(),
        };

        let mut encoded_data = Vec::new();
        original_payload.encode(&mut encoded_data);

        let decoded_payload = CommitPayload::decode(&mut encoded_data.as_slice()).unwrap();

        assert_eq!(original_payload, decoded_payload);
        assert_eq!(decoded_payload.committed_seal, MOCK_SIGNATURE());
    }

    #[test]
    fn test_commit_payload_qbft_payload_methods() {
        let payload = CommitPayload {
            round_identifier: MOCK_ROUND_IDENTIFIER(),
            digest: MOCK_DIGEST(),
            committed_seal: MOCK_SIGNATURE(),
        };

        assert_eq!(payload.round_identifier(), MOCK_ROUND_IDENTIFIER());
        assert_eq!(CommitPayload::msg_type(), COMMIT_MESSAGE_CODE); // Using static method from QbftPayload
        assert_eq!(payload.message_type(), COMMIT_MESSAGE_CODE); // Using instance method
    }
} 