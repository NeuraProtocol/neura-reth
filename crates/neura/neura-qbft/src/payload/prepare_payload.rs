use crate::types::ConsensusRoundIdentifier;
use crate::payload::qbft_payload::QbftPayload;
use crate::messagedata::qbft_v1;
use alloy_primitives::B256 as Hash; // Using B256 for hashes (fixed-size 32-byte array)
use alloy_rlp::{RlpEncodable, RlpDecodable};

/// Represents the payload of a QBFT Prepare message.
#[derive(Debug, Clone, PartialEq, Eq, RlpEncodable, RlpDecodable)]
pub struct PreparePayload {
    pub round_identifier: ConsensusRoundIdentifier,
    pub digest: Hash, // Hash of the proposed block
}

impl PreparePayload {
    pub fn new(round_identifier: ConsensusRoundIdentifier, digest: Hash) -> Self {
        Self { round_identifier, digest }
    }
}

impl QbftPayload for PreparePayload {
    fn round_identifier(&self) -> &ConsensusRoundIdentifier {
        &self.round_identifier
    }

    fn message_type(&self) -> u8 {
        qbft_v1::PREPARE
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::ConsensusRoundIdentifier;
    use alloy_primitives::B256;
    use alloy_rlp::{encode, Decodable as RlpDecodable};

    fn dummy_round_identifier(sequence: u64, round: u32) -> ConsensusRoundIdentifier {
        ConsensusRoundIdentifier { sequence_number: sequence, round_number: round }
    }

    #[test]
    fn test_prepare_payload_rlp_roundtrip() {
        let payload = PreparePayload {
            round_identifier: dummy_round_identifier(1, 5),
            digest: B256::from([0xAB; 32]),
        };

        let encoded_payload = encode(&payload);
        let decoded_payload = PreparePayload::decode(&mut encoded_payload.as_slice()).expect("Failed to decode PreparePayload");

        assert_eq!(payload, decoded_payload, "RLP roundtrip for PreparePayload failed");
    }
} 