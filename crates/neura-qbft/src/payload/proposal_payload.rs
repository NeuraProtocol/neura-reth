use crate::types::{ConsensusRoundIdentifier, QbftBlock};
use crate::payload::qbft_payload::QbftPayload; // Corrected path
use crate::messagedata::qbft_v1; // For message type codes
use alloy_rlp::{RlpEncodable, RlpDecodable}; // Added RlpEncodable, RlpDecodable

/// Represents the payload of a QBFT Proposal message.
/// This is the actual data that gets signed by the proposer.
#[derive(Debug, Clone, PartialEq, Eq, RlpEncodable, RlpDecodable)]
pub struct ProposalPayload {
    pub round_identifier: ConsensusRoundIdentifier,
    pub proposed_block: QbftBlock,
    // The block_encoder from Java is a transient field for encoding/decoding logic,
    // not part of the RLP structure itself. In Rust, RLP logic is usually handled by traits.
}

impl ProposalPayload {
    pub fn new(round_identifier: ConsensusRoundIdentifier, proposed_block: QbftBlock) -> Self {
        Self { round_identifier, proposed_block }
    }
}

impl QbftPayload for ProposalPayload {
    fn round_identifier(&self) -> &ConsensusRoundIdentifier {
        &self.round_identifier
    }

    fn message_type(&self) -> u8 {
        qbft_v1::PROPOSAL // We'll define qbft_v1::PROPOSAL later
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ConsensusRoundIdentifier, QbftBlock, QbftBlockHeader};
    use alloy_primitives::{Address, Bytes, B256, U256, Bloom};
    use alloy_rlp::{encode, Decodable};

    // Dummy ConsensusRoundIdentifier for testing
    fn dummy_round_identifier(sequence: u64, round: u32) -> ConsensusRoundIdentifier {
        ConsensusRoundIdentifier { sequence_number: sequence, round_number: round }
    }

    // Dummy QbftBlockHeader for testing
    fn dummy_block_header(block_number: u64, parent_hash_val: B256) -> QbftBlockHeader {
        QbftBlockHeader::new(
            parent_hash_val,                         // parent_hash
            B256::from([1; 32]),                  // ommers_hash (made distinct)
            Address::ZERO,                        // beneficiary (using Address::ZERO)
            B256::from([2; 32]),                  // state_root (made distinct)
            B256::from([3; 32]),                  // transactions_root (made distinct)
            B256::from([4; 32]),                  // receipts_root (made distinct)
            Bloom::default(),                     // logs_bloom
            U256::from(1),                        // difficulty
            block_number,                         // number
            1_000_000,                            // gas_limit
            0,                                    // gas_used
            1_000_000_000 + block_number,         // timestamp
            Bytes::from_static(&[0u8; 32]),      // extra_data (e.g., BftExtraData RLP)
            B256::from([5; 32]),                  // mix_hash (made distinct)
            Bytes::from_static(&[0u8; 8]),       // nonce (must be 8 bytes)
        )
    }

    // Dummy QbftBlock for testing
    fn dummy_qbft_block(block_number: u64, parent_hash_val: B256) -> QbftBlock {
        let header = dummy_block_header(block_number, parent_hash_val);
        QbftBlock::new(
            header,
            Vec::new(), // body_transactions (Vec<Transaction>)
            Vec::new(), // body_ommers (Vec<QbftBlockHeader>)
        )
    }

    #[test]
    fn test_proposal_payload_rlp_roundtrip() {
        let payload = ProposalPayload {
            round_identifier: dummy_round_identifier(1, 5),
            proposed_block: dummy_qbft_block(10, B256::from([0u8; 32])),
        };

        let encoded_payload = encode(&payload);
        let decoded_payload = ProposalPayload::decode(&mut encoded_payload.as_slice()).expect("Failed to decode ProposalPayload");

        assert_eq!(payload, decoded_payload, "RLP roundtrip for ProposalPayload failed");
    }
} 