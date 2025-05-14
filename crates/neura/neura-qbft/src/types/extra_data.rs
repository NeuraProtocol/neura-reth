use alloy_primitives::{Address, Bytes};
use alloy_rlp::{RlpEncodable, RlpDecodable, Encodable, Decodable, Error as RlpError};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
 // For vanity data matching Besu, not used in current struct
use crate::types::RlpSignature;

/// Represents the BFT-specific data stored in the `extraData` field of a block header.
#[derive(Debug, Clone, PartialEq, Eq, RlpEncodable, RlpDecodable)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[rlp(trailing)] // For committed_seals if it becomes Option or for future optional fields
pub struct BftExtraData {
    // Fixed-size byte array for vanity data, chosen to match Besu's 32 bytes.
    pub vanity_data: Bytes, // Should be exactly 32 bytes when encoding/decoding if enforced
    // List of validators for the *next* block.
    pub validators: Vec<Address>,
    // List of validator signatures (seals) that voted for the block.
    // This is RLP-encoded as a list of signatures.
    pub committed_seals: Vec<RlpSignature>,
    // The consensus round number in which this block was agreed upon.
    pub round_number: u32,
    // Besu also has vote: Option<BftVote> - not included for now for simplicity
}

// The BftExtraDataCodec trait might not be needed if BftExtraData itself is RLP-aware
// and QbftBlockHeader simply stores the raw extra_data: Bytes, and decodes it on demand.
// For now, we'll assume the header stores raw Bytes and we might have a codec helper.

pub trait BftExtraDataCodec: Send + Sync {
    fn decode(&self, extra_data_bytes: &Bytes) -> Result<BftExtraData, RlpError>;
    fn encode(&self, bft_extra_data: &BftExtraData) -> Result<Bytes, RlpError>;
}

// Default implementation for the codec using alloy-rlp for BftExtraData struct
#[derive(Debug, Clone, Default)]
pub struct AlloyBftExtraDataCodec;

impl BftExtraDataCodec for AlloyBftExtraDataCodec {
    fn decode(&self, extra_data_bytes: &Bytes) -> Result<BftExtraData, RlpError> {
        BftExtraData::decode(&mut extra_data_bytes.as_ref())
    }

    fn encode(&self, bft_extra_data: &BftExtraData) -> Result<Bytes, RlpError> {
        let mut out = Vec::new();
        bft_extra_data.encode(&mut out);
        Ok(Bytes::from(out))
    }
}

#[cfg(test)]
mod tests {
    use super::*;    
    use alloy_primitives::{hex, Address, U256, Bytes, B256, Signature};

    fn dummy_rlp_signature(val: u64) -> RlpSignature {
        let r = U256::from(val);
        let s = U256::from(val + 1);
        let parity_bool = val % 2 != 0;
        
        let r_b256 = B256::from(r.to_be_bytes());
        let s_b256 = B256::from(s.to_be_bytes());

        let sig = Signature::from_scalars_and_parity(r_b256, s_b256, parity_bool);
        RlpSignature(sig)
    }

    #[test]
    fn test_bft_extra_data_rlp_roundtrip() {
        let address1 = Address::from_slice(&hex!("0000000000000000000000000000000000000001"));
        let address2 = Address::from_slice(&hex!("0000000000000000000000000000000000000002"));
        let extra_data = BftExtraData {
            vanity_data: Bytes::from_static(&[0u8; 32]),
            validators: vec![address1, address2],
            committed_seals: vec![
                dummy_rlp_signature(1),
                dummy_rlp_signature(4),
            ],
            round_number: 5,
        };

        let codec = AlloyBftExtraDataCodec::default();
        let encoded = codec.encode(&extra_data).unwrap();
        let decoded = codec.decode(&encoded).unwrap();

        assert_eq!(extra_data, decoded);
    }

     #[test]
    fn test_bft_extra_data_empty_seals_validators() {
        let extra_data = BftExtraData {
            vanity_data: Bytes::from_static(&[1u8; 32]),
            validators: vec![],
            committed_seals: vec![],
            round_number: 0,
        };
        let codec = AlloyBftExtraDataCodec::default();
        let encoded = codec.encode(&extra_data).unwrap();
        let decoded = codec.decode(&encoded).unwrap();
        assert_eq!(extra_data, decoded);
    }

    #[test]
    fn test_besu_like_round_0_extra_data() {
        let extra_data = BftExtraData {
            vanity_data: Bytes::from_static(&[0u8; 32]),
            validators: vec![],
            committed_seals: vec![],
            round_number: 0,
        };

        let mut buffer = Vec::new();
        extra_data.encode(&mut buffer);

        // RLP of: 32 zero bytes for vanity, empty list for validators, empty list for committed_seals, integer 0 for round
        // vanity: 0xa00000000000000000000000000000000000000000000000000000000000000000
        // validators: 0xc0
        // committed_seals: 0xc0
        // round_number (0u32): 0x80
        let expected_rlp_hex = "e4a00000000000000000000000000000000000000000000000000000000000000000c0c080"; // Changed last byte from 00 to 80
        assert_eq!(hex::encode(buffer), expected_rlp_hex);
    }
} 