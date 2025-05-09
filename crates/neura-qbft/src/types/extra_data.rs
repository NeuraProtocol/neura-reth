use alloy_primitives::{Address, Bytes, Signature, B256};
use alloy_rlp::{RlpEncodable, RlpDecodable, Header, BufMut, Error as RlpError};
use crate::error::QbftError;
use std::collections::VecDeque; // For vanity data matching Besu, not used in current struct

/// Represents the structured data within a QBFT block header's extraData field.
#[derive(Debug, Clone, PartialEq, Eq, RlpEncodable, RlpDecodable, Default)]
pub struct BftExtraData {
    // In Besu, vanity_data is Bytes32. Here, using Bytes for flexibility, though it must be 32 bytes for QBFT spec typically.
    // Let's use a fixed-size array for vanity data if it's truly fixed or ensure it's handled correctly.
    // For now, assuming it's part of a larger RLP structure that the codec handles.
    // The RLP structure of extraData is: RLP_LIST[vanityData, validators, commitSeals, roundNumber]
    // Let's make BftExtraData directly RlpEncodable/Decodable.
    pub vanity_data: Bytes, // Typically 32 bytes of arbitrary data.
    pub validators: Vec<Address>,
    pub committed_seals: Vec<Signature>,
    pub round_number: u32, // In Besu, this is always present for QBFT.
}

// The BftExtraDataCodec trait might not be needed if BftExtraData itself is RLP-aware
// and QbftBlockHeader simply stores the raw extra_data: Bytes, and decodes it on demand.
// For now, we'll assume the header stores raw Bytes and we might have a codec helper.

pub trait BftExtraDataCodec: Send + Sync {
    fn decode(&self, extra_data_bytes: &Bytes) -> Result<BftExtraData, QbftError>;
    fn encode(&self, bft_extra_data: &BftExtraData) -> Result<Bytes, QbftError>;
}

// Default implementation for the codec using alloy-rlp for BftExtraData struct
pub struct AlloyBftExtraDataCodec;

impl BftExtraDataCodec for AlloyBftExtraDataCodec {
    fn decode(&self, extra_data_bytes: &Bytes) -> Result<BftExtraData, QbftError> {
        BftExtraData::decode(&mut extra_data_bytes.as_ref())
            .map_err(|e| QbftError::RlpDecodingError(format!("BftExtraData: {}", e)))
    }

    fn encode(&self, bft_extra_data: &BftExtraData) -> Result<Bytes, QbftError> {
        let mut out = Vec::new();
        bft_extra_data.encode(&mut out);
        Ok(Bytes::from(out))
    }
} 