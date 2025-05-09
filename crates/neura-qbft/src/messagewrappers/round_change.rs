use crate::payload::{RoundChangePayload, PreparePayload, PreparedRoundMetadata};
use crate::messagewrappers::bft_message::BftMessage;
use crate::types::{SignedData, QbftBlock, ConsensusRoundIdentifier};
use alloy_rlp::{Encodable, Decodable, Header, BufMut, Error as RlpError};
use std::ops::Deref;
use alloy_primitives::Address; // For author
use crate::error::QbftError; // For author

/// Represents a QBFT RoundChange message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoundChange {
    // signed_payload is the first element in the RLP list.
    signed_payload: SignedData<RoundChangePayload>,
    // Optional: Block from a prepared certificate, if any. This is the second element.
    // The Java version uses Optional<BlockHeader>. We use QbftBlock for now.
    // If prepared_round_metadata in payload is None, this should be RLP Null (effectively None).
    pub prepared_block: Option<QbftBlock>,
    // List of prepares from the prepared certificate. This is the third element.
    // If prepared_round_metadata in payload is None, this should be an empty RLP list.
    pub prepares: Vec<SignedData<PreparePayload>>,
}

// We are not using BftMessage<RoundChangePayload> directly here because the RLP structure
// of RoundChange is more complex than just its signed payload.

impl RoundChange {
    pub fn new(
        signed_payload: SignedData<RoundChangePayload>,
        prepared_block: Option<QbftBlock>,
        prepares: Vec<SignedData<PreparePayload>>,
    ) -> Result<Self, QbftError> {
        // Consistency check: if prepared_block or prepares are present, 
        // the payload's prepared_round_metadata must be Some.
        // And if metadata is Some, its prepares should match the provided prepares.
        match &signed_payload.payload().prepared_round_metadata {
            Some(metadata) => {
                if prepared_block.is_none() {
                    return Err(QbftError::ValidationError("RoundChange: prepared_block missing when metadata present".into()));
                }
                // This check might be too strict if prepares can be empty even with metadata
                // if metadata.prepares.len() != prepares.len() || !metadata.prepares.iter().zip(prepares.iter()).all(|(a,b)| a == b) {
                //     return Err(QbftError::ValidationError("RoundChange: prepares do not match metadata".into()));
                // }
            }
            None => {
                if prepared_block.is_some() || !prepares.is_empty() {
                    return Err(QbftError::ValidationError("RoundChange: prepared_block/prepares present when metadata is None".into()));
                }
            }
        }

        Ok(Self {
            signed_payload,
            prepared_block,
            prepares,
        })
    }

    pub fn signed_payload(&self) -> &SignedData<RoundChangePayload> {
        &self.signed_payload
    }

    // Helper methods to access parts of the BftMessage-like interface
    pub fn author(&self) -> Result<Address, QbftError> {
        self.signed_payload.recover_author()
    }

    pub fn payload(&self) -> &RoundChangePayload {
        self.signed_payload.payload()
    }

    pub fn round_identifier(&self) -> &ConsensusRoundIdentifier {
        self.payload().round_identifier() // This is the target_round_identifier
    }

    pub fn message_type(&self) -> u8 {
        self.payload().message_type()
    }

    // Convenience getters for data potentially derived from payload's metadata
    pub fn get_prepared_round_metadata(&self) -> Option<&PreparedRoundMetadata> {
        self.payload().prepared_round_metadata.as_ref()
    }
}

// RLP: OUTER_RLP_LIST(SignedRoundChangePayload, Optional<QbftBlock>, Vec<SignedData<PreparePayload>>)
impl Encodable for RoundChange {
    fn encode(&self, out: &mut dyn BufMut) {
        let header = Header { list: true, payload_length: self.length_no_header() };
        header.encode(out);
        self.signed_payload.encode(out);
        self.prepared_block.encode(out); // Option<T> is Encodable (RLP Null if None)
        self.prepares.encode(out);       // Vec<T> is Encodable (empty RLP list if empty)
    }

    fn length(&self) -> usize {
        let len = self.length_no_header();
        Header { list: true, payload_length: len }.length() + len
    }
}

impl RoundChange {
    // Helper for length calculation
    fn length_no_header(&self) -> usize {
        self.signed_payload.length() +
        self.prepared_block.length() +
        self.prepares.length()
    }
}

impl Decodable for RoundChange {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        let header = Header::decode(buf)?;
        if !header.list {
            return Err(RlpError::Custom("RoundChange RLP must be a list"));
        }
        let remaining_len_before = buf.len();

        let signed_payload = SignedData::<RoundChangePayload>::decode(buf)?;
        let prepared_block = Option::<QbftBlock>::decode(buf)?;
        let prepares = Vec::<SignedData<PreparePayload>>::decode(buf)?;

        let decoded_len = remaining_len_before - buf.len();
        if decoded_len != header.payload_length {
            return Err(RlpError::UnexpectedLength);
        }
        
        // The constructor performs consistency checks
        RoundChange::new(signed_payload, prepared_block, prepares)
            .map_err(|e| RlpError::Custom(Box::leak(e.to_string().into_boxed_str())))
    }
} 