use crate::messagewrappers::bft_message::BftMessage;
use crate::payload::RoundChangePayload;
use crate::types::{SignedData, QbftBlock};
use crate::payload::PreparePayload;
use alloy_rlp::{RlpEncodable, RlpDecodable, Encodable, Decodable}; // Correct RLP imports
use std::ops::Deref;
use alloy_primitives::Address; // For author
use crate::error::QbftError; // For author

/// Represents a QBFT RoundChange message, including any piggybacked prepared certificate.
#[derive(Debug, Clone, PartialEq, Eq, RlpEncodable, RlpDecodable)]
#[rlp(trailing)] // For Option fields
pub struct RoundChange {
    bft_message: BftMessage<RoundChangePayload>,
    prepared_block: Option<QbftBlock>, 
    prepares: Option<Vec<SignedData<PreparePayload>>>, 
}

impl Deref for RoundChange {
    type Target = BftMessage<RoundChangePayload>;
    fn deref(&self) -> &Self::Target {
        &self.bft_message
    }
}

impl RoundChange {
    pub fn new(
        signed_payload_data: SignedData<RoundChangePayload>,
        prepared_block: Option<QbftBlock>,
        prepares: Option<Vec<SignedData<PreparePayload>>>,
    ) -> Result<Self, crate::error::QbftError> { 
        let bft_message = BftMessage::new(signed_payload_data);
        
        let has_metadata = bft_message.payload().prepared_round_metadata.is_some();
        let has_block = prepared_block.is_some();
        let has_actual_prepares = prepares.as_ref().map_or(false, |p_vec| !p_vec.is_empty());

        if has_metadata {
            if !has_block {
                return Err(crate::error::QbftError::ValidationError(
                    "RoundChange: prepared_block missing when payload metadata present".into()
                ));
            }
        } else {
            if has_block {
                 return Err(crate::error::QbftError::ValidationError(
                    "RoundChange: prepared_block present when payload metadata is None".into()
                ));
            }
            if has_actual_prepares {
                 return Err(crate::error::QbftError::ValidationError(
                    "RoundChange: prepares present when payload metadata is None".into()
                ));
            }
        }

        Ok(Self {
            bft_message,
            prepared_block,
            prepares,
        })
    }

    pub fn bft_message(&self) -> &BftMessage<RoundChangePayload> {
        &self.bft_message
    }

    pub fn prepared_block(&self) -> Option<&QbftBlock> {
        self.prepared_block.as_ref()
    }

    pub fn prepares(&self) -> Option<&Vec<SignedData<PreparePayload>>> {
        self.prepares.as_ref()
    }
}

// Ensure NO manual impl Encodable or impl Decodable for RoundChange exists below this line. 