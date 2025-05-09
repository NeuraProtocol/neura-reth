use crate::payload::QbftPayload;
use crate::types::{SignedData, ConsensusRoundIdentifier};
use alloy_primitives::Address;
use crate::error::QbftError;
use alloy_rlp::{Encodable, Decodable}; // For the RLP bounds on P

// Generic BFT message wrapper.
// P is the specific payload type (e.g., ProposalPayload).
#[derive(Debug, Clone, PartialEq, Eq)] // RLP traits will be on concrete types
pub struct BftMessage<P: QbftPayload + Encodable + Decodable + Clone + std::fmt::Debug + Send + Sync> {
    pub signed_payload: SignedData<P>,
    // Author can be recovered from signed_payload, so not stored directly
    // to avoid redundancy unless performance dictates otherwise.
}

impl<P: QbftPayload + Encodable + Decodable + Clone + std::fmt::Debug + Send + Sync> BftMessage<P> {
    pub fn new(signed_payload: SignedData<P>) -> Self {
        Self { signed_payload }
    }

    pub fn author(&self) -> Result<Address, QbftError> {
        self.signed_payload.recover_author()
    }

    pub fn payload(&self) -> &P {
        self.signed_payload.payload()
    }

    pub fn round_identifier(&self) -> &ConsensusRoundIdentifier {
        self.payload().round_identifier()
    }

    pub fn message_type(&self) -> u8 {
        self.payload().message_type()
    }
}

// Note: The RLP encoding/decoding for BftMessage itself isn't defined here.
// Each concrete message type (Proposal, Prepare, etc.) will define its own full RLP structure,
// which includes how it embeds the SignedData<P> and any other fields.
// For example, Proposal.encode() handles its specific list structure. 