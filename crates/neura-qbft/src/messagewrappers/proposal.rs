use crate::payload::{ProposalPayload, RoundChangePayload, PreparePayload};
use crate::types::{SignedData, QbftBlock};
use crate::messagewrappers::bft_message::BftMessage;
use alloy_rlp::{Encodable, Decodable, Header, length_of_length, BufMut};
use std::ops::Deref;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proposal {
    // Inner BftMessage holds the SignedData<ProposalPayload>
    inner: BftMessage<ProposalPayload>,
    // Additional fields specific to Proposal wrapper
    round_changes: Vec<SignedData<RoundChangePayload>>,
    prepares: Vec<SignedData<PreparePayload>>,
}

// Implement Deref to easily access BftMessage methods (author, payload, round_identifier, etc.)
impl Deref for Proposal {
    type Target = BftMessage<ProposalPayload>;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl Proposal {
    pub fn new(
        signed_payload: SignedData<ProposalPayload>,
        round_changes: Vec<SignedData<RoundChangePayload>>,
        prepares: Vec<SignedData<PreparePayload>>,
    ) -> Self {
        Self {
            inner: BftMessage::new(signed_payload),
            round_changes,
            prepares,
        }
    }

    pub fn round_changes(&self) -> &Vec<SignedData<RoundChangePayload>> {
        &self.round_changes
    }

    pub fn prepares(&self) -> &Vec<SignedData<PreparePayload>> {
        &self.prepares
    }

    pub fn block(&self) -> &QbftBlock {
        &self.payload().proposed_block // Access payload via Deref
    }
}

// RLP Encoding: RLP_LIST(SignedProposalPayload, RLP_LIST(Vec<SignedRoundChange>, Vec<SignedPrepare>))
impl Encodable for Proposal {
    fn encode(&self, out: &mut dyn BufMut) {
        let signed_payload_len = self.inner.signed_payload.length();
        
        let mut round_changes_encoded = Vec::new();
        self.round_changes.encode(&mut round_changes_encoded);

        let mut prepares_encoded = Vec::new();
        self.prepares.encode(&mut prepares_encoded);

        let inner_list_items_payload_length = round_changes_encoded.len() + prepares_encoded.len();
        let inner_list_header = Header { list: true, payload_length: inner_list_items_payload_length };
        
        let total_payload_length = signed_payload_len + inner_list_header.length() + inner_list_items_payload_length;
        Header { list: true, payload_length: total_payload_length }.encode(out);
        
        self.inner.signed_payload.encode(out);
        inner_list_header.encode(out);
        out.put_slice(&round_changes_encoded);
        out.put_slice(&prepares_encoded);
    }

    fn length(&self) -> usize {
        let signed_payload_len = self.inner.signed_payload.length();
        
        let round_changes_encoded_len = self.round_changes.length();
        let prepares_encoded_len = self.prepares.length();

        let inner_list_items_payload_length = round_changes_encoded_len + prepares_encoded_len;
        let inner_list_header_len = Header { list: true, payload_length: inner_list_items_payload_length }.length();
        
        let total_payload_length = signed_payload_len + inner_list_header_len + inner_list_items_payload_length;
        Header { list: true, payload_length: total_payload_length }.length() + total_payload_length
    }
}

impl Decodable for Proposal {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        let outer_header = Header::decode(buf)?;
        if !outer_header.list {
            return Err(alloy_rlp::Error::Custom("Proposal RLP must be a list"));
        }
        let outer_payload_start_len = buf.len();

        let signed_payload = SignedData::<ProposalPayload>::decode(buf)?;

        let inner_list_header = Header::decode(buf)?;
        if !inner_list_header.list {
            return Err(alloy_rlp::Error::Custom("Proposal inner RLP for certs must be a list"));
        }
        let inner_list_payload_start_len = buf.len();

        let round_changes = Vec::<SignedData<RoundChangePayload>>::decode(buf)?;
        let prepares = Vec::<SignedData<PreparePayload>>::decode(buf)?;
        
        let inner_list_decoded_bytes = inner_list_payload_start_len - buf.len();
        if inner_list_decoded_bytes != inner_list_header.payload_length {
            // If the Vec<T>::decode consumed exactly the header.payload_length, this check might be redundant
            // or needs to account for how Vec<T>::decode works with the buffer length.
            // For now, let's assume Vec<T>::decode consumes its items and leaves the buffer at the end of its list.
            // The check here compares actual bytes consumed for items vs header.payload_length for those items.
             return Err(alloy_rlp::Error::UnexpectedLength);
        }

        let outer_decoded_bytes = outer_payload_start_len - buf.len();
        if outer_decoded_bytes != outer_header.payload_length {
            return Err(alloy_rlp::Error::UnexpectedLength);
        }

        Ok(Proposal::new(signed_payload, round_changes, prepares))
    }
} 