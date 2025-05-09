use crate::payload::CommitPayload;
use crate::messagewrappers::bft_message::BftMessage;
use crate::types::SignedData;
use alloy_rlp::{Encodable, Decodable, BufMut};
use std::ops::Deref;

/// Represents a QBFT Commit message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Commit {
    inner: BftMessage<CommitPayload>,
}

impl Deref for Commit {
    type Target = BftMessage<CommitPayload>;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl Commit {
    pub fn new(signed_payload: SignedData<CommitPayload>) -> Self {
        Self { inner: BftMessage::new(signed_payload) }
    }
}

// RLP encoding for Commit is just its SignedData<CommitPayload>.
impl Encodable for Commit {
    fn encode(&self, out: &mut dyn BufMut) {
        self.inner.signed_payload.encode(out);
    }
    fn length(&self) -> usize {
        self.inner.signed_payload.length()
    }
}

impl Decodable for Commit {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        let signed_payload = SignedData::<CommitPayload>::decode(buf)?;
        Ok(Self::new(signed_payload))
    }
} 