use crate::payload::PreparePayload;
use crate::messagewrappers::bft_message::BftMessage;
use crate::types::SignedData;
use alloy_rlp::{Encodable, Decodable, BufMut};
use std::ops::Deref;

/// Represents a QBFT Prepare message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Prepare {
    inner: BftMessage<PreparePayload>,
}

impl Deref for Prepare {
    type Target = BftMessage<PreparePayload>;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl Prepare {
    pub fn new(signed_payload: SignedData<PreparePayload>) -> Self {
        Self { inner: BftMessage::new(signed_payload) }
    }
}

// RLP encoding for Prepare is just its SignedData<PreparePayload>.
// The BftMessage itself is not directly RLP encoded; its content (SignedData) is.
// The P2P layer would send the RLP bytes of SignedData<PreparePayload>.
// However, to match Java structure where Prepare.decode(data) exists,
// this wrapper implies it can be decoded from a buffer containing just the signed payload.
impl Encodable for Prepare {
    fn encode(&self, out: &mut dyn BufMut) {
        self.inner.signed_payload.encode(out);
    }
    fn length(&self) -> usize {
        self.inner.signed_payload.length()
    }
}

impl Decodable for Prepare {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        let signed_payload = SignedData::<PreparePayload>::decode(buf)?;
        Ok(Self::new(signed_payload))
    }
} 