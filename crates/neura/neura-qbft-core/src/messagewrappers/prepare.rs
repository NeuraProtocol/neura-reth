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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::payload::PreparePayload;
    use crate::types::{ConsensusRoundIdentifier, SignedData, NodeKey};
    use alloy_primitives::B256;
    use k256::ecdsa::SigningKey;
    // Note: `encode` and `decode` are inherent methods for `Prepare` due to its Encodable/Decodable impl.

    fn dummy_node_key() -> NodeKey {
        SigningKey::from_bytes(&[2u8; 32].into()).unwrap()
    }

    fn dummy_round_identifier(sequence: u64, round: u32) -> ConsensusRoundIdentifier {
        ConsensusRoundIdentifier { sequence_number: sequence, round_number: round }
    }

    fn dummy_prepare_payload() -> PreparePayload {
        PreparePayload {
            round_identifier: dummy_round_identifier(2, 3),
            digest: B256::from([0xCD; 32]),
        }
    }

    #[test]
    fn test_prepare_message_rlp_roundtrip() {
        let node_key = dummy_node_key();
        let payload = dummy_prepare_payload();
        let signed_payload = SignedData::sign(payload, &node_key).expect("Failed to sign PreparePayload");
        
        let prepare_message = Prepare::new(signed_payload.clone()); // Clone signed_payload for assertion

        let mut encoded_prepare = Vec::new();
        prepare_message.encode(&mut encoded_prepare);
        
        // The custom RLP for Prepare should be identical to RLP of just SignedData<PreparePayload>
        let mut encoded_signed_payload = Vec::new();
        signed_payload.encode(&mut encoded_signed_payload);
        assert_eq!(encoded_prepare, encoded_signed_payload, "Prepare RLP should match SignedData<PreparePayload> RLP");

        let decoded_prepare = Prepare::decode(&mut encoded_prepare.as_slice()).expect("Failed to decode Prepare message");

        // Assert that the inner content is the same
        assert_eq!(prepare_message.inner.signed_payload, decoded_prepare.inner.signed_payload, "Decoded Prepare message content mismatch");
        // Since Prepare only contains BftMessage which contains SignedData, comparing signed_payload is key.
        // Direct equality on Prepare should also work if derived or implemented correctly.
        assert_eq!(prepare_message, decoded_prepare, "Full Prepare message RLP roundtrip failed");
    }
} 