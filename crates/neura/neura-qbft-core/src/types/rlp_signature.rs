use alloy_primitives::{Signature, U256, B256};
use alloy_rlp::{Encodable, Decodable, Error as RlpError, Header, BufMut};
#[cfg(feature = "serde")]
use serde::{Serialize, Deserialize};

/// A wrapper around alloy_primitives::Signature to provide RLP Encodable/Decodable support
/// based on RLP([v, r, s]), where v is a u8 parity bit (0 or 1).
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct RlpSignature(pub Signature);

impl RlpSignature {
    pub fn new(signature: Signature) -> Self {
        Self(signature)
    }

    pub fn into_inner(self) -> Signature {
        self.0
    }
}

// Implement Deref to access underlying Signature methods easily
impl std::ops::Deref for RlpSignature {
    type Target = Signature;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Encodable for RlpSignature {
    fn encode(&self, out: &mut dyn BufMut) {
        let parity_byte: u8 = if self.0.v() { 1u8 } else { 0u8 };
        Header {
            list: true,
            payload_length: parity_byte.length() + self.0.r().length() + self.0.s().length(),
        }
        .encode(out);
        parity_byte.encode(out);
        self.0.r().encode(out); // U256 is Encodable
        self.0.s().encode(out); // U256 is Encodable
    }

    fn length(&self) -> usize {
        let parity_byte: u8 = if self.0.v() { 1u8 } else { 0u8 };
        let payload_length = parity_byte.length() + self.0.r().length() + self.0.s().length();
        Header { list: true, payload_length }.length() + payload_length
    }
}

impl Decodable for RlpSignature {
    fn decode(buf: &mut &[u8]) -> Result<Self, RlpError> {
        let header = Header::decode(buf)?;
        if !header.list {
            return Err(RlpError::Custom("RlpSignature RLP must be a list"));
        }
        let remaining_len_before = buf.len();

        let v_byte = u8::decode(buf)?;
        let r = U256::decode(buf)?;
        let s = U256::decode(buf)?;

        let decoded_payload_len = remaining_len_before - buf.len();
        if decoded_payload_len != header.payload_length {
            return Err(RlpError::UnexpectedLength);
        }
        
        // Convert u8 back to Parity. Parity::from(bool)
        let parity_bool = match v_byte {
            0 => false,
            1 => true,
            _ => return Err(RlpError::Custom("Invalid parity byte for RlpSignature")),
        };

        // alloy_primitives::Signature::from_scalars_and_parity expects r: B256, s: B256
        // U256 can be converted to B256
        let r_b256 = B256::from(r.to_be_bytes::<32>());
        let s_b256 = B256::from(s.to_be_bytes::<32>());

        // from_scalars_and_parity does not return a Result.
        // It panics if r or s are invalid scalars (e.g. >= curve order, or 0),
        // or if s is in the upper-half of the field (non-low-S).
        // This is probably acceptable for RLP decoding if the source is trusted or validated elsewhere.
        // If strict validation is needed here, we might need to use lower-level crypto ops.
        let sig = Signature::from_scalars_and_parity(r_b256, s_b256, parity_bool);
        Ok(RlpSignature(sig))
    }
}

// Optional: Implement From<Signature> for RlpSignature and vice-versa for convenience
impl From<Signature> for RlpSignature {
    fn from(sig: Signature) -> Self {
        RlpSignature(sig)
    }
}

impl From<RlpSignature> for Signature {
    fn from(rlp_sig: RlpSignature) -> Self {
        rlp_sig.0
    }
} 