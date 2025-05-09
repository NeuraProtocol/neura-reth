use alloy_primitives::{Address, Signature, B256};
use alloy_rlp::{RlpEncodable, RlpDecodable, Encodable, Decodable, Header};
use k256::ecdsa::{SigningKey as K256SigningKey, VerifyingKey as K256VerifyingKey, signature::Signer, signature::Verifier };
use crate::error::QbftError;
use sha3::{Keccak256, Digest}; // For hashing the payload before signing

// Generic struct to hold a payload and its signature.
// T must be RLP-encodable to be signed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedData<T: Encodable + Decodable + Clone + std::fmt::Debug + Send + Sync> {
    payload: T,
    signature: Signature, 
    // Author is not stored directly, recovered on demand.
}

impl<T: Encodable + Decodable + Clone + std::fmt::Debug + Send + Sync> SignedData<T> {
    pub fn new(payload: T, signature: Signature) -> Self {
        Self { payload, signature }
    }

    pub fn payload(&self) -> &T {
        &self.payload
    }

    pub fn signature(&self) -> &Signature {
        &self.signature
    }

    fn payload_hash(payload: &T) -> B256 {
        let mut rlp_buf = Vec::new();
        payload.encode(&mut rlp_buf);
        B256::from_slice(Keccak256::digest(&rlp_buf).as_slice())
    }

    pub fn sign(payload: T, signing_key: &K256SigningKey) -> Result<Self, QbftError> {
        let payload_hash = Self::payload_hash(&payload);
        let k256_sig: k256::ecdsa::recoverable::Signature = signing_key.sign_prehash(&payload_hash.into())?;
        
        let alloy_sig = Signature::from_signature_and_parity(k256_sig, k256_sig.normalize_s().is_some())
            .map_err(|e| QbftError::CryptoError(format!("Failed to create alloy signature: {}", e)))?;

        Ok(Self::new(payload, alloy_sig))
    }

    pub fn recover_author(&self) -> Result<Address, QbftError> {
        let payload_hash = Self::payload_hash(&self.payload);
        let recovered_pubkey = self.signature.recover_address_from_prehash(&payload_hash)?;
        Ok(recovered_pubkey)
    }
}

impl<T: Encodable + Decodable + Clone + std::fmt::Debug + Send + Sync> Encodable for SignedData<T> {
    fn encode(&self, out: &mut dyn alloy_rlp::BufMut) {
        // RLP encoding for SignedData<T>: RLP_LIST(payload_rlp, signature_rlp)
        // This requires T to be Encodable and Signature to be Encodable.
        // alloy_primitives::Signature is already RlpEncodable.
        let header = Header { list: true, payload_length: self.payload.length() + self.signature.length() };
        header.encode(out);
        self.payload.encode(out);
        self.signature.encode(out);
    }

    fn length(&self) -> usize {
        let payload_len = self.payload.length();
        let sig_len = self.signature.length();
        let header_len = Header { list: true, payload_length: payload_len + sig_len }.length();
        header_len + payload_len + sig_len
    }
}

impl<T: Encodable + Decodable + Clone + std::fmt::Debug + Send + Sync> Decodable for SignedData<T> {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        let header = Header::decode(buf)?;
        if !header.list {
            return Err(alloy_rlp::Error::Custom("SignedData RLP must be a list"));
        }
        let remaining_before_payload = buf.len();
        let payload = T::decode(buf)?;
        let signature = Signature::decode(buf)?;
        let decoded_len = remaining_before_payload - buf.len();

        if decoded_len != header.payload_length {
             return Err(alloy_rlp::Error::UnexpectedLength);
        }
        Ok(Self { payload, signature })
    }
} 