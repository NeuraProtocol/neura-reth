use alloy_primitives::{Address, Signature as AlloyPrimitiveSignature, B256 as Hash, U256, keccak256};
use alloy_rlp::{Encodable, Decodable, Header, RlpMaxEncodedLen};
use k256::ecdsa::{
    // SigningKey as K256SigningKey, // NodeKey is K256SigningKey directly or Arc-wrapped
    // VerifyingKey as K256VerifyingKey, 
    // signature::Signer, 
    // signature::Verifier,
    hazmat::SignPrimitive, // Corrected path for SignPrimitive
    VerifyingKey as K256VerifyingKey,
    Signature as K256Signature,      // The standard Signature type
    RecoveryId as K256RecoveryId,    // For recovery ID
};
use k256::FieldBytes;
use crate::error::QbftError;
use sha3::{Keccak256, Digest}; // For hashing the payload before signing
use crate::payload::qbft_payload::QbftPayload;
use crate::types::NodeKey;
use serde::{Deserialize, Serialize};
use crate::types::RlpSignature; // Added import for RlpSignature

// Generic struct to hold a payload and its signature.
// T must be RLP-encodable to be signed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedData<T: Encodable + Decodable + Clone + std::fmt::Debug + Send + Sync> {
    payload: T,
    signature: RlpSignature, // Changed from Signature to RlpSignature
    // Author is not stored directly, recovered on demand.
}

impl<T: Encodable + Decodable + Clone + std::fmt::Debug + Send + Sync> SignedData<T> {
    pub fn new(payload: T, signature: RlpSignature) -> Self {
        Self { payload, signature }
    }

    pub fn payload(&self) -> &T {
        &self.payload
    }

    pub fn signature(&self) -> &RlpSignature {
        &self.signature
    }

    fn calculate_payload_hash(payload: &T) -> Hash { // Returns Hash (alias for B256)
        let mut payload_rlp = Vec::new();
        payload.encode(&mut payload_rlp);
        alloy_primitives::keccak256(&payload_rlp)
    }

    pub fn sign(payload: T, signing_key: &NodeKey) -> Result<Self, QbftError> {
        let payload_hash = Self::calculate_payload_hash(&payload);
        let (k256_sig, recovery_id): (K256Signature, K256RecoveryId) = signing_key.sign_prehash_recoverable(payload_hash.as_slice())?;
        
        let r_bytes = k256_sig.r().to_bytes();
        let s_bytes = k256_sig.s().to_bytes();
        let r = U256::from_be_slice(&r_bytes);
        let s = U256::from_be_slice(&s_bytes);
        // Parity directly as bool for from_scalars_and_parity

        let r_hash = Hash::from(r.to_be_bytes()); // Use Hash alias for B256
        let s_hash = Hash::from(s.to_be_bytes()); // Use Hash alias for B256

        let alloy_sig = AlloyPrimitiveSignature::from_scalars_and_parity(r_hash, s_hash, recovery_id.is_y_odd());

        Ok(Self {
            payload,
            signature: RlpSignature(alloy_sig), // Wrap in RlpSignature
        })
    }

    pub fn recover_author(&self) -> Result<Address, QbftError> {
        let payload_hash = Self::calculate_payload_hash(&self.payload);

        // Access inner Signature from RlpSignature using .0
        let r_primitive = self.signature.0.r(); 
        let s_primitive = self.signature.0.s(); 
        let parity_bool = self.signature.0.v();   
        
        let k256_recovery_id_val = if parity_bool { 1u8 } else { 0u8 };
        let k256_recovery_id = K256RecoveryId::try_from(k256_recovery_id_val)
            .map_err(|e| QbftError::CryptoError(format!("Failed to create k256 RecoveryId from Parity byte: {}", e)))?;

        let r_bytes_arr: [u8; 32] = r_primitive.to_be_bytes();
        let s_bytes_arr: [u8; 32] = s_primitive.to_be_bytes();

        let k256_sig_from_parts = K256Signature::from_scalars(r_bytes_arr, s_bytes_arr)
            .map_err(|e| QbftError::CryptoError(format!("Failed to create k256 Signature from parts: {}", e)))?;

        let recovered_k256_vk = K256VerifyingKey::recover_from_prehash(payload_hash.as_slice(), &k256_sig_from_parts, k256_recovery_id)
            .map_err(|e| QbftError::CryptoError(format!("k256 VerifyingKey recovery failed: {}", e)))?;

        let encoded_point = recovered_k256_vk.to_encoded_point(false);
        let uncompressed_pk_bytes = encoded_point.as_bytes();
        if uncompressed_pk_bytes.is_empty() || uncompressed_pk_bytes[0] != 0x04 {
            return Err(QbftError::InternalError("Invalid recovered uncompressed public key format".to_string()));
        }
        let hashed_pk = keccak256(&uncompressed_pk_bytes[1..]);
        let recovered_address = Address::from_slice(&hashed_pk[12..]);

        Ok(recovered_address)
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
        let signature = RlpSignature::decode(buf)?;
        let decoded_len = remaining_before_payload - buf.len();

        if decoded_len != header.payload_length {
             return Err(alloy_rlp::Error::UnexpectedLength);
        }
        Ok(Self { payload, signature })
    }
} 