use alloy_primitives::{Address, B256 as Hash, U256, keccak256, Signature as AlloySignature};
use alloy_rlp::{Encodable, Decodable, Header};
use k256::ecdsa::{
    VerifyingKey as K256VerifyingKey,
    Signature as K256EcdsaSignature,
    RecoveryId as K256RecoveryId,
};
use crate::error::QbftError;
use crate::types::NodeKey;
use crate::types::RlpSignature;

// Generic struct to hold a payload and its signature.
// T must be RLP-encodable to be signed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedData<T: Encodable + Decodable + Clone + std::fmt::Debug + Send + Sync> {
    payload: T,
    signature: RlpSignature,
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

    pub fn calculate_payload_hash(payload: &T) -> Hash {
        let mut payload_rlp = Vec::new();
        payload.encode(&mut payload_rlp);
        keccak256(&payload_rlp)
    }

    pub fn sign(payload: T, signing_key: &NodeKey) -> Result<Self, QbftError> {
        let payload_hash = Self::calculate_payload_hash(&payload);
        let (k256_sig, recovery_id): (K256EcdsaSignature, K256RecoveryId) = signing_key.sign_prehash_recoverable(payload_hash.as_slice())?;
        
        let r_bytes = k256_sig.r().to_bytes();
        let s_bytes = k256_sig.s().to_bytes();
        let r_u256 = U256::from_be_slice(&r_bytes);
        let s_u256 = U256::from_be_slice(&s_bytes);

        let r_b256 = Hash::from(r_u256.to_be_bytes());
        let s_b256 = Hash::from(s_u256.to_be_bytes());

        let alloy_sig = AlloySignature::from_scalars_and_parity(r_b256, s_b256, recovery_id.is_y_odd());

        Ok(Self {
            payload,
            signature: RlpSignature(alloy_sig),
        })
    }

    pub fn recover_author(&self) -> Result<Address, QbftError> {
        let payload_hash = Self::calculate_payload_hash(&self.payload);

        let r_primitive = self.signature.0.r(); 
        let s_primitive = self.signature.0.s(); 
        let parity_bool = self.signature.0.v();   
        
        let k256_recovery_id_val = if parity_bool { 1u8 } else { 0u8 };
        let k256_recovery_id = K256RecoveryId::try_from(k256_recovery_id_val)
            .map_err(|e| QbftError::CryptoError(format!("Failed to create k256 RecoveryId from Parity: {}", e)))?;

        let r_bytes_arr: [u8; 32] = r_primitive.to_be_bytes();
        let s_bytes_arr: [u8; 32] = s_primitive.to_be_bytes();

        let k256_sig_from_parts = K256EcdsaSignature::from_scalars(r_bytes_arr, s_bytes_arr)
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

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{hex, Address, Bytes};
    use k256::{
        ecdsa::{SigningKey as K256SigningKey, VerifyingKey as K256VerifyingKey},
        SecretKey as K256SecretKey,
    };
    use alloy_rlp::{RlpEncodable, RlpDecodable, Encodable, Decodable};

    // A simple RLP-encodable struct for testing
    #[derive(Debug, Clone, PartialEq, Eq, RlpEncodable, RlpDecodable)]
    struct TestPayload {
        id: u64,
        data: Bytes,
    }

    fn key_from_hex(hex_sk: &str) -> K256SigningKey {
        let sk_bytes = hex::decode(hex_sk).expect("Failed to decode hex private key");
        let k256_secret = K256SecretKey::from_slice(&sk_bytes).expect("Failed to create k256 secret key");
        K256SigningKey::from(k256_secret)
    }

    fn address_from_node_key(node_key: &K256SigningKey) -> Address {
        let k256_vk: K256VerifyingKey = *node_key.verifying_key();
        let uncompressed_pk_bytes = k256_vk.to_encoded_point(false).as_bytes().to_vec();
        if uncompressed_pk_bytes.is_empty() || uncompressed_pk_bytes[0] != 0x04 {
            panic!("Invalid recovered uncompressed public key format for node key");
        }
        let hashed_pk = keccak256(&uncompressed_pk_bytes[1..]);
        Address::from_slice(&hashed_pk[12..])
    }

    #[test]
    fn test_sign_and_recover_author() {
        let node_key = key_from_hex("4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318");
        let expected_author = address_from_node_key(&node_key);

        let payload = TestPayload {
            id: 123,
            data: Bytes::from_static(b"hello world"),
        };

        let signed_data = SignedData::sign(payload.clone(), &node_key).expect("Signing failed");
        
        // Check payload
        assert_eq!(signed_data.payload(), &payload, "Payload mismatch after signing");

        let recovered_author = signed_data.recover_author().expect("Author recovery failed");
        assert_eq!(recovered_author, expected_author, "Recovered author does not match expected author");
    }

    #[test]
    fn test_recover_author_tampered_payload() {
        let node_key = key_from_hex("8da4ef21b864d2cc526dbdb2a120bd2874c36c9d0a1fb7f8c63d7f7a8b41de8f");
        let original_author = address_from_node_key(&node_key);

        let payload = TestPayload {
            id: 456,
            data: Bytes::from_static(b"original data"),
        };
        let mut signed_data = SignedData::sign(payload, &node_key).expect("Signing failed");

        // Tamper the payload
        signed_data.payload.data = Bytes::from_static(b"tampered data");

        // Recovery should fail or yield a different address
        match signed_data.recover_author() {
            Ok(recovered_author) => {
                assert_ne!(recovered_author, original_author, "Recovered author should not match original with tampered payload");
            }
            Err(e) => {
                // It's also acceptable for recovery to outright fail
                println!("Recovery failed as expected for tampered payload: {:?}", e);
                assert!(matches!(e, QbftError::CryptoError(_)));
            }
        }
    }
    
    #[test]
    fn test_sign_with_different_keys() {
        let node_key1 = key_from_hex("0101010101010101010101010101010101010101010101010101010101010101");
        let author1 = address_from_node_key(&node_key1);

        let node_key2 = key_from_hex("0202020202020202020202020202020202020202020202020202020202020202");
        let author2 = address_from_node_key(&node_key2);

        let payload = TestPayload {
            id: 789,
            data: Bytes::from_static(b"data for key1"),
        };

        let signed_data_by_key1 = SignedData::sign(payload.clone(), &node_key1).expect("Signing with key1 failed");
        
        let recovered_author1 = signed_data_by_key1.recover_author().expect("Author recovery from key1's signature failed");
        assert_eq!(recovered_author1, author1, "Recovered author from key1's signature is incorrect");
        assert_ne!(recovered_author1, author2, "Recovered author from key1's signature should not be author2");

        // Attempt to recover with knowledge of key2 (not directly used in recover_author, but for assertion)
        // This test mainly confirms that the signature from key1 recovers to author1
        // and implicitly not author2 (unless keys were identical, which they are not).
        // A direct "verify_with_key(key2)" would be a different test, if such a method existed.
        // Here we just ensure the recovered author is indeed the one who signed.
    }


    #[test]
    fn test_signed_data_rlp_roundtrip() {
        let node_key = key_from_hex("3a0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318");
        let payload = TestPayload {
            id: 101,
            data: Bytes::from_static(b"rlp test data"),
        };
        let original_signed_data = SignedData::sign(payload, &node_key).expect("Signing failed");

        let mut rlp_encoded = Vec::new();
        original_signed_data.encode(&mut rlp_encoded);

        let decoded_signed_data = SignedData::<TestPayload>::decode(&mut rlp_encoded.as_slice()).expect("RLP decoding failed");

        assert_eq!(original_signed_data, decoded_signed_data, "Decoded SignedData does not match original");
        
        // Additionally verify author recovery on the decoded data
        let expected_author = address_from_node_key(&node_key);
        let recovered_author_from_decoded = decoded_signed_data.recover_author().expect("Author recovery from decoded data failed");
        assert_eq!(recovered_author_from_decoded, expected_author, "Author mismatch after RLP roundtrip");
    }
} 