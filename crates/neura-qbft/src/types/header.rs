use alloy_primitives::{Address, Bloom, Bytes, B256 as Hash, U256};
use alloy_rlp::{RlpEncodable, RlpDecodable, Header as RlpHeader, BufMut, Decodable, Encodable, Error as RlpError};

// Based on standard Ethereum block header structure
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QbftBlockHeader {
    pub parent_hash: Hash,
    pub ommers_hash: Hash, // Uncle hash, typically H160::zero() or specific for PoA
    pub beneficiary: Address,
    pub state_root: Hash,
    pub transactions_root: Hash,
    pub receipts_root: Hash,
    pub logs_bloom: Bloom,
    pub difficulty: U256, // Typically U256::from(1) for QBFT
    pub number: u64,
    pub gas_limit: u64, // Represented as U256 in some contexts, u64 is common too
    pub gas_used: u64,
    pub timestamp: u64, // Unix timestamp in seconds
    pub extra_data: Bytes,
    pub mix_hash: Hash,
    pub nonce: Bytes, // Typically 8 bytes, U64::from(0) for PoA
    // Seal fields (e.g. R, S, V for a signed header) are usually not part of the hash
    // but are part of the full block structure or transmitted separately.
    // QBFT seals are in extra_data.

    // Cached hash
    #[cfg_attr(feature = "serde", serde(skip))]
    hash: std::sync::OnceLock<Hash>,
}

impl QbftBlockHeader {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        parent_hash: Hash,
        ommers_hash: Hash,
        beneficiary: Address,
        state_root: Hash,
        transactions_root: Hash,
        receipts_root: Hash,
        logs_bloom: Bloom,
        difficulty: U256,
        number: u64,
        gas_limit: u64,
        gas_used: u64,
        timestamp: u64,
        extra_data: Bytes,
        mix_hash: Hash,
        nonce: Bytes, // Should be 8 bytes
    ) -> Self {
        // Basic validation for nonce length
        assert_eq!(nonce.len(), 8, "Nonce must be 8 bytes for standard header encoding");
        Self {
            parent_hash,
            ommers_hash,
            beneficiary,
            state_root,
            transactions_root,
            receipts_root,
            logs_bloom,
            difficulty,
            number,
            gas_limit,
            gas_used,
            timestamp,
            extra_data,
            mix_hash,
            nonce,
            hash: std::sync::OnceLock::new(),
        }
    }

    pub fn hash(&self) -> Hash {
        *self.hash.get_or_init(|| {
            let mut rlp_buf = Vec::new();
            self.encode_for_hashing(&mut rlp_buf);
            alloy_primitives::keccak256(&rlp_buf)
        })
    }

    // RLP encoding for hashing (omits seal fields if they were separate)
    // For QBFT, all relevant data for hashing is included.
    fn encode_for_hashing(&self, out: &mut dyn BufMut) {
        RlpHeader { list: true, payload_length: self.rlp_payload_length() }.encode(out);
        self.parent_hash.encode(out);
        self.ommers_hash.encode(out);
        self.beneficiary.encode(out);
        self.state_root.encode(out);
        self.transactions_root.encode(out);
        self.receipts_root.encode(out);
        self.logs_bloom.encode(out);
        self.difficulty.encode(out);
        U256::from(self.number).encode(out); // Number as U256 for RLP
        U256::from(self.gas_limit).encode(out);
        U256::from(self.gas_used).encode(out);
        U256::from(self.timestamp).encode(out);
        self.extra_data.encode(out);
        self.mix_hash.encode(out);
        self.nonce.encode(out);
    }

    fn rlp_payload_length(&self) -> usize {
        self.parent_hash.length() +
        self.ommers_hash.length() +
        self.beneficiary.length() +
        self.state_root.length() +
        self.transactions_root.length() +
        self.receipts_root.length() +
        self.logs_bloom.length() +
        self.difficulty.length() +
        U256::from(self.number).length() +
        U256::from(self.gas_limit).length() +
        U256::from(self.gas_used).length() +
        U256::from(self.timestamp).length() +
        self.extra_data.length() +
        self.mix_hash.length() +
        self.nonce.length()
    }
}

// Full RLP Encoding (same as for hashing for QBFT context usually)
impl Encodable for QbftBlockHeader {
    fn encode(&self, out: &mut dyn BufMut) {
        self.encode_for_hashing(out); 
    }
    fn length(&self) -> usize {
        let payload_len = self.rlp_payload_length();
        RlpHeader { list: true, payload_length: payload_len }.length() + payload_len
    }
}

impl Decodable for QbftBlockHeader {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        let rlp_header = RlpHeader::decode(buf)?;
        if !rlp_header.list {
            return Err(RlpError::Custom("QbftBlockHeader RLP must be a list"));
        }
        let remaining_len_before = buf.len();

        let header = Self {
            parent_hash: Decodable::decode(buf)?,
            ommers_hash: Decodable::decode(buf)?,
            beneficiary: Decodable::decode(buf)?,
            state_root: Decodable::decode(buf)?,
            transactions_root: Decodable::decode(buf)?,
            receipts_root: Decodable::decode(buf)?,
            logs_bloom: Decodable::decode(buf)?,
            difficulty: Decodable::decode(buf)?,
            number: <U256 as Decodable>::decode(buf)?.try_into().map_err(|_| RlpError::Custom("number too large"))?,
            gas_limit: <U256 as Decodable>::decode(buf)?.try_into().map_err(|_| RlpError::Custom("gas_limit too large"))?,
            gas_used: <U256 as Decodable>::decode(buf)?.try_into().map_err(|_| RlpError::Custom("gas_used too large"))?,
            timestamp: <U256 as Decodable>::decode(buf)?.try_into().map_err(|_| RlpError::Custom("timestamp too large"))?,
            extra_data: Decodable::decode(buf)?,
            mix_hash: Decodable::decode(buf)?,
            nonce: Decodable::decode(buf)?,
            hash: std::sync::OnceLock::new(),
        };

        let decoded_len = remaining_len_before - buf.len();
        if decoded_len != rlp_header.payload_length {
            return Err(RlpError::UnexpectedLength);
        }
        // Basic validation for nonce length after decoding
        if header.nonce.len() != 8 {
            return Err(RlpError::Custom("Decoded nonce must be 8 bytes"));
        }
        Ok(header)
    }
} 