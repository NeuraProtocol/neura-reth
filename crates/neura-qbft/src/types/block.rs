use crate::types::header::QbftBlockHeader;
use alloy_rlp::{RlpEncodable, RlpDecodable, Header as RlpHeader, BufMut, Encodable, Decodable, Error as RlpError};
use alloy_primitives::{Bytes, B256 as Hash};

#[derive(Debug, Clone, PartialEq, Eq, RlpEncodable, RlpDecodable)]
pub struct Transaction { // Placeholder
    pub rlp: Bytes,
}

// QbftBlockBody is a conceptual grouping, not directly RLP-encoded as part of the block's main list structure.
// The block RLP is RLP_LIST[Header, Vec<Transaction>, Vec<QbftBlockHeader> (ommers)].
#[derive(Debug, Clone, PartialEq, Eq)] 
pub struct QbftBlockBody {
    pub transactions: Vec<Transaction>,
    pub ommers: Vec<QbftBlockHeader>, // Typically empty for QBFT
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QbftBlock {
    pub header: QbftBlockHeader,
    pub body_transactions: Vec<Transaction>,
    pub body_ommers: Vec<QbftBlockHeader>,
}

impl QbftBlock {
    pub fn new(header: QbftBlockHeader, transactions: Vec<Transaction>, ommers: Vec<QbftBlockHeader>) -> Self {
        Self { header, body_transactions: transactions, body_ommers: ommers }
    }

    pub fn hash(&self) -> Hash {
        self.header.hash()
    }
    
    // Helper to get conceptual body for contexts that might need it grouped
    pub fn body(&self) -> QbftBlockBody {
        QbftBlockBody {
            transactions: self.body_transactions.clone(),
            ommers: self.body_ommers.clone(),
        }
    }

    // The `rlp: Bytes` field from the old placeholder is removed.
    // The block itself is RLP encoded as a list of [header, transactions_list, ommers_list]
}

// RLP Encoding for QbftBlock: RLP_LIST[Header, Transactions<Vec<Tx>>, Ommers<Vec<Header>>]
impl Encodable for QbftBlock {
    fn encode(&self, out: &mut dyn BufMut) {
        let mut header = RlpHeader { list: true, payload_length: 0 };
        let mut total_payload_length = 0;
        total_payload_length += self.header.length();
        total_payload_length += self.body_transactions.length();
        total_payload_length += self.body_ommers.length();
        header.payload_length = total_payload_length;

        header.encode(out);
        self.header.encode(out);
        self.body_transactions.encode(out); // Encodes as RLP list
        self.body_ommers.encode(out);     // Encodes as RLP list
    }

    fn length(&self) -> usize {
        let mut total_payload_length = 0;
        total_payload_length += self.header.length();
        total_payload_length += self.body_transactions.length();
        total_payload_length += self.body_ommers.length();
        
        RlpHeader { list: true, payload_length: total_payload_length }.length() + total_payload_length
    }
}

impl Decodable for QbftBlock {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        let rlp_header = RlpHeader::decode(buf)?;
        if !rlp_header.list {
            return Err(RlpError::Custom("QbftBlock RLP must be a list"));
        }
        let remaining_len_before = buf.len();

        let header = QbftBlockHeader::decode(buf)?;
        let body_transactions = Vec::<Transaction>::decode(buf)?;
        let body_ommers = Vec::<QbftBlockHeader>::decode(buf)?;
        
        let decoded_len = remaining_len_before - buf.len();
        if decoded_len != rlp_header.payload_length {
            return Err(RlpError::UnexpectedLength);
        }
        Ok(Self { header, body_transactions, body_ommers })
    }
}

// We'll also need a QbftBlockCodec equivalent trait/struct later
// For now, ProposalPayload will just embed QbftBlock directly. 