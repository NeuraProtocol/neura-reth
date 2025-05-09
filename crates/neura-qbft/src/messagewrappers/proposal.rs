use crate::payload::ProposalPayload;
use crate::types::{QbftBlock, QbftBlockHeader};
use crate::messagewrappers::bft_message::BftMessage;
use crate::messagewrappers::round_change::RoundChange;
use crate::messagewrappers::prepared_certificate::PreparedCertificateWrapper;
// Use derive macros from alloy_rlp directly when 'derive' feature is enabled
use alloy_rlp::{RlpEncodable, RlpDecodable};
use std::ops::Deref;

/// Represents a QBFT Proposal message.
/// RLP structure: [bft_message, proposed_block_header, [round_change_proofs], prepared_certificate_option]
/// where prepared_certificate_option is either an RLP list (if Some) or an RLP empty list 0xc0 (if None).
#[derive(Clone, Debug, PartialEq, Eq, RlpEncodable, RlpDecodable)]
#[rlp(trailing)]
pub struct Proposal {
    bft_message: BftMessage<ProposalPayload>,
    proposed_block_header: QbftBlockHeader, 
    round_change_proofs: Vec<RoundChange>,
    pub prepared_certificate: Option<PreparedCertificateWrapper>,
}

// Implement Deref to easily access BftMessage methods (author, payload, round_identifier, etc.)
impl Deref for Proposal {
    type Target = BftMessage<ProposalPayload>;
    fn deref(&self) -> &Self::Target {
        &self.bft_message
    }
}

impl Proposal {
    pub fn new(
        bft_message: BftMessage<ProposalPayload>,
        proposed_block_header: QbftBlockHeader,
        round_change_proofs: Vec<RoundChange>,
        prepared_certificate: Option<PreparedCertificateWrapper>,
    ) -> Self {
        Self {
            bft_message,
            proposed_block_header,
            round_change_proofs,
            prepared_certificate,
        }
    }

    pub fn bft_message(&self) -> &BftMessage<ProposalPayload> {
        &self.bft_message
    }

    pub fn proposed_block_header(&self) -> &QbftBlockHeader {
        &self.proposed_block_header
    }

    pub fn round_change_proofs(&self) -> &Vec<RoundChange> {
        &self.round_change_proofs
    }

    pub fn prepared_certificate(&self) -> Option<&PreparedCertificateWrapper> {
        self.prepared_certificate.as_ref()
    }

    pub fn block(&self) -> &QbftBlock { // Assuming ProposalPayload has a proposed_block field
        &self.bft_message.payload().proposed_block
    }
} 