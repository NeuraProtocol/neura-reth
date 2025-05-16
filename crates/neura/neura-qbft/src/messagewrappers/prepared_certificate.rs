// use crate::messagewrappers::Proposal; // Removed unused import
use crate::messagewrappers::Prepare;
use crate::messagewrappers::bft_message::BftMessage;
use crate::payload::ProposalPayload;
// Use traits and derive macros from alloy_rlp directly when 'derive' feature is enabled
use alloy_rlp::{RlpDecodable, RlpEncodable};

/// Wrapper for a PreparedCertificate, which consists of a signed proposal payload and a list of prepare messages.
/// This is used when a PreparedCertificate is piggybacked onto a new Proposal message.
#[derive(Clone, Debug, PartialEq, Eq, RlpEncodable, RlpDecodable)]
pub struct PreparedCertificateWrapper {
    pub proposal_message: BftMessage<ProposalPayload>,
    pub prepares: Vec<Prepare>,
}

impl PreparedCertificateWrapper {
    pub fn new(proposal_message: BftMessage<ProposalPayload>, prepares: Vec<Prepare>) -> Self {
        Self { proposal_message, prepares }
    }

    // Accessors remain pub due to struct fields being pub
    // pub fn proposal_message(&self) -> &BftMessage<ProposalPayload> {
    //     &self.proposal_message
    // }

    // pub fn prepares(&self) -> &Vec<Prepare> {
    //     &self.prepares
    // }
} 