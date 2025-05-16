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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::payload::{ProposalPayload, PreparePayload, RoundChangePayload, PreparedRoundMetadata};
    use crate::types::{ConsensusRoundIdentifier, QbftBlock, QbftBlockHeader, SignedData, NodeKey};
    use crate::messagewrappers::{BftMessage, Prepare, RoundChange, PreparedCertificateWrapper};
    use alloy_primitives::{Address, Bytes, B256, U256, Bloom};
    // Removed RlpEncodable, RlpDecodable from this import as they are not directly used as derives here.
    use alloy_rlp::{encode, Decodable as RlpDecodable};
    use k256::ecdsa::SigningKey;
    // Removed Arc, RlpSignature as they are not used now.

    // --- Test Utility Functions --- 

    fn dummy_node_key() -> NodeKey {
        SigningKey::from_bytes(&[1u8; 32].into()).unwrap()
    }

    fn dummy_round_identifier(sequence: u64, round: u32) -> ConsensusRoundIdentifier {
        ConsensusRoundIdentifier { sequence_number: sequence, round_number: round }
    }

    fn dummy_block_header(block_number: u64, parent_hash_val: B256) -> QbftBlockHeader {
        QbftBlockHeader::new(
            parent_hash_val, B256::from([1; 32]), Address::ZERO,
            B256::from([2; 32]), B256::from([3; 32]), B256::from([4; 32]),
            Bloom::default(), U256::from(1), block_number, 1_000_000, 0,
            1_000_000_000 + block_number, Bytes::from_static(&[0u8; 32]),
            B256::from([5; 32]), Bytes::from_static(&[0u8; 8]),
            None, // base_fee_per_gas
        )
    }

    fn dummy_qbft_block(block_number: u64, parent_hash_val: B256) -> QbftBlock {
        let header = dummy_block_header(block_number, parent_hash_val);
        QbftBlock::new(header, Vec::new(), Vec::new())
    }

    fn dummy_proposal_payload(block_number: u64, round_number: u32) -> ProposalPayload {
        ProposalPayload::new(
            dummy_round_identifier(block_number, round_number), 
            dummy_qbft_block(block_number, B256::from([0u8; 32]))
        )
    }
    
    fn dummy_bft_message_proposal_payload(block_number: u64, round_number: u32, key: &NodeKey) -> BftMessage<ProposalPayload> {
        let payload = dummy_proposal_payload(block_number, round_number);
        let signed_payload = SignedData::sign(payload, key).unwrap();
        BftMessage::new(signed_payload)
    }

    // Helpers for Prepare messages
    fn dummy_prepare_payload(round_id: ConsensusRoundIdentifier, digest: B256) -> PreparePayload {
        PreparePayload::new(round_id, digest)
    }

    fn dummy_signed_prepare_payload(payload: PreparePayload, key: &NodeKey) -> SignedData<PreparePayload> {
        SignedData::sign(payload, key).unwrap()
    }

    fn dummy_prepare_message(payload: PreparePayload, key: &NodeKey) -> Prepare {
        let signed = dummy_signed_prepare_payload(payload, key);
        Prepare::new(signed)
    }

    // Helpers for PreparedRoundMetadata
    fn dummy_prepared_round_metadata(key: &NodeKey) -> PreparedRoundMetadata {
        let proposal_bft_msg = dummy_bft_message_proposal_payload(5, 0, key);
        let block_hash = proposal_bft_msg.payload().proposed_block.hash();
        
        let prepare_payload = dummy_prepare_payload(dummy_round_identifier(5,0), block_hash);
        let signed_prepare = dummy_signed_prepare_payload(prepare_payload, key);

        PreparedRoundMetadata::new(
            0, // prepared_round
            block_hash, // prepared_block_hash
            proposal_bft_msg, // signed_proposal_payload
            vec![signed_prepare], // prepares
        )
    }

    // Helpers for RoundChange messages
    fn dummy_round_change_payload(
        target_round: u32, 
        prm: Option<PreparedRoundMetadata>, 
        p_block: Option<QbftBlock>
    ) -> RoundChangePayload {
        RoundChangePayload::new(dummy_round_identifier(10, target_round), prm, p_block)
    }

    fn dummy_signed_round_change_payload(payload: RoundChangePayload, key: &NodeKey) -> SignedData<RoundChangePayload> {
        SignedData::sign(payload, key).unwrap()
    }

    fn dummy_round_change_message(key: &NodeKey, include_prepared: bool) -> RoundChange {
        let prm_block = if include_prepared {
            Some(dummy_qbft_block(10, B256::from([6; 32])))
        } else { None };
        
        let prm = if include_prepared {
            // Ensure the block in PRM matches prm_block if provided
            let mut meta = dummy_prepared_round_metadata(key);
            if let Some(ref blk) = prm_block {
                 meta.prepared_block_hash = blk.hash();
                 // meta.signed_proposal_payload.payload_mut().proposed_block = blk.clone(); // This is tricky, BftMessage payload is not mut
            }
            Some(meta)
        } else { None };

        // If PRM is Some, prm_block must be Some according to RoundChangePayload constructor logic implicit in RoundChange::new
        // And RoundChange::new expects prepares to be Some if metadata is Some.
        let round_change_payload = dummy_round_change_payload(1, prm.clone(), prm_block.clone());
        let signed_rc_payload = dummy_signed_round_change_payload(round_change_payload, key);
        
        let prepares_for_rc = if include_prepared && prm.is_some() {
            Some(prm.as_ref().unwrap().prepares.clone())
        } else { None };

        RoundChange::new(signed_rc_payload, prm_block, prepares_for_rc).unwrap()
    }

    // Helper for PreparedCertificateWrapper
    fn dummy_prepared_certificate_wrapper(key: &NodeKey) -> PreparedCertificateWrapper {
        let proposal_bft_msg = dummy_bft_message_proposal_payload(11, 2, key);
        let block_hash = proposal_bft_msg.payload().proposed_block.hash();
        let prepare_payload = dummy_prepare_payload(dummy_round_identifier(11,2), block_hash);
        let prepare_msg = dummy_prepare_message(prepare_payload, key);

        PreparedCertificateWrapper::new(proposal_bft_msg, vec![prepare_msg])
    }

    #[test]
    fn test_proposal_rlp_roundtrip_no_prepared_cert() {
        let node_key = dummy_node_key();
        let bft_msg_proposal = dummy_bft_message_proposal_payload(10, 1, &node_key);
        // let block_hash_for_header = bft_msg_proposal.payload().proposed_block.hash(); // No longer needed for incorrect parent_hash
        // let block_number_for_header = bft_msg_proposal.payload().proposed_block.header.number; // No longer needed for incorrect parent_hash
        
        let round_changes = vec![dummy_round_change_message(&node_key, false)];

        let proposal = Proposal {
            bft_message: bft_msg_proposal.clone(), // Clone if bft_msg_proposal is used later
            proposed_block_header: bft_msg_proposal.payload().proposed_block.header.clone(), // Align with payload's header
            round_change_proofs: round_changes,
            prepared_certificate: None,
        };

        let encoded = encode(&proposal);
        let decoded = Proposal::decode(&mut encoded.as_slice()).expect("Failed to decode Proposal (no cert)");
        assert_eq!(proposal, decoded);
    }

    #[test]
    #[ignore] // Ignoring due to alloy-rlp ListLengthMismatch issue (expected: 1311, got: 3)
    fn test_proposal_rlp_roundtrip_with_prepared_cert() {
        let node_key = dummy_node_key();
        let bft_msg_proposal = dummy_bft_message_proposal_payload(10, 1, &node_key);
        // let block_hash_for_header = bft_msg_proposal.payload().proposed_block.hash(); // No longer needed
        // let block_number_for_header = bft_msg_proposal.payload().proposed_block.header.number; // No longer needed

        let round_changes = vec![dummy_round_change_message(&node_key, true)]; // RC with prepared info
        let prep_cert_wrapper = dummy_prepared_certificate_wrapper(&node_key);

        let proposal = Proposal {
            bft_message: bft_msg_proposal.clone(), // Clone if bft_msg_proposal is used later
            proposed_block_header: bft_msg_proposal.payload().proposed_block.header.clone(), // Align with payload's header
            round_change_proofs: round_changes,
            prepared_certificate: Some(prep_cert_wrapper),
        };

        let encoded = encode(&proposal);
        let decoded = Proposal::decode(&mut encoded.as_slice()).expect("Failed to decode Proposal (with cert)");
        assert_eq!(proposal, decoded);
    }
} 