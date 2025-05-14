#[cfg(test)]
mod tests {
    use crate::state::round_state::RoundState;
    use crate::types::{ConsensusRoundIdentifier, QbftBlock, QbftBlockHeader};
    use crate::types::block::Transaction;
    use crate::messagewrappers::{Proposal, Prepare, BftMessage};
    use crate::payload::{ProposalPayload, PreparePayload};
    use alloy_primitives::{Address, B256, Bytes};
    use k256::ecdsa::SigningKey;
    use rand::rngs::OsRng;
    use std::sync::Arc;
    use std::ops::Deref;

    // Helper to create a dummy ConsensusRoundIdentifier
    fn dummy_round_id(sequence_number: u64, round_number: u32) -> ConsensusRoundIdentifier {
        ConsensusRoundIdentifier { sequence_number, round_number }
    }

    // Helper to create a dummy Address
    fn dummy_address(val: u8) -> Address {
        Address::from([val; 20])
    }

    // Helper to create a dummy NodeKey (SigningKey)
    fn dummy_node_key() -> SigningKey {
        SigningKey::random(&mut OsRng)
    }

    // Helper to create a dummy QbftBlockHeader
    fn dummy_block_header(number: u64, timestamp: u64) -> Arc<QbftBlockHeader> {
        Arc::new(QbftBlockHeader::new(
            B256::ZERO, // parent_hash
            B256::ZERO, // ommers_hash
            Address::ZERO, // beneficiary
            B256::ZERO, // state_root
            B256::ZERO, // transactions_root
            B256::ZERO, // receipts_root
            Default::default(), // logs_bloom
            Default::default(), // difficulty
            number, // number
            0, // gas_limit
            0, // gas_used
            timestamp, // timestamp
            Bytes::new(), // extra_data
            B256::ZERO, // mix_hash
            Bytes::from_static(&[0u8;8]), // nonce (must be 8 bytes for QbftBlockHeader::new)
            None, // base_fee_per_gas
        ))
    }

    // Helper to create a dummy QbftBlock
    fn dummy_block(header: Arc<QbftBlockHeader>) -> QbftBlock {
        QbftBlock::new(
            (*header).clone(),
            Vec::<Transaction>::new(),
            Vec::<QbftBlockHeader>::new(),
        )
    }

    // Helper to create a dummy signed Proposal
    fn dummy_signed_proposal(
        round_id: ConsensusRoundIdentifier, 
        block: QbftBlock, 
        author_key: &SigningKey
    ) -> Proposal {
        let block_header_for_proposal = block.header.clone();
        let payload = ProposalPayload { 
            round_identifier: round_id,
            proposed_block: block, 
        };
        let signed_data = crate::types::SignedData::sign(payload, author_key).expect("Failed to sign dummy proposal payload");
        let bft_message = BftMessage::new(signed_data);
        
        Proposal::new(
            bft_message, 
            block_header_for_proposal,
            Vec::new(), // round_change_proofs for Proposal struct itself
            None // prepared_certificate for Proposal struct itself
        )
    }

    // Helper to create a dummy signed Prepare message
    fn dummy_signed_prepare(
        round_id: ConsensusRoundIdentifier, 
        digest: B256, 
        author_key: &SigningKey
    ) -> Prepare {
        let payload = PreparePayload { round_identifier: round_id, digest };
        let signed_data = crate::types::SignedData::sign(payload, author_key).expect("Failed to sign dummy prepare payload");
        Prepare::new(signed_data)
    }

    #[test]
    fn test_round_state_new() {
        let round_id = dummy_round_id(1, 0);
        let proposer_address = dummy_address(1);
        let round_state = RoundState::new(round_id, proposer_address);

        assert_eq!(round_state.round_identifier, round_id);
        assert_eq!(round_state.current_proposer, proposer_address);
        assert!(round_state.proposal_message.is_none());
        assert!(round_state.proposed_block_hash.is_none());
        assert!(round_state.proposed_block.is_none());
        assert!(round_state.prepared_certificate.is_none());
        assert!(round_state.round_change_messages.is_empty());
        assert!(round_state.prepare_messages.is_empty());
        assert!(round_state.commit_messages.is_empty());
        assert!(!round_state.timed_out);
    }

    #[test]
    fn test_round_state_set_proposal() {
        let round_id = dummy_round_id(1, 0);
        let proposer_address = dummy_address(1);
        let author_key = dummy_node_key();
        let mut round_state = RoundState::new(round_id, proposer_address);

        let block_header_arc = dummy_block_header(1, 100);
        let block_for_proposal = dummy_block(block_header_arc.clone());
        let expected_block_hash = block_for_proposal.header.hash();
        
        let proposal = dummy_signed_proposal(round_id, block_for_proposal.clone(), &author_key);
        
        round_state.set_proposal(proposal.clone());

        assert!(round_state.proposal_message.is_some());
        assert_eq!(
            round_state.proposal_message.as_ref().unwrap().bft_message().signed_payload, 
            proposal.bft_message().signed_payload
        );
        
        assert!(round_state.proposed_block_hash.is_some());
        assert_eq!(round_state.proposed_block_hash.unwrap(), expected_block_hash);
        
        assert!(round_state.proposed_block.is_some());
        assert_eq!(round_state.proposed_block.as_ref().unwrap().header.hash(), expected_block_hash);
        assert_eq!(round_state.proposed_block.as_ref().unwrap().header, block_for_proposal.header);
    }

    #[test]
    fn test_add_prepare_success() {
        let round_id = dummy_round_id(1, 0);
        let proposer_address = dummy_address(1);
        let mut round_state = RoundState::new(round_id, proposer_address);

        let author_key = dummy_node_key();
        let block_header_arc = dummy_block_header(1, 100);
        let block_for_proposal = dummy_block(block_header_arc.clone());
        let proposal = dummy_signed_proposal(round_id, block_for_proposal.clone(), &author_key);
        round_state.set_proposal(proposal);

        let prepare_author_key = dummy_node_key();
        let actual_proposed_digest = round_state.proposed_block_hash.unwrap();
        let signed_prepare_for_address_recovery = crate::types::SignedData::sign(
            PreparePayload{round_identifier: round_id, digest: actual_proposed_digest}, 
            &prepare_author_key
        );
        let prepare_author_address = signed_prepare_for_address_recovery.unwrap().recover_author().unwrap();
        let prepare_msg = dummy_signed_prepare(round_id, actual_proposed_digest, &prepare_author_key);
        
        let result = round_state.add_prepare(prepare_msg.clone());
        assert!(result.is_ok());
        assert_eq!(round_state.prepare_messages.len(), 1);
        assert!(round_state.prepare_messages.contains_key(&prepare_author_address));
        assert_eq!(round_state.prepare_messages.get(&prepare_author_address).unwrap().deref().signed_payload, prepare_msg.deref().signed_payload);
    }

    #[test]
    fn test_add_prepare_no_proposal() {
        let round_id = dummy_round_id(1, 0);
        let proposer_address = dummy_address(1);
        let mut round_state = RoundState::new(round_id, proposer_address);
        let prepare_author_key = dummy_node_key();
        
        let digest_for_author_calc = B256::from_slice(&[1;32]);
        let _signed_prepare_for_address_recovery = crate::types::SignedData::sign(
            PreparePayload{round_identifier: round_id, digest: digest_for_author_calc}, 
            &prepare_author_key
        );
        
        let prepare_msg_digest = B256::from_slice(&[2;32]);
        let prepare_msg = dummy_signed_prepare(round_id, prepare_msg_digest, &prepare_author_key);
        
        let result = round_state.add_prepare(prepare_msg);
        assert!(result.is_err());
        assert_eq!(result.err().unwrap(), "Cannot add Prepare: No proposal set in RoundState yet.");
        assert!(round_state.prepare_messages.is_empty());
    }

    #[test]
    fn test_add_prepare_wrong_digest() {
        let round_id = dummy_round_id(1, 0);
        let proposer_address = dummy_address(1);
        let mut round_state = RoundState::new(round_id, proposer_address);

        let author_key = dummy_node_key();
        let block_header_arc = dummy_block_header(1, 100);
        let block_for_proposal = dummy_block(block_header_arc.clone());
        let proposal = dummy_signed_proposal(round_id, block_for_proposal.clone(), &author_key);
        round_state.set_proposal(proposal);

        let wrong_digest = B256::from_slice(&[0xAA; 32]);
        assert_ne!(wrong_digest, round_state.proposed_block_hash.unwrap());

        let prepare_author_key = dummy_node_key();
        let _signed_prepare_for_address_recovery = crate::types::SignedData::sign(
            PreparePayload{round_identifier: round_id, digest: wrong_digest}, 
            &prepare_author_key
        );
        let prepare_msg = dummy_signed_prepare(round_id, wrong_digest, &prepare_author_key);
        
        let result = round_state.add_prepare(prepare_msg);
        assert!(result.is_err());
        assert_eq!(result.err().unwrap(), "Prepare digest does not match current proposal digest.");
        assert!(round_state.prepare_messages.is_empty());
    }

    #[test_log::test]
    fn test_add_prepare_wrong_round() {
        let round_id = dummy_round_id(1, 0);
        let proposer_address = dummy_address(1);
        let mut round_state = RoundState::new(round_id, proposer_address);

        let author_key = dummy_node_key();
        let block_header_arc = dummy_block_header(1, 100);
        let block_for_proposal = dummy_block(block_header_arc.clone());
        let proposal = dummy_signed_proposal(round_id, block_for_proposal.clone(), &author_key);
        round_state.set_proposal(proposal);

        let wrong_round_id = dummy_round_id(1, 1); 
        let correct_digest = round_state.proposed_block_hash.unwrap();
        let prepare_author_key = dummy_node_key();
        let _signed_prepare_for_address_recovery = crate::types::SignedData::sign(
            PreparePayload{round_identifier: wrong_round_id, digest: correct_digest}, 
            &prepare_author_key
        );
        let prepare_msg = dummy_signed_prepare(wrong_round_id, correct_digest, &prepare_author_key);
        
        let result = round_state.add_prepare(prepare_msg);
        assert!(result.is_err());
        let actual_err = result.err().unwrap();
        let expected_err = "Prepare round identifier does not match current round state.";
        assert_eq!(actual_err, expected_err, "Mismatch! Left (actual): {:?}, Right (expected): {:?}", actual_err, expected_err);
        assert!(round_state.prepare_messages.is_empty());
    }

    #[test]
    fn test_add_prepare_duplicate() {
        let round_id = dummy_round_id(1, 0);
        let proposer_address = dummy_address(1);
        let mut round_state = RoundState::new(round_id, proposer_address);

        let author_key = dummy_node_key();
        let block_header_arc = dummy_block_header(1, 100);
        let block_for_proposal = dummy_block(block_header_arc.clone());
        let proposal = dummy_signed_proposal(round_id, block_for_proposal.clone(), &author_key);
        round_state.set_proposal(proposal);

        let prepare_author_key = dummy_node_key();
        let correct_digest = round_state.proposed_block_hash.unwrap();
        let signed_prepare_for_address_recovery = crate::types::SignedData::sign(
            PreparePayload{round_identifier: round_id, digest:correct_digest}, 
            &prepare_author_key
        );
        let _prepare_author_address = signed_prepare_for_address_recovery.unwrap().recover_author().unwrap();
        let prepare_msg1 = dummy_signed_prepare(round_id, correct_digest, &prepare_author_key);
        let prepare_msg2 = dummy_signed_prepare(round_id, correct_digest, &prepare_author_key);

        let result1 = round_state.add_prepare(prepare_msg1.clone());
        assert!(result1.is_ok());
        assert_eq!(round_state.prepare_messages.len(), 1);

        let result2 = round_state.add_prepare(prepare_msg2);
        assert!(result2.is_ok()); 
        assert_eq!(round_state.prepare_messages.len(), 1); 
    }
} 