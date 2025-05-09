use std::sync::Arc;
use std::collections::HashSet;
use crate::messagewrappers::{Proposal, RoundChange, PreparedCertificateWrapper};
use crate::types::{QbftFinalState, QbftBlockHeader, BftExtraData, BftExtraDataCodec, ConsensusRoundIdentifier};
use crate::payload::QbftPayload;
use crate::error::QbftError;
use crate::validation::RoundChangeMessageValidatorFactory;
// Placeholder for block header validation logic
// use crate::validation::block_header_validator::BlockHeaderValidator;


pub struct ProposalValidator {
    final_state: Arc<dyn QbftFinalState>,
    parent_header: Arc<QbftBlockHeader>,
    extra_data_codec: Arc<dyn BftExtraDataCodec>,
    round_change_message_validator_factory: Arc<dyn RoundChangeMessageValidatorFactory>,
    // block_header_validator: Arc<BlockHeaderValidator>, // For detailed header checks
    // round_change_validator: Arc<RoundChangeMessageValidator>, // For piggybacked messages
}

impl ProposalValidator {
    pub fn new(
        final_state: Arc<dyn QbftFinalState>,
        parent_header: Arc<QbftBlockHeader>,
        extra_data_codec: Arc<dyn BftExtraDataCodec>,
        round_change_message_validator_factory: Arc<dyn RoundChangeMessageValidatorFactory>,
        // block_header_validator: Arc<BlockHeaderValidator>,
        // round_change_validator: Arc<RoundChangeMessageValidator>,
    ) -> Self {
        Self {
            final_state,
            parent_header,
            extra_data_codec,
            round_change_message_validator_factory,
            // block_header_validator,
            // round_change_validator,
        }
    }

    pub fn validate_proposal(&self, proposal: &Proposal) -> Result<bool, QbftError> {
        let author = proposal.author()?;
        let proposal_round_identifier = proposal.round_identifier();

        // 1. Author is a current validator
        if !self.final_state.is_validator(author) {
            log::warn!("Proposal from non-validator {:?}. Ignoring.", author);
            return Ok(false);
        }

        // 2. Author is the expected proposer for the round
        if !self.final_state.is_proposer_for_round(author, &proposal_round_identifier) {
            log::warn!(
                "Proposal from unexpected proposer {:?} for round {:?}. Expected {}. Ignoring.", 
                author, proposal_round_identifier, self.final_state.get_proposer_for_round(&proposal_round_identifier)
            );
            return Ok(false);
        }
        
        let block = proposal.block();
        let block_header = &block.header;

        // 3. Block header validation (basic checks for now, more can be added)
        // 3.1. Block number matches current height (round_identifier.sequence_number)
        if block_header.number != proposal_round_identifier.sequence_number {
            log::warn!(
                "Proposal block number {} does not match round sequence number {}.",
                block_header.number, proposal_round_identifier.sequence_number
            );
            return Ok(false);
        }

        // 3.2. Parent hash matches
        if block_header.parent_hash != self.parent_header.hash() {
            log::warn!(
                "Proposal parent hash {:?} does not match expected parent hash {:?}.",
                block_header.parent_hash, self.parent_header.hash()
            );
            return Ok(false);
        }

        // 3.3. Timestamp validation (must be greater than parent, within limits)
        if block_header.timestamp <= self.parent_header.timestamp {
            log::warn!(
                "Proposal timestamp {} not greater than parent timestamp {}.",
                block_header.timestamp, self.parent_header.timestamp
            );
            return Ok(false);
        }
        // TODO: Add future bound check for timestamp (e.g., not too far in the future).

        // 3.4. Round number in extra data matches proposal's round
        let bft_extra_data = match self.extra_data_codec.decode(&block_header.extra_data) {
            Ok(data) => data,
            Err(e) => {
                log::warn!("Failed to decode BftExtraData from proposal by {:?}: {}", author, e);
                return Ok(false); // Cannot validate if extra_data is malformed
            }
        };

        if bft_extra_data.round_number != proposal_round_identifier.round_number {
            log::warn!(
                "Proposal extra_data round {} does not match proposal round_identifier {}. Author: {:?}", 
                bft_extra_data.round_number, proposal_round_identifier.round_number, author
            );
            return Ok(false);
        }

        // 4. Validate piggybacked RoundChange messages
        // The Proposal struct directly contains Vec<RoundChange> (parsed from RLP list)
        for piggybacked_rc in proposal.round_change_proofs() {
            let rc_validator = self.round_change_message_validator_factory
                .create_round_change_message_validator(&self.parent_header, self.final_state.clone())?;
            
            if !rc_validator.validate(piggybacked_rc)? {
                log::warn!(
                    "Proposal from {:?} for round {:?} contains an invalid piggybacked RoundChange message from {:?}. Target round: {:?}", 
                    author, proposal_round_identifier, piggybacked_rc.author()?, piggybacked_rc.payload().target_round_identifier
                );
                return Ok(false);
            }
        }

        // 5. Validate piggybacked PreparedCertificate (if any)
        if let Some(cert_wrapper) = &proposal.prepared_certificate {
            log::debug!("Validating piggybacked PreparedCertificate in proposal for round {:?}", proposal_round_identifier);

            if proposal_round_identifier.round_number == 0 {
                log::warn!("Proposal for round 0 cannot have a prepared certificate.");
                return Ok(false); 
            }
            let prepared_round_number = proposal_round_identifier.round_number - 1;
            let prepared_round_id = ConsensusRoundIdentifier {
                sequence_number: proposal_round_identifier.sequence_number, 
                round_number: prepared_round_number,
            };

            // 5.2. Validate block in cert_wrapper
            let cert_block = &cert_wrapper.proposal_message.payload().proposed_block;
            let cert_block_header = &cert_block.header;

            if cert_block_header.number != proposal_round_identifier.sequence_number {
                log::warn!("Prepared cert block number {} mismatch proposal height {}.", cert_block_header.number, proposal_round_identifier.sequence_number);
                return Ok(false);
            }
            if cert_block_header.parent_hash != self.parent_header.hash() {
                log::warn!("Prepared cert block parent hash mismatch.");
                return Ok(false);
            }
            if cert_block_header.timestamp <= self.parent_header.timestamp || cert_block_header.timestamp > block_header.timestamp {
                log::warn!("Prepared cert block timestamp invalid. Parent: {}, Cert: {}, Proposal: {}", self.parent_header.timestamp, cert_block_header.timestamp, block_header.timestamp);
                return Ok(false);
            }

            let cert_bft_extra_data = self.extra_data_codec.decode(&cert_block_header.extra_data)?;
            if cert_bft_extra_data.round_number != prepared_round_number {
                log::warn!(
                    "Prepared cert block extra_data round {} mismatch derived prepared_round {}.", 
                    cert_bft_extra_data.round_number, prepared_round_number
                );
                return Ok(false);
            }

            // Validate proposer of the block in the certificate
            let original_proposer_of_cert_block_payload = cert_wrapper.proposal_message.author()?;
            let expected_proposer_for_prepared_round = self.final_state.get_proposer_for_round(&prepared_round_id);
            if original_proposer_of_cert_block_payload != expected_proposer_for_prepared_round {
                log::warn!(
                    "Author {:?} of proposal in cert is not expected proposer {:?} for its round {:?}.",
                    original_proposer_of_cert_block_payload, expected_proposer_for_prepared_round, prepared_round_id
                );
                return Ok(false);
            }
            // Also check beneficiary in header of the cert block against this original proposer
            if cert_block_header.beneficiary != original_proposer_of_cert_block_payload {
                 log::warn!(
                    "Prepared cert block beneficiary {:?} mismatch original proposer of cert payload {:?}.", 
                    cert_block_header.beneficiary, original_proposer_of_cert_block_payload
                );
                return Ok(false);
            }

            // 5.3. Validate cert_wrapper.prepares
            let mut unique_prepare_senders = HashSet::new();
            if cert_wrapper.prepares.len() < self.final_state.quorum_size() {
                log::warn!("Prepared cert has insufficient prepares ({}) for quorum ({}).", cert_wrapper.prepares.len(), self.final_state.quorum_size());
                return Ok(false);
            }

            for prepare_wrapper in &cert_wrapper.prepares {
                let prepare_author = prepare_wrapper.author()?;
                let prepare_payload = prepare_wrapper.payload();

                if !self.final_state.is_validator(prepare_author) {
                    log::warn!("Prepare in cert from non-validator {:?}.", prepare_author);
                    return Ok(false);
                }
                if prepare_payload.digest != cert_block.hash() {
                    log::warn!("Prepare in cert has digest mismatch. Prepare: {:?}, Block: {:?}", prepare_payload.digest, cert_block.hash());
                    return Ok(false);
                }
                if prepare_payload.round_identifier != prepared_round_id {
                    log::warn!("Prepare in cert has round_id {:?} mismatch expected prepared_round_id {:?}.", prepare_payload.round_identifier, prepared_round_id);
                    return Ok(false);
                }
                unique_prepare_senders.insert(prepare_author);
            }

            if unique_prepare_senders.len() < self.final_state.quorum_size() {
                log::warn!("Prepared cert has insufficient unique prepares ({}) for quorum ({}).", unique_prepare_senders.len(), self.final_state.quorum_size());
                return Ok(false);
            }
            log::debug!("Piggybacked PreparedCertificate validated successfully.");
        }

        log::debug!("Proposal from {:?} for round {:?} passed all validation including piggybacked data.", author, proposal_round_identifier);
        Ok(true)
    }
} 