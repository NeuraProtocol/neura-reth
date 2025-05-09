use std::sync::Arc;
use crate::messagewrappers::RoundChange;
use crate::types::{QbftFinalState, QbftBlockHeader};
use crate::payload::QbftPayload;
use crate::error::QbftError;
 // To validate proposals within prepared certs
use alloy_primitives::Address;


#[derive(Clone)]
pub struct RoundChangeMessageValidator {
    final_state: Arc<dyn QbftFinalState>,
    parent_header: Arc<QbftBlockHeader>, // Parent of the block for the height these RCs are for
    // To validate a proposal within a PreparedCertificate, we need a MessageValidator or its factory.
    // This creates a potential circular dependency if MessageValidator needs RCMV for piggybacked RCs.
    // Let's assume for now that RCMV can create a temporary ProposalValidator for this purpose.
    // Or, the factory for RCMV can also provide a factory for MessageValidator for one-off use.
    // For simplicity, let's require a MessageValidatorFactory to be passed in if needed.
    // This implies the validator for piggybacked RCs inside a Proposal would be simpler or use a different mechanism.
    // For now, let's focus on direct RC validation. Piggybacked RC validation in ProposalValidator can be simpler.
    // Consider what context this validator is created with via its factory.
    // It's for a specific height, so parent_header is known.
}

impl RoundChangeMessageValidator {
    pub fn new(
        final_state: Arc<dyn QbftFinalState>,
        parent_header: Arc<QbftBlockHeader>,
        // message_validator_factory: Arc<dyn MessageValidatorFactory> // If needed for deep cert validation
    ) -> Self {
        Self {
            final_state,
            parent_header,
            // message_validator_factory,
        }
    }

    pub fn validate(&self, round_change: &RoundChange) -> Result<bool, QbftError> {
        let author = round_change.author()?;
        let payload = round_change.payload();
        let target_round_id = payload.target_round_identifier;

        // 1. Author is a current validator
        if !self.final_state.is_validator(author) {
            log::warn!("RoundChange from non-validator {:?}. Ignoring.", author);
            return Ok(false);
        }

        // 2. Signature of the RoundChange message itself is validated by round_change.author() implicitly.

        // 3. Target round validation (basic)
        // Ensure sequence number matches expected height (derived from parent_header.number + 1)
        let expected_height = self.parent_header.number + 1;
        if target_round_id.sequence_number != expected_height {
            log::warn!(
                "RoundChange target sequence {} does not match expected height {}. Author: {:?}",
                target_round_id.sequence_number, expected_height, author
            );
            return Ok(false);
        }
        // TODO: Add check: target_round > local_node_committed_round_for_this_height
        // TODO: Add check: target_round > local_node_prepared_round_for_this_height (if any proposal prepared by local node)

        // 4. Validate PreparedCertificate if present
        if let Some(prepared_metadata) = &payload.prepared_round_metadata {
            let prepared_block = match round_change.prepared_block() {
                Some(block) => block,
                None => {
                    log::warn!(
                        "RoundChange from {:?} has prepared_metadata but no prepared_block.", author
                    );
                    return Ok(false); // Invalid structure
                }
            };

            // 4.1. Prepared round must be less than target round
            if prepared_metadata.prepared_round >= target_round_id.round_number {
                log::warn!(
                    "RoundChange from {:?}: prepared_round {} not less than target_round {}.",
                    author, prepared_metadata.prepared_round, target_round_id.round_number
                );
                return Ok(false);
            }

            // 4.2. Validate the block itself (as a proposal for its prepared_round)
            // This is tricky. We need to essentially run ProposalValidator logic for this block.
            // The ProposalValidator needs final_state and parent_header.
            // It also checks if author is proposer for *that* round. The author of the RC is not necessarily the proposer of the prepared block.
            // For now, basic block header checks against parent_header.
            if prepared_block.header.number != expected_height {
                 log::warn!("RC from {:?}: Prepared block number {} incorrect.", author, prepared_block.header.number);
                 return Ok(false);
            }
            if prepared_block.header.parent_hash != self.parent_header.hash() {
                log::warn!("RC from {:?}: Prepared block parent_hash incorrect.", author);
                return Ok(false);
            }
            // TODO: More rigorous validation of the prepared_block, potentially using a temporary ProposalValidator.

            // 4.3. Validate prepares in the certificate form a quorum for the prepared_block
            let mut unique_prepare_senders = std::collections::HashSet::<Address>::new();
            if prepared_metadata.prepares.len() < self.final_state.quorum_size() {
                log::warn!(
                    "RoundChange from {:?}: Not enough prepares ({}) in certificate for quorum ({}).",
                    author, prepared_metadata.prepares.len(), self.final_state.quorum_size()
                );
                return Ok(false);
            }

            for prepare_signed_data in &prepared_metadata.prepares {
                let prepare_payload = prepare_signed_data.payload();
                let prepare_author = prepare_signed_data.recover_author()?;

                if !self.final_state.is_validator(prepare_author) {
                    log::warn!("RC from {:?}: Prepare in cert from non-validator {:?}.", author, prepare_author);
                    return Ok(false);
                }
                if prepare_payload.digest != prepared_block.hash() {
                    log::warn!(
                        "RC from {:?}: Prepare in cert has digest {:?} mismatching block digest {:?}. Author: {:?}", 
                        author, prepare_payload.digest, prepared_block.hash(), prepare_author
                    );
                    return Ok(false);
                }
                // Check round of prepare matches prepared_round in metadata
                if prepare_payload.round_identifier.round_number != prepared_metadata.prepared_round || 
                   prepare_payload.round_identifier.sequence_number != expected_height {
                     log::warn!("RC from {:?}: Prepare in cert has round_id {:?} mismatching prepared_round {} or height {}. Author: {:?}", 
                        author, prepare_payload.round_identifier, prepared_metadata.prepared_round, expected_height, prepare_author);
                    return Ok(false);
                }
                unique_prepare_senders.insert(prepare_author);
            }
            if unique_prepare_senders.len() < self.final_state.quorum_size() {
                 log::warn!(
                    "RoundChange from {:?}: Not enough unique prepares ({}) in certificate for quorum ({}).",
                    author, unique_prepare_senders.len(), self.final_state.quorum_size()
                );
                return Ok(false);
            }
        }

        log::debug!("RoundChange from {:?} for target round {:?} passed basic validation.", author, target_round_id);
        Ok(true)
    }
} 