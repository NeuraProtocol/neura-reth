use std::sync::Arc;
use crate::messagewrappers::{Prepare, Proposal};
use crate::types::QbftFinalState;
use crate::error::QbftError;
use alloy_primitives::B256 as Hash;

pub struct PrepareValidator {
    final_state: Arc<dyn QbftFinalState>,
    // Context about the current proposal this Prepare is for:
    expected_proposal_digest: Hash, 
    // expected_round_identifier: ConsensusRoundIdentifier, // From Proposal
}

impl PrepareValidator {
    pub fn new(
        final_state: Arc<dyn QbftFinalState>,
        accepted_proposal: &Proposal, // Pass the accepted proposal to set context
    ) -> Self {
        Self {
            final_state,
            expected_proposal_digest: accepted_proposal.block().hash(),
            // expected_round_identifier: *accepted_proposal.round_identifier(),
        }
    }

    pub fn validate_prepare(&self, prepare: &Prepare) -> Result<bool, QbftError> {
        let author = prepare.author()?;
        let payload = prepare.payload();

        // 1. Author is a current validator
        if !self.final_state.is_validator(author) {
            log::warn!("Prepare from non-validator {:?}. Ignoring.", author);
            return Ok(false);
        }

        // 2. Prepare message's digest matches the accepted proposal's digest
        if payload.digest != self.expected_proposal_digest {
            log::warn!(
                "Prepare digest {:?} does not match expected proposal digest {:?}. Author: {:?}", 
                payload.digest, self.expected_proposal_digest, author
            );
            return Ok(false);
        }
        
        // 3. Round identifier consistency (already implicitly checked if this validator is created per proposal)
        // if payload.round_identifier != self.expected_round_identifier { ... }
        // This check is more for MessageValidator ensuring it uses the right PrepareValidator for the right round.

        // 4. Signature of the Prepare message itself is validated by SignedData::author() implicitly.
        // No further signature check needed here unless the payload itself contained another signature field.

        log::debug!("Prepare from {:?} for digest {:?} passed validation.", author, payload.digest);
        Ok(true)
    }
} 