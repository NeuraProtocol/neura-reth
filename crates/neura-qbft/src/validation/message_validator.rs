use std::sync::Arc;
use crate::messagewrappers::{Proposal, Prepare, Commit};
use crate::types::{QbftFinalState, QbftBlockHeader, BftExtraDataCodec, QbftConfig};
use crate::error::QbftError;
use crate::validation::{
    ProposalValidator, PrepareValidator, CommitValidator, RoundChangeMessageValidatorFactory
};
use alloy_primitives::B256 as Hash; // For storing proposal digest

/// Main validator for QBFT messages (Proposal, Prepare, Commit).
/// It orchestrates validation using specific sub-validators.
/// This validator is typically created per block height.
#[derive(Clone)] // QbftRound clones this, so it needs to be Clone
pub struct MessageValidator {
    final_state: Arc<dyn QbftFinalState>,
    parent_header: Arc<QbftBlockHeader>,
    extra_data_codec: Arc<dyn BftExtraDataCodec>,
    round_change_message_validator_factory: Arc<dyn RoundChangeMessageValidatorFactory>,
    config: Arc<QbftConfig>,

    // State for subsequent message validation (after a proposal is accepted)
    // These are set once a proposal for the round is validated and accepted.
    accepted_proposal_digest: Option<Hash>,
    // Subsequent validators are specific to an accepted proposal.
    // To keep MessageValidator Clone, these might need to be Arc or re-created.
    // For simplicity now, let's assume they are lightweight enough to be cloned if MessageValidator is cloned,
    // or MessageValidator itself isn't cloned frequently in a way that makes this an issue.
    // If cloning MessageValidator is frequent after proposal acceptance, these should be Arc'd.
    // Given QbftRound creates one MessageValidator and RoundState uses it, cloning is likely before proposal.
    prepare_validator: Option<PrepareValidator>, // Initialized after a valid proposal
    commit_validator: Option<CommitValidator>,   // Initialized after a valid proposal
}

impl MessageValidator {
    /// Creates a new `MessageValidator` for a specific consensus context (e.g., block height).
    /// `final_state` provides access to validator sets, proposer logic, etc.
    /// `parent_header` is the header of the block upon which the new block will be built.
    pub fn new(
        final_state: Arc<dyn QbftFinalState>, 
        parent_header: Arc<QbftBlockHeader>,
        extra_data_codec: Arc<dyn BftExtraDataCodec>,
        round_change_message_validator_factory: Arc<dyn RoundChangeMessageValidatorFactory>,
        config: Arc<QbftConfig>,
    ) -> Self {
        Self {
            final_state,
            parent_header,
            extra_data_codec,
            round_change_message_validator_factory,
            config,
            accepted_proposal_digest: None,
            prepare_validator: None,
            commit_validator: None,
        }
    }

    /// Validates a `Proposal` message.
    /// If valid, this method should also update the internal state of `MessageValidator`
    /// to set the context for subsequent `Prepare` and `Commit` messages for this proposal's round.
    pub fn validate_proposal(&mut self, proposal: &Proposal) -> Result<bool, QbftError> {
        // Always use a fresh ProposalValidator for each proposal check, as it doesn't carry state itself
        // beyond its construction parameters (final_state, parent_header).
        let proposal_validator = ProposalValidator::new(
            self.final_state.clone(), 
            self.parent_header.clone(),
            self.extra_data_codec.clone(),
            self.round_change_message_validator_factory.clone(),
            self.config.clone(),
        );
        let is_valid = proposal_validator.validate_proposal(proposal)?;

        if is_valid {
            // If the proposal is valid, set up for validating subsequent messages (Prepare, Commit)
            // related to *this* proposal.
            let proposal_digest = proposal.block().hash();
            self.accepted_proposal_digest = Some(proposal_digest);
            
            // Initialize subsequent validators with the context of this accepted proposal.
            self.prepare_validator = Some(PrepareValidator::new(self.final_state.clone(), proposal));
            self.commit_validator = Some(CommitValidator::new(self.final_state.clone(), proposal));
            log::debug!(
                "Proposal for round {:?} with digest {:?} accepted by MessageValidator. Subsequent validators initialized.", 
                proposal.round_identifier(), proposal_digest
            );
        } else {
            // If proposal is invalid, clear any previous state for subsequent messages.
            self.accepted_proposal_digest = None;
            self.prepare_validator = None;
            self.commit_validator = None;
        }
        Ok(is_valid)
    }

    /// Validates a `Prepare` message.
    /// This should only be called after a `Proposal` has been successfully validated by `validate_proposal`.
    pub fn validate_prepare(&self, prepare: &Prepare, current_proposal: Option<&Proposal>) -> Result<bool, QbftError> {
        if self.accepted_proposal_digest.is_none() || self.prepare_validator.is_none() {
            log::warn!("Validate_prepare called before a proposal was accepted. Ignoring Prepare.");
            return Ok(false); // Cannot validate without an accepted proposal context
        }

        // Ensure the prepare is for the currently accepted proposal
        if Some(prepare.payload().digest) != self.accepted_proposal_digest {
            log::warn!(
                "Prepare digest {:?} does not match currently accepted proposal digest {:?}. Ignoring.",
                prepare.payload().digest, self.accepted_proposal_digest.unwrap_or_default()
            );
            return Ok(false);
        }
        
        // Ensure the round identifier of prepare matches the round of the accepted proposal
        if let Some(proposal) = current_proposal {
            if prepare.round_identifier() != proposal.round_identifier() {
                 log::warn!(
                    "Prepare round_id {:?} does not match current proposal round_id {:?}. Ignoring.",
                    prepare.round_identifier(), proposal.round_identifier()
                );
                return Ok(false);
            }
        } else {
            log::error!("Current proposal missing in validate_prepare when accepted_proposal_digest is Some. This is inconsistent.");
            return Err(QbftError::InternalError("Proposal context missing in validate_prepare".into()));
        }

        // Delegate to the specific PrepareValidator initialized for the accepted proposal.
        self.prepare_validator.as_ref().unwrap().validate_prepare(prepare)
    }

    /// Validates a `Commit` message.
    /// This should only be called after a `Proposal` has been successfully validated by `validate_proposal`.
    pub fn validate_commit(&self, commit: &Commit, current_proposal: Option<&Proposal>) -> Result<bool, QbftError> {
        if self.accepted_proposal_digest.is_none() || self.commit_validator.is_none() {
            log::warn!("Validate_commit called before a proposal was accepted. Ignoring Commit.");
            return Ok(false); // Cannot validate without an accepted proposal context
        }

        if Some(commit.payload().digest) != self.accepted_proposal_digest {
            log::warn!(
                "Commit digest {:?} does not match currently accepted proposal digest {:?}. Ignoring.",
                commit.payload().digest, self.accepted_proposal_digest.unwrap_or_default()
            );
            return Ok(false);
        }

        if let Some(proposal) = current_proposal {
            if commit.round_identifier() != proposal.round_identifier() {
                 log::warn!(
                    "Commit round_id {:?} does not match current proposal round_id {:?}. Ignoring.",
                    commit.round_identifier(), proposal.round_identifier()
                );
                return Ok(false);
            }
        } else {
             log::error!("Current proposal missing in validate_commit when accepted_proposal_digest is Some. This is inconsistent.");
            return Err(QbftError::InternalError("Proposal context missing in validate_commit".into()));
        }

        self.commit_validator.as_ref().unwrap().validate_commit(commit)
    }
}

// Clone implementation for sub-validators if they are not Arc'd and need to be cloneable
// For now, they are re-created or their `new` methods take Arcs for shared data.
// If MessageValidator itself is cloned *after* a proposal is accepted, then PrepareValidator and CommitValidator
// would also need to be Clone. Let's make them Clone for now assuming they are lightweight or manage their own Arcs.

impl Clone for PrepareValidator {
    fn clone(&self) -> Self {
        // This is a shallow clone if final_state is Arc. If it held complex non-Arc state, deep clone needed.
        Self {
            final_state: self.final_state.clone(),
            expected_proposal_digest: self.expected_proposal_digest,
        }
    }
}

impl Clone for CommitValidator {
    fn clone(&self) -> Self {
        Self {
            final_state: self.final_state.clone(),
            expected_proposal_digest: self.expected_proposal_digest,
        }
    }
} 