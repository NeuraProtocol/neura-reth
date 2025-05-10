use crate::messagewrappers::{Commit, Prepare, Proposal};
use crate::payload::{PreparePayload, CommitPayload};
use crate::types::{ConsensusRoundIdentifier, SignedData, QbftBlock};
use crate::validation::MessageValidator;
use crate::error::QbftError;
use alloy_primitives::{Address, Signature};
use std::collections::HashMap;
use log;
 // For MessageValidator if it becomes shared

// Corresponds to PreparedCertificate.java but simplified as a struct within RoundState scope
// It might be promoted to its own type if used more widely.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedCertificate {
    pub block: QbftBlock, // The block that was prepared
    pub prepares: Vec<SignedData<PreparePayload>>, // The quorum of prepares
    pub prepared_round: u32, // The round in which it was prepared
}

impl PreparedCertificate {
    pub fn new(block: QbftBlock, prepares: Vec<SignedData<PreparePayload>>, prepared_round: u32) -> Self {
        Self { block, prepares, prepared_round }
    }
}

pub struct RoundState {
    round_identifier: ConsensusRoundIdentifier,
    // In Java, MessageValidator is created per round. We can pass it Arc'd if it has shared state
    // or pass a factory/config to create it internally if it's stateless for the round after init.
    // For now, let's assume it's owned per RoundState.
    validator: MessageValidator, 
    quorum_size: usize, // Number of messages needed for quorum

    // Current proposal for this round
    proposal: Option<Proposal>,
    // Valid Prepare messages received for the current proposal
    // Store by author to prevent duplicates for the same proposal digest
    prepare_messages: HashMap<Address, Prepare>,
    // Valid Commit messages received for the current proposal
    commit_messages: HashMap<Address, Commit>,

    // State flags
    is_prepared: bool,
    is_committed: bool,
}

impl RoundState {
    pub fn new(
        round_identifier: ConsensusRoundIdentifier,
        validator: MessageValidator, // Placeholder, will need actual type
        quorum_size: usize,
    ) -> Self {
        Self {
            round_identifier,
            validator,
            quorum_size,
            proposal: None,
            prepare_messages: HashMap::new(),
            commit_messages: HashMap::new(),
            is_prepared: false,
            is_committed: false,
        }
    }

    pub fn round_identifier(&self) -> &ConsensusRoundIdentifier {
        &self.round_identifier
    }

    pub fn set_proposal(&mut self, proposal_message: Proposal) -> Result<(), QbftError> {
        if self.proposal.is_some() {
            return Err(QbftError::ProposalAlreadyReceived);
        }
        // The validator.validate_proposal will internally set its own accepted_proposal_digest
        if !self.validator.validate_proposal(&proposal_message)? {
            return Err(QbftError::ValidationError("Invalid proposal".into()));
        }

        // If we reach here, the proposal is valid and is the first for this round.
        // Prepares and commits should only be for this proposal.
        // Ensure prepare_messages and commit_messages are clear for this new proposal context.
        self.prepare_messages.clear();
        self.commit_messages.clear();
        
        self.proposal = Some(proposal_message); 
        self.is_prepared = false; // Reset derived state, update_derived_state will re-evaluate
        self.is_committed = false;
        self.update_derived_state(); // update_derived_state will correctly set these based on empty prepares/commits initially
        Ok(())
    }

    pub fn add_prepare(&mut self, prepare: Prepare) -> Result<(), QbftError> {
        let author = prepare.author()?;
        // Check if we already have a prepare from this author FOR THE CURRENT PROPOSAL
        // MessageValidator.validate_prepare ensures it's for the current proposal's digest.
        if self.prepare_messages.contains_key(&author) {
            log::warn!(
                "Duplicate Prepare message received from author {:?} for round {:?} and current proposal. Ignoring.",
                author,
                self.round_identifier // Assuming round_identifier is accessible and loggable
            );
            return Ok(()); 
        }

        if !self.validator.validate_prepare(&prepare, self.proposal.as_ref())? {
            return Err(QbftError::ValidationError("Invalid prepare message".into()));
        }
        
        self.prepare_messages.insert(author, prepare);
        self.update_derived_state();
        Ok(())
    }

    pub fn add_commit(&mut self, commit: Commit) -> Result<(), QbftError> {
        let author = commit.author()?;
        // Check if we already have a commit from this author FOR THE CURRENT PROPOSAL
        if self.commit_messages.contains_key(&author) {
            log::warn!(
                "Duplicate Commit message received from author {:?} for round {:?} and current proposal. Ignoring.",
                author,
                self.round_identifier // Assuming round_identifier is accessible and loggable
            );
            return Ok(());
        }

        if !self.validator.validate_commit(&commit, self.proposal.as_ref())? {
            return Err(QbftError::ValidationError("Invalid commit message".into()));
        }

        self.commit_messages.insert(author, commit);
        self.update_derived_state();
        Ok(())
    }

    fn update_derived_state(&mut self) {
        if self.proposal.is_none() {
            self.is_prepared = false;
            self.is_committed = false;
            return;
        }

        self.is_prepared = self.prepare_messages.len() >= self.quorum_size;
        // Commits are for the specific proposed block's digest
        self.is_committed = self.commit_messages.len() >= self.quorum_size;
    }

    pub fn is_prepared(&self) -> bool {
        self.is_prepared
    }

    pub fn is_committed(&self) -> bool {
        self.is_committed
    }

    pub fn proposed_block(&self) -> Option<&QbftBlock> {
        self.proposal.as_ref().map(|p| p.block())
    }

    pub fn proposal_message(&self) -> Option<&Proposal> {
        self.proposal.as_ref()
    }

    pub fn quorum_size(&self) -> usize {
        self.quorum_size
    }

    pub fn get_prepare_messages(&self) -> Vec<&SignedData<PreparePayload>> {
        self.prepare_messages.values().map(|prepare_wrapper| &prepare_wrapper.signed_payload).collect()
    }

    pub fn get_commit_messages(&self) -> Vec<&SignedData<CommitPayload>> {
        self.commit_messages.values().map(|commit_wrapper| &commit_wrapper.signed_payload).collect()
    }

    // Get only the commit seals (signatures) for committed messages
    pub fn get_commit_seals_if_committed(&self) -> Option<Vec<Signature>> {
        if self.is_committed() { 
            Some(self.commit_messages.values()
                .map(|commit| commit.payload().committed_seal.0.clone())
                .collect())
        } else {
            None
        }
    }

    pub fn construct_prepared_certificate(&self) -> Option<PreparedCertificate> {
        if self.is_prepared() && self.proposal.is_some() {
            // self.proposal is Option<Proposal>. We need the block from it.
            let proposed_block = self.proposal.as_ref().unwrap().block().clone();
            Some(PreparedCertificate::new(
                proposed_block,
                self.prepare_messages.values().cloned().map(|p_wrapper| {
                    p_wrapper.signed_payload.clone()
                }).collect(),
                self.round_identifier.round_number,
            ))
        } else {
            None
        }
    }
} 