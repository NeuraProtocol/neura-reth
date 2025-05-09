use crate::messagewrappers::{Commit, Prepare, Proposal};
use crate::payload::{QbftPayload, PreparePayload, CommitPayload};
use crate::types::{ConsensusRoundIdentifier, SignedData, QbftBlock};
use crate::validation::MessageValidator;
use crate::error::QbftError;
use alloy_primitives::{Address, Signature};
use std::collections::HashMap;
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
        if !self.validator.validate_proposal(&proposal_message)? {
            return Err(QbftError::ValidationError("Invalid proposal".into()));
        }

        // Get digest from the *incoming* proposal's block for filtering
        let proposed_digest = proposal_message.block().hash(); 

        // Clear any prepares/commits that might have been for a different (now invalid) proposal
        self.prepare_messages.retain(|_, prepare| prepare.payload().digest == proposed_digest);
        self.commit_messages.retain(|_, commit| commit.payload().digest == proposed_digest);
        
        self.proposal = Some(proposal_message); // Now store it
        self.update_derived_state();
        Ok(())
    }

    pub fn add_prepare(&mut self, prepare: Prepare) -> Result<(), QbftError> {
        let author = prepare.author()?;
        if self.prepare_messages.contains_key(&author) {
            // Allow re-submission if content is same, or handle as per specific rules
            // For now, simple duplicate author check for this round.
            // return Ok(()); // Or error for duplicate
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
        if self.commit_messages.contains_key(&author) {
            // return Ok(()); // Or error for duplicate
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
    pub fn get_commit_seals_if_committing(&self) -> Option<Vec<Signature>> {
        if self.is_committed() { // Should likely be is_prepared_for_commit or similar state if one exists
            Some(self.commit_messages.values()
            .map(|commit| commit.payload().committed_seal.0.clone())
            .collect())
        } else {
            None
        }
    }

    pub fn construct_prepared_certificate(&self) -> Option<PreparedCertificate> {
        if self.is_prepared() && self.proposal.is_some() {
            Some(PreparedCertificate::new(
                self.proposed_block().unwrap().clone(), // unwrap safe due to is_prepared check
                self.prepare_messages.values().cloned().map(|p_ref| {
                    // This is tricky. SignedData<PreparePayload> is needed.
                    // The Prepare struct wraps SignedData<PreparePayload>.
                    // We need to get the underlying SignedData.
                    p_ref.signed_payload.clone() // Assuming Prepare has a public signed_payload or a getter
                }).collect(),
                self.round_identifier.round_number,
            ))
        } else {
            None
        }
    }
} 