use crate::messagewrappers::{Commit, Prepare, Proposal};
use crate::payload::{PreparePayload, CommitPayload};
use crate::types::{ConsensusRoundIdentifier, SignedData, QbftBlock, QbftBlockHeader, QbftFinalState, BftExtraDataCodec, QbftConfig};
use crate::validation::{ProposalValidator, PrepareValidator, CommitValidator, ValidationContext};
use crate::error::QbftError;
use alloy_primitives::{Address, Signature, B256 as Hash};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
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
    // Store individual validators and context components
    proposal_validator: Arc<dyn ProposalValidator + Send + Sync>,
    prepare_validator: Arc<dyn PrepareValidator + Send + Sync>,
    commit_validator: Arc<dyn CommitValidator + Send + Sync>,
    quorum_size: usize, 

    // For creating ValidationContext
    parent_header: Arc<QbftBlockHeader>,
    final_state: Arc<dyn QbftFinalState>,
    extra_data_codec: Arc<dyn BftExtraDataCodec>,
    config: Arc<QbftConfig>,
    accepted_proposal_digest: Option<Hash>, // Store accepted digest here

    proposal: Option<Proposal>,
    prepare_messages: HashMap<Address, Prepare>,
    commit_messages: HashMap<Address, Commit>,

    is_prepared: bool,
    is_committed: bool,
}

impl RoundState {
    pub fn new(
        round_identifier: ConsensusRoundIdentifier,
        proposal_validator: Arc<dyn ProposalValidator + Send + Sync>,
        prepare_validator: Arc<dyn PrepareValidator + Send + Sync>,
        commit_validator: Arc<dyn CommitValidator + Send + Sync>,
        quorum_size: usize,
        parent_header: Arc<QbftBlockHeader>,
        final_state: Arc<dyn QbftFinalState>,
        extra_data_codec: Arc<dyn BftExtraDataCodec>,
        config: Arc<QbftConfig>,
    ) -> Self {
        Self {
            round_identifier,
            proposal_validator,
            prepare_validator,
            commit_validator,
            quorum_size,
            parent_header,
            final_state,
            extra_data_codec,
            config,
            accepted_proposal_digest: None,
            proposal: None,
            prepare_messages: HashMap::new(),
            commit_messages: HashMap::new(),
            is_prepared: false,
            is_committed: false,
        }
    }

    fn create_validation_context(&self) -> ValidationContext {
        let round_id_for_proposer = self.round_identifier(); // Use current round_identifier
        let expected_proposer = self.final_state.get_proposer_for_round(&round_id_for_proposer)
            .unwrap_or_else(|e| {
                log::error!(
                    "Failed to get expected proposer for round {:?}: {:?}. Defaulting to Address::ZERO.", 
                    round_id_for_proposer, e
                );
                Address::ZERO // Or handle error more gracefully, perhaps by returning Result from create_validation_context
            });

        ValidationContext {
            parent_header: self.parent_header.clone(),
            final_state: self.final_state.clone(),
            extra_data_codec: self.extra_data_codec.clone(),
            config: self.config.clone(),
            current_round_number: self.round_identifier.round_number,
            current_sequence_number: self.round_identifier.sequence_number,
            accepted_proposal_digest: self.accepted_proposal_digest,
            current_validators: self.final_state.get_validators_for_block(self.round_identifier.sequence_number).unwrap_or_default().into_iter().collect::<HashSet<Address>>(),
            expected_proposer, // Add the new field
        }
    }

    pub fn round_identifier(&self) -> &ConsensusRoundIdentifier {
        &self.round_identifier
    }

    pub fn set_proposal(&mut self, proposal_message: Proposal) -> Result<(), QbftError> {
        if self.proposal.is_some() {
            return Err(QbftError::ProposalAlreadyReceived);
        }
        // Create context for validation
        let context = self.create_validation_context();
        self.proposal_validator.validate_proposal(&proposal_message, &context)?;
        
        self.prepare_messages.clear();
        self.commit_messages.clear();
        
        // Update accepted_proposal_digest after successful validation
        self.accepted_proposal_digest = Some(proposal_message.block().hash());
        self.proposal = Some(proposal_message); 
        self.is_prepared = false; 
        self.is_committed = false;
        self.update_derived_state(); 
        Ok(())
    }

    pub fn add_prepare(&mut self, prepare: Prepare) -> Result<(), QbftError> {
        let author = prepare.author()?;
        if self.prepare_messages.contains_key(&author) {
            log::warn!(
                "Duplicate Prepare message received from author {:?} for round {:?}. Ignoring.",
                author,
                self.round_identifier
            );
            return Ok(()); 
        }

        let mut context = self.create_validation_context(); // Create context
        // accepted_proposal_digest for prepare validation should be the one from the current proposal
        context.accepted_proposal_digest = self.proposal.as_ref().map(|p| p.block().hash());

        self.prepare_validator.validate_prepare(&prepare, &context)?;
        
        self.prepare_messages.insert(author, prepare);
        self.update_derived_state();
        Ok(())
    }

    pub fn add_commit(&mut self, commit: Commit) -> Result<(), QbftError> {
        let author = commit.author()?;
        if self.commit_messages.contains_key(&author) {
            log::warn!(
                "Duplicate Commit message received from author {:?} for round {:?}. Ignoring.",
                author,
                self.round_identifier
            );
            return Ok(());
        }

        let mut context = self.create_validation_context(); // Create context
        // accepted_proposal_digest for commit validation should be the one from the current proposal
        context.accepted_proposal_digest = self.proposal.as_ref().map(|p| p.block().hash());

        self.commit_validator.validate_commit(&commit, &context)?;

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