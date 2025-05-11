// This file should now ONLY contain ValidationContext, ProposalValidator trait, and ProposalValidatorImpl struct/impl.
// The old struct ProposalValidator and its impl block have been removed.

use crate::messagewrappers::Proposal;
use crate::types::{QbftBlockHeader, QbftFinalState, BftExtraDataCodec, QbftConfig};
use crate::error::QbftError;
use crate::payload::QbftPayload;
use alloy_primitives::{Address, B256 as Hash}; // Added Hash import
use std::collections::HashSet; // For validator set in ValidationContext
use std::sync::Arc;

// Note: Other imports from the old struct ProposalValidator like QbftFinalState, QbftConfig, etc. 
// will be needed here if/when ProposalValidatorImpl uses them.
// For now, keeping imports minimal for the current placeholder impl.

/// Provides necessary context from the current consensus state for message validation.
#[derive(Clone)]
pub struct ValidationContext {
    pub current_sequence_number: u64, 
    pub current_round_number: u32,
    pub current_validators: HashSet<Address>,
    // Added fields based on RoundState usage
    pub parent_header: Arc<QbftBlockHeader>,
    pub final_state: Arc<dyn QbftFinalState>,
    pub extra_data_codec: Arc<dyn BftExtraDataCodec>,
    pub config: Arc<QbftConfig>,
    pub accepted_proposal_digest: Option<Hash>, // Digest of the currently accepted proposal
    // TODO: Add more fields as needed, e.g.:
    // pub expected_proposer: Address,
    // pub latest_prepared_certificate: Option<crate::statemachine::PreparedCertificate>,
    // pub chain_head_hash: alloy_primitives::B256,
    // pub chain_id: u64, 
}

impl ValidationContext {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        current_sequence_number: u64, 
        current_round_number: u32, 
        current_validators: HashSet<Address>,
        parent_header: Arc<QbftBlockHeader>,
        final_state: Arc<dyn QbftFinalState>,
        extra_data_codec: Arc<dyn BftExtraDataCodec>,
        config: Arc<QbftConfig>,
        accepted_proposal_digest: Option<Hash>,
    ) -> Self {
        Self {
            current_sequence_number,
            current_round_number,
            current_validators,
            parent_header,
            final_state,
            extra_data_codec,
            config,
            accepted_proposal_digest,
        }
    }
}

/// Trait for validating a Proposal message.
pub trait ProposalValidator {
    /// Validates the given QBFT Proposal.
    /// # Returns
    /// * `Ok(())` if the proposal is valid.
    /// * `Err(QbftError)` if the proposal is invalid.
    fn validate_proposal(&self, proposal: &Proposal, context: &ValidationContext) -> Result<(), QbftError>;
}

/// Concrete implementation of the ProposalValidator trait.
#[derive(Debug, Default)]
pub struct ProposalValidatorImpl;

impl ProposalValidatorImpl {
    pub fn new() -> Self {
        // TODO: This might take dependencies like QbftConfig, QbftFinalState access, etc. later
        Self::default()
    }
}

impl ProposalValidator for ProposalValidatorImpl {
    fn validate_proposal(&self, proposal: &Proposal, context: &ValidationContext) -> Result<(), QbftError> {
        // TODO: Implement comprehensive proposal validation logic here, using context and proposal fields.
        // Example checks:
        // - proposal.author() is in context.current_validators
        // - proposal.author() is the expected proposer for context.current_sequence_number and context.current_round_number
        // - proposal.payload().round_identifier().sequence_number == context.current_sequence_number
        // - proposal.payload().round_identifier().round_number == context.current_round_number
        // - Block validation (parent_hash, number, timestamp, extra_data format etc.) 
        //   (needs chain_head_hash, parent_header from context or QbftFinalState)
        // - RoundChangeProofs validation (if present, needs to call RoundChangeMessageValidator recursively)
        // - PreparedCertificate validation (if present, needs to call PrepareValidator and ProposalValidator recursively for cert contents)

        println!(
            "ProposalValidatorImpl::validate_proposal called for proposal by {:?} for round: {}, sequence: {}. Context: round {}, sequence: {}. Validators in context: {}",
            proposal.author().ok(), // Display author if recoverable
            proposal.payload().round_identifier().round_number,
            proposal.payload().round_identifier().sequence_number,
            context.current_round_number,
            context.current_sequence_number,
            context.current_validators.len()
        );

        // Placeholder: Accessing fields to ensure imports and types are somewhat right.
        let _author = proposal.author()?;
        let _block_header = proposal.proposed_block_header();
        if context.current_validators.is_empty() {
            // Just a placeholder check to use context
            // In reality, an empty validator set might be a critical error depending on context
            log::warn!("ValidationContext has an empty validator set during proposal validation.");
        }

        // For now, assume valid if it reaches here (until actual logic is added)
        Ok(())
    }
} 