use std::sync::Arc;
use crate::validation::{
    ProposalValidator, PrepareValidator, CommitValidator, 
    MessageValidatorFactory, 
    RoundChangeMessageValidator, RoundChangeMessageValidatorFactory
};
use crate::error::QbftError;
use crate::messagewrappers::{Proposal, Prepare, Commit, RoundChange};
use crate::validation::ValidationContext;

// --- Minimal Mock Validators for this Factory ---
#[derive(Clone)] struct MockPropVal; #[derive(Clone)] struct MockPrepVal; #[derive(Clone)] struct MockCommVal; #[derive(Clone)] struct MockRCMVal;

impl ProposalValidator for MockPropVal {
    fn validate_proposal(&self, _proposal: &Proposal, _context: &ValidationContext) -> Result<(), QbftError> { Ok(()) } // Always Ok for this mock
}
impl PrepareValidator for MockPrepVal {
    fn validate_prepare(&self, _prepare: &Prepare, _context: &ValidationContext) -> Result<(), QbftError> { Ok(()) } // Always Ok
}
impl CommitValidator for MockCommVal {
    fn validate_commit(&self, _commit: &Commit, _context: &ValidationContext) -> Result<(), QbftError> { Ok(()) } // Always Ok
}
impl RoundChangeMessageValidator for MockRCMVal {
    fn validate_round_change(&self, _round_change: &RoundChange, _context: &ValidationContext) -> Result<(), QbftError> { Ok(()) } // Always Ok
}

// --- MockMessageValidatorFactory ---
#[derive(Default)]
pub struct MockMessageValidatorFactory {
    // If this factory needs to be configurable (e.g. to make its validators fail), add fields here.
    // For now, it always vends validators that return Ok(()).
    // It also needs a QbftConfig to pass to validators if they require it.
    // However, ProposalValidatorImpl is the one that takes config, not the trait methods.
    // The factory methods themselves don't take config.
}

impl MockMessageValidatorFactory {
    pub fn new() -> Self {
        Self::default()
    }
}

impl MessageValidatorFactory for MockMessageValidatorFactory {
    fn create_proposal_validator(self: Arc<Self>) -> Arc<dyn ProposalValidator + Send + Sync> {
        // The actual ProposalValidatorImpl takes MessageValidatorFactory and QbftConfig.
        // This mock factory returns a simpler mock that doesn't need these for its trait impl.
        Arc::new(MockPropVal)
    }

    fn create_prepare_validator(self: Arc<Self>) -> Arc<dyn PrepareValidator + Send + Sync> {
        Arc::new(MockPrepVal)
    }

    fn create_commit_validator(self: Arc<Self>) -> Arc<dyn CommitValidator + Send + Sync> {
        Arc::new(MockCommVal)
    }
}

// --- MockRoundChangeMessageValidatorFactory ---
#[derive(Default)]
pub struct MockRoundChangeMessageValidatorFactory {
    // config: Arc<QbftConfig>, // If the RCMV it creates needs config
}

impl MockRoundChangeMessageValidatorFactory {
    pub fn new(/*config: Arc<QbftConfig>*/) -> Self {
        Self::default()
        // Self { config }
    }
}

impl RoundChangeMessageValidatorFactory for MockRoundChangeMessageValidatorFactory {
    // Corrected signature: takes &self, returns Arc<dyn RoundChangeMessageValidator...>
    fn create_round_change_message_validator(&self) -> Arc<dyn RoundChangeMessageValidator + Send + Sync> {
        // The actual RoundChangeMessageValidatorImpl takes MessageValidatorFactory and QbftConfig.
        // This mock factory returns a simpler mock.
        // If MockRCMVal needed config, this factory would need to hold and pass it.
        Arc::new(MockRCMVal)
    }
} 