use std::sync::{Arc, Mutex};
use crate::types::{QbftBlock, QbftBlockImporter, ValidatorMulticaster};
use crate::messagewrappers::{Proposal, Prepare, Commit, RoundChange};
use crate::error::QbftError;

// --- MockValidatorMulticaster ---
#[derive(Default, Clone)]
pub struct MockValidatorMulticaster {
    pub proposals: Arc<Mutex<Vec<Proposal>>>,
    pub prepares: Arc<Mutex<Vec<Prepare>>>,
    pub commits: Arc<Mutex<Vec<Commit>>>,
    pub round_changes: Arc<Mutex<Vec<RoundChange>>>,
}

impl MockValidatorMulticaster {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn clear(&self) {
        self.proposals.lock().unwrap().clear();
        self.prepares.lock().unwrap().clear();
        self.commits.lock().unwrap().clear();
        self.round_changes.lock().unwrap().clear();
    }
}

impl ValidatorMulticaster for MockValidatorMulticaster {
    fn multicast_proposal(&self, proposal: &Proposal) {
        log::debug!("MockValidatorMulticaster: Multicasting Proposal for round {:?}", proposal.round_identifier());
        self.proposals.lock().unwrap().push(proposal.clone());
    }

    fn multicast_prepare(&self, prepare: &Prepare) {
        let author_for_log = prepare.author().map_or_else(|_| "<unknown>".to_string(), |a| format!("{:?}", a));
        log::debug!("MockValidatorMulticaster: Multicasting Prepare from {} for round {:?}", author_for_log, prepare.round_identifier());
        self.prepares.lock().unwrap().push(prepare.clone());
    }

    fn multicast_commit(&self, commit: &Commit) {
        let author_for_log = commit.author().map_or_else(|_| "<unknown>".to_string(), |a| format!("{:?}", a));
        log::debug!("MockValidatorMulticaster: Multicasting Commit from {} for round {:?}", author_for_log, commit.round_identifier());
        self.commits.lock().unwrap().push(commit.clone());
    }

    fn multicast_round_change(&self, round_change: &RoundChange) {
        let author_for_log = round_change.author().map_or_else(|_| "<unknown>".to_string(), |a| format!("{:?}", a));
        log::debug!("MockValidatorMulticaster: Multicasting RoundChange from {} for target round {:?}", author_for_log, round_change.round_identifier());
        self.round_changes.lock().unwrap().push(round_change.clone());
    }
}

// --- MockQbftBlockImporter ---
#[derive(Default, Clone)]
pub struct MockQbftBlockImporter {
    imported_blocks: Arc<Mutex<Vec<QbftBlock>>>,
    // Optionally, a hook to simulate import failures for testing error paths
    // fail_on_import: Arc<Mutex<bool>>,
}

impl MockQbftBlockImporter {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn get_imported_blocks(&self) -> Vec<QbftBlock> {
        self.imported_blocks.lock().unwrap().clone()
    }

    pub fn get_last_imported_block(&self) -> Option<QbftBlock> {
        self.imported_blocks.lock().unwrap().last().cloned()
    }

    pub fn clear(&self) {
        self.imported_blocks.lock().unwrap().clear();
    }
}

impl QbftBlockImporter for MockQbftBlockImporter {
    fn import_block(&self, block: &QbftBlock) -> Result<(), QbftError> {
        log::info!("MockQbftBlockImporter: Importing block {:?} (Hash: {:?})", block.header.number, block.hash());
        // if *self.fail_on_import.lock().unwrap() { return Err(QbftError::InternalError("Mock import failed".into())); }
        self.imported_blocks.lock().unwrap().push(block.clone());
        Ok(())
    }
} 