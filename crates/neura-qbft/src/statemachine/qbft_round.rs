use std::sync::Arc;
use std::collections::HashSet;

use crate::types::{
    ConsensusRoundIdentifier, QbftBlock, QbftBlockHeader, SignedData, 
    BftExtraData, BftExtraDataCodec, QbftFinalState, QbftBlockCreator, 
    QbftBlockImporter, RoundTimer, ValidatorMulticaster,
};
use crate::statemachine::round_state::{RoundState, PreparedCertificate};
use crate::payload::{MessageFactory, ProposalPayload, PreparePayload, CommitPayload, RoundChangePayload};
use crate::messagewrappers::{Proposal, Prepare, Commit};
use crate::error::QbftError;
use alloy_primitives::{Address, B256 as Hash, keccak256, Signature, Bytes};
use crate::statemachine::round_change_manager::RoundChangeArtifacts;

// Observers for when a block is mined/imported successfully.
pub trait QbftMinedBlockObserver: Send + Sync {
    fn block_imported(&self, block: &QbftBlock);
}

pub struct QbftRound {
    round_state: RoundState,
    parent_header: QbftBlockHeader,
    final_state: Arc<dyn QbftFinalState>,
    block_creator: Arc<dyn QbftBlockCreator>,
    block_importer: Arc<dyn QbftBlockImporter>,
    message_factory: Arc<MessageFactory>,
    transmitter: Arc<dyn ValidatorMulticaster>, 
    round_timer: Arc<dyn RoundTimer>,           
    extra_data_codec: Arc<dyn BftExtraDataCodec>,
    mined_block_observers: Vec<Arc<dyn QbftMinedBlockObserver>>,
}

impl QbftRound {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        round_identifier: ConsensusRoundIdentifier,
        parent_header: QbftBlockHeader,
        final_state: Arc<dyn QbftFinalState>,
        block_creator: Arc<dyn QbftBlockCreator>,
        block_importer: Arc<dyn QbftBlockImporter>,
        message_factory: Arc<MessageFactory>,
        validator_multicaster: Arc<dyn ValidatorMulticaster>,
        round_timer: Arc<dyn RoundTimer>,
        extra_data_codec: Arc<dyn BftExtraDataCodec>,
        message_validator: crate::validation::MessageValidator, 
        mined_block_observers: Vec<Arc<dyn QbftMinedBlockObserver>>,
    ) -> Self {
        let round_state = RoundState::new(
            round_identifier,
            message_validator, 
            final_state.quorum_size(),
        );
        round_timer.start_timer(round_identifier);
        Self {
            round_state,
            parent_header,
            final_state,
            block_creator,
            block_importer,
            message_factory,
            transmitter: validator_multicaster,
            round_timer,
            extra_data_codec,
            mined_block_observers,
        }
    }

    pub fn round_identifier(&self) -> &ConsensusRoundIdentifier {
        self.round_state.round_identifier()
    }

    pub fn create_and_propose_block(&mut self, timestamp_seconds: u64) -> Result<(), QbftError> {
        log::debug!("Creating proposed block for round {:?}", self.round_identifier());
        let block = self.block_creator.create_block(
            &self.parent_header,
            self.round_identifier(),
            timestamp_seconds,
        )?;
        let block_hash_for_log = block.hash(); 
        self.propose_block(block, Vec::new(), Vec::new(), block_hash_for_log)
    }
    
    pub fn start_round_with_prepared_artifacts(
        &mut self,
        round_change_artifacts: &RoundChangeArtifacts, 
        header_timestamp: u64,
    ) -> Result<(), QbftError> {
        let (block_to_propose, block_hash_for_log) = match round_change_artifacts.best_prepared_peer() {
            Some(prepared_cert) => {
                let block = prepared_cert.block.clone();
                let block_hash = block.hash();
                log::debug!(
                    "Re-proposing block from PreparedCertificate for round {:?}: Hash={:?}", 
                    self.round_identifier(), block_hash
                );
                (block, block_hash)
            }
            None => {
                log::debug!("Creating new block for round {:?} as no prepared certificate found.", self.round_identifier());
                let block = self.block_creator.create_block(
                    &self.parent_header, 
                    self.round_identifier(), 
                    header_timestamp
                )?;
                let block_hash = block.hash();
                (block, block_hash)
            }
        };

        let piggybacked_round_changes = round_change_artifacts.round_changes().clone();
        let piggybacked_prepares = round_change_artifacts
            .best_prepared_peer()
            .map_or(Vec::new(), |cert| cert.prepares.clone());

        self.propose_block(block_to_propose, piggybacked_round_changes, piggybacked_prepares, block_hash_for_log)
    }

    fn propose_block(
        &mut self,
        block: QbftBlock,
        round_changes: Vec<SignedData<RoundChangePayload>>,
        prepares: Vec<SignedData<PreparePayload>>,
        block_hash_for_log: Hash,
    ) -> Result<(), QbftError> {
        let proposal = self.message_factory.create_proposal(
            *self.round_identifier(),
            block.clone(), 
            round_changes,
            prepares,
        )?;
        log::trace!("Proposing block {:?} for round {:?}", block_hash_for_log, self.round_identifier());
        self.round_state.set_proposal(proposal.clone())?;
        self.transmitter.multicast_proposal(&proposal);
        self.send_prepare(block, block_hash_for_log)
    }

    fn send_prepare(&mut self, block: QbftBlock, block_digest: Hash) -> Result<(), QbftError> {
        let prepare = self.message_factory.create_prepare(*self.round_identifier(), block_digest)?;
        log::trace!("Sending Prepare for block {:?} in round {:?}", block_digest, self.round_identifier());
        self.round_state.add_prepare(prepare.clone())?;
        self.transmitter.multicast_prepare(&prepare);
        Ok(())
    }
    
    pub fn handle_proposal_message(&mut self, proposal: Proposal) -> Result<(), QbftError> {
        let author = proposal.author()?;
        let block_hash = proposal.block().hash();
        log::debug!(
            "Handling Proposal message for round {:?} from {:?}, block hash: {:?}", 
            self.round_identifier(), 
            author, 
            block_hash
        );

        match self.round_state.set_proposal(proposal.clone()) {
            Ok(_) => {
                log::trace!("Proposal for round {:?} accepted. Sending Prepare.", self.round_identifier());
                self.send_prepare(proposal.block().clone(), block_hash)
            }
            Err(QbftError::ProposalAlreadyReceived) => {
                log::warn!("Duplicate Proposal received for round {:?}. Ignoring.", self.round_identifier());
                Ok(())
            }
            Err(e @ QbftError::ValidationError(_)) => {
                log::warn!("Invalid Proposal for round {:?}: {}. Ignoring.", self.round_identifier(), e);
                Err(e) 
            }
            Err(e) => Err(e),
        }
    }

    pub fn handle_prepare_message(&mut self, prepare: Prepare) -> Result<(), QbftError> {
        let author = prepare.author()?;
        log::debug!(
            "Handling Prepare message for round {:?} from {:?}, digest: {:?}",
            self.round_identifier(),
            author,
            prepare.payload().digest
        );

        match self.round_state.add_prepare(prepare.clone()) {
            Ok(_) => {
                if self.round_state.is_prepared() && !self.round_state.is_committed() {
                    log::trace!("Round {:?} is PREPARED. Sending Commit.", self.round_identifier());
                    if let Some(proposed_block) = self.round_state.proposed_block() {
                        let block_digest = proposed_block.hash();
                        let commit_seal = self.message_factory.create_commit_seal(block_digest)?;
                        let commit = self.message_factory.create_commit(*self.round_identifier(), block_digest, commit_seal)?;
                        self.round_state.add_commit(commit.clone())?;
                        log::info!("[TODO] Transmit Commit: {:?}", commit);
                        self.transmitter.multicast_commit(&commit);

                        if self.round_state.is_committed() {
                            log::trace!("Round {:?} is COMMITTED after sending local commit. Importing block.", self.round_identifier());
                            return self.import_block_to_chain();
                        }
                    } else {
                        log::warn!("Round {:?} is prepared, but no proposed block found. Cannot send Commit.", self.round_identifier());
                    }
                }
                Ok(())
            }
            Err(QbftError::ValidationError(_)) => {
                 log::warn!("Invalid Prepare message for round {:?}. Ignoring.", self.round_identifier());
                 Ok(())
            }
            Err(e) => Err(e),
        }
    }

    pub fn handle_commit_message(&mut self, commit: Commit) -> Result<(), QbftError> {
        let author = commit.author()?;
        log::debug!(
            "Handling Commit message for round {:?} from {:?}, digest: {:?}",
            self.round_identifier(),
            author,
            commit.payload().digest
        );

        // Add commit to round state. RoundState's add_commit uses MessageValidator.
        match self.round_state.add_commit(commit) {
            Ok(_) => {
                // Check if we have enough commits to be "committed"
                if self.round_state.is_committed() {
                    log::trace!(
                        "Round {:?} is COMMITTED after receiving remote commit. Importing block.",
                        self.round_identifier()
                    );
                    // Attempt to import the block
                    // This import_block_to_chain should be idempotent or handle already imported blocks gracefully.
                    return self.import_block_to_chain(); 
                }
                Ok(())
            }
            Err(QbftError::ValidationError(_)) => {
                log::warn!("Invalid Commit message for round {:?}. Ignoring.", self.round_identifier());
                // Propagate validation error if needed, or just log and ignore
                Ok(())
            }
            Err(e) => Err(e), // Other errors from add_commit
        }
    }

    fn notify_new_block_listeners(&self, block: &QbftBlock) {
        for observer in &self.mined_block_observers {
            observer.block_imported(block);
        }
    }

    fn import_block_to_chain(&mut self) -> Result<(), QbftError> {
        if let Some(proposed_block_ref) = self.round_state.proposal_message().map(|p| p.block()) {
            let original_header = &proposed_block_ref.header;
            let commit_seals = self.round_state.get_commit_seals();

            let mut bft_extra_data = self.extra_data_codec.decode(&original_header.extra_data)
                .map_err(|e| QbftError::InternalError(format!("Failed to decode existing extra_data: {}", e)))?;

            bft_extra_data.committed_seals = commit_seals;
            bft_extra_data.round_number = self.round_identifier().round_number;
            
            let new_extra_data_bytes = self.extra_data_codec.encode(&bft_extra_data)?;

            let new_header = QbftBlockHeader::new(
                original_header.parent_hash,
                original_header.ommers_hash,
                original_header.beneficiary,
                original_header.state_root,
                original_header.transactions_root,
                original_header.receipts_root,
                original_header.logs_bloom.clone(),
                original_header.difficulty,
                original_header.number,
                original_header.gas_limit,
                original_header.gas_used,
                original_header.timestamp,
                new_extra_data_bytes,
                original_header.mix_hash,
                original_header.nonce.clone(),
            );
            
            let block_to_import = QbftBlock::new(
                new_header,
                proposed_block_ref.body_transactions.clone(),
                proposed_block_ref.body_ommers.clone(),
            );
            let block_hash = block_to_import.hash();

            log::info!(
                "Block {:?} prepared for import with {} commit seals. Round: {}", 
                block_hash,
                bft_extra_data.committed_seals.len(),
                bft_extra_data.round_number
            );

            self.block_importer.import_block(&block_to_import)?;
            log::info!("Successfully imported block {:?} for round {:?}", block_hash, self.round_identifier());
            self.round_timer.cancel_timer(*self.round_identifier());
            self.notify_new_block_listeners(&block_to_import);
            Ok(())
        } else {
            Err(QbftError::InternalError("Attempted to import block but no proposal in RoundState".into()))
        }
    }

    pub fn construct_prepared_certificate(&self) -> Option<PreparedCertificate> {
        self.round_state.construct_prepared_certificate()
    }
} 