use crate::error::QbftError;
// use std::collections::HashSet; // Removed based on build log
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::types::{
    ConsensusRoundIdentifier, NodeKey, QbftBlock, QbftBlockHeader, SignedData, /* BftExtraData, */ BftExtraDataCodec, QbftFinalState, QbftBlockCreator, 
    QbftBlockImporter, RoundTimer, ValidatorMulticaster, RlpSignature,
    // PreparedCertificate // Removed this line
};
use crate::statemachine::round_state::{RoundState, PreparedCertificate as RoundStatePreparedCertificate};
// Removed CommitPayload, ProposalPayload from payload import based on build log
use crate::payload::{MessageFactory, PreparePayload, RoundChangePayload};
use crate::messagewrappers::{Proposal, Prepare, Commit, RoundChange, PreparedCertificateWrapper};
// Removing this problematic line again, as the types are imported directly or aliased above.
// use crate::statemachine::{PreparedCertificate as StatemachinePreparedCertificate, RoundState as StatemachineRoundState};
use crate::validation::{MessageValidator, RoundChangeMessageValidator};
// Removed Address, Bytes, keccak256 from alloy_primitives import based on build log
use alloy_primitives::{B256 as Hash, Signature};
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
    multicaster: Arc<dyn ValidatorMulticaster>,
    round_timer: Arc<dyn RoundTimer>,
    extra_data_codec: Arc<dyn BftExtraDataCodec>,
    mined_block_observers: Vec<Arc<dyn QbftMinedBlockObserver>>,
    locked_block: Option<QbftBlock>,
    proposal_sent: bool,
    prepare_sent: bool,
    finalized_block_hash_in_round: Option<Hash>,
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
            multicaster: validator_multicaster,
            round_timer,
            extra_data_codec,
            mined_block_observers,
            locked_block: None,
            proposal_sent: false,
            prepare_sent: false,
            finalized_block_hash_in_round: None,
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
        let block_to_propose_from_cert = round_change_artifacts
            .best_prepared_certificate()
            .map(|cert| cert.block.clone());

        let (block_to_propose, block_hash_for_log) = match block_to_propose_from_cert {
            Some(block) => {
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
            .best_prepared_certificate()
            .map_or(Vec::new(), |cert| cert.prepares.clone());

        self.propose_block(block_to_propose, piggybacked_round_changes, piggybacked_prepares, block_hash_for_log)
    }

    fn propose_block(
        &mut self,
        block: QbftBlock,
        round_change_payloads: Vec<SignedData<RoundChangePayload>>,
        prepare_payloads: Vec<SignedData<PreparePayload>>,
        block_hash_for_log: Hash,
    ) -> Result<(), QbftError> {
        // Convert RoundChangePayloads to Vec<RoundChange>
        let round_change_proofs: Vec<RoundChange> = round_change_payloads
            .into_iter()
            .map(|rc_payload| RoundChange::new(rc_payload, None, None)) // Assuming no block/prepares for these proofs
            .collect::<Result<Vec<RoundChange>, QbftError>>()?;

        // Convert PreparePayloads to Option<PreparedCertificateWrapper>
        // This is complex: requires the original Proposal for these prepares.
        // For now, if prepare_payloads are present, it implies a prepared state, but we lack the original proposal.
        // Placeholder: Create None. This needs to be properly implemented if re-proposing with a cert.
        let prepared_certificate: Option<PreparedCertificateWrapper> = if prepare_payloads.is_empty() {
            None
        } else {
            // TODO: Construct PreparedCertificateWrapper correctly.
            // This needs the original Proposal that these `prepare_payloads` validated.
            // And `prepare_payloads` need to be wrapped into `Prepare` messages first.
            log::warn!("Proposing with non-empty prepares, but PreparedCertificateWrapper construction is placeholder.");
            None 
        };

        let proposal = self.message_factory.create_proposal(
            *self.round_identifier(),
            block.clone(), 
            round_change_proofs, // Corrected type
            prepared_certificate, // Corrected type
        )?;
        log::trace!("Proposing block {:?} for round {:?}", block_hash_for_log, self.round_identifier());
        self.round_state.set_proposal(proposal.clone())?;
        self.multicaster.multicast_proposal(&proposal);
        self.send_prepare(block, block_hash_for_log)
    }

    fn send_prepare(&mut self, block: QbftBlock, block_digest: Hash) -> Result<(), QbftError> {
        let prepare = self.message_factory.create_prepare(*self.round_identifier(), block_digest)?;
        log::trace!("Sending Prepare for block {:?} in round {:?}", block_digest, self.round_identifier());
        self.round_state.add_prepare(prepare.clone())?;
        self.multicaster.multicast_prepare(&prepare);
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
                        self.multicaster.multicast_commit(&commit);

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
        // Ensure the round is committed
        if !self.round_state.is_committed() {
            log::error!(
                "Attempted to import block for round {:?} which is not committed.", 
                self.round_identifier()
            );
            return Err(QbftError::InvalidState("Round not committed".into()));
        }

        let _finalized_block = self.round_state.proposed_block().cloned(); // Prefixed with _
        if let Some(block_to_import) = self.round_state.proposed_block() {
            let block_hash = block_to_import.hash();
            let original_header = &block_to_import.header;
            let commit_seals_option: Option<Vec<Signature>> = self.round_state.get_commit_seals_if_committed();

            let rlp_commit_seals: Vec<RlpSignature> = commit_seals_option
                .map(|seals| seals.into_iter().map(RlpSignature::from).collect()) // Use RlpSignature::from or RlpSignature() if From is impl
                .unwrap_or_default();

            let mut bft_extra_data = self.extra_data_codec.decode(&original_header.extra_data)
                .map_err(|e| QbftError::InternalError(format!("Failed to decode existing extra_data: {}", e)))?;

            bft_extra_data.committed_seals = rlp_commit_seals; // Assign Vec<RlpSignature>
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
                block_to_import.body_transactions.clone(),
                block_to_import.body_ommers.clone(),
            );

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

    pub fn construct_prepared_certificate(&self) -> Option<RoundStatePreparedCertificate> {
        self.round_state.construct_prepared_certificate()
    }

    // Method to get a block to propose, creating one if necessary
    fn get_block_to_propose(&mut self, target_round_identifier: ConsensusRoundIdentifier) -> Result<QbftBlock, QbftError> {
        if let Some(ref block) = self.locked_block {
            log::debug!(target: "consensus", "Proposing locked block {:?} for round {:?}", block.hash(), target_round_identifier);
            return Ok(block.clone());
        }
        log::debug!(target: "consensus", "Creating new block for round {:?}", target_round_identifier);
        self.block_creator.create_block(&self.parent_header, &target_round_identifier, /* TODO: timestamp */ SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs())
    }

    // If a new block is available (either newly created or a new best target from round changes),
    // and proposal not yet sent for this round, create and send a proposal.
    fn send_proposal_if_new_block_available(
        &mut self,
        block: &QbftBlock,
        round_change_payloads: Vec<SignedData<RoundChangePayload>>,
        input_prepares: Vec<SignedData<PreparePayload>>,
    ) -> Result<(), QbftError> {
        if self.proposal_sent || self.finalized_block_hash_in_round.is_some() {
            return Ok(());
        }

        let round_change_proofs: Vec<RoundChange> = round_change_payloads
            .into_iter()
            .map(|signed_rc_payload| RoundChange::new(signed_rc_payload, None, None))
            .collect::<Result<Vec<RoundChange>, QbftError>>()?;

        let prepared_certificate: Option<PreparedCertificateWrapper> = if input_prepares.is_empty() {
            None
        } else {
            log::warn!("send_proposal_if_new_block_available called with non-empty prepares, but PreparedCertificateWrapper construction is not fully implemented.");
            None
        };

        log::info!(target: "consensus", "Sending proposal for block {} round {:?}", block.header.number, self.round_identifier().round_number);
        let proposal = self.message_factory.create_proposal(
            *self.round_identifier(),
            block.clone(),
            round_change_proofs,
            prepared_certificate,
        )?;
        self.multicaster.multicast_proposal(&proposal);
        self.proposal_sent = true;
        self.round_state.set_proposal(proposal)?;
        Ok(())
    }

    // If a proposal is accepted, send a PREPARE message.
    fn send_prepare_if_proposal_accepted(&mut self) -> Result<(), QbftError> {
        if self.prepare_sent {
            return Ok(());
        }
        if let Some(proposed_block) = self.round_state.proposed_block() {
            let digest = proposed_block.hash();
            log::debug!(target: "consensus", "Sending prepare for block digest {:?} in round {:?}", digest, self.round_identifier());
            let prepare_msg = self.message_factory.create_prepare(*self.round_identifier(), digest)?;
            self.multicaster.multicast_prepare(&prepare_msg);
            self.prepare_sent = true;
            self.add_prepare_if_valid(prepare_msg)?;
        }
        Ok(())
    }

    // Placeholder for cancel_timers method
    pub fn cancel_timers(&self) {
        log::debug!("QbftRound: Cancelling timers for round {:?}", self.round_identifier());
        self.round_timer.cancel_timer(*self.round_identifier());
    }

    // Placeholder for add_prepare_if_valid
    fn add_prepare_if_valid(&mut self, prepare: Prepare) -> Result<bool, QbftError> {
        // Minimal implementation for now, actual validation is in RoundState
        // This method might be more about whether this specific QbftRound instance should process it locally
        log::trace!("QbftRound::add_prepare_if_valid called for prepare from {:?}", prepare.author()?);
        // The main logic is in round_state.add_prepare()
        // This function in Besu seems to be about local prepare handling after sending.
        // For now, let's assume it just tries to add to state, and if it was already there or invalid, RoundState handles it.
        // Return value could indicate if it was newly added and valid.
        // self.round_state.add_prepare(prepare).map(|_| true) // Assuming add_prepare returns Result<(), Error>
        // Let's return based on whether it changed state, or defer to round_state's detailed handling.
        // For now, make it a simple pass-through or a no-op if local prepare is handled by add_prepare itself.
        // Besu: `boolean localPrepareMessageAdded = roundState.addPrepare(prepare);`
        // And then: `if (localPrepareMessageAdded && roundState.isPrepared()) { prepare LocallyCommitted(); }`
        // So RoundState.addPrepare should return a bool.
        // Our RoundState.add_prepare returns Result<(), QbftError>. We can adapt.
        match self.round_state.add_prepare(prepare) {
            Ok(_) => Ok(true), // Assume it was added or was valid and already there.
            Err(QbftError::ValidationError(_)) => Ok(false), // Invalid prepare, not added.
            Err(e) => Err(e), // Other error.
        }
    }
} 