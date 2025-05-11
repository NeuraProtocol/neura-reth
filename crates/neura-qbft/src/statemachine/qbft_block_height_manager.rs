use std::sync::Arc;
use crate::types::{
    ConsensusRoundIdentifier, QbftBlockHeader, QbftFinalState, 
    BlockTimer, RoundTimer, QbftBlockCreator, QbftBlockImporter, ValidatorMulticaster,
    BftExtraDataCodec, QbftBlock, QbftConfig
};
use crate::statemachine::round_change_manager::CertifiedPrepareInfo;
use crate::statemachine::{
    QbftRound, RoundChangeManager, RoundChangeArtifacts, QbftMinedBlockObserver
};
use crate::payload::{MessageFactory, PreparedRoundMetadata};
use crate::validation::{
    RoundChangeMessageValidatorImpl,
    ProposalValidator,
    PrepareValidator, CommitValidator,
    RoundChangeMessageValidatorFactory, MessageValidatorFactory, ValidationContext
};
use crate::error::QbftError;
use crate::messagewrappers::{Proposal, Prepare, Commit, RoundChange};
use std::collections::{HashMap, HashSet}; // Added HashSet here
use alloy_primitives::Address; // Added Address import


// TODO: Define QbftEventQueue or similar for handling events like timer expiries, received messages.

// Manages the consensus process for a single block height.
pub struct QbftBlockHeightManager {
    height: u64, // The block height this manager is responsible for
    parent_header: Arc<QbftBlockHeader>,
    final_state: Arc<dyn QbftFinalState>,
    block_creator: Arc<dyn QbftBlockCreator>,
    block_importer: Arc<dyn QbftBlockImporter>,
    message_factory: Arc<MessageFactory>,
    validator_multicaster: Arc<dyn ValidatorMulticaster>,
    block_timer: Arc<dyn BlockTimer>,
    round_timer: Arc<dyn RoundTimer>,
    extra_data_codec: Arc<dyn BftExtraDataCodec>,
    config: Arc<QbftConfig>,
    proposal_validator: Arc<dyn ProposalValidator + Send + Sync>,
    prepare_validator: Arc<dyn PrepareValidator + Send + Sync>,
    commit_validator: Arc<dyn CommitValidator + Send + Sync>,
    mined_block_observers: Vec<Arc<dyn QbftMinedBlockObserver>>,

    current_round: Option<QbftRound>, // The active round manager
    round_change_manager: RoundChangeManager,
    locked_block: Option<CertifiedPrepareInfo>,
    #[allow(dead_code)] // Set by process_round_state_change, which needs to be properly called
    finalized_block: Option<QbftBlock>,

    // Buffers for messages for future rounds at this height
    future_proposals: HashMap<u32, Vec<Proposal>>,
    future_prepares: HashMap<u32, Vec<Prepare>>,
    future_commits: HashMap<u32, Vec<Commit>>,
}

impl QbftBlockHeightManager {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        parent_header: Arc<QbftBlockHeader>,
        final_state: Arc<dyn QbftFinalState>,
        block_creator: Arc<dyn QbftBlockCreator>,
        block_importer: Arc<dyn QbftBlockImporter>,
        message_factory: Arc<MessageFactory>,
        validator_multicaster: Arc<dyn ValidatorMulticaster>,
        block_timer: Arc<dyn BlockTimer>,
        round_timer: Arc<dyn RoundTimer>,
        extra_data_codec: Arc<dyn BftExtraDataCodec>,
        config: Arc<QbftConfig>,
        proposal_validator: Arc<dyn ProposalValidator + Send + Sync>,
        prepare_validator: Arc<dyn PrepareValidator + Send + Sync>,
        commit_validator: Arc<dyn CommitValidator + Send + Sync>,
        actual_message_validator_factory: Arc<dyn MessageValidatorFactory>,
        _round_change_message_validator_factory: Arc<dyn RoundChangeMessageValidatorFactory>,
        mined_block_observers: Vec<Arc<dyn QbftMinedBlockObserver>>
    ) -> Self {
        let height = parent_header.number + 1;

        let round_change_validator = RoundChangeMessageValidatorImpl::new(
            actual_message_validator_factory.clone(), 
            config.clone(),
        );
        let round_change_manager = RoundChangeManager::new(
            final_state.get_byzantine_fault_tolerance() + 1, 
            round_change_validator
        );
        
        Self {
            height,
            parent_header,
            final_state,
            block_creator,
            block_importer,
            message_factory,
            validator_multicaster,
            block_timer,
            round_timer,
            extra_data_codec,
            config,
            proposal_validator,
            prepare_validator,
            commit_validator,
            mined_block_observers,
            current_round: None,
            round_change_manager,
            locked_block: None,
            finalized_block: None,
            future_proposals: HashMap::new(),
            future_prepares: HashMap::new(),
            future_commits: HashMap::new(),
        }
    }

    pub fn height(&self) -> u64 {
        self.height
    }

    /// Starts the consensus process for this block height, beginning with round 0.
    pub fn start_consensus(&mut self) -> Result<(), QbftError> {
        log::info!("Starting consensus for height {}", self.height);
        self.advance_to_new_round(0, None) // Start with round 0, no prior artifacts
    }

    /// Advances to a new consensus round for the current block height.
    fn advance_to_new_round(&mut self, round_number: u32, artifacts: Option<RoundChangeArtifacts>) -> Result<(), QbftError> {
        let round_identifier = ConsensusRoundIdentifier {
            sequence_number: self.height,
            round_number,
        };
        log::debug!("Advancing to new round: {:?}", round_identifier);

        // Cancel timer for the previous round, if one existed and its timer was running.
        // Also, capture its locked_info to potentially pass to the new round.
        let mut initial_locked_info_for_new_round = self.locked_block.clone(); // Start with BHM's current lock

        if let Some(existing_round) = self.current_round.as_ref() {
            log::trace!("Cancelling timer for previous round: {:?}", existing_round.round_identifier());
            self.round_timer.cancel_timer(*existing_round.round_identifier());
            
            // Get locked info from the outgoing round. This might be more up-to-date.
            if let Some(outgoing_round_lock) = existing_round.locked_info() {
                // Decide if the outgoing round's lock is "better" or should supersede BHM's current lock.
                // For now, let's assume the outgoing round's lock is the most current for this height.
                log::debug!(
                    "Retrieved locked_info (block: {:?}, round: {}) from outgoing round {:?}. Updating BHM lock.", 
                    outgoing_round_lock.block.hash(), 
                    outgoing_round_lock.prepared_round, 
                    existing_round.round_identifier()
                );
                initial_locked_info_for_new_round = Some(outgoing_round_lock);
            }
        }
        // Update BHM's own locked_block with what we are about to pass to the new round.
        self.locked_block = initial_locked_info_for_new_round.clone();

        let new_qbft_round = QbftRound::new(
            round_identifier,
            (*self.parent_header).clone(),
            self.final_state.clone(),
            self.block_creator.clone(),
            self.block_importer.clone(),
            self.message_factory.clone(),
            self.validator_multicaster.clone(),
            self.round_timer.clone(),
            self.extra_data_codec.clone(),
            self.proposal_validator.clone(),
            self.prepare_validator.clone(),
            self.commit_validator.clone(),
            self.config.clone(),
            self.mined_block_observers.clone(),
            initial_locked_info_for_new_round,
        );
        self.current_round = Some(new_qbft_round);

        // Handle proposal based on whether we are starting with prior artifacts or fresh.
        let current_round_mut = self.current_round.as_mut().expect("Current round was just set");

        if self.final_state.is_local_node_proposer_for_round(&round_identifier) {
            log::info!("Local node is proposer for round {:?}", round_identifier);
            // Determine block timestamp: use BlockTimer or parent_timestamp + delta
            // For simplicity here, let's use parent + fixed increment or rely on BlockTimer logic if available.
            // Besu: blockTimestamp = max(parentTimestamp + 1, blockTimer.getTimestampForFutureBlock())
            // Placeholder: just use parent timestamp + 1 for now. BlockTimer logic will be more complex.
            let _current_time_seconds = std::time::SystemTime::now() // Prefixed with _
                .duration_since(std::time::UNIX_EPOCH)
                .expect("Time went backwards")
                .as_secs();
            
            let block_creation_timestamp = self.block_timer.get_timestamp_for_future_block(
                &round_identifier, 
                self.parent_header.timestamp
            );

            if let Some(rc_artifacts) = artifacts {
                log::debug!("Starting round {:?} with prepared artifacts.", round_identifier);
                current_round_mut.start_round_with_prepared_artifacts(&rc_artifacts, block_creation_timestamp)?;
            } else {
                log::debug!("Starting round {:?} by creating a new block proposal.", round_identifier);
                current_round_mut.create_and_propose_block(block_creation_timestamp)?;
            }
        } else {
            log::info!("Local node is NOT proposer for round {:?}. Waiting for proposal.", round_identifier);
            // If not proposer, and there are artifacts, we might have already received the proposal
            // via the RoundChange message that contained it (if we were not the proposer).
            // QbftRound::start_round_with_prepared_artifacts internally handles this if artifacts are provided,
            // even if not proposer, by setting its internal state based on the prepared certificate.
            if let Some(rc_artifacts) = artifacts {
                if rc_artifacts.best_prepared_certificate().is_some() {
                    log::debug!(
                        "Non-proposer starting round {:?} with prepared artifacts. Setting up round state.", 
                        round_identifier
                    );
                    // Use a timestamp that would be valid if we were proposing.
                    // The actual block in artifacts already has a timestamp.
                     let block_creation_timestamp = self.block_timer.get_timestamp_for_future_block(
                        &round_identifier, 
                        self.parent_header.timestamp
                    );
                    current_round_mut.start_round_with_prepared_artifacts(&rc_artifacts, block_creation_timestamp)?;
                }
            }
            // Otherwise, just wait for messages.
        }

        // After the main logic for starting the new round (proposing or setting up from artifacts)
        // process any messages that were buffered for this newly started round.
        if let Err(e) = self.process_buffered_messages(round_number) {
            log::error!("Error processing buffered messages for round {:?}: {:?}", round_identifier, e);
            // Decide if this error should propagate or just be logged.
            // For now, logging, as advance_to_new_round itself might have succeeded in starting the round.
        }

        Ok(())
    }

    fn process_buffered_messages(&mut self, round_number: u32) -> Result<(), QbftError> {
        if self.finalized_block.is_some() {
            log::debug!(
                "Block for height {} already finalized. Skipping processing of buffered messages for round {}.", 
                self.height, round_number
            );
            // Clear any buffered messages for this round as they are no longer needed.
            self.future_proposals.remove(&round_number);
            self.future_prepares.remove(&round_number);
            self.future_commits.remove(&round_number);
            return Ok(());
        }

        // Process Proposals
        if let Some(proposals) = self.future_proposals.remove(&round_number) {
            log::debug!("Processing {} buffered Proposals for round {}", proposals.len(), round_number);
            for proposal in proposals {
                if self.finalized_block.is_some() { break; } // Stop if block got finalized mid-processing
                // Ensure the message is still relevant for the *current state* of current_round
                if let Some(cr) = self.current_round.as_mut() {
                    if cr.round_identifier().round_number == round_number { // Double check round
                        if let Err(e) = cr.handle_proposal_message(proposal) {
                            log::error!("Error processing buffered Proposal for round {}: {:?}", round_number, e);
                            // Depending on error, may need to return e
                        }
                    } else {
                        log::warn!("Buffered proposal for round {} is no longer for current round {:?}. Re-queuing or dropping? For now, dropping.", round_number, cr.round_identifier());
                    }
                } else {
                    log::warn!("No current round to process buffered Proposal for round {}. This should not happen here.", round_number);
                    break; // Should not happen if called correctly from advance_to_new_round
                }
            }
        }
        if self.finalized_block.is_some() { return Ok(()); } // Check after proposals

        // Process Prepares
        if let Some(prepares) = self.future_prepares.remove(&round_number) {
            log::debug!("Processing {} buffered Prepares for round {}", prepares.len(), round_number);
            for prepare in prepares {
                if self.finalized_block.is_some() { break; }
                if let Some(cr) = self.current_round.as_mut() {
                    if cr.round_identifier().round_number == round_number {
                        match cr.handle_prepare_message(prepare) {
                            Ok(Some(block)) => {
                                log::info!("Block finalized from buffered Prepare in round {}.", round_number);
                                self.process_round_state_change(round_number, block)?;
                                break; // Stop processing further buffered messages for this round
                            }
                            Ok(None) => {}
                            Err(e) => log::error!("Error processing buffered Prepare for round {}: {:?}", round_number, e),
                        }
                    } else {
                        log::warn!("Buffered prepare for round {} is no longer for current round {:?}. Re-queuing or dropping? For now, dropping.", round_number, cr.round_identifier());
                    }
                } else {
                    log::warn!("No current round to process buffered Prepare for round {}.", round_number);
                    break;
                }
            }
        }
        if self.finalized_block.is_some() { return Ok(()); } // Check after prepares

        // Process Commits
        if let Some(commits) = self.future_commits.remove(&round_number) {
            log::debug!("Processing {} buffered Commits for round {}", commits.len(), round_number);
            for commit in commits {
                if self.finalized_block.is_some() { break; }
                if let Some(cr) = self.current_round.as_mut() {
                    if cr.round_identifier().round_number == round_number {
                        match cr.handle_commit_message(commit) {
                            Ok(Some(block)) => {
                                log::info!("Block finalized from buffered Commit in round {}.", round_number);
                                self.process_round_state_change(round_number, block)?;
                                break; // Stop processing further buffered messages for this round
                            }
                            Ok(None) => {}
                            Err(e) => log::error!("Error processing buffered Commit for round {}: {:?}", round_number, e),
                        }
                    } else {
                         log::warn!("Buffered commit for round {} is no longer for current round {:?}. Re-queuing or dropping? For now, dropping.", round_number, cr.round_identifier());
                    }
                } else {
                    log::warn!("No current round to process buffered Commit for round {}.", round_number);
                    break;
                }
            }
        }
        Ok(())
    }

    pub fn handle_proposal_message(&mut self, proposal: Proposal) -> Result<(), QbftError> {
        if proposal.round_identifier().sequence_number != self.height {
            log::warn!(
                "Received Proposal for wrong height. Expected: {}, Got: {}. Ignoring.",
                self.height,
                proposal.round_identifier().sequence_number
            );
            return Ok(()); // Not an error, just irrelevant
        }

        if let Some(current_round) = self.current_round.as_mut() {
            if *current_round.round_identifier() == *proposal.round_identifier() {
                log::debug!("Dispatching Proposal to current round: {:?}", proposal.round_identifier());
                return current_round.handle_proposal_message(proposal); // Return the result directly
            } else if proposal.round_identifier().round_number > current_round.round_identifier().round_number {
                log::debug!(
                    "Received Proposal for future round {:?} at current height {}. Buffering.",
                    proposal.round_identifier(), self.height
                );
                self.future_proposals
                    .entry(proposal.round_identifier().round_number)
                    .or_default()
                    .push(proposal);
                return Ok(());
            } else {
                log::debug!(
                    "Received Proposal for past round {:?} at current height {}. Current round is {:?}. Ignoring.",
                    proposal.round_identifier(), self.height, current_round.round_identifier()
                );
                return Ok(());
            }
        } else {
            // No current round, buffer if it's for this height and round 0 or greater.
            // This could happen if BHM is initialized but start_consensus not yet called, or between rounds.
            if proposal.round_identifier().sequence_number == self.height {
                 log::debug!(
                    "Received Proposal for round {:?} at height {} with no current round. Buffering.",
                    proposal.round_identifier(), self.height
                );
                self.future_proposals
                    .entry(proposal.round_identifier().round_number)
                    .or_default()
                    .push(proposal);
            } else {
                log::warn!("Received Proposal for different height {} while no current round for height {}. Ignoring.", proposal.round_identifier().sequence_number, self.height);
            }
            Ok(())
        }
    }

    pub fn handle_prepare_message(&mut self, prepare: Prepare) -> Result<(), QbftError> {
        if prepare.round_identifier().sequence_number != self.height {
            log::warn!(
                "Received Prepare for wrong height. Expected: {}, Got: {}. Ignoring.",
                self.height,
                prepare.round_identifier().sequence_number
            );
            return Ok(());
        }

        if let Some(current_round) = self.current_round.as_mut() {
            if *current_round.round_identifier() == *prepare.round_identifier() {
                log::debug!("Dispatching Prepare to current round: {:?}", prepare.round_identifier());
                let round_number = current_round.round_identifier().round_number;
                let block_finalized_in_round = match current_round.handle_prepare_message(prepare) {
                    Ok(Some(imported_block)) => {
                        log::info!("Block {:?} will be processed for finalization (from Prepare) in round {:?}.", imported_block.hash(), round_number);
                        Some(imported_block)
                    }
                    Ok(None) => None, // Processed, no block finalized yet
                    Err(e) => return Err(e),
                };

                if let Some(imported_block) = block_finalized_in_round {
                    return self.process_round_state_change(round_number, imported_block);
                }
                return Ok(()); 
            } else if prepare.round_identifier().round_number > current_round.round_identifier().round_number {
                log::debug!(
                    "Received Prepare for future round {:?} at current height {}. Buffering.",
                    prepare.round_identifier(), self.height
                );
                self.future_prepares
                    .entry(prepare.round_identifier().round_number)
                    .or_default()
                    .push(prepare);
                return Ok(());
            } else {
                log::debug!(
                    "Received Prepare for past round {:?} at current height {}. Current round is {:?}. Ignoring.",
                    prepare.round_identifier(), self.height, current_round.round_identifier()
                );
                return Ok(());
            }
        } else {
            if prepare.round_identifier().sequence_number == self.height {
                log::debug!(
                    "Received Prepare for round {:?} at height {} with no current round. Buffering.",
                    prepare.round_identifier(), self.height
                );
                self.future_prepares
                    .entry(prepare.round_identifier().round_number)
                    .or_default()
                    .push(prepare);
            } else {
                 log::warn!("Received Prepare for different height {} while no current round for height {}. Ignoring.", prepare.round_identifier().sequence_number, self.height);
            }
            Ok(())
        }
    }

    pub fn handle_commit_message(&mut self, commit: Commit) -> Result<(), QbftError> {
        if commit.round_identifier().sequence_number != self.height {
            log::warn!(
                "Received Commit for wrong height. Expected: {}, Got: {}. Ignoring.",
                self.height,
                commit.round_identifier().sequence_number
            );
            return Ok(());
        }

        if let Some(current_round) = self.current_round.as_mut() {
            if *current_round.round_identifier() == *commit.round_identifier() {
                log::debug!("Dispatching Commit to current round: {:?}", commit.round_identifier());
                let round_number = current_round.round_identifier().round_number;
                let block_finalized_in_round = match current_round.handle_commit_message(commit) {
                    Ok(Some(imported_block)) => {
                        log::info!("Block {:?} will be processed for finalization (from Commit) in round {:?}.", imported_block.hash(), round_number);
                        Some(imported_block)
                    }
                    Ok(None) => None, // Processed, no block finalized yet
                    Err(e) => return Err(e),
                };

                if let Some(imported_block) = block_finalized_in_round {
                    return self.process_round_state_change(round_number, imported_block);
                }
                return Ok(());
            } else if commit.round_identifier().round_number > current_round.round_identifier().round_number {
                log::debug!(
                    "Received Commit for future round {:?} at current height {}. Buffering.",
                    commit.round_identifier(), self.height
                );
                self.future_commits
                    .entry(commit.round_identifier().round_number)
                    .or_default()
                    .push(commit);
                return Ok(());
            } else {
                log::debug!(
                    "Received Commit for past round {:?} at current height {}. Current round is {:?}. Ignoring.",
                    commit.round_identifier(), self.height, current_round.round_identifier()
                );
                return Ok(());
            }
        } else {
            if commit.round_identifier().sequence_number == self.height {
                log::debug!(
                    "Received Commit for round {:?} at height {} with no current round. Buffering.",
                    commit.round_identifier(), self.height
                );
                self.future_commits
                    .entry(commit.round_identifier().round_number)
                    .or_default()
                    .push(commit);
            } else {
                log::warn!("Received Commit for different height {} while no current round for height {}. Ignoring.", commit.round_identifier().sequence_number, self.height);
            }
            Ok(())
        }
    }

    pub fn handle_round_change_message(&mut self, round_change: RoundChange) -> Result<(), QbftError> {
        let target_round_identifier = round_change.round_identifier().clone();

        if target_round_identifier.sequence_number != self.height {
            log::warn!(
                "Received RoundChange for wrong height. Expected: {}, Got: {}. Ignoring.",
                self.height,
                target_round_identifier.sequence_number
            );
            return Ok(());
        }

        if let Some(current_round_ref) = self.current_round.as_ref() {
            if target_round_identifier.round_number <= current_round_ref.round_identifier().round_number {
                log::debug!(
                    "Received RoundChange for past or current round {:?}. Current round is {:?}. Handing to RoundChangeManager.",
                    target_round_identifier, current_round_ref.round_identifier()
                );
            }
        }

        // Create ValidationContext for the RoundChange message
        // The context reflects the BHM's current state.
        // Specific checks within validate_round_change will use this context against the RC's target round.
        let context = ValidationContext::new(
            self.height, // current_sequence_number
            self.current_round.as_ref().map_or(0, |cr| cr.round_identifier().round_number), // current_round_number
            self.final_state.get_validators_for_block(self.height).unwrap_or_default().into_iter().collect::<HashSet<Address>>(), // current_validators for this height
            self.parent_header.clone(),
            self.final_state.clone(),
            self.extra_data_codec.clone(),
            self.config.clone(),
            // accepted_proposal_digest is tricky for RC, as RC might be for a future round or carry its own cert.
            // For the basic validation of an incoming RC message itself (e.g. signature, author is validator),
            // this might be None or not strictly needed by the top-level RC validation.
            // Inner proposal/prepare validation within RC will create their own specific contexts.
            None, // accepted_proposal_digest for the BHM context
        );

        log::debug!("Dispatching RoundChange to RoundChangeManager for target round: {:?}", target_round_identifier);
        match self.round_change_manager.add_round_change_message(round_change, &context) { // Pass context
            Ok(newly_added) => {
                if newly_added {
                    log::info!(
                        "RoundChangeManager processed new RC for target round {}. Checking for quorum.", 
                        target_round_identifier.round_number
                    );
                    if self.round_change_manager.has_sufficient_round_changes(&target_round_identifier) {
                        log::info!(
                            "RoundChangeManager reported quorum for round change to round {}. Advancing.", 
                            target_round_identifier.round_number
                        );
                        let artifacts = self.round_change_manager.get_round_change_artifacts(&target_round_identifier);
                        self.advance_to_new_round(target_round_identifier.round_number, Some(artifacts))?
                    } else {
                        log::trace!("Sufficient RoundChanges not yet received for target round {:?}", target_round_identifier);
                    }
                } else {
                    log::trace!("RoundChange message was duplicate or already processed by manager.");
                }
                /* // TODO: Re-evaluate if early round change detection is needed for QBFT basic operation.
                   // This logic was for a more proactive round change based on f+1 messages for *any* future round.
                let current_round_num = self.current_round.as_ref().map(|cr| cr.round_identifier().round_number).unwrap_or(0);
                if let Some(future_round_num) = self.round_change_manager.lowest_future_round_with_early_quorum(current_round_num, self.height) {
                    log::info!(
                        "Early RoundChange quorum detected for future round {}. Initiating round change.", 
                        future_round_num
                    );
                    // This implies we should trigger a local round change to this future_round_num
                    // self.send_round_change_message(future_round_num, true); // true indicates we are behind
                }
                */
                Ok(())
            }
            Err(e) => {
                log::error!("Failed to process RoundChange message: {:?}", e);
                Err(e)
            }
        }
    }

    /// Handles a round timeout event for the given round identifier.
    pub fn handle_round_timeout_event(&mut self, timed_out_round_id: ConsensusRoundIdentifier) -> Result<(), QbftError> {
        log::warn!("Round timeout event for {:?}", timed_out_round_id);

        if timed_out_round_id.sequence_number != self.height {
            log::debug!(
                "Round timeout for wrong height. Expected: {}, Got: {}. Ignoring.", 
                self.height, timed_out_round_id.sequence_number
            );
            return Ok(());
        }

        // Check if this timeout is for the current round we are actively managing.
        // If we have already moved to a later round, this timeout is stale.
        if let Some(current_round_ref) = self.current_round.as_ref() {
            if timed_out_round_id != *current_round_ref.round_identifier() {
                log::info!(
                    "Stale round timeout for {:?}. Current round is {:?}. Ignoring.", 
                    timed_out_round_id, current_round_ref.round_identifier()
                );
                return Ok(());
            }
        } else {
            log::warn!("Round timeout event for {:?} but no current round. Ignoring.", timed_out_round_id);
            return Ok(()); // No current round to compare against, likely already moved on or not started.
        }

        // If the timeout is for the current round, initiate a round change.
        log::info!("Current round {:?} timed out. Initiating round change.", timed_out_round_id);

        let next_round_number = timed_out_round_id.round_number + 1;
        let new_target_round_id = ConsensusRoundIdentifier {
            sequence_number: self.height,
            round_number: next_round_number,
        };

        // Get PreparedRoundMetadata and corresponding QbftBlock if current round was prepared.
        let prepared_round_metadata_opt: Option<PreparedRoundMetadata> = self.current_round.as_ref()
            .and_then(|cr| cr.get_prepared_round_metadata_for_round_change());

        let prepared_block_opt: Option<QbftBlock> = if let Some(ref metadata) = prepared_round_metadata_opt {
            self.current_round.as_ref().and_then(|cr| {
                cr.round_state().proposed_block().and_then(|block| {
                    if block.hash() == metadata.prepared_block_hash {
                        Some(block.clone())
                    } else {
                        log::warn!(
                            "Block hash mismatch for prepared round. Metadata hash: {:?}, Current round block hash: {:?}. Proceeding without prepared block for RoundChange.",
                            metadata.prepared_block_hash,
                            block.hash()
                        );
                        None
                    }
                })
            })
        } else {
            None
        };
        
        // If metadata was present but block could not be consistently retrieved, log and send RC without prepared info.
        if prepared_round_metadata_opt.is_some() && prepared_block_opt.is_none() {
            log::warn!(
                "PreparedRoundMetadata was available for timed-out round {:?}, but corresponding QbftBlock could not be retrieved or was inconsistent. Sending RoundChange without prepared certificate.",
                timed_out_round_id
            );
        }


        let round_change_message = self.message_factory.create_round_change(
            new_target_round_id,
            // If block is None, metadata should also be None for create_round_change logic
            if prepared_block_opt.is_some() { prepared_round_metadata_opt } else { None },
            prepared_block_opt,
        )?;

        log::debug!("Created RoundChange message for target {:?}: {:?}", new_target_round_id, round_change_message);

        // Multicast this round change message
        self.validator_multicaster.multicast_round_change(&round_change_message);

        // Process our own round change message immediately
        // This will add it to the RoundChangeManager and potentially trigger advance_to_new_round if it forms a quorum.
        self.handle_round_change_message(round_change_message)
    }

    // TODO: Implement methods for:
    // - handle_block_timer_event()

    fn on_block_finalized(&self, block: &QbftBlock) {
        for observer in self.mined_block_observers.iter() { // Iter over Vec<Arc<dyn QbftMinedBlockObserver>>
            observer.block_imported(block); // Assuming QbftMinedBlockObserver has block_imported
        }
    }

    fn process_round_state_change(&mut self, round_number: u32, block: QbftBlock) -> Result<(), QbftError> {
        if self.finalized_block.is_some() {
            log::debug!("Block at height {} already finalized. Ignoring further state changes.", self.height);
            return Ok(());
        }

        // Logic for handling a committed block from a round
        if self.locked_block.is_none() || block.header.number > self.locked_block.as_ref().unwrap().block.header.number {
            // self.locked_block = Some(block.clone()); // This needs to be CertifiedPrepareInfo
            // TODO: If a block is finalized, how does it affect the BHM's locked_block (CertifiedPrepareInfo)?
            // For now, process_round_state_change sets self.finalized_block. 
            // The BHM's locked_block should be cleared upon finalization (see Step 4 of the plan).
        }

        // For QBFT, a block is final once committed by a 2F+1 quorum in a round.
        self.finalized_block = Some(block.clone());
        // Since a block is finalized for this height, any previous lock is no longer relevant.
        self.locked_block = None;
        log::info!(target: "consensus", "Height {}: Block {:?} finalized in round {}. Locked block for height cleared.", self.height, block.hash(), round_number);
        
        self.on_block_finalized(&block); // Use the helper method

        // TODO: Stop all activity for this height? Or allow subsequent rounds to proceed if needed by protocol?
        // For now, assume we stop and wait for controller to move to next height.
        if let Some(current_round) = self.current_round.as_mut() {
            current_round.cancel_timers();
        }
        Ok(())
    }

    pub fn lowest_future_round_with_early_quorum(&self) -> Option<u32> {
        // Assuming current_round_identifier is correctly maintained and accessible
        // The sequence number must match the current block height being processed.
        // let _current_round_number = self.current_round.as_ref().map(|cr| cr.round_identifier().round_number).unwrap_or(0); // Prefixed with _
        // self.round_change_manager.lowest_future_round_with_early_quorum(
        // _current_round_number, 
        // self.height
        // )
        // The method `lowest_future_round_with_early_quorum` was removed from `RoundChangeManager`.
        // This functionality is currently not active.
        log::trace!("lowest_future_round_with_early_quorum called, but underlying functionality in RoundChangeManager is removed.");
        None
    }
} 