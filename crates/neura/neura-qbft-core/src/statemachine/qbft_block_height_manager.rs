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
use std::collections::{HashMap}; // Added HashSet here


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
        mined_block_observers: Vec<Arc<dyn QbftMinedBlockObserver>>,
    ) -> Self {
        let height = parent_header.number + 1;

        let round_change_validator = RoundChangeMessageValidatorImpl::new(
            config.clone(),
            proposal_validator.clone(), 
            prepare_validator.clone(),
            actual_message_validator_factory.clone()
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

        let is_proposer = self.final_state.is_local_node_proposer_for_round(&round_identifier);
        log::info!("[BHM_ADVANCE_ROUND] For round {:?}, local node is_proposer: {}", round_identifier, is_proposer);

        if is_proposer {
            log::info!("[BHM_ADVANCE_ROUND] Local node IS proposer for round {:?}. Determining action.", round_identifier);
            let block_creation_timestamp = self.block_timer.get_timestamp_for_future_block(
                &round_identifier, 
                self.parent_header.timestamp
            );

            if let Some(rc_artifacts) = artifacts {
                log::info!("[BHM_ADVANCE_ROUND] Starting round {:?} WITH prepared artifacts. Timestamp: {}", round_identifier, block_creation_timestamp);
                current_round_mut.start_round_with_prepared_artifacts(&rc_artifacts, block_creation_timestamp)?;
            } else {
                log::info!("[BHM_ADVANCE_ROUND] Starting round {:?} by CREATING AND PROPOSING new block. Timestamp: {}", round_identifier, block_creation_timestamp);
                current_round_mut.create_and_propose_block(block_creation_timestamp)?;
            }
        } else {
            log::info!("[BHM_ADVANCE_ROUND] Local node is NOT proposer for round {:?}. Waiting for proposal or using artifacts.", round_identifier);
            if let Some(rc_artifacts) = artifacts {
                if rc_artifacts.best_prepared_certificate().is_some() {
                    log::info!(
                        "[BHM_ADVANCE_ROUND] Non-proposer starting round {:?} WITH prepared artifacts from RC.", 
                        round_identifier
                    );
                     let block_creation_timestamp = self.block_timer.get_timestamp_for_future_block(
                        &round_identifier, 
                        self.parent_header.timestamp
                    );
                    current_round_mut.start_round_with_prepared_artifacts(&rc_artifacts, block_creation_timestamp)?;
                } else {
                    log::info!("[BHM_ADVANCE_ROUND] Non-proposer for round {:?}, artifacts present but no best_prepared_certificate.", round_identifier);
                }
            } else {
                log::info!("[BHM_ADVANCE_ROUND] Non-proposer for round {:?}, no artifacts. Round will wait for messages.", round_identifier);
            }
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
        let round_change_payload = round_change.payload();
        let target_round_identifier = round_change_payload.round_identifier;
        let author = round_change.author().unwrap_or_default();

        log::debug!(
            "BHM height {}: Handling RoundChange from {:?} for target round {:?}",
            self.height,
            author,
            target_round_identifier
        );

        // Ensure the RoundChange is for the current height this manager is responsible for.
        if target_round_identifier.sequence_number != self.height {
            log::warn!(
                "BHM height {}: Discarding RoundChange for different height {}. Target: {:?}",
                self.height, target_round_identifier.sequence_number, target_round_identifier
            );
            return Ok(());
        }

        if self.finalized_block.is_some() {
            log::debug!(
                "BHM height {}: Block already finalized. Discarding RoundChange for target {:?}.",
                self.height, target_round_identifier
            );
            return Ok(());
        }

        // Create ValidationContext for the RoundChangeMessageValidator.
        // The context should reflect the state relevant to validating this specific RoundChange message.
        // The RoundChange itself contains the proposed round number, and potentially prepared metadata.
        // The validator will use this information.
        let current_round_for_context = self.current_round.as_ref()
            .map_or(0, |r| r.round_identifier().round_number);

        // Expected proposer for the *target* round might be part of advanced validation, 
        // but core validation context might not need it directly for RoundChange itself.
        // For now, construct a general context.
        // The RoundChangeMessageValidatorImpl may internally create more specific contexts if needed for sub-validations.
        let validation_context = ValidationContext::new(
            self.height, // current_sequence_number
            current_round_for_context, // current_round_number (of BHM)
            self.final_state.validators().into_iter().collect(), // current_validators for this height
            Some(self.parent_header.clone()), // parent_header
            self.final_state.clone(), // final_state provider
            self.extra_data_codec.clone(), // extra_data_codec
            self.config.clone(), // config
             // `accepted_proposal_digest` for RC validation is tricky. 
             // The RC message might carry its own prepared cert. The validator handles this.
            None, 
            // `expected_proposer` for RC validation context. Proposer of the target round.
            // This can be calculated, but let the validator handle if it needs it.
            self.final_state.get_proposer_for_round(&target_round_identifier)?
        );

        match self.round_change_manager.add_round_change_message(round_change, &validation_context) {
            Ok(true) => { // Message was new and added
                log::debug!(
                    "BHM height {}: Added RoundChange from {:?} for target {:?}. Checking for quorum.",
                    self.height, author, target_round_identifier
                );

                if self.round_change_manager.has_sufficient_round_changes(&target_round_identifier) {
                    let current_known_round = self.current_round.as_ref()
                        .map_or(u32::MAX, |r| r.round_identifier().round_number);
                    
                    // Ensure we are advancing to a future round relative to our current round, if one exists.
                    // If no current_round, any valid quorum for round 0 or higher is fine.
                    let should_advance = if let Some(current_r) = self.current_round.as_ref() {
                        target_round_identifier.round_number > current_r.round_identifier().round_number
                    } else {
                        // No current round, so if target is valid, it's an advance (or start)
                        true // round_number is u32, so always >= 0
                    };

                    if should_advance {
                        log::info!(
                            "BHM height {}: Quorum for RoundChange to {:?} met. Advancing round.",
                            self.height, target_round_identifier
                        );
                        let artifacts = self.round_change_manager.get_round_change_artifacts(&target_round_identifier);
                        // Clear messages for this target round from RoundChangeManager as we are acting on it.
                        // TODO: Add method to RoundChangeManager to prune processed rounds.
                        return self.advance_to_new_round(target_round_identifier.round_number, Some(artifacts));
                    } else {
                        log::debug!(
                            "BHM height {}: Quorum for RoundChange to {:?} met, but target round ({}) is not newer than current round ({}). Not advancing yet.",
                            self.height, target_round_identifier, target_round_identifier.round_number, current_known_round
                        );
                    }
                } else {
                    log::trace!(
                        "BHM height {}: Not enough RoundChange messages yet for target {:?}. Have {}/{}", 
                        self.height, 
                        target_round_identifier, 
                        self.round_change_manager.get_round_change_messages_for_target_round(&target_round_identifier).map_or(0, |v| v.len()),
                        self.round_change_manager.quorum_size() // Add a getter for quorum_size to RCM
                    );
                }
            }
            Ok(false) => { // Duplicate message
                log::debug!(
                    "BHM height {}: Duplicate RoundChange message from {:?} for target {:?}. Not re-evaluating quorum.",
                    self.height, author, target_round_identifier
                );
            }
            Err(e) => {
                log::warn!(
                    "BHM height {}: Invalid RoundChange message from {:?} for target {:?}: {:?}",
                    self.height, author, target_round_identifier, e
                );
                return Err(e); // Propagate validation error
            }
        }
        Ok(())
    }

    /// Handles a round timeout event for the given round identifier.
    pub fn handle_round_timeout_event(&mut self, timed_out_round_id: ConsensusRoundIdentifier) -> Result<(), QbftError> {
        log::info!(
            "BHM height {}: Handling RoundTimeout event for round: {:?}",
            self.height,
            timed_out_round_id
        );

        // Verify the timeout is for the current height and active round.
        if timed_out_round_id.sequence_number != self.height {
            log::warn!(
                "BHM height {}: Received RoundTimeout for incorrect height {}. Current height is {}",
                self.height, timed_out_round_id.sequence_number, self.height
            );
            return Ok(());
        }

        if let Some(current_round) = self.current_round.as_ref() {
            if current_round.round_identifier() != &timed_out_round_id {
                log::warn!(
                    "BHM height {}: Received RoundTimeout for {:?}, but current active round is {:?}. Ignoring.",
                    self.height, timed_out_round_id, current_round.round_identifier()
                );
                return Ok(());
            }
        } else {
            log::warn!(
                "BHM height {}: Received RoundTimeout for {:?}, but no current round is active. Ignoring.",
                self.height, timed_out_round_id
            );
            return Ok(());
        }

        if self.finalized_block.is_some() {
            log::debug!(
                "BHM height {}: Block already finalized. Ignoring RoundTimeout for {:?}.",
                self.height, timed_out_round_id
            );
            return Ok(());
        }

        let new_target_round_number = timed_out_round_id.round_number + 1;
        let new_target_round_id = ConsensusRoundIdentifier::new(self.height, new_target_round_number);

        log::info!(
            "BHM height {}: Round {:?} timed out. Initiating RoundChange to target round {:?}.",
            self.height, timed_out_round_id, new_target_round_id
        );

        // Get PreparedRoundMetadata from the current timed-out round.
        let prepared_metadata: Option<PreparedRoundMetadata> = self.current_round.as_ref()
            .and_then(|r| r.get_prepared_round_metadata_for_round_change());

        // Attempt to get the corresponding prepared block if metadata exists.
        let prepared_block_for_rc: Option<QbftBlock> = if let Some(meta) = &prepared_metadata {
            self.locked_block.as_ref().and_then(|locked| {
                if locked.block.hash() == meta.prepared_block_hash && locked.prepared_round == meta.prepared_round {
                    Some(locked.block.clone())
                } else {
                    None
                }
            })
        } else {
            None
        };

        if prepared_metadata.is_some() && prepared_block_for_rc.is_none() {
            log::warn!(
                "BHM height {}: Prepared metadata found for round change, but corresponding locked block (hash: {:?}, round: {:?}) not available or inconsistent. Sending RoundChange without block.",
                self.height, 
                prepared_metadata.as_ref().unwrap().prepared_block_hash,
                prepared_metadata.as_ref().unwrap().prepared_round
            );
        }

        let round_change_message = self.message_factory.create_round_change(
            new_target_round_id,
            prepared_metadata, 
            prepared_block_for_rc, 
        )?;

        log::debug!(
            "BHM height {}: Sending our own RoundChange message for target round {:?}.",
            self.height, new_target_round_id
        );
        self.validator_multicaster.multicast_round_change(&round_change_message);

        // Add our own RoundChange message to the manager.
        // Context for validating our own message (somewhat simplified as we trust ourselves).
        let validation_context = ValidationContext::new(
            self.height, 
            timed_out_round_id.round_number, // The round we are changing FROM
            self.final_state.validators().into_iter().collect(),
            Some(self.parent_header.clone()),
            self.final_state.clone(),
            self.extra_data_codec.clone(),
            self.config.clone(),
            None, // accepted_proposal_digest for context (validator handles specifics for piggybacked cert)
            self.final_state.get_proposer_for_round(&new_target_round_id)? // proposer of the target round
        );

        // This will internally use the RoundChangeMessageValidator.
        match self.round_change_manager.add_round_change_message(round_change_message, &validation_context) {
            Ok(true) => {
                log::debug!(
                    "BHM height {}: Added own RoundChange to manager for target {:?}. Checking for quorum.",
                    self.height, new_target_round_id
                );
                // After adding our own, check if we now have a quorum to advance.
                if self.round_change_manager.has_sufficient_round_changes(&new_target_round_id) {
                    log::info!(
                        "BHM height {}: Quorum for RoundChange to {:?} met after sending our own. Advancing round.",
                        self.height, new_target_round_id
                    );
                    let artifacts = self.round_change_manager.get_round_change_artifacts(&new_target_round_id);
                    return self.advance_to_new_round(new_target_round_id.round_number, Some(artifacts));
                } else {
                    log::trace!(
                        "BHM height {}: Not enough RoundChange messages yet for target {:?} after sending our own. Have {}/{}", 
                        self.height, 
                        new_target_round_id, 
                        self.round_change_manager.get_round_change_messages_for_target_round(&new_target_round_id).map_or(0, |v| v.len()),
                        self.round_change_manager.quorum_size()
                    );
                }
            }
            Ok(false) => {
                // This case (duplicate of our own message) should ideally not happen if logic is correct.
                log::warn!(
                    "BHM height {}: Own RoundChange message for target {:?} was considered a duplicate. This is unexpected.",
                    self.height, new_target_round_id
                );
            }
            Err(e) => {
                // Should not happen if we construct our own message correctly.
                log::error!(
                    "BHM height {}: Failed to add own RoundChange message for target {:?} to manager: {:?}. This is critical.",
                    self.height, new_target_round_id, e
                );
                return Err(e); // Propagate error
            }
        }

        Ok(())
    }

    /// Handles the expiration of the block timer for the current height.
    /// If this node is the proposer for the current round and hasn't proposed yet,
    /// it should trigger block creation and proposal.
    pub fn handle_block_timer_expiry(&mut self) -> Result<(), QbftError> {
        log::debug!(
            "BHM height {}: Handling BlockTimer expiry.",
            self.height
        );

        if self.finalized_block.is_some() {
            log::trace!("BHM height {}: Block already finalized. Ignoring block timer expiry.", self.height);
            return Ok(());
        }

        if let Some(current_round_mut) = self.current_round.as_mut() {
            let round_id = *current_round_mut.round_identifier();
            // Check if this node is the proposer for the current round
            if self.final_state.is_local_node_proposer_for_round(&round_id) {
                // Check if a proposal has already been made or accepted in this round.
                // QbftRound.proposal_sent is one way, or check round_state.proposal().
                // For simplicity, let's assume QbftRound's propose methods handle not re-proposing if already done.
                if current_round_mut.round_state().proposal_message().is_none() { // Or a more specific flag like `current_round_mut.has_proposed()`
                    log::info!(
                        "BHM height {}: BlockTimer expired. Node is proposer for round {:?} and has not yet proposed. Triggering proposal.",
                        self.height, round_id
                    );
                    let block_creation_timestamp = self.block_timer.get_timestamp_for_future_block(
                        &round_id, 
                        self.parent_header.timestamp
                    );
                    // Here, we assume no prior RoundChangeArtifacts because this is a proactive proposal due to block timer expiry,
                    // not a round change response.
                    current_round_mut.create_and_propose_block(block_creation_timestamp)?;
                } else {
                    log::trace!(
                        "BHM height {}: BlockTimer expired for round {:?}, but proposal already exists or sent. No action.",
                        self.height, round_id
                    );
                }
            } else {
                log::trace!(
                    "BHM height {}: BlockTimer expired for round {:?}, but node is not the proposer. No action.",
                    self.height, round_id
                );
            }
        } else {
            log::warn!(
                "BHM height {}: BlockTimer expired, but no current round is active. Cannot determine proposer action.",
                self.height
            );
        }
        Ok(())
    }

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

#[cfg(test)]
mod tests {
    use super::*;    
    use crate::mocks::{
        mock_final_state::MockQbftFinalState,
        mock_block_creator::MockQbftBlockCreator,
        mock_services::{MockQbftBlockImporter, MockValidatorMulticaster},
        MockBlockTimer, MockRoundTimer,
    };
    use crate::types::{NodeKey, BftExtraData, AlloyBftExtraDataCodec, QbftConfig, BftExtraDataCodec, ConsensusRoundIdentifier, QbftBlock, QbftBlockHeader};
    use crate::payload::MessageFactory;
    use alloy_primitives::{Address, B256, Bytes, U256};
    use alloy_rlp::{Error as RlpError, Encodable, Decodable};
    use std::sync::Arc;
    use std::collections::HashSet;
    use k256::ecdsa::{VerifyingKey};
    use crate::validation::{ProposalValidator, PrepareValidator, CommitValidator, ValidationContext, MessageValidatorFactory};
    use crate::error::QbftError;
    use crate::messagewrappers::Proposal;
    // Ensure Mutex is imported for tests, if not already present due to other edits.
    // If an outer `use std::sync::Mutex` exists, this might be redundant but harmless.
    use std::sync::Mutex;

    // --- Copied Test Helper Functions and Mocks from qbft_round.rs ---

    // --- Mock Validators with Failure Configuration (Copied) ---
    #[derive(Clone)]
    struct ConfigurableMockProposalValidator { fail_on_validate: bool, error_to_return: Option<QbftError> }
    impl ProposalValidator for ConfigurableMockProposalValidator {
        fn validate_proposal(&self, proposal: &Proposal, context: &ValidationContext) -> Result<(), QbftError> {
            if self.fail_on_validate {
                Err(self.error_to_return.clone().unwrap_or_else(|| 
                    QbftError::ProposalInvalidAuthor { 
                        expected: context.expected_proposer, 
                        actual: proposal.author().unwrap_or_default(),
                    }
                ))
            } else { Ok(()) }
        }
        fn validate_block_header_for_proposal(&self, _header: &QbftBlockHeader, _context: &ValidationContext) -> Result<(), QbftError> {
            // Adjusted to use a more specific error for header validation if desired, or keep generic
            if self.fail_on_validate {
                 Err(self.error_to_return.clone().unwrap_or_else(|| QbftError::ValidationError("MockProposalValidator header failed as configured".to_string())))
            } else { Ok(()) }
        }
    }

    #[derive(Clone, Default)]
    struct ConfigurableMockPrepareValidator { 
        fail_for_author: Option<Address> 
    }
    impl PrepareValidator for ConfigurableMockPrepareValidator {
        fn validate_prepare(&self, prepare: &crate::messagewrappers::Prepare, _context: &ValidationContext) -> Result<(), QbftError> {
            if let Some(fail_addr) = self.fail_for_author {
                if prepare.author().map_or(false, |auth| auth == fail_addr) {
                    return Err(QbftError::ValidationError(format!("MockPrepareValidator failed as configured for author {:?}", fail_addr)));
                }
            }
            Ok(())
        }
    }

    #[derive(Clone)]
    struct ConfigurableMockCommitValidator { fail_on_validate: bool }
    impl CommitValidator for ConfigurableMockCommitValidator {
        fn validate_commit(&self, _commit: &crate::messagewrappers::Commit, _context: &ValidationContext) -> Result<(), QbftError> {
            if self.fail_on_validate { Err(QbftError::ValidationError("MockCommitValidator failed as configured".to_string())) } else { Ok(()) }
        }
    }
    
    #[derive(Clone, Default)]
    struct ConfigurableMockMessageValidatorFactory {
        proposal_should_fail: bool,
        proposal_error: Option<QbftError>,
        prepare_fail_for_author: Option<Address>,
        commit_should_fail: bool,
    }

    impl ConfigurableMockMessageValidatorFactory {
        fn new() -> Self { Default::default() } 

        fn set_proposal_failure(mut self, fail: bool, error: Option<QbftError>) -> Self {
            self.proposal_should_fail = fail;
            self.proposal_error = error;
            self
        }

        #[allow(dead_code)] // To be used in future tests if needed
        fn set_prepare_failure_for_author(mut self, author: Option<Address>) -> Self {
            self.prepare_fail_for_author = author;
            self
        }
        
        #[allow(dead_code)] // To be used in future tests if needed
        fn set_commit_failure(mut self, fail: bool) -> Self {
            self.commit_should_fail = fail;
            self
        }
    }

    impl MessageValidatorFactory for ConfigurableMockMessageValidatorFactory {
        fn create_proposal_validator(self: Arc<Self>) -> Arc<dyn ProposalValidator + Send + Sync> {
            Arc::new(ConfigurableMockProposalValidator { 
                fail_on_validate: self.proposal_should_fail, 
                error_to_return: self.proposal_error.clone()
            })
        }
        fn create_prepare_validator(self: Arc<Self>) -> Arc<dyn PrepareValidator + Send + Sync> {
            Arc::new(ConfigurableMockPrepareValidator { fail_for_author: self.prepare_fail_for_author })
        }
        fn create_commit_validator(self: Arc<Self>) -> Arc<dyn CommitValidator + Send + Sync> {
            Arc::new(ConfigurableMockCommitValidator { fail_on_validate: self.commit_should_fail })
        }
    }

    fn deterministic_node_key(seed: u8) -> Arc<NodeKey> {
        if seed == 0 { 
            panic!("Seed for deterministic_node_key cannot be 0 to avoid zero key");
        }
        let mut bytes = [0u8; 32];
        for i in 0..32 {
            bytes[i] = seed.wrapping_add(i as u8); 
        }
        
        let secret_key = k256::SecretKey::from_slice(&bytes)
            .unwrap_or_else(|_| panic!("Failed to create secret_key from slice with seed: {}", seed));
        Arc::new(NodeKey::from(secret_key))
    }

    fn address_from_arc_key(key: &Arc<NodeKey>) -> Address {
        let verifying_key: &VerifyingKey = key.verifying_key();
        let uncompressed_pk_bytes = verifying_key.to_encoded_point(false).as_bytes().to_vec();
        let hash = alloy_primitives::keccak256(&uncompressed_pk_bytes[1..]);
        Address::from_slice(&hash[12..])
    }
    
    #[derive(Debug, Clone)]
    struct TestExtraDataCodec;
    impl BftExtraDataCodec for TestExtraDataCodec {
        fn decode(&self, data: &Bytes) -> Result<BftExtraData, RlpError> {
            BftExtraData::decode(&mut data.as_ref())
        }
        fn encode(&self, extra_data: &BftExtraData) -> Result<Bytes, RlpError> {
            let mut out_vec = Vec::new();
            extra_data.encode(&mut out_vec);
            Ok(Bytes::from(out_vec))
        }
    }
    fn testing_extradata_codec_local() -> Arc<dyn BftExtraDataCodec> { 
        Arc::new(TestExtraDataCodec)
    }

    fn default_test_qbft_config() -> Arc<QbftConfig> {
        Arc::new(QbftConfig::default())
    }

    fn simple_parent_header(number: u64, hash: B256) -> QbftBlockHeader {
        let header = QbftBlockHeader::new( 
            hash, 
            B256::ZERO, 
            Address::ZERO, 
            B256::ZERO, 
            B256::ZERO, 
            B256::ZERO, 
            Default::default(), 
            U256::from(1), 
            number, 
            1_000_000, 
            0, 
            number * 10, // timestamp
            Bytes::new(), 
            B256::ZERO, 
            Bytes::from_static(&[0u8; 8]), 
            None, 
        );
        let _ = header.hash(); // Precompute hash
        header
    }

    // MockObserver (Copied) - Make sure QbftMinedBlockObserver is in scope
    // Updated MockObserver to store hashes and provide counting/retrieval methods.
    #[derive(Default, Clone)]
    struct MockObserver {
        observed_block_hashes: Arc<Mutex<Vec<B256>>>,
    }

    impl MockObserver {
        // new() is not strictly needed if Default is derived and used.
        // pub fn new() -> Self {
        //     Default::default()
        // }

        fn blocks_imported(&self) -> usize {
            self.observed_block_hashes.lock().unwrap().len()
        }

        fn get_observed_block_hashes(&self) -> Vec<B256> {
            self.observed_block_hashes.lock().unwrap().clone()
        }

        #[allow(dead_code)] // May be useful for other tests
        fn clear_observed_blocks(&self) {
            self.observed_block_hashes.lock().unwrap().clear();
        }
    }

    impl QbftMinedBlockObserver for MockObserver {
        fn block_imported(&self, block: &QbftBlock) {
            self.observed_block_hashes.lock().unwrap().push(block.hash());
        }
    }
    // --- End of Copied Test Helpers ---


    use crate::validation::RoundChangeMessageValidatorFactory; // For the trait

    struct MockRoundChangeMessageValidatorFactory;
    impl RoundChangeMessageValidatorFactory for MockRoundChangeMessageValidatorFactory {
        fn create_round_change_message_validator(
            &self,
        ) -> Arc<dyn crate::validation::RoundChangeMessageValidator + Send + Sync> {
            // For this mock, the actual validator created isn't important unless a test
            // specifically needs to validate a RoundChange message through the BHM.
            // If such a test is added, this mock will need to return a more functional
            // mock RoundChangeMessageValidator.
            panic!("MockRoundChangeMessageValidatorFactory::create_round_change_message_validator called. If RoundChange validation is needed, provide a functional mock.");
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn setup_bhm(
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
        actual_msg_val_factory: Arc<dyn MessageValidatorFactory>,
        _round_change_message_validator_factory: Arc<dyn RoundChangeMessageValidatorFactory>,
        mined_block_observers: Vec<Arc<dyn QbftMinedBlockObserver>>,
    ) -> QbftBlockHeightManager {
        QbftBlockHeightManager::new(
            parent_header,
            final_state as Arc<dyn QbftFinalState>,
            block_creator as Arc<dyn QbftBlockCreator>,
            block_importer as Arc<dyn QbftBlockImporter>,
            message_factory,
            validator_multicaster as Arc<dyn ValidatorMulticaster>,
            block_timer as Arc<dyn BlockTimer>,
            round_timer as Arc<dyn RoundTimer>,
            extra_data_codec,
            config,
            proposal_validator,
            prepare_validator,
            commit_validator,
            actual_msg_val_factory as Arc<dyn MessageValidatorFactory>,
            _round_change_message_validator_factory as Arc<dyn RoundChangeMessageValidatorFactory>,
            mined_block_observers,
        )
    }

    #[test]
    fn test_bhm_initialization_and_start_consensus() {
        let local_node_key_arc: Arc<NodeKey> = deterministic_node_key(1);
        let local_address = address_from_arc_key(&local_node_key_arc);
        let validators: HashSet<Address> = vec![local_address].into_iter().collect();

        let parent_block_num = 0u64;
        let parent_h = simple_parent_header(parent_block_num, B256::random());
        let arc_parent_h = Arc::new(parent_h.clone());

        let mock_final_state = Arc::new(MockQbftFinalState::new(local_node_key_arc.clone(), validators.clone()));
        let message_factory = Arc::new(MessageFactory::new(local_node_key_arc.clone()).unwrap());
        
        let mock_block_creator_final_state = Arc::new(MockQbftFinalState::new(local_node_key_arc.clone(), validators.clone()));
        let mock_block_creator = Arc::new(MockQbftBlockCreator::new(arc_parent_h.clone(), mock_block_creator_final_state, Arc::new(AlloyBftExtraDataCodec::default())));
        
        let mock_block_importer = Arc::new(MockQbftBlockImporter::default());
        let mock_multicaster = Arc::new(MockValidatorMulticaster::default());
        
        let test_codec = testing_extradata_codec_local(); 
        let config = default_test_qbft_config();

        // Instantiate MockBlockTimer with the block period from the config
        let mock_block_timer_instance = MockBlockTimer::new(config.block_period_seconds);
        let mock_round_timer_instance = MockRoundTimer::new(); // MockRoundTimer::new takes no args

        let arc_mock_block_timer = Arc::new(mock_block_timer_instance);
        let arc_mock_round_timer = Arc::new(mock_round_timer_instance);

        let expected_round_0_id = ConsensusRoundIdentifier::new(parent_block_num + 1, 0);
        // No direct expectation setting on MockBlockTimer, its behavior is fixed by its init params.

        let configurable_msg_validator_factory = Arc::new(
            ConfigurableMockMessageValidatorFactory::new().set_proposal_failure(false, None)
        );
        let mock_rc_validator_factory = Arc::new(MockRoundChangeMessageValidatorFactory);

        let proposal_validator = configurable_msg_validator_factory.clone().create_proposal_validator();
        let prepare_validator = configurable_msg_validator_factory.clone().create_prepare_validator();
        let commit_validator = configurable_msg_validator_factory.clone().create_commit_validator();

        let mut bhm = setup_bhm(
            arc_parent_h.clone(),
            mock_final_state.clone(),
            mock_block_creator.clone(),
            mock_block_importer.clone(),
            message_factory.clone(),
            mock_multicaster.clone(),
            arc_mock_block_timer, 
            arc_mock_round_timer.clone(), 
            test_codec.clone(),
            config.clone(),
            proposal_validator,
            prepare_validator,
            commit_validator,
            configurable_msg_validator_factory.clone(),
            mock_rc_validator_factory.clone(),
            vec![Arc::new(MockObserver::default())],
        );

        assert_eq!(bhm.height(), parent_block_num + 1, "BHM height mismatch");
        assert!(bhm.current_round.is_none(), "Current round should be None initially");

        let result = bhm.start_consensus();
        assert!(result.is_ok(), "start_consensus failed: {:?}", result.err());

        assert!(bhm.current_round.is_some(), "Current round should be Some after start_consensus");
        let current_round = bhm.current_round.as_ref().unwrap();
        assert_eq!(*current_round.round_identifier(), expected_round_0_id, "Round identifier mismatch");
        
        // Check if round timer was started for round 0 using the public getter
        let active_timers = arc_mock_round_timer.get_active_timers();
        assert_eq!(active_timers.len(), 1, "Expected exactly one active round timer");
        assert!(active_timers.contains(&expected_round_0_id), "Round timer for round 0 was not found in active timers");
        // Note: We can't assert the duration with the current mock, only its presence.

        // Since local_node is the only validator, it should be the proposer for round 0.
        assert!(!mock_multicaster.proposals.lock().unwrap().is_empty(), "Proposal should have been multicast");
        assert!(!mock_multicaster.prepares.lock().unwrap().is_empty(), "Prepare should have been multicast");
    }

    #[test]
    fn test_bhm_handle_proposal_current_round_not_proposer() {
        // Setup: 3 Validators. We need to determine who will be proposer for (seq=1, round=0).
        // Proposer index = (sequence_number + round_number) % num_validators = (1 + 0) % 3 = 1.
        // The address at index 1 of the sorted list of validator addresses will be the proposer.

        let key_node_a = deterministic_node_key(1);
        let addr_node_a = address_from_arc_key(&key_node_a);
        let key_node_b = deterministic_node_key(2);
        let addr_node_b = address_from_arc_key(&key_node_b);
        let key_node_c = deterministic_node_key(3);
        let addr_node_c = address_from_arc_key(&key_node_c);

        let mut all_addresses = vec![addr_node_a, addr_node_b, addr_node_c];
        all_addresses.sort(); // Sort to determine proposer order

        let sorted_addr_idx0 = all_addresses[0];
        let sorted_addr_idx1_proposer = all_addresses[1]; // This will be the proposer for round (1,0)
        let sorted_addr_idx2 = all_addresses[2];

        let key_v1_local: Arc<NodeKey>;
        let addr_v1_local: Address;
        let key_v2_proposer: Arc<NodeKey>;
        let addr_v2_proposer: Address; 
        let _key_v3_other: Arc<NodeKey>; // Prefixed with underscore
        let addr_v3_other: Address;

        // Arbitrarily choose local node to be the one corresponding to addr_node_a's original key
        key_v1_local = key_node_a.clone();
        addr_v1_local = addr_node_a;

        // Assign key_v2_proposer and addr_v2_proposer to match sorted_addr_idx1_proposer
        if sorted_addr_idx1_proposer == addr_node_a {
            key_v2_proposer = key_node_a.clone(); 
        } else if sorted_addr_idx1_proposer == addr_node_b {
            key_v2_proposer = key_node_b.clone(); 
        } else { // sorted_addr_idx1_proposer == addr_node_c
            key_v2_proposer = key_node_c.clone(); 
        }
        addr_v2_proposer = sorted_addr_idx1_proposer; // This is the actual address for the proposer key

        // Assign _key_v3_other and addr_v3_other to be the remaining address and its original key
        if addr_v1_local != sorted_addr_idx0 && addr_v2_proposer != sorted_addr_idx0 {
            addr_v3_other = sorted_addr_idx0;
            if addr_node_a == sorted_addr_idx0 { _key_v3_other = key_node_a.clone(); }
            else if addr_node_b == sorted_addr_idx0 { _key_v3_other = key_node_b.clone(); }
            else { _key_v3_other = key_node_c.clone(); } 
        } else if addr_v1_local != sorted_addr_idx2 && addr_v2_proposer != sorted_addr_idx2 {
            addr_v3_other = sorted_addr_idx2;
            if addr_node_a == sorted_addr_idx2 { _key_v3_other = key_node_a.clone(); }
            else if addr_node_b == sorted_addr_idx2 { _key_v3_other = key_node_b.clone(); }
            else { _key_v3_other = key_node_c.clone(); }
        } else { 
            if addr_node_a != addr_v1_local && addr_node_a != addr_v2_proposer {
                addr_v3_other = addr_node_a; _key_v3_other = key_node_a.clone();
            } else if addr_node_b != addr_v1_local && addr_node_b != addr_v2_proposer {
                addr_v3_other = addr_node_b; _key_v3_other = key_node_b.clone();
            } else {
                addr_v3_other = addr_node_c; _key_v3_other = key_node_c.clone();
            }
        }

        let validators_vec = vec![addr_v1_local, addr_v2_proposer, addr_v3_other];
        let validator_set_check: HashSet<Address> = validators_vec.iter().cloned().collect();
        assert_eq!(validator_set_check.len(), 3, "Final validator set should have 3 unique addresses. Got: {:?}", validators_vec);
        
        let validators: HashSet<Address> = validator_set_check;

        let parent_block_num = 0u64;
        let sequence_number = parent_block_num + 1;
        let round_number = 0u32;
        let current_round_id = ConsensusRoundIdentifier::new(sequence_number, round_number);

        let parent_h = simple_parent_header(parent_block_num, B256::random());
        let arc_parent_h = Arc::new(parent_h.clone());
        let config = default_test_qbft_config();
        let test_codec = testing_extradata_codec_local();

        let mock_final_state_v1 = Arc::new(MockQbftFinalState::new(
            key_v1_local.clone(),
            validators.clone(),
        ));
        
        let determined_proposer_for_round0 = mock_final_state_v1.get_proposer_for_round(&current_round_id).unwrap();
        assert_eq!(
            determined_proposer_for_round0,
            addr_v2_proposer, // This is sorted_addr_idx1_proposer
            "V2 (sorted_addr_idx1) was not determined as the proposer for round (1,0). Sorted validator list used by mock: {:?}",
            mock_final_state_v1.current_validators()
        );
        assert_ne!(
            addr_v1_local, determined_proposer_for_round0,
            "Local node V1 should not be the proposer for this test (unless it happened to be sorted_addr_idx1)"
        );
        // If local IS the proposer, this specific test setup is invalid for its intent.
        if addr_v1_local == determined_proposer_for_round0 {
            panic!("Test setup error: Local node V1 (addr: {:?}) was selected as proposer ({:?}), but test requires local node NOT to be proposer.", addr_v1_local, determined_proposer_for_round0);
        }

        // Message Factories
        let local_mf_v1 = Arc::new(MessageFactory::new(key_v1_local.clone()).unwrap());
        let proposer_mf_v2 = Arc::new(MessageFactory::new(key_v2_proposer.clone()).unwrap());

        // Block Creator needs a final state; using the actual proposer's key for its internal mock state.
        let block_creator_final_state = Arc::new(MockQbftFinalState::new(key_v2_proposer.clone(), validators.clone()));
        let mock_block_creator = Arc::new(MockQbftBlockCreator::new(
            arc_parent_h.clone(),
            block_creator_final_state,
            Arc::new(AlloyBftExtraDataCodec::default()),
        ));

        let mock_block_importer = Arc::new(MockQbftBlockImporter::default());
        let mock_multicaster_v1 = Arc::new(MockValidatorMulticaster::default());
        let mock_block_timer_v1 = Arc::new(MockBlockTimer::new(config.block_period_seconds));
        let mock_round_timer_v1 = Arc::new(MockRoundTimer::new());

        let configurable_msg_validator_factory = Arc::new(
            ConfigurableMockMessageValidatorFactory::new().set_proposal_failure(false, None),
        );
        let mock_rc_validator_factory = Arc::new(MockRoundChangeMessageValidatorFactory);

        let proposal_validator = configurable_msg_validator_factory.clone().create_proposal_validator();
        let prepare_validator = configurable_msg_validator_factory.clone().create_prepare_validator();
        let commit_validator = configurable_msg_validator_factory.clone().create_commit_validator();

        let mut bhm_v1 = setup_bhm(
            arc_parent_h.clone(),
            mock_final_state_v1.clone(), 
            mock_block_creator.clone(),  
            mock_block_importer.clone(),
            local_mf_v1.clone(),         
            mock_multicaster_v1.clone(),
            mock_block_timer_v1.clone(),
            mock_round_timer_v1.clone(),
            test_codec.clone(),
            config.clone(),
            proposal_validator,
            prepare_validator,
            commit_validator,
            configurable_msg_validator_factory.clone(),
            mock_rc_validator_factory.clone(),
            vec![Arc::new(MockObserver::default())],
        );

        bhm_v1.start_consensus().expect("BHM start_consensus failed for V1");
        assert!(bhm_v1.current_round.is_some(), "BHM should have a current round after start_consensus");
        assert_eq!(*bhm_v1.current_round.as_ref().unwrap().round_identifier(), current_round_id, "BHM current round ID mismatch");
        assert!(
            bhm_v1.current_round.as_ref().unwrap().round_state().proposal_message().is_none(),
            "V1's round should not have a proposal yet"
        );
        assert_eq!(mock_multicaster_v1.proposals.lock().unwrap().len(), 0, "V1 should not have sent any proposal");

        let proposed_block_by_v2 = mock_block_creator.create_block(
            &parent_h,
            &current_round_id,
            parent_h.timestamp + config.block_period_seconds,
        ).unwrap();
        let proposal_digest_v2 = proposed_block_by_v2.hash();
        let proposal_from_v2 = proposer_mf_v2.create_proposal(
            current_round_id,
            proposed_block_by_v2.clone(),
            vec![], 
            None,   
        ).unwrap();

        let handle_result = bhm_v1.handle_proposal_message(proposal_from_v2.clone());

        assert!(handle_result.is_ok(), "BHM handle_proposal_message failed: {:?}", handle_result.err());

        let current_round_in_bhm = bhm_v1.current_round.as_ref().expect("BHM current_round is None after handling proposal");
        
        assert!(current_round_in_bhm.round_state().proposal_message().is_some(), "Proposal not set in V1's current round state");
        assert_eq!(
            current_round_in_bhm.round_state().proposal_message().unwrap().block().hash(),
            proposal_digest_v2,
            "Digest of proposal in V1's round state mismatch"
        );

        let prepares_sent_by_v1 = mock_multicaster_v1.prepares.lock().unwrap();
        assert_eq!(prepares_sent_by_v1.len(), 1, "V1 should have sent exactly one Prepare message");
        let prepare_msg_v1 = prepares_sent_by_v1.get(0).unwrap();
        assert_eq!(prepare_msg_v1.author().unwrap(), addr_v1_local, "Prepare sender mismatch, expected V1");
        assert_eq!(prepare_msg_v1.payload().digest, proposal_digest_v2, "Prepare digest mismatch");
        assert_eq!(*prepare_msg_v1.round_identifier(), current_round_id, "Prepare round ID mismatch");

        assert!(current_round_in_bhm.round_state().is_prepared(), "V1's round state should be PREPARED after its own Prepare");
    }

    #[test]
    fn test_bhm_handle_proposal_future_round_buffered() {
        // Setup: 3 Validators: V1 (local, proposer for round 0), V2, V3 (proposer for round 1)
        let key_v1_local = deterministic_node_key(1);
        let addr_v1_local = address_from_arc_key(&key_v1_local);
        let key_v2 = deterministic_node_key(2);
        let addr_v2 = address_from_arc_key(&key_v2);
        let key_v3_proposer_r1 = deterministic_node_key(3);
        let addr_v3_proposer_r1 = address_from_arc_key(&key_v3_proposer_r1);

        let mut all_addresses_for_sort = vec![addr_v1_local, addr_v2, addr_v3_proposer_r1];
        all_addresses_for_sort.sort();

        let validators: HashSet<Address> = all_addresses_for_sort.iter().cloned().collect();
        assert_eq!(validators.len(), 3, "Should be 3 unique validators");

        let parent_block_num = 0u64;
        let sequence_number = parent_block_num + 1;
        
        let current_round_num = 0u32;
        let current_round_id = ConsensusRoundIdentifier::new(sequence_number, current_round_num);
        let future_round_num = 1u32;
        let future_round_id = ConsensusRoundIdentifier::new(sequence_number, future_round_num);

        let parent_h = simple_parent_header(parent_block_num, B256::random());
        let arc_parent_h = Arc::new(parent_h.clone());
        let config = default_test_qbft_config();
        let test_codec = testing_extradata_codec_local();

        // FinalState for V1's BHM. V1 (addr_v1_local) should be proposer for round 0.
        // (1+0)%3 = 1. So addr_v1_local needs to be at index 1 if it is key_node_b (seed 2).
        // Let's ensure V1 (local) is the proposer for round 0 for this test's premise.
        // If addr_v1_local is all_addresses_for_sort[1], it's proposer for R0.
        // If not, we would need to pick key_v1_local to be the one whose address IS all_addresses_for_sort[1].
        // For simplicity, let's re-assign key_v1_local if needed to ensure it is proposer for R0.
        
        let actual_proposer_r0: Address = all_addresses_for_sort[ (current_round_id.sequence_number as usize + current_round_id.round_number as usize) % 3 ];
        let final_key_v1_local: Arc<NodeKey>;
        let final_addr_v1_local: Address;

        if actual_proposer_r0 == addr_v1_local { final_key_v1_local = key_v1_local.clone(); final_addr_v1_local = addr_v1_local; }
        else if actual_proposer_r0 == addr_v2 { final_key_v1_local = key_v2.clone(); final_addr_v1_local = addr_v2;}
        else { final_key_v1_local = key_v3_proposer_r1.clone(); final_addr_v1_local = addr_v3_proposer_r1; }
        
        assert_eq!(final_addr_v1_local, actual_proposer_r0, "V1 (local) setup as proposer for R0 failed.");

        // Ensure V3 is proposer for Round 1: (1+1)%3 = 2. So addr_v3_proposer_r1 needs to be at index 2.
        // This should be handled by the mock if keys are distinct and sorted correctly.
        let actual_proposer_r1: Address = all_addresses_for_sort[ (future_round_id.sequence_number as usize + future_round_id.round_number as usize) % 3 ];
        let key_for_v3_proposer_r1: Arc<NodeKey>; // This is the key for the one who sends future proposal.
        if actual_proposer_r1 == addr_v1_local { key_for_v3_proposer_r1 = key_v1_local.clone();}
        else if actual_proposer_r1 == addr_v2 { key_for_v3_proposer_r1 = key_v2.clone();}
        else { key_for_v3_proposer_r1 = key_v3_proposer_r1.clone();}
        assert_eq!(actual_proposer_r1, address_from_arc_key(&key_for_v3_proposer_r1), "V3 proposer for R1 setup failed");

        let mock_final_state_v1 = Arc::new(MockQbftFinalState::new(
            final_key_v1_local.clone(),
            validators.clone(),
        ));
        assert_eq!(mock_final_state_v1.get_proposer_for_round(&current_round_id).unwrap(), final_addr_v1_local, "Mock did not identify V1 as R0 proposer");
        assert_eq!(mock_final_state_v1.get_proposer_for_round(&future_round_id).unwrap(), actual_proposer_r1, "Mock did not identify correct R1 proposer");

        let local_mf_v1 = Arc::new(MessageFactory::new(final_key_v1_local.clone()).unwrap());
        let proposer_mf_v3_r1 = Arc::new(MessageFactory::new(key_for_v3_proposer_r1.clone()).unwrap());

        let block_creator_final_state_v1 = Arc::new(MockQbftFinalState::new(final_key_v1_local.clone(), validators.clone()));
        let mock_block_creator_v1 = Arc::new(MockQbftBlockCreator::new( arc_parent_h.clone(), block_creator_final_state_v1, Arc::new(AlloyBftExtraDataCodec::default()) ));
        
        // Block creator for V3's proposal for R1
        let block_creator_final_state_v3 = Arc::new(MockQbftFinalState::new(key_for_v3_proposer_r1.clone(), validators.clone()));
        let mock_block_creator_v3 = Arc::new(MockQbftBlockCreator::new( arc_parent_h.clone(), block_creator_final_state_v3, Arc::new(AlloyBftExtraDataCodec::default()) ));

        let mock_block_importer = Arc::new(MockQbftBlockImporter::default());
        let mock_multicaster_v1 = Arc::new(MockValidatorMulticaster::default());
        let mock_block_timer_v1 = Arc::new(MockBlockTimer::new(config.block_period_seconds));
        let mock_round_timer_v1 = Arc::new(MockRoundTimer::new());

        let configurable_msg_validator_factory = Arc::new(
            ConfigurableMockMessageValidatorFactory::new().set_proposal_failure(false, None),
        );
        let mock_rc_validator_factory = Arc::new(MockRoundChangeMessageValidatorFactory);

        let proposal_validator = configurable_msg_validator_factory.clone().create_proposal_validator();
        let prepare_validator = configurable_msg_validator_factory.clone().create_prepare_validator();
        let commit_validator = configurable_msg_validator_factory.clone().create_commit_validator();

        let mut bhm_v1 = setup_bhm(
            arc_parent_h.clone(),
            mock_final_state_v1.clone(),
            mock_block_creator_v1.clone(), // V1 is proposer for R0, so its block creator
            mock_block_importer.clone(),
            local_mf_v1.clone(),
            mock_multicaster_v1.clone(),
            mock_block_timer_v1.clone(),
            mock_round_timer_v1.clone(),
            test_codec.clone(),
            config.clone(),
            proposal_validator,
            prepare_validator,
            commit_validator,
            configurable_msg_validator_factory.clone(),
            mock_rc_validator_factory.clone(),
            vec![Arc::new(MockObserver::default())],
        );

        // V1 (local) starts consensus, proposes for round 0, sends Prepare.
        bhm_v1.start_consensus().expect("BHM start_consensus failed for V1");
        assert_eq!(*bhm_v1.current_round.as_ref().unwrap().round_identifier(), current_round_id, "BHM current round ID mismatch");
        let proposal_from_v1_r0 = bhm_v1.current_round.as_ref().unwrap().round_state().proposal_message().unwrap().clone();
        let prepares_after_r0_start = mock_multicaster_v1.prepares.lock().unwrap().len();
        assert_eq!(prepares_after_r0_start, 1, "V1 should have sent 1 prepare for its R0 proposal");

        // Action: V3 (proposer for R1) creates and sends a Proposal for future_round_id (R1).
        let proposed_block_by_v3_r1 = mock_block_creator_v3.create_block(
            &parent_h,
            &future_round_id, // For R1
            parent_h.timestamp + config.block_period_seconds * 2, // Different timestamp
        ).unwrap();
        let proposal_from_v3_for_r1 = proposer_mf_v3_r1.create_proposal(
            future_round_id,
            proposed_block_by_v3_r1.clone(),
            vec![], 
            None,   
        ).unwrap();

        let handle_result = bhm_v1.handle_proposal_message(proposal_from_v3_for_r1.clone());

        // Assertions
        assert!(handle_result.is_ok(), "BHM handle_proposal_message for future round failed: {:?}", handle_result.err());

        // BHM current round should still be R0
        assert!(bhm_v1.current_round.is_some());
        assert_eq!(*bhm_v1.current_round.as_ref().unwrap().round_identifier(), current_round_id, "BHM current round ID mismatch");
        
        // Proposal in current round (R0) should be V1's original proposal
        assert_eq!(
            bhm_v1.current_round.as_ref().unwrap().round_state().proposal_message().unwrap().block().hash(),
            proposal_from_v1_r0.block().hash(),
            "Proposal in current round (R0) changed after future proposal"
        );

        // Check future_proposals buffer
        assert_eq!(bhm_v1.future_proposals.len(), 1, "future_proposals should have 1 entry for R1");
        assert!(bhm_v1.future_proposals.contains_key(&future_round_num), "future_proposals does not contain key for R1");
        let buffered_proposals_for_r1 = bhm_v1.future_proposals.get(&future_round_num).unwrap();
        assert_eq!(buffered_proposals_for_r1.len(), 1, "Should be 1 proposal buffered for R1");
        assert_eq!(
            buffered_proposals_for_r1[0].block().hash(),
            proposal_from_v3_for_r1.block().hash(),
            "Buffered proposal for R1 is not the one sent by V3"
        );

        // No new Prepare/Commit messages should have been sent by V1 due to future proposal
        assert_eq!(mock_multicaster_v1.prepares.lock().unwrap().len(), prepares_after_r0_start, "No new Prepare should be sent for future proposal");
        assert_eq!(mock_multicaster_v1.commits.lock().unwrap().len(), 0, "No Commit should be sent");
    }

    #[test]
    fn test_bhm_handle_proposal_past_round_ignored() {
        // Setup: 3 Validators: V1 (local), V2, V3.
        // BHM for V1 will be advanced to Round 1.
        // A proposal for Round 0 (past) will be sent from V3.

        let key_v1_local = deterministic_node_key(1);
        let addr_v1_local = address_from_arc_key(&key_v1_local);
        let key_v2 = deterministic_node_key(2);
        let addr_v2 = address_from_arc_key(&key_v2);
        let key_v3_proposer_r0 = deterministic_node_key(3);
        let addr_v3_proposer_r0 = address_from_arc_key(&key_v3_proposer_r0);

        let mut all_addresses_for_sort = vec![addr_v1_local, addr_v2, addr_v3_proposer_r0];
        all_addresses_for_sort.sort();
        let validators: HashSet<Address> = all_addresses_for_sort.iter().cloned().collect();

        let parent_block_num = 0u64;
        let sequence_number = parent_block_num + 1;
        let past_round_num = 0u32;
        let past_round_id = ConsensusRoundIdentifier::new(sequence_number, past_round_num);
        let current_round_num_for_bhm = 1u32;
        let bhm_current_round_id = ConsensusRoundIdentifier::new(sequence_number, current_round_num_for_bhm);

        let parent_h = simple_parent_header(parent_block_num, B256::random());
        let arc_parent_h = Arc::new(parent_h.clone());
        let config = default_test_qbft_config();
        let test_codec = testing_extradata_codec_local();

        // Determine actual proposer for past_round_id (Round 0)
        let actual_proposer_r0: Address = all_addresses_for_sort[ (past_round_id.sequence_number as usize + past_round_id.round_number as usize) % 3 ];
        let key_for_proposer_r0: Arc<NodeKey>;
        if actual_proposer_r0 == addr_v1_local { key_for_proposer_r0 = key_v1_local.clone(); }
        else if actual_proposer_r0 == addr_v2 { key_for_proposer_r0 = key_v2.clone(); }
        else { key_for_proposer_r0 = key_v3_proposer_r0.clone(); } // Must be one of them
        assert_eq!(address_from_arc_key(&key_for_proposer_r0), actual_proposer_r0, "Proposer for R0 key mismatch");
        
        let mock_final_state_v1 = Arc::new(MockQbftFinalState::new(key_v1_local.clone(), validators.clone()));
        let local_mf_v1 = Arc::new(MessageFactory::new(key_v1_local.clone()).unwrap());
        let proposer_mf_r0 = Arc::new(MessageFactory::new(key_for_proposer_r0.clone()).unwrap());

        // Block creator for R0 proposal (from V3 or whoever is actual_proposer_r0)
        let block_creator_final_state_r0 = Arc::new(MockQbftFinalState::new(key_for_proposer_r0.clone(), validators.clone()));
        let mock_block_creator_r0 = Arc::new(MockQbftBlockCreator::new(arc_parent_h.clone(), block_creator_final_state_r0, Arc::new(AlloyBftExtraDataCodec::default())));
        
        // Block creator for BHM's current round (R1), V1 may or may not be proposer - doesn't strictly matter for this test focus.
        let block_creator_final_state_v1 = Arc::new(MockQbftFinalState::new(key_v1_local.clone(), validators.clone()));
        let mock_block_creator_v1 = Arc::new(MockQbftBlockCreator::new(arc_parent_h.clone(), block_creator_final_state_v1, Arc::new(AlloyBftExtraDataCodec::default())));

        let mock_block_importer = Arc::new(MockQbftBlockImporter::default());
        let mock_multicaster_v1 = Arc::new(MockValidatorMulticaster::default());
        let mock_block_timer_v1 = Arc::new(MockBlockTimer::new(config.block_period_seconds));
        let mock_round_timer_v1 = Arc::new(MockRoundTimer::new());

        let configurable_msg_validator_factory = Arc::new(
            ConfigurableMockMessageValidatorFactory::new().set_proposal_failure(false, None),
        );
        let mock_rc_validator_factory = Arc::new(MockRoundChangeMessageValidatorFactory);

        let proposal_validator = configurable_msg_validator_factory.clone().create_proposal_validator();
        let prepare_validator = configurable_msg_validator_factory.clone().create_prepare_validator();
        let commit_validator = configurable_msg_validator_factory.clone().create_commit_validator();

        let mut bhm_v1 = setup_bhm(
            arc_parent_h.clone(),
            mock_final_state_v1.clone(),
            mock_block_creator_v1.clone(), // Use V1's block creator for BHM internal ops
            mock_block_importer.clone(),
            local_mf_v1.clone(),
            mock_multicaster_v1.clone(),
            mock_block_timer_v1.clone(),
            mock_round_timer_v1.clone(),
            test_codec.clone(),
            config.clone(),
            proposal_validator,
            prepare_validator,
            commit_validator,
            configurable_msg_validator_factory.clone(),
            mock_rc_validator_factory.clone(),
            vec![Arc::new(MockObserver::default())],
        );

        // Start BHM. It will attempt to start round 0.
        bhm_v1.start_consensus().expect("BHM start_consensus (for R0) failed");
        // Now, advance BHM to Round 1 to set the test's premise.
        bhm_v1.advance_to_new_round(current_round_num_for_bhm, None).expect("Failed to advance BHM to Round 1");
        assert!(bhm_v1.current_round.is_some(), "BHM should have a current round after advancing");
        assert_eq!(*bhm_v1.current_round.as_ref().unwrap().round_identifier(), bhm_current_round_id, "BHM not in expected Round 1");

        let proposal_in_bhm_round1_before = bhm_v1.current_round.as_ref().unwrap().round_state().proposal_message().cloned();
        let prepares_count_before = mock_multicaster_v1.prepares.lock().unwrap().len();
        let future_proposals_count_before = bhm_v1.future_proposals.len();

        // Action: Proposer for R0 sends a Proposal for past_round_id (R0).
        let proposed_block_for_r0 = mock_block_creator_r0.create_block(
            &parent_h,
            &past_round_id, // For R0
            parent_h.timestamp + config.block_period_seconds, 
        ).unwrap();
        let proposal_for_past_round = proposer_mf_r0.create_proposal(
            past_round_id,
            proposed_block_for_r0.clone(),
            vec![], 
            None,   
        ).unwrap();

        let handle_result = bhm_v1.handle_proposal_message(proposal_for_past_round.clone());

        // Assertions
        assert!(handle_result.is_ok(), "BHM handle_proposal_message for past round should not error: {:?}", handle_result.err());

        // BHM current round should still be R1
        assert!(bhm_v1.current_round.is_some());
        assert_eq!(*bhm_v1.current_round.as_ref().unwrap().round_identifier(), bhm_current_round_id, "BHM current round changed");
        
        // Proposal in current round (R1) should be unchanged.
        let proposal_in_bhm_round1_after = bhm_v1.current_round.as_ref().unwrap().round_state().proposal_message().cloned(); //TODO check hash
        assert_eq!(
            proposal_in_bhm_round1_after.map(|p| p.block().hash()),
            proposal_in_bhm_round1_before.map(|p| p.block().hash()),
            "Proposal in current round (R1) changed after past proposal"
        );

        // future_proposals buffer should be unchanged
        assert_eq!(bhm_v1.future_proposals.len(), future_proposals_count_before, "future_proposals count changed");

        // No new messages should have been sent
        assert_eq!(mock_multicaster_v1.prepares.lock().unwrap().len(), prepares_count_before, "New Prepare sent for past proposal");
        assert_eq!(mock_multicaster_v1.commits.lock().unwrap().len(), 0, "Commit sent for past proposal");
        assert_eq!(mock_multicaster_v1.proposals.lock().unwrap().len(), if mock_final_state_v1.is_local_node_proposer_for_round(&bhm_current_round_id) {1} else {0} + if mock_final_state_v1.is_local_node_proposer_for_round(&ConsensusRoundIdentifier::new(sequence_number,0)) {1} else {0} , "New Proposal sent by BHM");

    }

    #[test]
    fn test_bhm_handle_prepare_current_round_does_not_finalize() {
        // Setup: 4 Validators: V1 (local), V2 (proposer R0), V3 (sends prepare), V4
        // BHM for V1 receives proposal from V2, sends its own Prepare.
        // Then, BHM receives Prepare from V3. With N=4, Quorum=3. Two prepares are not enough.

        let key_v1_local = deterministic_node_key(1);
        let addr_v1_local = address_from_arc_key(&key_v1_local);
        let key_v2_proposer_r0 = deterministic_node_key(2);
        let addr_v2_proposer_r0 = address_from_arc_key(&key_v2_proposer_r0);
        let key_v3_preparer = deterministic_node_key(3);
        let addr_v3_preparer = address_from_arc_key(&key_v3_preparer);
        let key_v4 = deterministic_node_key(4);
        let addr_v4 = address_from_arc_key(&key_v4);

        let mut all_addresses_for_sort = vec![addr_v1_local, addr_v2_proposer_r0, addr_v3_preparer, addr_v4];
        all_addresses_for_sort.sort();
        let validators: HashSet<Address> = all_addresses_for_sort.iter().cloned().collect();
        assert_eq!(validators.len(), 4, "Should be 4 unique validators");

        let parent_block_num = 0u64;
        let sequence_number = parent_block_num + 1;
        let round_num = 0u32;
        let current_round_id = ConsensusRoundIdentifier::new(sequence_number, round_num);

        let parent_h = simple_parent_header(parent_block_num, B256::random());
        let arc_parent_h = Arc::new(parent_h.clone());
        let config = default_test_qbft_config();
        let test_codec = testing_extradata_codec_local();

        // Determine actual proposer for Round 0
        let actual_proposer_r0: Address = all_addresses_for_sort[ (current_round_id.sequence_number as usize + current_round_id.round_number as usize) % 4 ];
        let key_for_proposer_r0: Arc<NodeKey>;
        if actual_proposer_r0 == addr_v1_local { key_for_proposer_r0 = key_v1_local.clone(); }
        else if actual_proposer_r0 == addr_v2_proposer_r0 { key_for_proposer_r0 = key_v2_proposer_r0.clone(); }
        else if actual_proposer_r0 == addr_v3_preparer { key_for_proposer_r0 = key_v3_preparer.clone(); }
        else { key_for_proposer_r0 = key_v4.clone(); }
        assert_eq!(address_from_arc_key(&key_for_proposer_r0), actual_proposer_r0, "Proposer for R0 key mismatch");

        let mock_final_state_v1 = Arc::new(MockQbftFinalState::new(key_v1_local.clone(), validators.clone()));
        // With N=4, F=(4-1)/3 = 1. Quorum for BHM/RoundState = 2F+1 = 3.
        assert_eq!(mock_final_state_v1.quorum_size(), 3, "Quorum size for N=4 should be 3");

        let local_mf_v1 = Arc::new(MessageFactory::new(key_v1_local.clone()).unwrap());
        let proposer_mf_r0 = Arc::new(MessageFactory::new(key_for_proposer_r0.clone()).unwrap());
        let preparer_mf_v3 = Arc::new(MessageFactory::new(key_v3_preparer.clone()).unwrap());

        let block_creator_final_state_r0 = Arc::new(MockQbftFinalState::new(key_for_proposer_r0.clone(), validators.clone()));
        let mock_block_creator_r0 = Arc::new(MockQbftBlockCreator::new(arc_parent_h.clone(), block_creator_final_state_r0, Arc::new(AlloyBftExtraDataCodec::default())));

        let mock_block_importer = Arc::new(MockQbftBlockImporter::default());
        let mock_multicaster_v1 = Arc::new(MockValidatorMulticaster::default());
        let mock_block_timer_v1 = Arc::new(MockBlockTimer::new(config.block_period_seconds));
        let mock_round_timer_v1 = Arc::new(MockRoundTimer::new());

        let configurable_msg_validator_factory = Arc::new(
            ConfigurableMockMessageValidatorFactory::new().set_proposal_failure(false, None)
        );
        let mock_rc_validator_factory = Arc::new(MockRoundChangeMessageValidatorFactory);

        let proposal_validator = configurable_msg_validator_factory.clone().create_proposal_validator();
        let prepare_validator = configurable_msg_validator_factory.clone().create_prepare_validator();
        let commit_validator = configurable_msg_validator_factory.clone().create_commit_validator();

        let mut bhm_v1 = setup_bhm(
            arc_parent_h.clone(),
            mock_final_state_v1.clone(),
            mock_block_creator_r0.clone(), // Use R0's block creator for BHM as it will make/handle R0 proposal
            mock_block_importer.clone(),
            local_mf_v1.clone(),
            mock_multicaster_v1.clone(),
            mock_block_timer_v1.clone(),
            mock_round_timer_v1.clone(),
            test_codec.clone(),
            config.clone(),
            proposal_validator,
            prepare_validator,
            commit_validator,
            configurable_msg_validator_factory.clone(),
            mock_rc_validator_factory.clone(),
            vec![Arc::new(MockObserver::default())],
        );

        // BHM (V1) starts consensus. If V1 is proposer, it proposes. If not, it waits.
        bhm_v1.start_consensus().expect("BHM start_consensus failed");
        
        // Ensure proposal is processed by BHM (V1), whether V1 proposed or received it.
        let proposed_block_r0: QbftBlock;
        if mock_final_state_v1.is_local_node_proposer_for_round(&current_round_id) {
            assert_eq!(mock_multicaster_v1.proposals.lock().unwrap().len(), 1, "V1 (proposer) should have sent proposal");
            proposed_block_r0 = bhm_v1.current_round.as_ref().unwrap().round_state().proposal_message().unwrap().block().clone();
        } else {
            // V1 is not proposer, so send proposal from actual_proposer_r0 to BHM V1.
            let temp_block = mock_block_creator_r0.create_block(&parent_h, &current_round_id, parent_h.timestamp + 1).unwrap();
            let proposal_to_v1 = proposer_mf_r0.create_proposal(current_round_id, temp_block.clone(), vec![], None).unwrap();
            bhm_v1.handle_proposal_message(proposal_to_v1).expect("BHM V1 failed to handle proposal from actual proposer");
            proposed_block_r0 = temp_block;
        }
        assert!(bhm_v1.current_round.as_ref().unwrap().round_state().proposal_message().is_some(), "Proposal not set in BHM V1 for R0");
        let proposal_digest_r0 = proposed_block_r0.hash();

        // After V1 processes the proposal (either self-made or received), it (as a validator) should send its own Prepare.
        assert_eq!(mock_multicaster_v1.prepares.lock().unwrap().len(), 1, "V1 should have sent its Prepare after proposal processing");
        assert!(!bhm_v1.current_round.as_ref().unwrap().round_state().is_prepared(), "Round should not be prepared yet (1/3 prepares)");
        let commits_sent_by_v1_after_self_prepare = mock_multicaster_v1.commits.lock().unwrap().len(); // Should be 0
        assert_eq!(commits_sent_by_v1_after_self_prepare, 0, "V1 should not have sent commit yet");


        // Action: V3 sends a Prepare for the R0 proposal.
        let prepare_from_v3 = preparer_mf_v3.create_prepare(current_round_id, proposal_digest_r0).unwrap();
        let handle_result = bhm_v1.handle_prepare_message(prepare_from_v3.clone());

        // Assertions
        assert!(handle_result.is_ok(), "BHM handle_prepare_message from V3 failed: {:?}", handle_result.err());
        assert!(bhm_v1.finalized_block.is_none(), "Block should not be finalized by V3's prepare (2/3 prepares)");
        
        let round_state_v1 = bhm_v1.current_round.as_ref().unwrap().round_state();
        assert_eq!(round_state_v1.get_prepare_messages().len(), 2, "RoundState should have 2 prepares (V1 + V3)");
        assert!(!round_state_v1.is_prepared(), "RoundState should still not be prepared (2/3 prepares)");
        
        // No new commit should be sent by V1 as round is not yet prepared by V1's standard (needs 3 prepares).
        assert_eq!(mock_multicaster_v1.commits.lock().unwrap().len(), commits_sent_by_v1_after_self_prepare, "V1 should not have sent a new commit");
    }

    #[test]
    fn test_bhm_handle_prepare_reaches_prepared_sends_commit_not_finalized() {
        // Setup: 4 Validators: V1 (local), V2 (proposer R0), V3, V4 (send prepares)
        // BHM V1 receives proposal from V2, sends self-Prepare.
        // V1 receives Prepare from V3.
        // V1 receives Prepare from V4. Now round should be prepared (3/4 prepares, Quorum=3).
        // V1 should send its Commit, but BHM should not finalize block yet.

        let key_v1_local = deterministic_node_key(1);
        let addr_v1_local = address_from_arc_key(&key_v1_local);
        let key_v2_proposer_r0 = deterministic_node_key(2);
        let addr_v2_proposer_r0 = address_from_arc_key(&key_v2_proposer_r0);
        let key_v3_preparer = deterministic_node_key(3);
        let addr_v3_preparer = address_from_arc_key(&key_v3_preparer);
        let key_v4_preparer = deterministic_node_key(4);
        let addr_v4_preparer = address_from_arc_key(&key_v4_preparer);

        let mut all_addresses_for_sort = vec![addr_v1_local, addr_v2_proposer_r0, addr_v3_preparer, addr_v4_preparer];
        all_addresses_for_sort.sort();
        let validators: HashSet<Address> = all_addresses_for_sort.iter().cloned().collect();
        assert_eq!(validators.len(), 4, "Should be 4 unique validators");

        let parent_block_num = 0u64;
        let sequence_number = parent_block_num + 1;
        let round_num = 0u32;
        let current_round_id = ConsensusRoundIdentifier::new(sequence_number, round_num);

        let parent_h = simple_parent_header(parent_block_num, B256::random());
        let arc_parent_h = Arc::new(parent_h.clone());
        let config = default_test_qbft_config();
        let test_codec = testing_extradata_codec_local();

        let actual_proposer_r0: Address = all_addresses_for_sort[ (current_round_id.sequence_number as usize + current_round_id.round_number as usize) % 4 ];
        let key_for_proposer_r0: Arc<NodeKey>;
        if actual_proposer_r0 == addr_v1_local { key_for_proposer_r0 = key_v1_local.clone(); }
        else if actual_proposer_r0 == addr_v2_proposer_r0 { key_for_proposer_r0 = key_v2_proposer_r0.clone(); }
        else if actual_proposer_r0 == addr_v3_preparer { key_for_proposer_r0 = key_v3_preparer.clone(); }
        else { key_for_proposer_r0 = key_v4_preparer.clone(); }

        let mock_final_state_v1 = Arc::new(MockQbftFinalState::new(key_v1_local.clone(), validators.clone()));
        assert_eq!(mock_final_state_v1.quorum_size(), 3, "Quorum size for N=4 should be 3");

        let local_mf_v1 = Arc::new(MessageFactory::new(key_v1_local.clone()).unwrap());
        let proposer_mf_r0 = Arc::new(MessageFactory::new(key_for_proposer_r0.clone()).unwrap());
        let preparer_mf_v3 = Arc::new(MessageFactory::new(key_v3_preparer.clone()).unwrap());
        let preparer_mf_v4 = Arc::new(MessageFactory::new(key_v4_preparer.clone()).unwrap());

        let block_creator_final_state_r0 = Arc::new(MockQbftFinalState::new(key_for_proposer_r0.clone(), validators.clone()));
        let mock_block_creator_r0 = Arc::new(MockQbftBlockCreator::new(arc_parent_h.clone(), block_creator_final_state_r0, Arc::new(AlloyBftExtraDataCodec::default())));

        let mock_block_importer = Arc::new(MockQbftBlockImporter::default());
        let mock_multicaster_v1 = Arc::new(MockValidatorMulticaster::default());
        let mock_block_timer_v1 = Arc::new(MockBlockTimer::new(config.block_period_seconds));
        let mock_round_timer_v1 = Arc::new(MockRoundTimer::new());

        let configurable_msg_validator_factory = Arc::new(
            ConfigurableMockMessageValidatorFactory::new().set_proposal_failure(false, None)
        );
        let mock_rc_validator_factory = Arc::new(MockRoundChangeMessageValidatorFactory);
        let proposal_validator = configurable_msg_validator_factory.clone().create_proposal_validator();
        let prepare_validator = configurable_msg_validator_factory.clone().create_prepare_validator();
        let commit_validator = configurable_msg_validator_factory.clone().create_commit_validator();

        let mut bhm_v1 = setup_bhm(
            arc_parent_h.clone(), mock_final_state_v1.clone(), mock_block_creator_r0.clone(), 
            mock_block_importer.clone(), local_mf_v1.clone(), mock_multicaster_v1.clone(), 
            mock_block_timer_v1.clone(), mock_round_timer_v1.clone(), test_codec.clone(), config.clone(),
            proposal_validator, prepare_validator, commit_validator, 
            configurable_msg_validator_factory.clone(), mock_rc_validator_factory.clone(), vec![Arc::new(MockObserver::default())],
        );

        bhm_v1.start_consensus().expect("BHM start_consensus failed");
        let proposed_block_r0: QbftBlock;
        if mock_final_state_v1.is_local_node_proposer_for_round(&current_round_id) {
            proposed_block_r0 = bhm_v1.current_round.as_ref().unwrap().round_state().proposal_message().unwrap().block().clone();
        } else {
            let temp_block = mock_block_creator_r0.create_block(&parent_h, &current_round_id, parent_h.timestamp + 1).unwrap();
            let proposal_to_v1 = proposer_mf_r0.create_proposal(current_round_id, temp_block.clone(), vec![], None).unwrap();
            bhm_v1.handle_proposal_message(proposal_to_v1).expect("BHM V1 failed to handle R0 proposal");
            proposed_block_r0 = temp_block;
        }
        let proposal_digest_r0 = proposed_block_r0.hash();
        assert_eq!(mock_multicaster_v1.prepares.lock().unwrap().len(), 1, "V1 should have sent its Prepare after proposal");
        assert!(!bhm_v1.current_round.as_ref().unwrap().round_state().is_prepared(), "Round should not be prepared (1/3 prepares)");

        // V3 sends Prepare
        let prepare_from_v3 = preparer_mf_v3.create_prepare(current_round_id, proposal_digest_r0).unwrap();
        bhm_v1.handle_prepare_message(prepare_from_v3.clone()).expect("Handle V3 Prepare failed");
        assert_eq!(bhm_v1.current_round.as_ref().unwrap().round_state().get_prepare_messages().len(), 2, "Should have 2 prepares (V1,V3)");
        assert!(!bhm_v1.current_round.as_ref().unwrap().round_state().is_prepared(), "Round should not be prepared (2/3 prepares)");
        assert_eq!(mock_multicaster_v1.commits.lock().unwrap().len(), 0, "V1 should not have sent commit yet");

        // Action: V4 sends Prepare. This should make V1's round PREPARED.
        let prepare_from_v4 = preparer_mf_v4.create_prepare(current_round_id, proposal_digest_r0).unwrap();
        let handle_result = bhm_v1.handle_prepare_message(prepare_from_v4.clone());

        // Assertions
        assert!(handle_result.is_ok(), "BHM handle_prepare_message from V4 failed: {:?}", handle_result.err());
        assert!(bhm_v1.finalized_block.is_none(), "Block should not be finalized by V4's prepare");
        
        let round_v1 = bhm_v1.current_round.as_ref().unwrap();
        let round_state_v1 = round_v1.round_state();
        assert_eq!(round_state_v1.get_prepare_messages().len(), 3, "RoundState should have 3 prepares (V1,V3,V4)");
        assert!(round_state_v1.is_prepared(), "RoundState should now be prepared (3/3 prepares)");
        
        // V1 should have sent its Commit message because its round became prepared.
        assert_eq!(mock_multicaster_v1.commits.lock().unwrap().len(), 1, "V1 should have sent its Commit");
        let sent_commit_v1 = mock_multicaster_v1.commits.lock().unwrap()[0].clone();
        assert_eq!(sent_commit_v1.author().unwrap(), addr_v1_local, "Commit author mismatch");
        assert_eq!(sent_commit_v1.payload().digest, proposal_digest_r0, "Commit digest mismatch");
        // assert!(round_v1.commit_sent, "QbftRound commit_sent flag should be true for V1"); // commit_sent is private
        
        assert!(!round_state_v1.is_committed(), "RoundState should not be committed yet (only 1 commit from V1)");
    }

    #[test]
    fn test_bhm_handle_prepare_future_round_buffered() {
        // Setup: 3 Validators: V1 (local, proposer for R0), V2, V3 (sends Prepare for R1)
        let key_v1_local = deterministic_node_key(1);
        let addr_v1_local = address_from_arc_key(&key_v1_local);
        let key_v2 = deterministic_node_key(2);
        let addr_v2 = address_from_arc_key(&key_v2);
        let key_v3_preparer_r1 = deterministic_node_key(3);
        let addr_v3_preparer_r1 = address_from_arc_key(&key_v3_preparer_r1);

        let mut all_addresses_for_sort = vec![addr_v1_local, addr_v2, addr_v3_preparer_r1];
        all_addresses_for_sort.sort();
        let validators: HashSet<Address> = all_addresses_for_sort.iter().cloned().collect();

        let parent_block_num = 0u64;
        let sequence_number = parent_block_num + 1;
        let current_round_num = 0u32;
        let current_round_id = ConsensusRoundIdentifier::new(sequence_number, current_round_num);
        let future_round_num = 1u32;
        let future_round_id = ConsensusRoundIdentifier::new(sequence_number, future_round_num);

        let parent_h = simple_parent_header(parent_block_num, B256::random());
        let arc_parent_h = Arc::new(parent_h.clone());
        let config = default_test_qbft_config();
        let test_codec = testing_extradata_codec_local();

        // Ensure V1 (local) is proposer for R0
        let actual_proposer_r0: Address = all_addresses_for_sort[ (current_round_id.sequence_number as usize + current_round_id.round_number as usize) % 3 ];
        let final_key_v1_local: Arc<NodeKey>;
        if actual_proposer_r0 == addr_v1_local { final_key_v1_local = key_v1_local.clone(); }
        else if actual_proposer_r0 == addr_v2 { final_key_v1_local = key_v2.clone(); }
        else { final_key_v1_local = key_v3_preparer_r1.clone(); }
        assert_eq!(address_from_arc_key(&final_key_v1_local), actual_proposer_r0, "V1 (local) setup as R0 proposer failed");

        let mock_final_state_v1 = Arc::new(MockQbftFinalState::new(final_key_v1_local.clone(), validators.clone()));
        let local_mf_v1 = Arc::new(MessageFactory::new(final_key_v1_local.clone()).unwrap());
        let preparer_mf_v3_r1 = Arc::new(MessageFactory::new(key_v3_preparer_r1.clone()).unwrap());

        let block_creator_final_state_v1 = Arc::new(MockQbftFinalState::new(final_key_v1_local.clone(), validators.clone()));
        let mock_block_creator_v1 = Arc::new(MockQbftBlockCreator::new( arc_parent_h.clone(), block_creator_final_state_v1, Arc::new(AlloyBftExtraDataCodec::default()) ));
        
        let mock_block_importer = Arc::new(MockQbftBlockImporter::default());
        let mock_multicaster_v1 = Arc::new(MockValidatorMulticaster::default());
        let mock_block_timer_v1 = Arc::new(MockBlockTimer::new(config.block_period_seconds));
        let mock_round_timer_v1 = Arc::new(MockRoundTimer::new());

        let configurable_msg_validator_factory = Arc::new(
            ConfigurableMockMessageValidatorFactory::new().set_proposal_failure(false, None)
        );
        let mock_rc_validator_factory = Arc::new(MockRoundChangeMessageValidatorFactory);
        let proposal_validator = configurable_msg_validator_factory.clone().create_proposal_validator();
        let prepare_validator = configurable_msg_validator_factory.clone().create_prepare_validator();
        let commit_validator = configurable_msg_validator_factory.clone().create_commit_validator();

        let mut bhm_v1 = setup_bhm(
            arc_parent_h.clone(), mock_final_state_v1.clone(), mock_block_creator_v1.clone(), 
            mock_block_importer.clone(), local_mf_v1.clone(), mock_multicaster_v1.clone(), 
            mock_block_timer_v1.clone(), mock_round_timer_v1.clone(), test_codec.clone(), config.clone(),
            proposal_validator, prepare_validator, commit_validator, 
            configurable_msg_validator_factory.clone(), mock_rc_validator_factory.clone(), vec![Arc::new(MockObserver::default())],
        );

        // V1 (local) starts, proposes for R0, and sends its own Prepare.
        bhm_v1.start_consensus().expect("BHM start_consensus failed for V1");
        assert_eq!(*bhm_v1.current_round.as_ref().unwrap().round_identifier(), current_round_id);
        let r0_proposal_digest = bhm_v1.current_round.as_ref().unwrap().round_state().proposal_message().unwrap().block().hash();
        assert_eq!(mock_multicaster_v1.proposals.lock().unwrap().len(), 1, "V1 should have sent 1 proposal for R0");
        assert_eq!(mock_multicaster_v1.prepares.lock().unwrap().len(), 1, "V1 should have sent 1 prepare for R0 proposal");
        let r0_prepare_count_in_state = bhm_v1.current_round.as_ref().unwrap().round_state().get_prepare_messages().len();
        assert_eq!(r0_prepare_count_in_state, 1, "R0 state should have 1 prepare from V1");

        // Action: V3 sends a Prepare for future_round_id (R1) for some hypothetical digest.
        let hypothetical_r1_proposal_digest = B256::random(); 
        let prepare_from_v3_for_r1 = preparer_mf_v3_r1.create_prepare(future_round_id, hypothetical_r1_proposal_digest).unwrap();
        let handle_result = bhm_v1.handle_prepare_message(prepare_from_v3_for_r1.clone());

        // Assertions
        assert!(handle_result.is_ok(), "BHM handle_prepare_message for future round failed: {:?}", handle_result.err());

        // BHM current round should still be R0
        assert!(bhm_v1.current_round.is_some());
        assert_eq!(*bhm_v1.current_round.as_ref().unwrap().round_identifier(), current_round_id, "BHM current round changed");
        
        // State of current round (R0) should be unchanged by the future prepare
        let r0_round_state_after = bhm_v1.current_round.as_ref().unwrap().round_state();
        assert_eq!(r0_round_state_after.proposal_message().unwrap().block().hash(), r0_proposal_digest, "R0 proposal changed");
        assert_eq!(r0_round_state_after.get_prepare_messages().len(), r0_prepare_count_in_state, "R0 prepare count changed");

        // Check future_prepares buffer
        assert_eq!(bhm_v1.future_prepares.len(), 1, "future_prepares should have 1 entry for R1");
        assert!(bhm_v1.future_prepares.contains_key(&future_round_num), "future_prepares does not contain key for R1");
        let buffered_prepares_for_r1 = bhm_v1.future_prepares.get(&future_round_num).unwrap();
        assert_eq!(buffered_prepares_for_r1.len(), 1, "Should be 1 prepare buffered for R1");
        assert_eq!(buffered_prepares_for_r1[0].payload().digest, hypothetical_r1_proposal_digest, "Buffered prepare for R1 is not the one sent");
        assert_eq!(*buffered_prepares_for_r1[0].round_identifier(), future_round_id, "Buffered prepare R1 has wrong round_id");

        // No new messages (beyond initial R0 proposal/prepare) should have been sent by V1
        assert_eq!(mock_multicaster_v1.proposals.lock().unwrap().len(), 1);
        assert_eq!(mock_multicaster_v1.prepares.lock().unwrap().len(), 1);
        assert_eq!(mock_multicaster_v1.commits.lock().unwrap().len(), 0);
    }

    #[test]
    fn test_bhm_handle_prepare_past_round_ignored() {
        // Setup: 3 Validators: V1 (local), V2, V3 (sends Prepare for R0).
        // BHM V1 is advanced to R1. Then V3 sends Prepare for R0 (past).

        let key_v1_local = deterministic_node_key(1);
        let addr_v1_local = address_from_arc_key(&key_v1_local);
        let key_v2 = deterministic_node_key(2);
        let addr_v2 = address_from_arc_key(&key_v2);
        let key_v3_preparer_r0 = deterministic_node_key(3);
        let addr_v3_preparer_r0 = address_from_arc_key(&key_v3_preparer_r0);

        let mut all_addresses_for_sort = vec![addr_v1_local, addr_v2, addr_v3_preparer_r0];
        all_addresses_for_sort.sort();
        let validators: HashSet<Address> = all_addresses_for_sort.iter().cloned().collect();

        let parent_block_num = 0u64;
        let sequence_number = parent_block_num + 1;
        let past_round_num = 0u32;
        let past_round_id = ConsensusRoundIdentifier::new(sequence_number, past_round_num);
        let bhm_round_num = 1u32;
        let bhm_current_round_id = ConsensusRoundIdentifier::new(sequence_number, bhm_round_num);

        let parent_h = simple_parent_header(parent_block_num, B256::random());
        let arc_parent_h = Arc::new(parent_h.clone());
        let config = default_test_qbft_config();
        let test_codec = testing_extradata_codec_local();

        let mock_final_state_v1 = Arc::new(MockQbftFinalState::new(key_v1_local.clone(), validators.clone()));
        let local_mf_v1 = Arc::new(MessageFactory::new(key_v1_local.clone()).unwrap());
        let preparer_mf_v3_r0 = Arc::new(MessageFactory::new(key_v3_preparer_r0.clone()).unwrap());

        // Mock block creator for BHM internal ops (e.g. if it proposes for R1)
        let mock_block_creator_v1 = Arc::new(MockQbftBlockCreator::new( arc_parent_h.clone(), mock_final_state_v1.clone(), Arc::new(AlloyBftExtraDataCodec::default()) ));
        
        let mock_block_importer = Arc::new(MockQbftBlockImporter::default());
        let mock_multicaster_v1 = Arc::new(MockValidatorMulticaster::default());
        let mock_block_timer_v1 = Arc::new(MockBlockTimer::new(config.block_period_seconds));
        let mock_round_timer_v1 = Arc::new(MockRoundTimer::new());

        let configurable_msg_validator_factory = Arc::new(
            ConfigurableMockMessageValidatorFactory::new().set_proposal_failure(false, None)
        );
        let mock_rc_validator_factory = Arc::new(MockRoundChangeMessageValidatorFactory);
        let proposal_validator = configurable_msg_validator_factory.clone().create_proposal_validator();
        let prepare_validator = configurable_msg_validator_factory.clone().create_prepare_validator();
        let commit_validator = configurable_msg_validator_factory.clone().create_commit_validator();

        let mut bhm_v1 = setup_bhm(
            arc_parent_h.clone(), mock_final_state_v1.clone(), mock_block_creator_v1.clone(), 
            mock_block_importer.clone(), local_mf_v1.clone(), mock_multicaster_v1.clone(), 
            mock_block_timer_v1.clone(), mock_round_timer_v1.clone(), test_codec.clone(), config.clone(),
            proposal_validator, prepare_validator, commit_validator, 
            configurable_msg_validator_factory.clone(), mock_rc_validator_factory.clone(), vec![Arc::new(MockObserver::default())],
        );

        // Start BHM (tries R0), then advance to R1.
        bhm_v1.start_consensus().expect("BHM start_consensus (R0) failed");
        bhm_v1.advance_to_new_round(bhm_round_num, None).expect("Failed to advance BHM to R1");
        assert_eq!(*bhm_v1.current_round.as_ref().unwrap().round_identifier(), bhm_current_round_id, "BHM not in R1");

        let r1_prepare_count_before = bhm_v1.current_round.as_ref().unwrap().round_state().get_prepare_messages().len();
        let future_prepares_count_before = bhm_v1.future_prepares.len();
        let multicaster_prepares_before = mock_multicaster_v1.prepares.lock().unwrap().len();
        let multicaster_commits_before = mock_multicaster_v1.commits.lock().unwrap().len();

        // Action: V3 sends a Prepare for past_round_id (R0).
        let hypothetical_r0_proposal_digest = B256::random(); 
        let prepare_for_past_round = preparer_mf_v3_r0.create_prepare(past_round_id, hypothetical_r0_proposal_digest).unwrap();
        let handle_result = bhm_v1.handle_prepare_message(prepare_for_past_round.clone());

        // Assertions
        assert!(handle_result.is_ok(), "BHM handle_prepare_message for past round should not error: {:?}", handle_result.err());

        // BHM current round should still be R1
        assert!(bhm_v1.current_round.is_some());
        assert_eq!(*bhm_v1.current_round.as_ref().unwrap().round_identifier(), bhm_current_round_id, "BHM current round changed");
        
        // State of current round (R1) should be unchanged by the past prepare
        let r1_round_state_after = bhm_v1.current_round.as_ref().unwrap().round_state();
        assert_eq!(r1_round_state_after.get_prepare_messages().len(), r1_prepare_count_before, "R1 prepare count changed");

        // future_prepares buffer should be unchanged
        assert_eq!(bhm_v1.future_prepares.len(), future_prepares_count_before, "future_prepares count changed");

        // No new messages should have been sent by V1 due to this past prepare
        assert_eq!(mock_multicaster_v1.prepares.lock().unwrap().len(), multicaster_prepares_before);
        assert_eq!(mock_multicaster_v1.commits.lock().unwrap().len(), multicaster_commits_before);
    }

    #[test]
    fn test_bhm_handle_commit_current_round_does_not_finalize() {
        // Setup: 4 Validators: V1 (local), V2 (proposer R0), V3 (sends commit), V4.
        // Round 0 becomes prepared after prepares from V1(self), V3, V4.
        // V1 sends self-commit. Then V3 sends its commit. (Total 2 commits, Quorum=3)
        // BHM should not finalize.

        let key_v1_local = deterministic_node_key(1);
        let addr_v1_local = address_from_arc_key(&key_v1_local);
        let key_v2_proposer_r0 = deterministic_node_key(2);
        let addr_v2_proposer_r0 = address_from_arc_key(&key_v2_proposer_r0);
        let key_v3_actor = deterministic_node_key(3); // Will send Prepare and Commit
        let addr_v3_actor = address_from_arc_key(&key_v3_actor);
        let key_v4_preparer = deterministic_node_key(4); // Will send Prepare
        let addr_v4_preparer = address_from_arc_key(&key_v4_preparer);

        let mut all_addresses_for_sort = vec![addr_v1_local, addr_v2_proposer_r0, addr_v3_actor, addr_v4_preparer];
        all_addresses_for_sort.sort();
        let validators: HashSet<Address> = all_addresses_for_sort.iter().cloned().collect();
        assert_eq!(validators.len(), 4, "Should be 4 unique validators");

        let parent_block_num = 0u64;
        let sequence_number = parent_block_num + 1;
        let round_num = 0u32;
        let current_round_id = ConsensusRoundIdentifier::new(sequence_number, round_num);

        let parent_h = simple_parent_header(parent_block_num, B256::random());
        let arc_parent_h = Arc::new(parent_h.clone());
        let config = default_test_qbft_config();
        let test_codec = testing_extradata_codec_local();

        let actual_proposer_r0: Address = all_addresses_for_sort[ (current_round_id.sequence_number as usize + current_round_id.round_number as usize) % 4 ];
        let key_for_proposer_r0: Arc<NodeKey>;
        if actual_proposer_r0 == addr_v1_local { key_for_proposer_r0 = key_v1_local.clone(); }
        else if actual_proposer_r0 == addr_v2_proposer_r0 { key_for_proposer_r0 = key_v2_proposer_r0.clone(); }
        else if actual_proposer_r0 == addr_v3_actor { key_for_proposer_r0 = key_v3_actor.clone(); }
        else { key_for_proposer_r0 = key_v4_preparer.clone(); }

        let mock_final_state_v1 = Arc::new(MockQbftFinalState::new(key_v1_local.clone(), validators.clone()));
        assert_eq!(mock_final_state_v1.quorum_size(), 3, "Quorum size for N=4 should be 3");

        let local_mf_v1 = Arc::new(MessageFactory::new(key_v1_local.clone()).unwrap());
        let proposer_mf_r0 = Arc::new(MessageFactory::new(key_for_proposer_r0.clone()).unwrap());
        let actor_mf_v3 = Arc::new(MessageFactory::new(key_v3_actor.clone()).unwrap());
        let preparer_mf_v4 = Arc::new(MessageFactory::new(key_v4_preparer.clone()).unwrap());

        let block_creator_final_state_r0 = Arc::new(MockQbftFinalState::new(key_for_proposer_r0.clone(), validators.clone()));
        let mock_block_creator_r0 = Arc::new(MockQbftBlockCreator::new(arc_parent_h.clone(), block_creator_final_state_r0, Arc::new(AlloyBftExtraDataCodec::default())));

        let mock_block_importer = Arc::new(MockQbftBlockImporter::new()); // Use .new() for default inner state
        let mock_multicaster_v1 = Arc::new(MockValidatorMulticaster::default());
        let mock_block_timer_v1 = Arc::new(MockBlockTimer::new(config.block_period_seconds));
        let mock_round_timer_v1 = Arc::new(MockRoundTimer::new());

        let configurable_msg_validator_factory = Arc::new( ConfigurableMockMessageValidatorFactory::new().set_proposal_failure(false, None) );
        let mock_rc_validator_factory = Arc::new(MockRoundChangeMessageValidatorFactory);
        let proposal_validator = configurable_msg_validator_factory.clone().create_proposal_validator();
        let prepare_validator = configurable_msg_validator_factory.clone().create_prepare_validator();
        let commit_validator = configurable_msg_validator_factory.clone().create_commit_validator();

        let mut bhm_v1 = setup_bhm(
            arc_parent_h.clone(), mock_final_state_v1.clone(), mock_block_creator_r0.clone(), 
            mock_block_importer.clone(), local_mf_v1.clone(), mock_multicaster_v1.clone(), 
            mock_block_timer_v1.clone(), mock_round_timer_v1.clone(), test_codec.clone(), config.clone(),
            proposal_validator, prepare_validator, commit_validator, 
            configurable_msg_validator_factory.clone(), mock_rc_validator_factory.clone(), vec![Arc::new(MockObserver::default())],
        );

        // Initial proposal phase
        bhm_v1.start_consensus().expect("BHM start_consensus failed");
        let proposed_block_r0: QbftBlock;
        if mock_final_state_v1.is_local_node_proposer_for_round(&current_round_id) {
            proposed_block_r0 = bhm_v1.current_round.as_ref().unwrap().round_state().proposal_message().unwrap().block().clone();
        } else {
            let temp_block = mock_block_creator_r0.create_block(&parent_h, &current_round_id, parent_h.timestamp + 1).unwrap();
            let proposal_to_v1 = proposer_mf_r0.create_proposal(current_round_id, temp_block.clone(), vec![], None).unwrap();
            bhm_v1.handle_proposal_message(proposal_to_v1).expect("BHM V1 failed to handle R0 proposal");
            proposed_block_r0 = temp_block;
        }
        let proposal_digest_r0 = proposed_block_r0.hash();
        // V1 sends self-Prepare
        assert_eq!(mock_multicaster_v1.prepares.lock().unwrap().len(), 1);

        // V3 sends Prepare
        let prepare_from_v3 = actor_mf_v3.create_prepare(current_round_id, proposal_digest_r0).unwrap();
        bhm_v1.handle_prepare_message(prepare_from_v3.clone()).expect("Handle V3 Prepare failed");
        
        // V4 sends Prepare - round becomes prepared, V1 sends self-Commit
        let prepare_from_v4 = preparer_mf_v4.create_prepare(current_round_id, proposal_digest_r0).unwrap();
        bhm_v1.handle_prepare_message(prepare_from_v4.clone()).expect("Handle V4 Prepare failed");
        assert!(bhm_v1.current_round.as_ref().unwrap().round_state().is_prepared(), "Round should be prepared after 3rd prepare");
        assert_eq!(mock_multicaster_v1.commits.lock().unwrap().len(), 1, "V1 should have sent its self-Commit");
        let commits_by_v1_before_v3_commit = mock_multicaster_v1.commits.lock().unwrap().clone();

        // Action: V3 sends its Commit.
        let commit_from_v3 = actor_mf_v3.create_commit(current_round_id, proposal_digest_r0, 
            actor_mf_v3.create_commit_seal(proposal_digest_r0).unwrap()
        ).unwrap();
        let handle_result = bhm_v1.handle_commit_message(commit_from_v3.clone());

        // Assertions
        assert!(handle_result.is_ok(), "BHM handle_commit_message from V3 failed: {:?}", handle_result.err());
        assert!(bhm_v1.finalized_block.is_none(), "Block should not be finalized by V3's commit (2/3 commits)");
        
        let round_state_v1 = bhm_v1.current_round.as_ref().unwrap().round_state();
        assert_eq!(round_state_v1.get_commit_messages().len(), 2, "RoundState should have 2 commits (V1 + V3)"); // Check BftRound internal state for commits
        assert!(round_state_v1.is_prepared(), "RoundState should still be prepared");
        assert!(!round_state_v1.is_committed(), "RoundState should NOT be committed yet (2/3 commits)");
        
        // No new messages should be sent by V1 due to V3's commit in this state.
        assert_eq!(mock_multicaster_v1.commits.lock().unwrap().len(), commits_by_v1_before_v3_commit.len(), "V1 should not have sent a new commit");
    }

    #[test]
    fn test_bhm_handle_commit_messages_reaches_committed_finalizes_block() {
        // Setup: 4 Validators: V1 (local), V2 (proposer R0), V3, V4
        // 1. V1 starts consensus (R0).
        // 2. V2 (proposer) sends Proposal. V1 handles it, sends self-Prepare.
        //    (V1 multicaster: 1P sent. V1 RoundState: 1P_V1)
        // 3. V3 sends Prepare. V1 handles it.
        //    (V1 RoundState: 1P_V1, 1P_V3)
        // 4. V4 sends Prepare. V1 handles it. Round becomes PREPARED. V1 sends self-Commit.
        //    (V1 multicaster: 1P, 1C sent. V1 RoundState: 1P_V1, 1P_V3, 1P_V4; 1C_V1. LockedBlock set)
        // 5. V2 sends Commit. V1 handles it.
        //    (V1 RoundState: 1P_V1, 1P_V3, 1P_V4; 1C_V1, 1C_V2)
        // 6. V3 sends Commit. V1 handles it. Round becomes COMMITTED. Block is FINALIZED.
        //    (V1 RoundState: 1P_V1, 1P_V3, 1P_V4; 1C_V1, 1C_V2, 1C_V3. Block imported. Observer notified)

        let key_v1_local = deterministic_node_key(11); // Use different seeds to avoid address clashes
        let addr_v1_local = address_from_arc_key(&key_v1_local);
        let key_v2_actor = deterministic_node_key(12);
        let addr_v2_actor = address_from_arc_key(&key_v2_actor);
        let key_v3_actor = deterministic_node_key(13);
        let addr_v3_actor = address_from_arc_key(&key_v3_actor);
        let key_v4_actor = deterministic_node_key(14);
        let addr_v4_actor = address_from_arc_key(&key_v4_actor);

        let mut all_addresses_for_sort = vec![addr_v1_local, addr_v2_actor, addr_v3_actor, addr_v4_actor];
        all_addresses_for_sort.sort();
        let validators: HashSet<Address> = all_addresses_for_sort.iter().cloned().collect();
        assert_eq!(validators.len(), 4, "Should be 4 unique validators");

        let parent_block_num = 0u64;
        let sequence_number = parent_block_num + 1;
        let round_num = 0u32;
        let current_round_id = ConsensusRoundIdentifier::new(sequence_number, round_num);

        let parent_h = simple_parent_header(parent_block_num, B256::random());
        let arc_parent_h = Arc::new(parent_h.clone());
        let config = default_test_qbft_config();
        let test_codec = Arc::new(AlloyBftExtraDataCodec::default());

        let proposer_index_r0 = (current_round_id.sequence_number as usize + current_round_id.round_number as usize) % validators.len();
        let actual_proposer_addr_r0 = all_addresses_for_sort[proposer_index_r0];
        
        let key_for_proposer_r0 = if actual_proposer_addr_r0 == addr_v1_local { key_v1_local.clone() }
                                else if actual_proposer_addr_r0 == addr_v2_actor { key_v2_actor.clone() }
                                else if actual_proposer_addr_r0 == addr_v3_actor { key_v3_actor.clone() }
                                else { key_v4_actor.clone() }; // Must be addr_v4_actor if others not matched

        let mock_final_state_v1 = Arc::new(MockQbftFinalState::new(key_v1_local.clone(), validators.clone()));
        assert_eq!(mock_final_state_v1.quorum_size(), 3, "Quorum size for N=4 should be 3");

        let local_mf_v1 = Arc::new(MessageFactory::new(key_v1_local.clone()).unwrap());
        let proposer_mf_r0 = Arc::new(MessageFactory::new(key_for_proposer_r0.clone()).unwrap());
        
        let block_creator_final_state_r0 = Arc::new(MockQbftFinalState::new(key_for_proposer_r0.clone(), validators.clone()));
        let mock_block_creator_r0 = Arc::new(MockQbftBlockCreator::new(arc_parent_h.clone(), block_creator_final_state_r0, test_codec.clone()));

        let mock_block_importer_v1 = Arc::new(MockQbftBlockImporter::default());
        let mock_multicaster_v1 = Arc::new(MockValidatorMulticaster::default());
        let mock_block_timer_v1 = Arc::new(MockBlockTimer::new(config.block_period_seconds));
        let mock_round_timer_v1 = Arc::new(MockRoundTimer::new());
        let mock_observer_v1 = Arc::new(MockObserver::default());

        let configurable_msg_validator_factory = Arc::new(ConfigurableMockMessageValidatorFactory::new());
        let mock_rc_validator_factory = Arc::new(MockRoundChangeMessageValidatorFactory);
        let proposal_validator = configurable_msg_validator_factory.clone().create_proposal_validator();
        let prepare_validator = configurable_msg_validator_factory.clone().create_prepare_validator();
        let commit_validator = configurable_msg_validator_factory.clone().create_commit_validator();

        let mut bhm_v1 = setup_bhm(
            arc_parent_h.clone(), mock_final_state_v1.clone(), mock_block_creator_r0.clone(), 
            mock_block_importer_v1.clone(), local_mf_v1.clone(), mock_multicaster_v1.clone(), 
            mock_block_timer_v1.clone(), mock_round_timer_v1.clone(), test_codec.clone(), config.clone(),
            proposal_validator, prepare_validator, commit_validator, 
            configurable_msg_validator_factory.clone(), mock_rc_validator_factory.clone(), vec![mock_observer_v1.clone()],
        );

        bhm_v1.start_consensus().expect("BHM start_consensus failed");

        let proposed_block_r0: QbftBlock;
        if mock_final_state_v1.is_local_node_proposer_for_round(&current_round_id) {
            proposed_block_r0 = bhm_v1.current_round.as_ref().unwrap().round_state().proposal_message().unwrap().block().clone();
            assert_eq!(mock_multicaster_v1.proposals.lock().unwrap().len(), 1);
        } else {
            let temp_block = mock_block_creator_r0.create_block(&parent_h, &current_round_id, parent_h.timestamp + 1).unwrap();
            let proposal_to_v1 = proposer_mf_r0.create_proposal(current_round_id, temp_block.clone(), vec![], None).unwrap();
            bhm_v1.handle_proposal_message(proposal_to_v1).expect("BHM V1 failed to handle R0 proposal");
            proposed_block_r0 = temp_block;
            assert_eq!(mock_multicaster_v1.proposals.lock().unwrap().len(), 0);
        }
        let proposal_digest_r0 = proposed_block_r0.hash();
        assert_eq!(mock_multicaster_v1.prepares.lock().unwrap().len(), 1);
        assert_eq!(bhm_v1.current_round.as_ref().unwrap().round_state().get_prepare_messages().len(), 1);

        // Create MFs for all actors for flexibility in choosing preparers/committers
        let mf_actor_keys: HashMap<Address, Arc<MessageFactory>> = validators.iter()
            .map(|addr| {
                let key = if *addr == addr_v1_local { key_v1_local.clone() }
                          else if *addr == addr_v2_actor { key_v2_actor.clone() }
                          else if *addr == addr_v3_actor { key_v3_actor.clone() }
                          else if *addr == addr_v4_actor { key_v4_actor.clone() }
                          else { unreachable!("Address not in initial actor list") };
                (*addr, Arc::new(MessageFactory::new(key).unwrap()))
            })
            .collect();

        let mut preparer_mfs: Vec<Arc<MessageFactory>> = validators.iter()
            .filter(|addr| **addr != addr_v1_local && **addr != actual_proposer_addr_r0)
            .take(2)
            .map(|addr| mf_actor_keys.get(addr).unwrap().clone())
            .collect();
        
        assert_eq!(preparer_mfs.len(), 2, "Failed to get 2 distinct preparers");
        
        let mf_preparer_1 = preparer_mfs.remove(0);
        let mf_preparer_2 = preparer_mfs.remove(0);

        let prepare_from_p1 = mf_preparer_1.create_prepare(current_round_id, proposal_digest_r0).unwrap();
        bhm_v1.handle_prepare_message(prepare_from_p1).expect("Handle P1 Prepare failed");
        assert_eq!(bhm_v1.current_round.as_ref().unwrap().round_state().get_prepare_messages().len(), 2);
        assert_eq!(mock_multicaster_v1.proposals.lock().unwrap().len(), 0, "DEBUG: V1 proposals after handling P1's prepare");

        let prepare_from_p2 = mf_preparer_2.create_prepare(current_round_id, proposal_digest_r0).unwrap();
        bhm_v1.handle_prepare_message(prepare_from_p2).expect("Handle P2 Prepare failed");
        assert_eq!(mock_multicaster_v1.proposals.lock().unwrap().len(), 0, "DEBUG: V1 proposals after handling P2's prepare (round becomes prepared)");
        
        assert!(bhm_v1.current_round.as_ref().unwrap().round_state().is_prepared());
        assert_eq!(mock_multicaster_v1.prepares.lock().unwrap().len(), 1);
        assert_eq!(mock_multicaster_v1.commits.lock().unwrap().len(), 1); // V1's self-commit
        assert_eq!(bhm_v1.current_round.as_ref().unwrap().round_state().get_commit_messages().len(), 1);
        assert!(bhm_v1.current_round.as_ref().unwrap().locked_info().is_some()); // Check QbftRound's lock

        // Need 2 more commit messages from distinct validators (not V1)
        let mut committer_mfs: Vec<Arc<MessageFactory>> = validators.iter()
            .filter(|addr| **addr != addr_v1_local) // Anyone but V1
            .take(2) // Take the first two available
            .map(|addr| mf_actor_keys.get(addr).unwrap().clone())
            .collect();

        assert_eq!(committer_mfs.len(), 2, "Failed to get 2 distinct committers");

        let mf_committer_1 = committer_mfs.remove(0);
        let mf_committer_2 = committer_mfs.remove(0);

        let commit_seal_c1 = mf_committer_1.create_commit_seal(proposal_digest_r0).unwrap();
        let commit_from_c1 = mf_committer_1.create_commit(current_round_id, proposal_digest_r0, commit_seal_c1).unwrap();
        bhm_v1.handle_commit_message(commit_from_c1).expect("Handle C1 Commit failed");
        
        assert_eq!(bhm_v1.current_round.as_ref().unwrap().round_state().get_commit_messages().len(), 2); // V1's + C1's
        assert!(!bhm_v1.current_round.as_ref().unwrap().round_state().is_committed());
        assert!(bhm_v1.finalized_block.is_none());
        assert_eq!(mock_block_importer_v1.get_imported_blocks().len(), 0);
        assert_eq!(mock_observer_v1.blocks_imported(), 0);
        assert_eq!(mock_multicaster_v1.proposals.lock().unwrap().len(), 0, "DEBUG: V1 proposals after handling C1's commit");

        let commit_seal_c2 = mf_committer_2.create_commit_seal(proposal_digest_r0).unwrap();
        let commit_from_c2 = mf_committer_2.create_commit(current_round_id, proposal_digest_r0, commit_seal_c2).unwrap();
        bhm_v1.handle_commit_message(commit_from_c2).expect("Handle C2 Commit failed");

        assert!(bhm_v1.current_round.as_ref().unwrap().round_state().is_committed());
        assert!(bhm_v1.finalized_block.is_some());
        let finalized_block_in_bhm = bhm_v1.finalized_block.as_ref().unwrap();
        assert_eq!(finalized_block_in_bhm.hash(), proposal_digest_r0);
        
        assert_eq!(mock_block_importer_v1.get_imported_blocks().len(), 1);
        let imported_block = mock_block_importer_v1.get_imported_blocks().remove(0);
        assert_eq!(imported_block.hash(), proposal_digest_r0);

        let decoded_extra_data = test_codec.decode(&imported_block.header.extra_data).expect("Failed to decode extra_data");
        assert_eq!(decoded_extra_data.committed_seals.len(), mock_final_state_v1.quorum_size() as usize);

        assert_eq!(mock_observer_v1.blocks_imported(), 1);
        let observed_block_hash = mock_observer_v1.get_observed_block_hashes().remove(0);
        assert_eq!(observed_block_hash, imported_block.hash(), "Observed block hash should match the hash of the block after extra_data modification");

        // Based on BHM logs, V1 (local node) is NOT the proposer for round (1,0) in this test.
        // Therefore, it should not have sent any proposals itself.
        // If this fails with left > 0, it means V1 is erroneously sending proposals.
        assert_eq!(mock_multicaster_v1.proposals.lock().unwrap().len(), 0, "V1 (local node) should not have sent any proposals as it was not the proposer for round (1,0) per BHM startup logs");
        assert_eq!(mock_multicaster_v1.prepares.lock().unwrap().len(), 1);
        assert_eq!(mock_multicaster_v1.commits.lock().unwrap().len(), 1);
    }

    #[test]
    fn test_bhm_round_timeout_initiates_round_change_does_not_advance_without_quorum() {
        // Setup: N=4 (V1 local, V2, V3, V4). F=1. RC Quorum = F+1 = 2.
        // V1 is in round 0. Round 0 times out. V1 sends RC for R1.
        // With only its own RC, V1 should not advance to R1.

        let key_v1_local = deterministic_node_key(21);
        let addr_v1_local = address_from_arc_key(&key_v1_local);
        let key_v2 = deterministic_node_key(22);
        let addr_v2 = address_from_arc_key(&key_v2);
        let key_v3 = deterministic_node_key(23);
        let addr_v3 = address_from_arc_key(&key_v3);
        let key_v4 = deterministic_node_key(24);
        let addr_v4 = address_from_arc_key(&key_v4);

        let mut all_addresses_for_sort = vec![addr_v1_local, addr_v2, addr_v3, addr_v4];
        all_addresses_for_sort.sort();
        let validators: HashSet<Address> = all_addresses_for_sort.iter().cloned().collect();
        assert_eq!(validators.len(), 4);

        let parent_block_num = 0u64;
        let sequence_number = parent_block_num + 1;
        let round_0_num = 0u32;
        let round_0_id = ConsensusRoundIdentifier::new(sequence_number, round_0_num);
        let round_1_num = 1u32;
        let round_1_id = ConsensusRoundIdentifier::new(sequence_number, round_1_num);

        let parent_h = simple_parent_header(parent_block_num, B256::random());
        let arc_parent_h = Arc::new(parent_h.clone());
        let config = default_test_qbft_config();
        let test_codec = Arc::new(AlloyBftExtraDataCodec::default());

        let mock_final_state_v1 = Arc::new(MockQbftFinalState::new(key_v1_local.clone(), validators.clone()));
        // F = (4-1)/3 = 1. RoundChangeManager quorum = F+1 = 2.
        assert_eq!(mock_final_state_v1.get_byzantine_fault_tolerance(), 1, "F should be 1 for N=4");
        // The RoundChangeManager is created with quorum final_state.get_byzantine_fault_tolerance() + 1

        let local_mf_v1 = Arc::new(MessageFactory::new(key_v1_local.clone()).unwrap());
        
        // Determine proposer for R0 to set up block creator correctly
        let proposer_addr_r0 = mock_final_state_v1.get_proposer_for_round(&round_0_id).unwrap();
        let key_for_proposer_r0 = if proposer_addr_r0 == addr_v1_local { key_v1_local.clone() }
                                else if proposer_addr_r0 == addr_v2 { key_v2.clone() }
                                else if proposer_addr_r0 == addr_v3 { key_v3.clone() }
                                else { key_v4.clone() };
        let block_creator_final_state_r0 = Arc::new(MockQbftFinalState::new(key_for_proposer_r0.clone(), validators.clone()));
        let mock_block_creator_r0 = Arc::new(MockQbftBlockCreator::new(arc_parent_h.clone(), block_creator_final_state_r0, test_codec.clone()));

        let mock_block_importer_v1 = Arc::new(MockQbftBlockImporter::default());
        let mock_multicaster_v1 = Arc::new(MockValidatorMulticaster::default());
        let mock_block_timer_v1 = Arc::new(MockBlockTimer::new(config.block_period_seconds));
        let mock_round_timer_v1 = Arc::new(MockRoundTimer::new()); // Round timer for BHM
        
        // Actual MessageValidatorFactory for BHM's internal RoundChangeMessageValidatorImpl
        let actual_msg_validator_factory = Arc::new(ConfigurableMockMessageValidatorFactory::new());
        // Mock RoundChangeMessageValidatorFactory for BHM constructor (panics if create_round_change_message_validator is called)
        // We will be calling add_round_change_message directly to RoundChangeManager which uses its own validator.
        let mock_rc_msg_val_factory = Arc::new(MockRoundChangeMessageValidatorFactory);


        let proposal_validator = actual_msg_validator_factory.clone().create_proposal_validator();
        let prepare_validator = actual_msg_validator_factory.clone().create_prepare_validator();
        let commit_validator = actual_msg_validator_factory.clone().create_commit_validator();
        
        let mut bhm_v1 = setup_bhm(
            arc_parent_h.clone(), mock_final_state_v1.clone(), mock_block_creator_r0.clone(), 
            mock_block_importer_v1.clone(), local_mf_v1.clone(), mock_multicaster_v1.clone(), 
            mock_block_timer_v1.clone(), mock_round_timer_v1.clone(), test_codec.clone(), config.clone(),
            proposal_validator, prepare_validator, commit_validator, 
            actual_msg_validator_factory.clone(), // Pass the actual factory
            mock_rc_msg_val_factory.clone(),    // Pass the mock factory for the BHM constructor param
            vec![Arc::new(MockObserver::default())],
        );

        // V1 starts consensus for R0.
        // If V1 is proposer, it will propose and send Prepare. If not, it just starts the round.
        bhm_v1.start_consensus().expect("BHM start_consensus failed for V1");
        assert_eq!(*bhm_v1.current_round.as_ref().unwrap().round_identifier(), round_0_id, "BHM should be in R0");
        
        // Round 0 was not prepared (at most V1's own prepare if it was proposer).
        // So, get_prepared_round_metadata_for_round_change should return None.
        let metadata_before_timeout = bhm_v1.current_round.as_ref().unwrap().get_prepared_round_metadata_for_round_change();
        assert!(metadata_before_timeout.is_none(), "Round 0 should not have prepared metadata before timeout");

        // Action: Round 0 times out
        let timeout_result = bhm_v1.handle_round_timeout_event(round_0_id);
        assert!(timeout_result.is_ok(), "handle_round_timeout_event failed: {:?}", timeout_result.err());

        // Assertions
        // 1. V1 should have multicast a RoundChange message for round_1_id
        let sent_round_changes = mock_multicaster_v1.round_changes.lock().unwrap();
        assert_eq!(sent_round_changes.len(), 1, "V1 should have sent one RoundChange message");
        let round_change_msg = sent_round_changes.get(0).unwrap();
        assert_eq!(*round_change_msg.round_identifier(), round_1_id, "Sent RoundChange has incorrect target round ID");
        assert_eq!(round_change_msg.author().unwrap(), addr_v1_local, "Sent RoundChange author mismatch");
        assert!(round_change_msg.payload().prepared_round_metadata.is_none(), "Sent RoundChange should not have prepared metadata");
        assert!(round_change_msg.payload().prepared_block.is_none(), "Sent RoundChange should not have prepared block");

        // 2. V1's RoundChangeManager should contain this message
        let rcm_messages_for_r1 = bhm_v1.round_change_manager.get_round_change_messages_for_target_round(&round_1_id);
        assert!(rcm_messages_for_r1.is_some(), "RoundChangeManager should have messages for R1");
        assert_eq!(rcm_messages_for_r1.unwrap().len(), 1, "RoundChangeManager should have 1 message for R1");

        // 3. BHM should NOT have advanced to Round 1 yet (quorum for RC is 2, only has 1)
        assert_eq!(*bhm_v1.current_round.as_ref().unwrap().round_identifier(), round_0_id, "BHM should still be in Round 0 as quorum not met");
        
        // 4. Timer for Round 0 should have been cancelled by advance_to_new_round (called by start_consensus)
        //    And timer for Round 1 should have been started by `create_round_change` -> `add_round_change` -> `advance_to_new_round` (if it advanced)
        //    Since it didn't advance, only R0 timer started by QbftRound::new and then cancelled by itself if timeout logic was internal to round
        //    OR cancelled by BHM.advance_to_new_round when it created R0.
        //    The handle_round_timeout_event does NOT start a new timer for R1 unless it advances.
        //    The previous R0 timer was started by QbftRound::new(). It should now be cancelled by BHM.advance_to_new_round when it created R0.
        //    Let's verify current_round (R0) timer is active (started by its own constructor) and round_1_timer is NOT (because no advance)
        //    Actually, when R0 is created by advance_to_new_round, its timer is started.
        //    When handle_round_timeout_event is called for R0, and advance_to_new_round is NOT called for R1,
        //    the R0 timer should still be conceptually "timed out" but not explicitly cancelled by BHM *unless* BHM advanced to R1.
        //    What we *can* check is that a timer for R1 was *not* started.
        let active_timers = mock_round_timer_v1.get_active_timers();
        assert!(active_timers.contains(&round_0_id), "Timer for Round 0 should have been started"); // It might still be "active" in mock until explicitly cancelled
        assert!(!active_timers.contains(&round_1_id), "Timer for Round 1 should NOT have been started as BHM did not advance");
    }

} 