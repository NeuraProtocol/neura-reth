use std::sync::Arc;
use crate::types::{
    ConsensusRoundIdentifier, QbftBlockHeader, QbftFinalState, 
    BlockTimer, RoundTimer, QbftBlockCreator, QbftBlockImporter, ValidatorMulticaster,
    BftExtraDataCodec, QbftBlock
};
use crate::statemachine::{
    QbftRound, RoundChangeManager, RoundChangeArtifacts, QbftMinedBlockObserver
};
use crate::payload::{MessageFactory, PreparedRoundMetadata};
use crate::validation::{MessageValidator, RoundChangeMessageValidator}; // Assuming these are configured and passed in
use crate::error::QbftError;
use crate::messagewrappers::{Proposal, Prepare, Commit, RoundChange};
 // For proposerded import


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
    message_validator: MessageValidator, // Configured for this height/validators
    round_change_message_validator: RoundChangeMessageValidator, // Configured
    mined_block_observers: Vec<Arc<dyn QbftMinedBlockObserver>>,

    current_round: Option<QbftRound>, // The active round manager
    round_change_manager: RoundChangeManager,
    // TODO: state like current_round_identifier, is_committed_locally etc.
    locked_block: Option<QbftBlock>,
    finalized_block: Option<QbftBlock>,
    round_timeout_count: u32
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
        message_validator: MessageValidator, // Should be pre-configured for this height
        round_change_message_validator: RoundChangeMessageValidator, // Pre-configured
        mined_block_observers: Vec<Arc<dyn QbftMinedBlockObserver>>
    ) -> Self {
        let height = parent_header.number + 1;
        let round_change_validator = RoundChangeMessageValidator::new(final_state.clone(), parent_header.clone());
        let round_change_manager = RoundChangeManager::new(
            final_state.get_byzantine_fault_tolerance() + 1, // f+1 for round_change_quorum_size
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
            message_validator, 
            round_change_message_validator, // Stored for re-config if needed, or passed to RCM
            mined_block_observers,
            current_round: None,
            round_change_manager,
            locked_block: None,
            finalized_block: None,
            round_timeout_count: 0,
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
        if let Some(existing_round) = self.current_round.as_ref() {
            log::trace!("Cancelling timer for previous round: {:?}", existing_round.round_identifier());
            self.round_timer.cancel_timer(*existing_round.round_identifier());
        }

        let new_qbft_round = QbftRound::new(
            round_identifier,
            (*self.parent_header).clone(), // Deref and clone Arc<QbftBlockHeader>
            self.final_state.clone(),
            self.block_creator.clone(),
            self.block_importer.clone(),
            self.message_factory.clone(),
            self.validator_multicaster.clone(),
            self.round_timer.clone(),
            self.extra_data_codec.clone(),
            self.message_validator.clone(), // Assuming MessageValidator is configured for this height and can be cloned or is Arc'd
            self.mined_block_observers.clone(),
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
                current_round.handle_proposal_message(proposal)
            } else if proposal.round_identifier().round_number > current_round.round_identifier().round_number {
                log::debug!(
                    "Received Proposal for future round {:?} at current height {}. Current round is {:?}. Ignoring for now.",
                    proposal.round_identifier(), self.height, current_round.round_identifier()
                );
                // TODO: Potentially buffer future messages if a robust buffering strategy is implemented.
                Ok(())
            } else {
                log::debug!(
                    "Received Proposal for past round {:?} at current height {}. Current round is {:?}. Ignoring.",
                    proposal.round_identifier(), self.height, current_round.round_identifier()
                );
                Ok(())
            }
        } else {
            log::warn!("Received Proposal but no current round for height {}. Ignoring.", self.height);
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
                current_round.handle_prepare_message(prepare)
            } else if prepare.round_identifier().round_number > current_round.round_identifier().round_number {
                log::debug!(
                    "Received Prepare for future round {:?} at current height {}. Current round is {:?}. Ignoring for now.",
                    prepare.round_identifier(), self.height, current_round.round_identifier()
                );
                Ok(())
            } else {
                log::debug!(
                    "Received Prepare for past round {:?} at current height {}. Current round is {:?}. Ignoring.",
                    prepare.round_identifier(), self.height, current_round.round_identifier()
                );
                Ok(())
            }
        } else {
            log::warn!("Received Prepare but no current round for height {}. Ignoring.", self.height);
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
                current_round.handle_commit_message(commit)
            } else if commit.round_identifier().round_number > current_round.round_identifier().round_number {
                log::debug!(
                    "Received Commit for future round {:?} at current height {}. Current round is {:?}. Ignoring for now.",
                    commit.round_identifier(), self.height, current_round.round_identifier()
                );
                Ok(())
            } else {
                log::debug!(
                    "Received Commit for past round {:?} at current height {}. Current round is {:?}. Ignoring.",
                    commit.round_identifier(), self.height, current_round.round_identifier()
                );
                Ok(())
            }
        } else {
            log::warn!("Received Commit but no current round for height {}. Ignoring.", self.height);
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

        // Check if this RoundChange is for a round prior to or same as our current round (if any).
        // Such messages might be late/redundant unless they contribute to an f+1 for an even later round.
        // The RoundChangeManager's internal logic should handle this by not forming a quorum for an old round.
        if let Some(current_round_ref) = self.current_round.as_ref() {
            if target_round_identifier.round_number <= current_round_ref.round_identifier().round_number {
                log::debug!(
                    "Received RoundChange for past or current round {:?}. Current round is {:?}. Handing to RoundChangeManager.",
                    target_round_identifier, current_round_ref.round_identifier()
                );
            }
        }

        log::debug!("Dispatching RoundChange to RoundChangeManager for target round: {:?}", target_round_identifier);
        match self.round_change_manager.add_round_change_message(round_change) {
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
                let current_round_num = self.current_round.as_ref().map_or(0, |r| r.round_identifier().round_number);
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

        // Construct PreparedCertificate if current timed-out round was prepared.
        let prepared_certificate = self.current_round.as_ref().and_then(|cr| cr.construct_prepared_certificate());
        
        let prepared_round_metadata = prepared_certificate.as_ref().map(|cert| {
            PreparedRoundMetadata::new(cert.prepared_round, cert.block.hash(), cert.prepares.clone())
        });
        let prepared_block_for_wrapper = prepared_certificate.as_ref().map(|cert| cert.block.clone());
        let prepares_for_wrapper = prepared_certificate.map_or(Vec::new(), |cert| cert.prepares.clone());

        let round_change_message = self.message_factory.create_round_change(
            new_target_round_id,
            prepared_round_metadata,
            prepared_block_for_wrapper,
            prepares_for_wrapper,
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
        if self.locked_block.is_none() || block.header.number > self.locked_block.as_ref().unwrap().header.number {
            self.locked_block = Some(block.clone());
            // TODO: Further logic if needed when a block is locked
        }

        // For QBFT, a block is final once committed by a 2F+1 quorum in a round.
        self.finalized_block = Some(block.clone());
        log::info!(target: "consensus", "Height {}: Block {:?} finalized in round {}.", self.height, block.hash(), round_number);
        
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
        let _current_round_number = self.current_round.as_ref().map(|cr| cr.round_identifier().round_number).unwrap_or(0); // Prefixed with _
        self.round_change_manager.lowest_future_round_with_early_quorum(
            _current_round_number, 
            self.height
        )
    }

    fn send_round_change_message(&mut self, target_round_num: u32, is_timeout: bool) -> Result<(), QbftError> {
        let new_target_round_id = ConsensusRoundIdentifier {
            sequence_number: self.height,
            round_number: target_round_num,
        };

        // Get PreparedRoundMetadata if current round is prepared
        let prepared_round_metadata_opt: Option<PreparedRoundMetadata> = self.current_round.as_ref()
            .and_then(|cr| cr.get_prepared_round_metadata_for_round_change());

        let prepared_block_opt: Option<QbftBlock> = if prepared_round_metadata_opt.is_some() {
            self.current_round.as_ref().and_then(|cr| cr.round_state().proposed_block().cloned())
        } else {
            None
        };
        
        if prepared_round_metadata_opt.is_some() && 
           (prepared_block_opt.is_none() || prepared_block_opt.as_ref().unwrap().hash() != prepared_round_metadata_opt.as_ref().unwrap().prepared_block_hash) {
            log::error!(
                "Inconsistency when creating RoundChange: Prepared metadata present but block is missing or hash mismatch. Metadata: {:?}, Block: {:?}",
                prepared_round_metadata_opt, prepared_block_opt.as_ref().map(|b| b.hash())
            );
            // Fallback to sending without prepared info
            
            let own_round_change = self.message_factory.create_round_change(
                new_target_round_id, 
                None, // Send without cert
                None  // Send without cert block
            )?;
            self.validator_multicaster.multicast_round_change(&own_round_change);
            return Ok(());
        }

        log::debug!(
            "Sending RoundChange for target round {:?}. Timeout: {}. Prepared metadata: {:?}, Prepared block: {:?}",
            new_target_round_id, is_timeout, prepared_round_metadata_opt.is_some(), prepared_block_opt.is_some()
        );

        let own_round_change = self.message_factory.create_round_change(
            new_target_round_id, 
            prepared_round_metadata_opt, 
            prepared_block_opt
        )?;
        self.validator_multicaster.multicast_round_change(&own_round_change);
        self.handle_round_change_message(own_round_change)
    }
} 