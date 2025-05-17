use std::sync::Arc;
use crate::types::{
    QbftBlockHeader, QbftFinalState, BlockTimer, RoundTimer, QbftBlockImporter, ValidatorMulticaster, BftExtraDataCodec, 
    ConsensusRoundIdentifier, QbftBlockCreatorFactory, QbftConfig
};
use crate::statemachine::{QbftBlockHeightManager, QbftMinedBlockObserver};
use crate::payload::MessageFactory;
use crate::validation::{ValidationContext, MessageValidatorFactory, RoundChangeMessageValidatorFactory};
use crate::error::QbftError;
use crate::messagewrappers::{Proposal, Prepare, Commit, RoundChange};
use tokio::sync::mpsc::{self, Receiver, Sender};
use tracing::{info, warn, trace};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControllerEvent {
    StartConsensus(QbftBlockHeader), // Parent header to start from
    // Network Messages
    ReceivedProposal(Box<Proposal>),
    ReceivedPrepare(Box<Prepare>),
    ReceivedCommit(Box<Commit>),
    ReceivedRoundChange(Box<RoundChange>),
    // Internal Timer Events
    RoundTimeout(ConsensusRoundIdentifier),
    BlockTimerFired(u64), // u64 is the sequence number
    // External Triggers/Observations
    ObservedNewBlock(Box<QbftBlockHeader>), // A new block observed from network/sync
}

// The QbftController is the main entry point for QBFT consensus events.
// It manages instances of QbftBlockHeightManager for specific block heights.
pub struct QbftController {
    // Dependencies needed to create QbftBlockHeightManager instances
    final_state_provider: Arc<dyn QbftFinalState>,
    block_creator_factory: Arc<dyn QbftBlockCreatorFactory>,
    block_importer: Arc<dyn QbftBlockImporter>,
    message_factory: Arc<MessageFactory>,
    validator_multicaster: Arc<dyn ValidatorMulticaster>,
    block_timer: Arc<dyn BlockTimer>,
    round_timer: Arc<dyn RoundTimer>,
    extra_data_codec: Arc<dyn BftExtraDataCodec>,
    message_validator_factory: Arc<dyn MessageValidatorFactory>,
    round_change_message_validator_factory: Arc<dyn RoundChangeMessageValidatorFactory>,
    mined_block_observers: Vec<Arc<dyn QbftMinedBlockObserver>>,
    config: Arc<QbftConfig>,

    current_height_manager: Option<QbftBlockHeightManager>,
    // In Besu, there's also a concept of a "future_height_manager" for working ahead.
    // For now, we'll focus on a single active height.

    external_event_sender: Sender<ControllerEvent>,
    external_event_receiver: Receiver<ControllerEvent>, // Added for completeness, might be used by a run loop
}

impl QbftController {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        final_state_provider: Arc<dyn QbftFinalState>,
        block_creator_factory: Arc<dyn QbftBlockCreatorFactory>,
        block_importer: Arc<dyn QbftBlockImporter>,
        message_factory: Arc<MessageFactory>,
        validator_multicaster: Arc<dyn ValidatorMulticaster>,
        block_timer: Arc<dyn BlockTimer>,
        round_timer: Arc<dyn RoundTimer>,
        extra_data_codec: Arc<dyn BftExtraDataCodec>,
        message_validator_factory: Arc<dyn MessageValidatorFactory>,
        round_change_message_validator_factory: Arc<dyn RoundChangeMessageValidatorFactory>,
        mined_block_observers: Vec<Arc<dyn QbftMinedBlockObserver>>,
        config: Arc<QbftConfig>,
    ) -> Self {
        let (tx, rx) = mpsc::channel(100); // Channel for external events
        Self {
            final_state_provider,
            block_creator_factory,
            block_importer,
            message_factory,
            validator_multicaster,
            block_timer,
            round_timer,
            extra_data_codec,
            message_validator_factory,
            round_change_message_validator_factory,
            mined_block_observers,
            config,
            current_height_manager: None,
            external_event_sender: tx,
            external_event_receiver: rx,
        }
    }

    pub fn message_validator_factory(&self) -> Arc<dyn MessageValidatorFactory> {
        self.message_validator_factory.clone()
    }

    pub fn round_change_message_validator_factory(&self) -> Arc<dyn RoundChangeMessageValidatorFactory> {
        self.round_change_message_validator_factory.clone()
    }

    /// Starts or restarts consensus for a new block height, using the given parent header.
    pub fn start_consensus_at_height(&mut self, parent_header: QbftBlockHeader) -> Result<(), QbftError> {
        let target_height = parent_header.number + 1;
        info!("QbftController: Attempting to start consensus for height {}", target_height);

        if let Some(existing_manager) = &self.current_height_manager {
            if existing_manager.height() >= target_height {
                warn!(
                    "QbftController: Consensus for height {} or later already active (current: {}). Ignoring request.",
                    target_height, existing_manager.height()
                );
                return Ok(());
            }
            info!("QbftController: Replacing existing consensus manager for height {} with new one for height {}", existing_manager.height(), target_height);
        }

        let proposal_validator = self.message_validator_factory.clone().create_proposal_validator();
        let prepare_validator = self.message_validator_factory.clone().create_prepare_validator();
        let commit_validator = self.message_validator_factory.clone().create_commit_validator();

        let block_creator = self.block_creator_factory.create_block_creator(
            &parent_header, 
            self.final_state_provider.clone()
        )?;

        let mut height_manager = QbftBlockHeightManager::new(
            Arc::new(parent_header),
            self.final_state_provider.clone(),
            block_creator,
            self.block_importer.clone(),
            self.message_factory.clone(),
            self.validator_multicaster.clone(),
            self.block_timer.clone(),
            self.round_timer.clone(),
            self.extra_data_codec.clone(),
            self.config.clone(),
            proposal_validator,
            prepare_validator,
            commit_validator,
            self.message_validator_factory.clone(),
            self.round_change_message_validator_factory.clone(),
            self.mined_block_observers.clone(),
        );

        height_manager.start_consensus()?;
        self.current_height_manager = Some(height_manager);
        Ok(())
    }

    // --- Message Dispatchers ---
    pub fn handle_proposal_message(&mut self, proposal: Proposal) -> Result<(), QbftError> {
        if let Some(manager) = self.current_height_manager.as_mut() {
            if proposal.round_identifier().sequence_number == manager.height() {
                return manager.handle_proposal_message(proposal);
            }
        }
        trace!("QbftController: Discarding Proposal for non-current height or no active manager. Proposal: {:?}", proposal.round_identifier());
        Ok(())
    }

    pub fn handle_prepare_message(&mut self, prepare: Prepare) -> Result<(), QbftError> {
        if let Some(manager) = self.current_height_manager.as_mut() {
            if prepare.round_identifier().sequence_number == manager.height() {
                return manager.handle_prepare_message(prepare);
            }
        }
        trace!("QbftController: Discarding Prepare for non-current height or no active manager. Prepare: {:?}", prepare.round_identifier());
        Ok(())
    }

    pub fn handle_commit_message(&mut self, commit: Commit) -> Result<(), QbftError> {
        if let Some(manager) = self.current_height_manager.as_mut() {
            if commit.round_identifier().sequence_number == manager.height() {
                return manager.handle_commit_message(commit);
            }
        }
        trace!("QbftController: Discarding Commit for non-current height or no active manager. Commit: {:?}", commit.round_identifier());
        Ok(())
    }

    pub fn handle_round_change_message(&mut self, round_change: RoundChange) -> Result<(), QbftError> {
        if let Some(manager) = self.current_height_manager.as_mut() {
            if round_change.round_identifier().sequence_number == manager.height() {
                return manager.handle_round_change_message(round_change);
            }
        }
        trace!("QbftController: Discarding RoundChange for non-current height or no active manager. RoundChange: {:?}", round_change.round_identifier());
        Ok(())
    }

    // --- Timer Event Dispatchers ---
    pub fn handle_round_timeout_event(&mut self, timed_out_round_id: ConsensusRoundIdentifier) -> Result<(), QbftError> {
        if let Some(manager) = self.current_height_manager.as_mut() {
            if timed_out_round_id.sequence_number == manager.height() {
                return manager.handle_round_timeout_event(timed_out_round_id);
            }
        }
        // log::trace!("QbftController: Discarding RoundTimeout for non-current height or no active manager. Round: {:?}", timed_out_round_id);
        Ok(())
    }

    // TODO: Implement handle_block_timer_event dispatcher if needed, or ensure BHM handles it via RoundTimer.
    // For now, BlockTimerFired event will be dispatched directly to the BHM if the height matches.
    pub fn handle_block_timer_event(&mut self, sequence_number: u64) -> Result<(), QbftError> {
        if let Some(manager) = self.current_height_manager.as_mut() {
            if sequence_number == manager.height() {
                log::debug!(
                    "QbftController: Received BlockTimerFired for height {}, passing to BHM to handle expiry.", 
                    sequence_number
                );
                return manager.handle_block_timer_expiry();
            } else {
                log::trace!(
                    "QbftController: Discarding BlockTimerFired for height {} as current manager is for height {}.",
                    sequence_number, manager.height()
                );
            }
        } else {
            log::trace!(
                "QbftController: Discarding BlockTimerFired for height {} as no current BHM is active.",
                sequence_number
            );
        }
        Ok(())
    }

    pub fn on_new_block_header(&mut self, header: &QbftBlockHeader) -> Result<(), QbftError> {
        let _block_number = header.number; 
        info!(
            "Observed new block header via on_new_block_header: Number={}, Hash={:?}. QBFT controller may update its state.", 
            header.number, header.hash()
        );
        Ok(())
    }

    pub fn validate_header_for_proposal(
        &self,
        header: &QbftBlockHeader,
        final_state: Arc<dyn QbftFinalState>, // Use the passed-in final_state for context
    ) -> Result<(), QbftError> {
        let proposal_validator = self.message_validator_factory.clone().create_proposal_validator();

        let current_sequence_number = header.number;
        let current_round_number = 0; // Assume round 0 for standalone header validation as proposal candidate

        // Simplified: The ProposalValidatorImpl will handle cases like genesis
        // or missing parent internally.
        let parent_header_for_context = final_state.get_block_header(&header.parent_hash).map(Arc::new);
        
        // Validators are determined based on the parent block for non-genesis.
        // For genesis (header.number == 0), validators would come from genesis config or be empty,
        // depending on how initial validators are established.
        // The ProposalValidator should handle this appropriately based on its logic.
        // Let's assume get_validators_for_block handles block_number 0 correctly if it's a genesis-like scenario.
        let validators_for_context = if header.number == 0 {
            // For genesis, validators might be defined in the header itself or via config.
            // If QbftFinalState::get_validators_for_block(0) is expected to return genesis validators, use that.
            // Or, if they are in header.extra_data, that's handled by validate_block_header_for_proposal's decode.
            // For now, let's rely on what the final_state provides for block 0, or an empty set if none.
            // This matches how current_validators in RethQbftFinalState might behave for best_block_number=0.
             final_state.get_validators_for_block(0)?
        } else {
            final_state.get_validators_for_block(header.number.saturating_sub(1))?
        };
        
        let round_id_for_proposer = ConsensusRoundIdentifier::new(current_sequence_number, current_round_number);
        let expected_proposer = final_state.get_proposer_for_round(&round_id_for_proposer)?;

        let context = ValidationContext::new(
            current_sequence_number,
            current_round_number,
            validators_for_context.into_iter().collect(),
            parent_header_for_context, // Pass the Option<Arc<QbftBlockHeader>> directly
            final_state, // Use the passed-in final_state
            Arc::clone(&self.extra_data_codec),
            Arc::clone(&self.config),
            None, // No accepted proposal digest for this standalone check
            expected_proposer,
        );

        proposal_validator.validate_block_header_for_proposal(header, &context)
    }

    /// The main event processing loop for the QbftController.
    pub async fn run(&mut self) -> Result<(), QbftError> {
        log::info!("QbftController event loop started.");
        loop {
            if let Some(event) = self.external_event_receiver.recv().await {
                log::trace!("QbftController: Received event: {:?}", event);
                match event {
                    ControllerEvent::StartConsensus(parent_header) => {
                        if let Err(e) = self.start_consensus_at_height(parent_header) {
                            log::error!("QbftController: Error starting consensus: {:?}", e);
                        }
                    }
                    ControllerEvent::ReceivedProposal(proposal) => {
                        if let Err(e) = self.handle_proposal_message(*proposal) {
                            log::error!("QbftController: Error handling Proposal: {:?}", e);
                        }
                    }
                    ControllerEvent::ReceivedPrepare(prepare) => {
                        if let Err(e) = self.handle_prepare_message(*prepare) {
                            log::error!("QbftController: Error handling Prepare: {:?}", e);
                        }
                    }
                    ControllerEvent::ReceivedCommit(commit) => {
                        if let Err(e) = self.handle_commit_message(*commit) {
                            log::error!("QbftController: Error handling Commit: {:?}", e);
                        }
                    }
                    ControllerEvent::ReceivedRoundChange(round_change) => {
                        if let Err(e) = self.handle_round_change_message(*round_change) {
                            log::error!("QbftController: Error handling RoundChange: {:?}", e);
                        }
                    }
                    ControllerEvent::RoundTimeout(round_id) => {
                        if let Err(e) = self.handle_round_timeout_event(round_id) {
                            log::error!("QbftController: Error handling RoundTimeout: {:?}", e);
                        }
                    }
                    ControllerEvent::BlockTimerFired(sequence_number) => {
                         if let Err(e) = self.handle_block_timer_event(sequence_number) {
                            log::error!("QbftController: Error handling BlockTimerFired: {:?}", e);
                        }
                    }
                    ControllerEvent::ObservedNewBlock(header) => {
                        // This logic needs to be more robust.
                        // It should check if the new block extends the current chain head
                        // and if we should advance our consensus height.
                        log::info!("QbftController: Observed new block header (height {}). Potential height advancement.", header.number);
                        // Basic advancement: if it's the next expected block's parent
                        let should_advance = if let Some(manager) = &self.current_height_manager {
                             // If new header's number is the height the current manager is working on,
                             // and the current manager has finalized its block, and new header's parent is that finalized block.
                             // This is complex. Simpler: if header.number is what current_manager *was* working on.
                             // Or, if the new header means we should start consensus for header.number + 1
                            header.number >= manager.height() // Simplified: if observed block is at or ahead of our current target
                        } else {
                            true // No current manager, so any new block might be a trigger
                        };

                        if should_advance {
                             // We should start consensus for header.number + 1, making *header the parent.
                            if let Err(e) = self.start_consensus_at_height(*header) { // Pass the header as parent
                                log::error!("QbftController: Error starting consensus from ObservedNewBlock: {:?}", e);
                            }
                        }
                    }
                    // Placeholder for other events
                    /* _ => {
                        log::warn!("QbftController: Unhandled event: {:?}", event);
                    } */
                }
            } else {
                log::info!("QbftController: Event channel closed. Shutting down.");
                break;
            }
        }
        // Removed unreachable _ => {} arm, loop handles all events or breaks.
        Ok(())
    }

    /// Provides a way to send events to the controller from external sources (e.g., network layer).
    pub fn get_event_sender(&self) -> Sender<ControllerEvent> {
        self.external_event_sender.clone()
    }

    // Method to check if the controller is currently processing a given height.
    pub fn is_processing_height(&self, height: u64) -> bool {
        self.current_height_manager.as_ref().map_or(false, |manager| manager.height() == height)
    }
} 