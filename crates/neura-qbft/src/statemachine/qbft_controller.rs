use std::sync::Arc;
use crate::types::{
    QbftBlockHeader, QbftFinalState, BlockTimer, RoundTimer, QbftBlockImporter, ValidatorMulticaster, BftExtraDataCodec, 
    ConsensusRoundIdentifier, QbftBlockCreatorFactory, QbftConfig
};
use crate::statemachine::{QbftBlockHeightManager, QbftMinedBlockObserver};
use crate::payload::MessageFactory;
use crate::validation::{MessageValidatorFactory, RoundChangeMessageValidatorFactory};
use crate::error::QbftError;
use crate::messagewrappers::{Proposal, Prepare, Commit, RoundChange};

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
        }
    }

    /// Starts or restarts consensus for a new block height, using the given parent header.
    pub fn start_consensus_at_height(&mut self, parent_header: QbftBlockHeader) -> Result<(), QbftError> {
        let target_height = parent_header.number + 1;
        log::info!("QbftController: Attempting to start consensus for height {}", target_height);

        if let Some(existing_manager) = &self.current_height_manager {
            if existing_manager.height() >= target_height {
                log::warn!(
                    "QbftController: Consensus for height {} or later already active (current: {}). Ignoring request.",
                    target_height, existing_manager.height()
                );
                return Ok(());
            }
            // If starting a new height, the old one is implicitly abandoned or should have completed.
            // TODO: Add explicit cleanup or check for completion of the old manager if necessary.
            log::info!("QbftController: Replacing existing consensus manager for height {} with new one for height {}", existing_manager.height(), target_height);
        }

        // Create individual validators using the factory
        let proposal_validator = self.message_validator_factory.create_proposal_validator();
        let prepare_validator = self.message_validator_factory.create_prepare_validator();
        let commit_validator = self.message_validator_factory.create_commit_validator();

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
        log::trace!("QbftController: Discarding Proposal for non-current height or no active manager. Proposal: {:?}", proposal.round_identifier());
        Ok(())
    }

    pub fn handle_prepare_message(&mut self, prepare: Prepare) -> Result<(), QbftError> {
        if let Some(manager) = self.current_height_manager.as_mut() {
            if prepare.round_identifier().sequence_number == manager.height() {
                return manager.handle_prepare_message(prepare);
            }
        }
        log::trace!("QbftController: Discarding Prepare for non-current height or no active manager. Prepare: {:?}", prepare.round_identifier());
        Ok(())
    }

    pub fn handle_commit_message(&mut self, commit: Commit) -> Result<(), QbftError> {
        if let Some(manager) = self.current_height_manager.as_mut() {
            if commit.round_identifier().sequence_number == manager.height() {
                return manager.handle_commit_message(commit);
            }
        }
        log::trace!("QbftController: Discarding Commit for non-current height or no active manager. Commit: {:?}", commit.round_identifier());
        Ok(())
    }

    pub fn handle_round_change_message(&mut self, round_change: RoundChange) -> Result<(), QbftError> {
        if let Some(manager) = self.current_height_manager.as_mut() {
            if round_change.round_identifier().sequence_number == manager.height() {
                return manager.handle_round_change_message(round_change);
            }
        }
        log::trace!("QbftController: Discarding RoundChange for non-current height or no active manager. RoundChange: {:?}", round_change.round_identifier());
        Ok(())
    }

    // --- Timer Event Dispatchers ---
    pub fn handle_round_timeout_event(&mut self, timed_out_round_id: ConsensusRoundIdentifier) -> Result<(), QbftError> {
        if let Some(manager) = self.current_height_manager.as_mut() {
            if timed_out_round_id.sequence_number == manager.height() {
                return manager.handle_round_timeout_event(timed_out_round_id);
            }
        }
        log::trace!("QbftController: Discarding RoundTimeout for non-current height or no active manager. Round: {:?}", timed_out_round_id);
        Ok(())
    }

    // TODO: handle_block_timer_event if the BlockTimer itself emits events.
    // Current design uses BlockTimer more as a utility for timestamp calculation.

    pub fn on_new_block_header(&mut self, header: &QbftBlockHeader) -> Result<(), QbftError> {
        // This would be called when a new block is externally observed (e.g., from network sync)
        // It might trigger state updates, potentially halting local proposal if a valid future block is seen.
        let _block_number = header.number; // Prefixed with _
        log::info!(
            "Observed new block header via on_new_block_header: Number={}, Hash={:?}. QBFT controller may update its state.", 
            header.number, header.hash()
        );
        Ok(())
    }
} 