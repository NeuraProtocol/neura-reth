use std::sync::Arc;
use crate::types::{
    QbftBlockHeader, QbftFinalState, BlockTimer, RoundTimer, QbftBlockImporter, ValidatorMulticaster, BftExtraDataCodec, 
    ConsensusRoundIdentifier, QbftBlockCreatorFactory
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

        let message_validator = self.message_validator_factory.create_message_validator(
            &parent_header, 
            self.final_state_provider.clone(),
            self.extra_data_codec.clone(),
            self.round_change_message_validator_factory.clone()
        )?;
        let round_change_message_validator = self.round_change_message_validator_factory.create_round_change_message_validator(
            &parent_header, 
            self.final_state_provider.clone()
        )?;
        let block_creator = self.block_creator_factory.create_block_creator(
            &parent_header, 
            self.final_state_provider.clone()
        )?;

        let mut height_manager = QbftBlockHeightManager::new(
            parent_header.clone(),
            self.final_state_provider.clone(),
            block_creator,
            self.block_importer.clone(),
            self.message_factory.clone(),
            self.validator_multicaster.clone(),
            self.block_timer.clone(),
            self.round_timer.clone(),
            self.extra_data_codec.clone(),
            message_validator,
            round_change_message_validator,
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

    fn create_height_manager(&self, parent_header: &QbftBlockHeader) -> Result<QbftBlockHeightManager, QbftError> {
        let block_number = parent_header.number + 1;

        // Determine the proposer for the first round (round 0) at this new height.
        let validators = self.final_state_provider.get_validators_for_block(block_number)?;
        if validators.is_empty() {
            return Err(QbftError::NoValidators);
        }
        let proposer_index = (block_number as usize) % validators.len();
        let _proposer_address = validators[proposer_index]; // Prefixed with _ // This is for MessageValidator config if it needs initial proposer

        // Create a MessageValidator instance for this height.
        // Note: MessageValidator constructor might not need proposer_address directly if it's derived from final_state + round_id.
        // The trait for MessageValidatorFactory::create_message_validator expects parent_header, final_state, codec, and rc_validator_factory.
        // It does not take block_number or proposer_address directly in its trait signature.
        // The `MessageValidator` itself might use these via the `final_state_provider`.
        let message_validator = self.message_validator_factory.create_message_validator(
            parent_header, // Correct: parent_header
            self.final_state_provider.clone(), // Correct: final_state_view
            self.extra_data_codec.clone(),     // Correct: extra_data_codec
            self.round_change_message_validator_factory.clone() // Correct: round_change_message_validator_factory
        )?;

        // Create RoundChangeMessageValidator for this height
        let round_change_message_validator = self.round_change_message_validator_factory.create_round_change_message_validator(
            parent_header,
            self.final_state_provider.clone()
        )?;

        // Create BlockCreator for this height
        let block_creator = self.block_creator_factory.create_block_creator(
            parent_header, 
            self.final_state_provider.clone()
        )?;

        let height_manager = QbftBlockHeightManager::new(
            parent_header.clone(), // BHM takes parent_header by value
            self.final_state_provider.clone(),
            block_creator, // Pass the created Arc<dyn QbftBlockCreator>
            self.block_importer.clone(),
            self.message_factory.clone(), 
            self.validator_multicaster.clone(),
            self.block_timer.clone(), 
            self.round_timer.clone(),
            self.extra_data_codec.clone(),
            message_validator, // The specific message validator for this height
            round_change_message_validator, // The specific RC validator for this height
            self.mined_block_observers.clone(),
        );
        Ok(height_manager)
    }

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