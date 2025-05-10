use crate::error::QbftError;
// use std::collections::HashSet; // Removed based on build log
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::types::{
    ConsensusRoundIdentifier, QbftBlock, QbftBlockHeader, SignedData, /* BftExtraData, */ BftExtraDataCodec, QbftFinalState, QbftBlockCreator, 
    QbftBlockImporter, RoundTimer, ValidatorMulticaster, RlpSignature,
    // PreparedCertificate // Removed this line
};
use crate::statemachine::round_state::{RoundState, PreparedCertificate as RoundStatePreparedCertificate};
// Removed CommitPayload, ProposalPayload from payload import based on build log
use crate::payload::{MessageFactory, PreparePayload, RoundChangePayload, ProposalPayload, PreparedRoundMetadata};
use crate::messagewrappers::{Proposal, Prepare, Commit, RoundChange, PreparedCertificateWrapper, BftMessage};
// Removing this problematic line again, as the types are imported directly or aliased above.
// use crate::statemachine::{PreparedCertificate as StatemachinePreparedCertificate, RoundState as StatemachineRoundState};
// Removed Address, Bytes, keccak256 from alloy_primitives import based on build log
use alloy_primitives::B256 as Hash;
use crate::statemachine::round_change_manager::{RoundChangeArtifacts, CertifiedPrepareInfo};

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

    pub fn round_state(&self) -> &RoundState {
        &self.round_state
    }

    pub fn create_and_propose_block(&mut self, timestamp_seconds: u64) -> Result<(), QbftError> {
        log::debug!("Creating proposed block for round {:?}", self.round_identifier());
        let block = self.block_creator.create_block(
            &self.parent_header,
            self.round_identifier(),
            timestamp_seconds,
        )?;
        let block_hash_for_log = block.hash(); 
        self.propose_block(block, Vec::new(), None, block_hash_for_log)
    }
    
    pub fn start_round_with_prepared_artifacts(
        &mut self,
        round_change_artifacts: &RoundChangeArtifacts, 
        header_timestamp: u64,
    ) -> Result<(), QbftError> {
        let best_cert_option: Option<&CertifiedPrepareInfo> = round_change_artifacts.best_prepared_certificate();

        let (block_to_propose, block_hash_for_log, prepared_artifact_for_proposal) = 
            if let Some(cert_info) = best_cert_option {
                log::debug!(
                    "Re-proposing block from CertifiedPrepareInfo for round {:?}: Hash={:?}, Original Round={:?}", 
                    self.round_identifier(), cert_info.block.hash(), cert_info.prepared_round
                );
                (
                    cert_info.block.clone(), 
                    cert_info.block.hash(), 
                    Some((cert_info.original_signed_proposal.clone(), cert_info.prepares.clone()))
                )
            } else {
                log::debug!("Creating new block for round {:?} as no certified prepare info found.", self.round_identifier());
                let new_block = self.block_creator.create_block(
                    &self.parent_header, 
                    self.round_identifier(), 
                    header_timestamp
                )?;
                let new_block_hash = new_block.hash();
                (new_block, new_block_hash, None)
            };

        let piggybacked_round_changes = round_change_artifacts.round_changes().clone();
        
        self.propose_block(block_to_propose, piggybacked_round_changes, prepared_artifact_for_proposal, block_hash_for_log)
    }

    fn propose_block(
        &mut self,
        block: QbftBlock,
        round_change_payloads: Vec<SignedData<RoundChangePayload>>,
        prepared_certificate_artifact: Option<(BftMessage<ProposalPayload>, Vec<SignedData<PreparePayload>>)>,
        block_hash_for_log: Hash,
    ) -> Result<(), QbftError> {
        let round_change_proofs: Vec<RoundChange> = round_change_payloads
            .into_iter()
            .map(|rc_payload| RoundChange::new(rc_payload, None, None)) 
            .collect::<Result<Vec<RoundChange>, QbftError>>()?;

        let prepared_certificate_wrapper: Option<PreparedCertificateWrapper> = 
            if let Some((original_signed_proposal, prepare_payloads_from_cert)) = prepared_certificate_artifact {
                if prepare_payloads_from_cert.is_empty() {
                    log::warn!(
                        "Prepared certificate artifact provided but has no prepare payloads. Ignoring for wrapper."
                    );
                    None
                } else {
                    log::debug!(
                        "Constructing PreparedCertificateWrapper for new proposal in round {:?} using original proposal from round {:?}",
                        self.round_identifier(),
                        original_signed_proposal.payload().round_identifier
                    );
                    let prepares_for_wrapper: Vec<Prepare> = prepare_payloads_from_cert
                        .into_iter() 
                        .map(Prepare::new) 
                        .collect();
                                        
                    Some(PreparedCertificateWrapper::new(original_signed_proposal, prepares_for_wrapper))
                }
            } else {
                None
            };

        let proposal = self.message_factory.create_proposal(
            *self.round_identifier(),
            block.clone(),
            round_change_proofs,
            prepared_certificate_wrapper,
        )?;
        log::trace!("Proposing block {:?} for round {:?}", block_hash_for_log, self.round_identifier());
        self.round_state.set_proposal(proposal.clone())?;
        self.multicaster.multicast_proposal(&proposal);
        self.send_prepare(block, block_hash_for_log)
    }

    fn send_prepare(&mut self, _block: QbftBlock, block_digest: Hash) -> Result<(), QbftError> {
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
            "Handling Commit message for round {:?} from {:?}, digest: {:?}" ,
            self.round_identifier(),
            author,
            commit.payload().digest
        );

        match self.round_state.add_commit(commit.clone()) {
            Ok(_) => {
                if self.round_state.is_committed() {
                    log::trace!(
                        "Round {:?} is COMMITTED after receiving remote commit. Importing block.",
                        self.round_identifier()
                    );
                    // Attempt to import the block. If this fails, the round continues,
                    // but we might have a problem. If it succeeds, the round ends.
                    return self.import_block_to_chain();
                }
                Ok(())
            }
            Err(QbftError::ValidationError(reason)) => {
                 log::warn!(
                    "Invalid Commit message for round {:?}: {}. Ignoring.",
                    self.round_identifier(),
                    reason
                );
                 // Still return Ok(()) as per Besu logic for invalid messages unless they are fatal
                 Ok(())
            }
            Err(e) => {
                log::error!(
                    "Error processing Commit message for round {:?}: {}",
                    self.round_identifier(),
                    e
                );
                Err(e)
            }
        }
    }

    fn notify_new_block_listeners(&self, block: &QbftBlock) {
        for observer in &self.mined_block_observers {
            observer.block_imported(block);
        }
    }

    fn import_block_to_chain(&mut self) -> Result<(), QbftError> {
        if self.finalized_block_hash_in_round.is_some() {
            log::debug!(
                "Block for round {:?} already finalized and imported. Skipping.",
                self.round_identifier()
            );
            return Ok(());
        }

        let proposed_block = self.round_state.proposed_block().ok_or_else(|| {
            log::error!("Attempted to import block, but no proposal exists in round state for {:?}", self.round_identifier());
            QbftError::InvalidState("Cannot import block: No proposal in round state".to_string())
        })?;

        let commit_seals_signatures = self.round_state.get_commit_seals_if_committed().ok_or_else(|| {
            log::error!("Attempted to import block, but not enough commit seals for {:?}", self.round_identifier());
            QbftError::InvalidState("Cannot import block: Not enough commit seals".to_string())
        })?;
        
        // Convert alloy_primitives::Signature to RlpSignature for encoding in extra data
        let commit_seals_rlp: Vec<RlpSignature> = commit_seals_signatures.into_iter().map(RlpSignature).collect();

        log::debug!(
            "Importing block {:?} for round {:?} with {} commit seals.",
            proposed_block.hash(),
            self.round_identifier(),
            commit_seals_rlp.len()
        );

        let mut block_to_import = proposed_block.clone();
        
        // Create BftExtraData with the commit seals
        let mut bft_extra_data = self.extra_data_codec.decode(&block_to_import.header.extra_data)?;
        bft_extra_data.committed_seals = commit_seals_rlp;
        
        // Encode the updated BftExtraData back into the block header
        block_to_import.header.extra_data = self.extra_data_codec.encode(&bft_extra_data)?;
        // The block hash will change after updating extra_data, so it needs to be recalculated if used after this point for consistency,
        // though the block_importer should handle the final validation with the new hash.
        // For logging or internal state, ensure it's understood that block_to_import.hash() will be different now.

        match self.block_importer.import_block(&block_to_import) { // Pass by reference
            Ok(_) => {
                log::info!(
                    "Successfully imported block {:?} for round {:?}",
                    block_to_import.hash(), // Use the potentially new hash
                    self.round_identifier()
                );
                self.finalized_block_hash_in_round = Some(block_to_import.hash());
                self.notify_new_block_listeners(&block_to_import);
                self.cancel_timers(); // Stop round timer as round is complete
                // Potentially notify QbftBlockHeightManager that a block for this height is done.
                Ok(())
            }
            Err(e) => {
                log::error!(
                    "Failed to import block {:?} for round {:?}: {:?}",
                    block_to_import.hash(),
                    self.round_identifier(),
                    e // Assuming e is an error type that can be logged meaningfully
                );
                // This is a critical error. The QBFT spec might have guidance on how to proceed.
                // For now, we return an error. The round might need to be restarted or an error propagated upwards.
                Err(QbftError::BlockImportFailed(format!("Failed to import block: {:?}", e)))
            }
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

    pub fn get_prepared_round_metadata_for_round_change(&self) -> Option<PreparedRoundMetadata> {
        if self.round_state.is_prepared() {
            if let Some(proposal_wrapper) = self.round_state.proposal_message() { 
                let original_signed_proposal = proposal_wrapper.bft_message().clone(); 
                let block = proposal_wrapper.block(); 
                
                // Use the public getter for prepare messages
                let prepare_payloads: Vec<SignedData<PreparePayload>> = self.round_state.get_prepare_messages()
                    .into_iter()
                    .cloned() // Deref &SignedData to SignedData
                    .collect();
                
                // Use the public getter for quorum size
                if prepare_payloads.len() < self.round_state.quorum_size() { 
                     log::warn!(
                        "Attempted to get PreparedRoundMetadata for round {:?}, but not enough prepares ({}) for quorum ({}).", 
                        self.round_identifier(), prepare_payloads.len(), self.round_state.quorum_size()
                    );
                    return None;
                }

                Some(PreparedRoundMetadata::new(
                    self.round_identifier().round_number, 
                    block.hash(),
                    original_signed_proposal, 
                    prepare_payloads,
                ))
            } else {
                 log::warn!(
                    "Round {:?} is_prepared but has no proposal in RoundState. Cannot create PreparedRoundMetadata.", 
                    self.round_identifier()
                );
                None 
            }
        } else {
            None 
        }
    }
} 