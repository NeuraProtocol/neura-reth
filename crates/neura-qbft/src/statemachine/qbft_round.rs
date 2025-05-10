use crate::error::QbftError;
// use std::collections::HashSet; // Removed based on build log
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::types::{
    ConsensusRoundIdentifier, QbftBlock, QbftBlockHeader, SignedData, /* BftExtraData, */ BftExtraDataCodec, QbftFinalState, QbftBlockCreator, 
    QbftBlockImporter, RoundTimer, ValidatorMulticaster, RlpSignature, QbftConfig,
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
    #[allow(dead_code)] // Used by RoundState, which is owned by QbftRound
    final_state: Arc<dyn QbftFinalState>,
    block_creator: Arc<dyn QbftBlockCreator>,
    block_importer: Arc<dyn QbftBlockImporter>,
    message_factory: Arc<MessageFactory>,
    multicaster: Arc<dyn ValidatorMulticaster>,
    round_timer: Arc<dyn RoundTimer>,
    extra_data_codec: Arc<dyn BftExtraDataCodec>,
    mined_block_observers: Vec<Arc<dyn QbftMinedBlockObserver>>,
    locked_block: Option<CertifiedPrepareInfo>,
    #[allow(dead_code)] // Tied to send_proposal_if_new_block_available
    proposal_sent: bool,
    commit_sent: bool, // Tracks if this node has sent a commit for the current proposal
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
        config: Arc<QbftConfig>,
        mined_block_observers: Vec<Arc<dyn QbftMinedBlockObserver>>,
        initial_locked_info: Option<CertifiedPrepareInfo>,
    ) -> Self {
        let round_state = RoundState::new(
            round_identifier,
            message_validator, 
            final_state.quorum_size(),
        );
        round_timer.start_timer(round_identifier, config.message_round_timeout_ms);
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
            locked_block: initial_locked_info,
            proposal_sent: false,
            commit_sent: false, // Initialize commit_sent to false
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
        log::debug!("Attempting to create/retrieve block for proposal in round {:?}", self.round_identifier());

        let block_to_propose: QbftBlock;
        let prepared_certificate_artifact_for_proposal: Option<(BftMessage<ProposalPayload>, Vec<SignedData<PreparePayload>>)>;

        if let Some(locked_info) = &self.locked_block {
            log::info!(
                "CAPB: Found locked block from round {}. Re-proposing block {:?} for current round {:?}.", 
                locked_info.prepared_round, locked_info.block.hash(), self.round_identifier()
            );
            block_to_propose = locked_info.block.clone();
            prepared_certificate_artifact_for_proposal = Some((
                locked_info.original_signed_proposal.clone(),
                locked_info.prepares.clone(),
            ));
        } else {
            log::debug!(
                "CAPB: No locked block. Creating new block for round {:?}, timestamp {}.", 
                self.round_identifier(), timestamp_seconds
            );
            block_to_propose = self.block_creator.create_block(
                &self.parent_header,
                self.round_identifier(),
                timestamp_seconds,
            )?;
            prepared_certificate_artifact_for_proposal = None;
        }
        
        let block_hash_for_log = block_to_propose.hash(); 
        self.propose_block(block_to_propose, Vec::new(), prepared_certificate_artifact_for_proposal, block_hash_for_log)
    }
    
    pub fn start_round_with_prepared_artifacts(
        &mut self,
        round_change_artifacts: &RoundChangeArtifacts, 
        header_timestamp: u64,
    ) -> Result<(), QbftError> {
        let rc_cert_info_opt: Option<&CertifiedPrepareInfo> = round_change_artifacts.best_prepared_certificate();
        let locked_info_opt: Option<&CertifiedPrepareInfo> = self.locked_block.as_ref();

        let chosen_candidate: Option<&CertifiedPrepareInfo> = 
            match (rc_cert_info_opt, locked_info_opt) {
                (Some(rc_cert), Some(locked_cert)) => {
                    if rc_cert.prepared_round > locked_cert.prepared_round {
                        log::debug!(
                            "SRWPA: Preferring RoundChange Cert (round {}) over locked block (round {}).", 
                            rc_cert.prepared_round, locked_cert.prepared_round
                        );
                        Some(rc_cert)
                    } else if locked_cert.prepared_round > rc_cert.prepared_round {
                        log::debug!(
                            "SRWPA: Preferring locked block (round {}) over RoundChange Cert block (round {}).",
                            locked_cert.prepared_round, rc_cert.prepared_round
                        );
                        Some(locked_cert)
                    } else { // prepared_rounds are equal, use block hash tie-breaking (lower hash is better)
                        if rc_cert.block.hash() <= locked_cert.block.hash() { // Prefer RC cert on exact hash match too
                            log::debug!(
                                "SRWPA: Prepared rounds equal, preferring RoundChange Cert block by hash: RC hash {:?}, Locked hash {:?}", 
                                rc_cert.block.hash(), locked_cert.block.hash()
                            );
                            Some(rc_cert)
                        } else {
                            log::debug!(
                                "SRWPA: Prepared rounds equal, preferring Locked block by hash: Locked hash {:?}, RC hash {:?}", 
                                locked_cert.block.hash(), rc_cert.block.hash()
                            );
                            Some(locked_cert)
                        }
                    }
                }
                (Some(rc_cert), None) => {
                    log::debug!("SRWPA: Using block from RoundChange Cert as no locked block present.");
                    Some(rc_cert)
                }
                (None, Some(locked_cert)) => {
                    log::debug!("SRWPA: Using locked block as no RoundChange Cert present.");
                    Some(locked_cert)
                }
                (None, None) => {
                    log::debug!("SRWPA: No RoundChange Cert or locked block.");
                    None
                }
            };

        let (block_to_propose, block_hash_for_log, prepared_artifact_for_proposal) = 
            if let Some(candidate_info) = chosen_candidate {
                log::debug!(
                    "SRWPA: Re-proposing block from chosen candidate for round {:?}: Hash={:?}, Original Round={:?}", 
                    self.round_identifier(), candidate_info.block.hash(), candidate_info.prepared_round
                );
                (
                    candidate_info.block.clone(), 
                    candidate_info.block.hash(), 
                    Some((candidate_info.original_signed_proposal.clone(), candidate_info.prepares.clone()))
                )
            } else {
                log::debug!("SRWPA: Creating new block for round {:?} as no suitable candidate found.", self.round_identifier());
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

    pub fn handle_prepare_message(&mut self, prepare: Prepare) -> Result<Option<QbftBlock>, QbftError> {
        let author = prepare.author()?;
        log::debug!(
            "Handling Prepare message for round {:?} from {:?}, digest: {:?}",
            self.round_identifier(),
            author,
            prepare.payload().digest
        );

        match self.round_state.add_prepare(prepare.clone()) {
            Ok(_) => {
                if self.round_state.is_prepared() {
                    // Block is now prepared. Update locked_block.
                    if let (Some(proposed_block_ref), Some(proposal_message_wrapper)) = 
                        (self.round_state.proposed_block(), self.round_state.proposal_message()) {
                        
                        let block_clone = proposed_block_ref.clone();
                        let original_signed_proposal_clone = proposal_message_wrapper.bft_message().clone();
                        // TODO: For CertifiedPrepareInfo to be shared (e.g. in RoundChange),
                        // prepares_clone should ideally contain only the quorum of prepares, not all.
                        // For local locked_block, containing all is currently acceptable.
                        let prepares_clone: Vec<SignedData<PreparePayload>> = self.round_state.get_prepare_messages().into_iter().cloned().collect();
                        let current_round_number = self.round_identifier().round_number;

                        let new_locked_info = CertifiedPrepareInfo {
                            block: block_clone,
                            original_signed_proposal: original_signed_proposal_clone,
                            prepares: prepares_clone,
                            prepared_round: current_round_number, 
                        };
                        log::info!(
                            "Round {:?} is PREPARED. Updating locked_block with block {:?} prepared in round {}.", 
                            self.round_identifier(), new_locked_info.block.hash(), new_locked_info.prepared_round
                        );
                        self.locked_block = Some(new_locked_info);
                    } else {
                        log::warn!(
                            "Round {:?} is_prepared, but failed to retrieve proposed_block or proposal_message from RoundState. Cannot update locked_block.", 
                            self.round_identifier()
                        );
                    }
                    
                    // Continue to check if we can also commit
                    if !self.round_state.is_committed() && !self.commit_sent {
                        log::trace!("Round {:?} is PREPARED and commit not yet sent. Sending Commit.", self.round_identifier());
                        if let Some(proposed_block) = self.round_state.proposed_block() { 
                            let block_digest = proposed_block.hash();
                            let commit_seal = self.message_factory.create_commit_seal(block_digest)?;
                            let commit = self.message_factory.create_commit(*self.round_identifier(), block_digest, commit_seal)?;
                            
                            self.round_state.add_commit(commit.clone())?; 
                            self.multicaster.multicast_commit(&commit);
                            self.commit_sent = true; // Mark that we've sent a commit for this proposal
    
                            if self.round_state.is_committed() {
                                log::trace!("Round {:?} is COMMITTED after sending local commit. Importing block.", self.round_identifier());
                                match self.import_block_to_chain() {
                                    Ok(imported_block) => return Ok(Some(imported_block)),
                                    Err(e) => return Err(e),
                                }
                            }
                        } else {
                            log::warn!("Round {:?} is prepared, but no proposed block found when attempting to send Commit.", self.round_identifier());
                        }
                    }
                }
                Ok(None) 
            }
            Err(QbftError::ValidationError(_)) => {
                 log::warn!("Invalid Prepare message for round {:?}. Ignoring.", self.round_identifier());
                 Ok(None)
            }
            Err(e) => Err(e),
        }
    }

    pub fn handle_commit_message(&mut self, commit: Commit) -> Result<Option<QbftBlock>, QbftError> {
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
                    match self.import_block_to_chain() {
                        Ok(imported_block) => return Ok(Some(imported_block)),
                        Err(e) => return Err(e),
                    }
                }
                Ok(None)
            }
            Err(QbftError::ValidationError(reason)) => {
                 log::warn!(
                    "Invalid Commit message for round {:?}: {}. Ignoring.",
                    self.round_identifier(),
                    reason
                );
                 Ok(None)
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

    fn import_block_to_chain(&mut self) -> Result<QbftBlock, QbftError> {
        if self.finalized_block_hash_in_round.is_some() {
            log::debug!(
                "Block for round {:?} already finalized and imported. Skipping.",
                self.round_identifier()
            );
            // If already finalized, we need to return a QbftBlock. 
            // This implies we should perhaps store the finalized block itself or re-fetch it.
            // For now, if this case is hit, it means it was finalized *in this round instance* before.
            // We should have the proposed_block which became that finalized block.
            // This path indicates an issue if called again after finalization as we don't store the *exact* instance
            // that was successfully imported if it was modified with seals.
            // However, the guard `finalized_block_hash_in_round.is_some()` should mean `proposed_block` is the one.
            // Let's return the current proposed block, assuming it's what was finalized.
            // A more robust solution might involve storing the successfully imported `QbftBlock` instance.
            return self.round_state.proposed_block().cloned().ok_or_else(|| {
                QbftError::InvalidState("Block already finalized but no proposed block found in round state".to_string())
            });
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
                Ok(block_to_import)
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
    #[allow(dead_code)] // Part of an alternative proposal flow, to be integrated or removed
    fn get_block_to_propose(&mut self, target_round_identifier: ConsensusRoundIdentifier) -> Result<QbftBlock, QbftError> {
        if let Some(ref block) = self.locked_block {
            log::debug!(target: "consensus", "Proposing locked block {:?} for round {:?}", block.block.hash(), target_round_identifier);
            return Ok(block.block.clone());
        }
        log::debug!(target: "consensus", "Creating new block for round {:?}", target_round_identifier);
        self.block_creator.create_block(&self.parent_header, &target_round_identifier, /* TODO: timestamp */ SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs())
    }

    // If a new block is available (either newly created or a new best target from round changes),
    // and proposal not yet sent for this round, create and send a proposal.
    #[allow(dead_code)] // Part of an alternative proposal flow, to be integrated or removed
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

    // Placeholder for cancel_timers method
    pub fn cancel_timers(&self) {
        log::debug!("QbftRound: Cancelling timers for round {:?}", self.round_identifier());
        self.round_timer.cancel_timer(*self.round_identifier());
    }

    // Getter for the current locked information held by the round
    pub fn locked_info(&self) -> Option<CertifiedPrepareInfo> {
        self.locked_block.clone()
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