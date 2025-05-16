use crate::error::QbftError;
// use std::collections::HashSet; // Removed based on build log
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::types::{
    ConsensusRoundIdentifier, QbftBlock, QbftBlockHeader, SignedData, /* BftExtraData, */ BftExtraDataCodec, QbftFinalState, QbftBlockCreator, 
    QbftBlockImporter, RoundTimer, ValidatorMulticaster, QbftConfig,
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
// Import individual validator traits
use crate::validation::{ProposalValidator, PrepareValidator, CommitValidator};

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
    #[allow(dead_code)] // Passed to RoundState
    proposal_validator: Arc<dyn ProposalValidator + Send + Sync>,
    #[allow(dead_code)] // Passed to RoundState
    prepare_validator: Arc<dyn PrepareValidator + Send + Sync>,
    #[allow(dead_code)] // Passed to RoundState
    commit_validator: Arc<dyn CommitValidator + Send + Sync>,
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
        proposal_validator: Arc<dyn ProposalValidator + Send + Sync>,
        prepare_validator: Arc<dyn PrepareValidator + Send + Sync>,
        commit_validator: Arc<dyn CommitValidator + Send + Sync>,
        config: Arc<QbftConfig>,
        mined_block_observers: Vec<Arc<dyn QbftMinedBlockObserver>>,
        initial_locked_info: Option<CertifiedPrepareInfo>,
    ) -> Self {
        let round_state = RoundState::new(
            round_identifier,
            proposal_validator.clone(), 
            prepare_validator.clone(),
            commit_validator.clone(),
            final_state.quorum_size(),
            Arc::new(parent_header.clone()),
            final_state.clone(),
            extra_data_codec.clone(),
            config.clone(),
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
            proposal_validator,
            prepare_validator,
            commit_validator,
            locked_block: initial_locked_info,
            proposal_sent: false,
            commit_sent: false, // Initialize commit_sent to false
            finalized_block_hash_in_round: None,
        }
    }

    // Placeholder for sending a Prepare message
    // This will be called if the node is a validator after accepting a proposal.
    fn send_prepare(&mut self, block: QbftBlock, block_digest: Hash) -> Result<(), QbftError> {
        log::info!(
            "Round {:?}: Placeholder for sending PREPARE for block {:?}, digest {:?}",
            self.round_identifier(),
            block.header.number, // Use block.header.number for logging
            block_digest
        );
        // TODO: Implement actual Prepare message creation using self.message_factory
        // let prepare_payload = PreparePayload {
        //     round_identifier: *self.round_identifier(),
        //     prepared_block_digest: block_digest,
        // };
        // let signed_prepare = self.message_factory.create_prepare(prepare_payload)?;

        // TODO: Add self prepare to round_state, as if we received it.
        // self.round_state.add_prepare(signed_prepare.message_wrapper_for_state())?;
        // It's important that adding our own prepare also checks if the state becomes PREPARED.
        // This might trigger sending a COMMIT if this node is also a validator.

        // TODO: Multicast the signed_prepare via self.multicaster
        // self.multicaster.multicast_prepare(&signed_prepare)?;
        Ok(())
    }

    // Placeholder for sending a Commit message
    // This will be called if the node is a validator after the round becomes PREPARED.
    fn send_commit(&mut self, block: QbftBlock, block_digest: Hash) -> Result<(), QbftError> {
        log::info!(
            "Round {:?}: Placeholder for sending COMMIT for block {:?}, digest {:?}",
            self.round_identifier(),
            block.header.number,
            block_digest
        );
        // TODO: Implement actual Commit message creation using self.message_factory
        // TODO: Add self commit to round_state
        // TODO: Multicast the signed_commit via self.multicaster
        // TODO: Update self.commit_sent = true;
        Ok(())
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

    pub fn handle_proposal_message(&mut self, proposal: Proposal) -> Result<(), QbftError> {
        log::debug!(
            "Round {:?}: Handling Proposal from {:?} for block digest: {:?}",
            self.round_identifier(),
            proposal.author().unwrap_or_default(), // Safely get author
            proposal.block().hash()
        );

        // The QbftBlockHeightManager ensures this message is for the current round.
        // Validation of the sender (is it the expected proposer?) and the proposal content
        // is handled by the ProposalValidator, which is called within self.round_state.set_proposal().

        match self.round_state.set_proposal(proposal.clone()) { // Clone if proposal is used by send_prepare
            Ok(()) => {
                log::info!(
                    "Round {:?}: Accepted Proposal with digest: {:?}. Current state: prepared={}, committed={}",
                    self.round_identifier(),
                    self.round_state.get_prepared_digest().unwrap_or_default(),
                    self.round_state.is_prepared(),
                    self.round_state.is_committed()
                );

                // If this node is a validator, it should now send a PREPARE message.
                // The is_local_node_validator() method needs to be implemented on QbftFinalState.
                if self.final_state.is_local_node_validator() {
                    if let Some(accepted_block_digest) = self.round_state.get_prepared_digest() {
                        if let Some(accepted_proposal_block) = self.round_state.proposed_block() {
                             log::info!(
                                "Round {:?}: Node is validator. Sending PREPARE for accepted block digest: {:?}",
                                self.round_identifier(),
                                accepted_block_digest
                            );
                            // Pass a clone of the block to send_prepare.
                            return self.send_prepare(accepted_proposal_block.clone(), accepted_block_digest);
                        } else {
                            log::warn!(
                                "Round {:?}: Node is validator, but could not retrieve proposed block from RoundState after accepting proposal. Cannot send PREPARE.",
                                self.round_identifier()
                            );
                        }
                    } else {
                        log::warn!(
                            "Round {:?}: Node is validator, but no prepared digest found in RoundState after accepting proposal. Cannot send PREPARE.",
                            self.round_identifier()
                        );
                    }
                }
                // If not a validator, or if prepare couldn't be sent, successfully return Ok.
                // The proposal was still accepted by RoundState.
                Ok(())
            }
            Err(e) => {
                log::warn!(
                    "Round {:?}: Rejected Proposal (block digest {:?}): {:?}",
                    self.round_identifier(),
                    proposal.block().hash(),
                    e
                );
                Err(e)
            }
        }
    }

    pub fn handle_prepare_message(&mut self, prepare: Prepare) -> Result<Option<QbftBlock>, QbftError> {
        log::debug!(
            "Round {:?}: Handling Prepare from {:?} for digest: {:?}",
            self.round_identifier(),
            prepare.author().unwrap_or_default(),
            prepare.payload().digest
        );

        // Add the prepare message to the round state. This validates the prepare internally.
        match self.round_state.add_prepare(prepare.clone()) { // Clone if prepare is used later
            Ok(()) => {
                // Check if the round has become prepared.
                if self.round_state.is_prepared() {
                    log::info!(
                        "Round {:?}: Now PREPARED for block digest: {:?}. Current state: prepared={}, committed={}",
                        self.round_identifier(),
                        self.round_state.get_prepared_digest().unwrap_or_default(),
                        self.round_state.is_prepared(),
                        self.round_state.is_committed()
                    );

                    // Update self.locked_block with the new certificate from RoundState
                    if let Some(round_state_cert) = self.round_state.construct_prepared_certificate() {
                        if let Some(proposal_msg) = self.round_state.proposal_message() {
                            self.locked_block = Some(CertifiedPrepareInfo {
                                block: round_state_cert.block.clone(),
                                prepares: round_state_cert.prepares.clone(),
                                prepared_round: round_state_cert.prepared_round,
                                // Ensure original_signed_proposal is the BftMessage<ProposalPayload>
                                original_signed_proposal: proposal_msg.bft_message().clone(), 
                            });
                            log::debug!(
                                "Round {:?}: Updated locked_block to: digest {:?}, round {}", 
                                self.round_identifier(), 
                                self.locked_block.as_ref().map(|lb| lb.block.hash()).unwrap_or_default(),
                                self.locked_block.as_ref().map(|lb| lb.prepared_round).unwrap_or_default()
                            );
                        } else {
                             log::warn!(
                                "Round {:?}: Is PREPARED, but no proposal message found in RoundState to create full CertifiedPrepareInfo for locked_block.", 
                                self.round_identifier()
                            );
                        }
                    } else {
                        log::warn!(
                            "Round {:?}: Is PREPARED, but failed to construct prepared certificate from RoundState. Cannot update locked_block.", 
                            self.round_identifier()
                        );
                    }

                    // If this node is a validator and hasn't sent a commit for this proposal yet.
                    if self.final_state.is_local_node_validator() && !self.commit_sent {
                        if let Some(prepared_digest) = self.round_state.get_prepared_digest() {
                             if let Some(prepared_block) = self.round_state.proposed_block() {
                                log::info!(
                                    "Round {:?}: Node is validator and round is PREPARED. Sending COMMIT for digest: {:?}",
                                    self.round_identifier(),
                                    prepared_digest
                                );
                                // The send_commit method would internally set self.commit_sent = true after successfully sending.
                                // If send_commit can fail and not send, self.commit_sent should only be set on success inside send_commit.
                                // For now, we assume send_commit tries its best and might update commit_sent or returns an error.
                                if let Err(e) = self.send_commit(prepared_block.clone(), prepared_digest) {
                                    log::error!("Round {:?}: Failed to send COMMIT: {:?}", self.round_identifier(), e);
                                    // Decide if this error should be propagated. For now, log and continue.
                                    // The round is still prepared locally.
                                }
                             } else {
                                log::warn!(
                                    "Round {:?}: Node is validator and round is PREPARED, but could not retrieve proposed block. Cannot send COMMIT.", 
                                    self.round_identifier()
                                );
                             }
                        } else {
                            log::warn!(
                                "Round {:?}: Node is validator and round is PREPARED, but no prepared digest found. Cannot send COMMIT.", 
                                self.round_identifier()
                            );
                        }
                    }
                }
                // Handling a Prepare message doesn't directly result in a finalized block to be returned up.
                Ok(None)
            }
            Err(e) => {
                log::warn!(
                    "Round {:?}: Rejected Prepare for digest {:?}: {:?}",
                    self.round_identifier(),
                    prepare.payload().digest,
                    e
                );
                Err(e)
            }
        }
    }

    pub fn handle_commit_message(&mut self, commit: Commit) -> Result<Option<QbftBlock>, QbftError> {
        log::debug!(
            "Round {:?}: Handling Commit from {:?} for digest: {:?}",
            self.round_identifier(),
            commit.author().unwrap_or_default(),
            commit.payload().digest
        );

        // Add the commit message to the round state. This validates the commit internally.
        match self.round_state.add_commit(commit.clone()) { // Clone if commit is used later
            Ok(()) => {
                // Check if the round has become committed and we haven't already finalized a block in this round instance.
                if self.round_state.is_committed() && self.finalized_block_hash_in_round.is_none() {
                    log::info!(
                        "Round {:?}: Now COMMITTED for block digest: {:?}. Attempting to import.",
                        self.round_identifier(),
                        self.round_state.get_prepared_digest().unwrap_or_default(),
                    );

                    match self.import_block_to_chain() {
                        Ok(imported_block) => {
                            log::info!(
                                "Round {:?}: Successfully imported block {:?} with hash {:?}.",
                                self.round_identifier(),
                                imported_block.header.number,
                                imported_block.header.hash()
                            );
                            self.finalized_block_hash_in_round = Some(imported_block.header.hash());
                            // This block is now finalized for this height. QbftBlockHeightManager will be notified.
                            return Ok(Some(imported_block));
                        }
                        Err(e) => {
                            log::error!(
                                "Round {:?}: Failed to import block after commit: {:?}. State: prepared={}, committed={}",
                                self.round_identifier(),
                                e,
                                self.round_state.is_prepared(),
                                self.round_state.is_committed()
                            );
                            // Even if import fails, the round is logically committed by QBFT. 
                            // The error will propagate up. Retaining the committed state is important.
                            return Err(e);
                        }
                    }
                } else if self.round_state.is_committed() && self.finalized_block_hash_in_round.is_some() {
                    log::debug!(
                        "Round {:?}: Already committed and finalized a block. Ignoring further commit processing for import.",
                        self.round_identifier()
                    );
                }
                // If not committed yet, or already finalized, no block to return upwards from this message.
                Ok(None)
            }
            Err(e) => {
                log::warn!(
                    "Round {:?}: Rejected Commit for digest {:?}: {:?}",
                    self.round_identifier(),
                    commit.payload().digest,
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
        if !self.round_state.is_committed() {
            log::error!(
                "import_block_to_chain called for round {:?} but RoundState is not committed. This should not happen.", 
                self.round_identifier()
            );
            return Err(QbftError::InvalidState("Attempted to import block when round not committed".to_string()));
        }

        let proposed_block_opt = self.round_state.proposed_block();
        let commit_seals_opt = self.round_state.get_commit_seals_if_committed();

        match (proposed_block_opt, commit_seals_opt) {
            (Some(block_to_finalize_ref), Some(commit_seals)) => {
                let mut block_to_finalize = block_to_finalize_ref.clone();
                log::debug!(
                    "Round {:?}: Preparing to import block {:?} with {} commit seals.",
                    self.round_identifier(),
                    block_to_finalize.header.hash(),
                    commit_seals.len()
                );

                // Create BftExtraData with commit seals
                // Assuming BftExtraData has a way to be created/updated with commit seals.
                // The BftExtraDataCodec will handle the RLP encoding.
                let current_extra_data = self.extra_data_codec.decode(&block_to_finalize.header.extra_data)?;
                let new_bft_extra_data = current_extra_data.with_commit_seals(commit_seals);
                block_to_finalize.header.extra_data = self.extra_data_codec.encode(&new_bft_extra_data)?;
                
                // Recalculate block hash after modifying extra_data if necessary.
                // Some Ethereum client designs recompute the hash here, others expect it to be fixed.
                // For simplicity, assuming the hash is not recomputed or QbftBlock handles it.
                // If recomputation is needed: block_to_finalize.header.update_hash();

                log::info!(
                    "Round {:?}: Importing finalized block {:?} (Number: {}) into chain storage.",
                    self.round_identifier(),
                    block_to_finalize.header.hash(),
                    block_to_finalize.header.number
                );

                match self.block_importer.import_block(&block_to_finalize) {
                    Ok(_) => {
                        log::info!(
                            "Round {:?}: Block {:?} successfully imported by BlockImporter.",
                            self.round_identifier(),
                            block_to_finalize.header.hash()
                        );
                        self.notify_new_block_listeners(&block_to_finalize);
                        self.cancel_timers(); // Block finalized for this round, cancel timers.
                        Ok(block_to_finalize)
                    }
                    Err(e) => {
                        log::error!(
                            "Round {:?}: BlockImporter failed to import block {:?}: {:?}",
                            self.round_identifier(),
                            block_to_finalize.header.hash(),
                            e
                        );
                        Err(QbftError::BlockImportFailed(e.to_string())) // Wrap the error
                    }
                }
            }
            (None, _) => {
                log::error!(
                    "Round {:?}: Round is committed, but no proposed block found in RoundState.", 
                    self.round_identifier()
                );
                Err(QbftError::InvalidState("Committed round has no proposed block".to_string()))
            }
            (_, None) => {
                log::error!(
                    "Round {:?}: Round is committed, but no commit seals found in RoundState.", 
                    self.round_identifier()
                );
                Err(QbftError::InvalidState("Committed round has no commit seals".to_string()))
            }
        }
    }

    pub fn construct_prepared_certificate(&self) -> Option<RoundStatePreparedCertificate> {
        self.round_state.construct_prepared_certificate()
    }

    // Method to get a block to propose, creating one if necessary
    #[allow(dead_code)]
    fn get_block_to_propose(&mut self, target_round_identifier: ConsensusRoundIdentifier) -> Result<QbftBlock, QbftError> {
        let _current_time_seconds = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs();
        // For now, create a new block. Later, this should check for existing transactions etc.
        // Also, timestamp should be managed correctly (e.g. max(parent_ts + 1, current_time))
        // self.block_creator.create_block(&self.parent_header, &target_round_identifier, current_time_seconds)
        // Create block is fallible, so propagate the error with `?`
        self.block_creator.create_block(
            &self.parent_header,
            &target_round_identifier,
            // Placeholder timestamp - this needs to be properly determined
            // based on BlockTimer and parent_header.timestamp
            self.parent_header.timestamp + 1
        )
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