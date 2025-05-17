use crate::error::QbftError;
// use std::collections::HashSet; // Removed based on build log
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
// use std::mem::discriminant; // Removed unused import

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
use alloy_primitives::{B256 as Hash}; // Removed Bloom, U256, FixedBytes
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
        _mined_block_observers: Vec<Arc<dyn QbftMinedBlockObserver>>, // Parameter can be kept if new() signature is public API, but mark unused
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
        log::debug!(
            "Round {:?}: Sending PREPARE for block digest {:?}, number {}",
            self.round_identifier(),
            block_digest,
            block.header.number,
        );

        // Create and sign the Prepare message
        let prepare_message = self.message_factory.create_prepare(
            *self.round_identifier(),
            block_digest
        )?;

        // Add our own Prepare message to the RoundState.
        // This allows our own message to contribute to reaching a prepared state.
        // The `add_prepare` method in RoundState should handle validation and state updates.
        // We clone the message because add_prepare might take ownership,
        // and we still need to multicast the original.
        // Note: Ensure `Prepare::new` (used by factory) or `Prepare::message_wrapper_for_state`
        // creates a `Prepare` that `RoundState::add_prepare` can consume.
        // `MessageFactory::create_prepare` returns `Prepare`, which is what `add_prepare` expects.
        if let Err(e) = self.round_state.add_prepare(prepare_message.clone()) {
            log::error!(
                "Round {:?}: Failed to add own Prepare message to RoundState: {:?}. This may indicate an issue.",
                self.round_identifier(), e
            );
            // Propagate the error, as it's not a simple duplicate if it originates here.
            return Err(e);
        }

        // Multicast the Prepare message to other validators
        self.multicaster.multicast_prepare(&prepare_message);
        log::debug!(
            "Round {:?}: Multicasted PREPARE for block digest {:?}",
            self.round_identifier(),
            block_digest
        );
        Ok(())
    }

    // Placeholder for sending a Commit message
    // This will be called if the node is a validator after the round becomes PREPARED.
    fn send_commit(&mut self, block: QbftBlock, block_digest: Hash) -> Result<(), QbftError> {
        // Determine if the local node is a validator for this round.
        // The validator set for round R is determined by the parent block (R-1).
        let parent_block_number = self.round_identifier().sequence_number.saturating_sub(1);
        
        // Check if genesis block (parent is 0 but sequence_number is 1 for first block)
        // or if it's a non-genesis block.
        // For sequence_number 0 (which shouldn't happen for a round trying to commit),
        // get_validators_for_block might have specific logic.
        // For sequence_number 1, parent_block_number will be 0.
        let validators_for_round = self.final_state.get_validators_for_block(parent_block_number)?;
        let local_address = self.final_state.local_address();

        if !validators_for_round.contains(&local_address) {
            log::debug!(
                "Round {:?}: Local node ({:?}) is not a validator for this round (parent block {}). Skipping sending COMMIT for block digest {:?}.",
                self.round_identifier(),
                local_address,
                parent_block_number,
                block_digest
            );
            return Ok(());
        }

        if self.commit_sent {
            log::debug!(
                "Round {:?}: COMMIT message already sent for block digest {:?}. Skipping.",
                self.round_identifier(),
                block_digest
            );
            return Ok(());
        }

        log::debug!(
            "Round {:?}: Sending COMMIT for block digest {:?}, number {}",
            self.round_identifier(),
            block_digest,
            block.header.number
        );

        // Create the commit seal (signature over the block digest)
        let commit_seal = self.message_factory.create_commit_seal(block_digest)?;

        // Create and sign the Commit message
        let commit_message = self.message_factory.create_commit(
            *self.round_identifier(),
            block_digest,
            commit_seal 
        )?;

        // Add our own Commit message to the RoundState.
        if let Err(e) = self.round_state.add_commit(commit_message.clone()) {
            log::error!(
                "Round {:?}: Failed to add own Commit message to RoundState: {:?}. This may indicate an issue.",
                self.round_identifier(), e
            );
            // Propagate the error.
            return Err(e);
        }

        // Multicast the Commit message to other validators
        self.multicaster.multicast_commit(&commit_message);
        self.commit_sent = true; // Mark commit as sent

        log::debug!(
            "Round {:?}: Multicasted COMMIT for block digest {:?}",
            self.round_identifier(),
            block_digest
        );
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
        // eprintln!("INSIDE QbftRound::propose_block - THIS IS A TEST PRINT"); // TEST PRINT REMOVED
        log::debug!("[QBFT_ROUND.PROPOSE_BLOCK] Called for block {:?}, round {:?}", block_hash_for_log, self.round_identifier());
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
        
        // Call the helper that internally calls RoundState's set_proposal
        match self.handle_proposal_message_for_state(proposal.clone()) { 
            Ok(processed) => {
                if processed {
                    log::info!(
                        "[QBFT_ROUND.PROPOSE_BLOCK] Node {:?} successfully processed own proposal for round {:?}, block hash {:?}. Actions based on proposer status.", 
                        self.final_state.local_address(), 
                        self.round_identifier(), 
                        block_hash_for_log
                    );
                    // Determine if this node is the proposer for the current round
                    let current_round_proposer = self.final_state.get_proposer_for_round(self.round_identifier())?;
                    if self.final_state.local_address() == current_round_proposer {
                        log::info!("[QBFT_ROUND.PROPOSE_BLOCK] Local node IS proposer for round {:?}. Multicasting proposal.", self.round_identifier());
                        self.multicaster.multicast_proposal(&proposal);
                    } else {
                        log::info!("[QBFT_ROUND.PROPOSE_BLOCK] Local node IS NOT proposer for round {:?}. Proposal was processed internally (e.g. from RC artifacts), NOT multicasting new proposal message.", self.round_identifier());
                    }
                    // The call to send_prepare is handled within handle_proposal_message_for_state if needed.
                    Ok(())
                } else {
                    log::warn!(
                        "[QBFT_ROUND.PROPOSE_BLOCK] Node {:?} attempted to set proposal in RoundState for round {:?}, block hash {:?} (new), but it was considered a duplicate or not processed further by handle_proposal_message_for_state. NOT MULTICASTING.", 
                        self.final_state.local_address(), 
                        self.round_identifier(), 
                        block_hash_for_log
                    );
                    Ok(()) // Not an error, just not processed as new
                }
            }
            Err(e) => {
                log::error!(
                    "[QBFT_ROUND.PROPOSE_BLOCK] Node {:?} failed to process own proposal via handle_proposal_message_for_state for round {:?}, block hash {:?}: {:?}. NOT MULTICASTING.",
                    self.final_state.local_address(), 
                    self.round_identifier(), 
                    block_hash_for_log,
                    e
                );
                Err(e) 
            }
        }
    }

    pub fn handle_proposal_message(&mut self, proposal: Proposal) -> Result<(), QbftError> {
        log::debug!(
            "Round {:?}: Handling Proposal from {:?} for block digest: {:?}",
            self.round_identifier(),
            proposal.author().unwrap_or_default(), // Safely get author
            proposal.block().hash()
        );

        // Call the helper that internally calls RoundState's set_proposal and then sends Prepare if needed.
        match self.handle_proposal_message_for_state(proposal.clone()) { 
            Ok(processed_newly) => {
                if processed_newly {
                    log::debug!("Round {:?}: Proposal processed successfully and was new.", self.round_identifier());
                } else {
                    log::debug!("Round {:?}: Proposal processed, but was likely a duplicate or already handled.", self.round_identifier());
                }
                Ok(())
            }
            Err(e) => {
                log::warn!(
                    "Round {:?}: Rejected Proposal (block digest {:?} from {:?}): {:?}",
                    self.round_identifier(),
                    proposal.block().hash(),
                    proposal.author().unwrap_or_default(),
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
                                self.send_commit(prepared_block.clone(), prepared_digest)?;
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
            "[QBFT_ROUND LOG] Round {:?}: Entering handle_commit_message from {:?} for digest: {:?}",
            self.round_identifier(),
            commit.author().unwrap_or_default(),
            commit.payload().digest
        );

        // Add the commit message to the round state. This validates the commit internally.
        let add_commit_result = self.round_state.add_commit(commit.clone());
        log::debug!(
            "[QBFT_ROUND LOG] Round {:?}: Result from round_state.add_commit: {:?}", 
            self.round_identifier(), 
            add_commit_result.is_ok()
        );

        match add_commit_result { // Clone if commit is used later
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
                        // self.notify_new_block_listeners(&block_to_finalize); // Removed: BHM will notify.
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

    // Internal helper to process a proposal and update round state.
    // This is called by both `propose_block` (for self-generated proposals) 
    // and `handle_proposal_message` (for externally received proposals).
    fn handle_proposal_message_for_state(&mut self, proposal: Proposal) -> Result<bool, QbftError> {
        // Basic validation: ensure the proposal is for the current round of this QbftRound instance.
        if proposal.round_identifier() != self.round_identifier() {
            log::error!(
                "Internal Error: QbftRound {:?} received proposal for different round {:?} in handle_proposal_message_for_state. This should not happen.", 
                self.round_identifier(), proposal.round_identifier()
            );
            // This indicates a logic error in how messages are routed or QbftRound instances are managed.
            return Err(QbftError::InternalError(format!(
                "Proposal for round {:?} processed by QbftRound instance for {:?}",
                proposal.round_identifier(), self.round_identifier()
            )));
        }

        // `RoundState::set_proposal` will perform further validation (e.g., proposer, block header) 
        // and update its internal state, including `is_prepared` if the proposal contains a valid certificate.
        match self.round_state.set_proposal(proposal.clone()) { // Use the renamed set_proposal
            Ok(()) => {
                log::info!(
                    "Round {:?}: Accepted Proposal with digest: {:?}. Current state: prepared={}, committed={}",
                    self.round_identifier(),
                    self.round_state.get_prepared_digest().unwrap_or_default(),
                    self.round_state.is_prepared(),
                    self.round_state.is_committed()
                );
                // If the round became prepared (either by this proposal's cert or later by prepares),
                // and we are a validator, we might need to send a commit and/or prepare.
                // For a proposal being processed (either self-generated or external):
                // 1. If validator: always send PREPARE.
                // 2. If prepared (possibly from cert in proposal) AND validator AND commit not sent: send COMMIT.

                let mut prepare_sent_this_call = false;
                if self.final_state.is_local_node_validator() {
                    if let Some(accepted_block_digest) = self.round_state.get_prepared_digest() {
                        if let Some(accepted_proposal_block) = self.round_state.proposed_block() {
                             log::info!(
                                "Round {:?}: Node is validator. Sending PREPARE for accepted block digest: {:?}",
                                self.round_identifier(),
                                accepted_block_digest
                            );
                            if let Err(e) = self.send_prepare(accepted_proposal_block.clone(), accepted_block_digest) {
                                log::error!("Round {:?}: Error sending PREPARE after proposal: {:?}", self.round_identifier(), e);
                                return Err(e); // Propagate error from send_prepare
                            }
                            prepare_sent_this_call = true;
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

                if self.round_state.is_prepared() && self.final_state.is_local_node_validator() && !self.commit_sent {
                    if let Some(prepared_digest) = self.round_state.get_prepared_digest() {
                        log::info!(
                            "Round {:?}: Became PREPARED after processing proposal (possibly from cert). Validator sending COMMIT for digest: {:?}. Prepare was sent: {}", 
                            self.round_identifier(), prepared_digest, prepare_sent_this_call
                        );
                        let prepared_block = self.round_state.proposed_block().expect("Proposed block must exist if round is prepared");
                        if let Err(e) = self.send_commit(prepared_block.clone(), prepared_digest) {
                            log::error!("Round {:?}: Error sending commit after becoming prepared from proposal: {:?}", self.round_identifier(), e);
                            return Err(e); // Propagate error from send_commit
                        }
                    } else {
                        log::error!(
                            "Round {:?}: Is prepared after proposal, but no prepared digest found. Cannot send commit.", self.round_identifier()
                        );
                    }
                }
                Ok(true) // Proposal was accepted and processed by RoundState (either new or benign duplicate)
            }
            Err(QbftError::ProposalAlreadyReceived) => {
                log::warn!(
                    "Round {:?}: ProposalAlreadyReceived error from RoundState. Propagating.",
                    self.round_identifier()
                );
                Err(QbftError::ProposalAlreadyReceived) // Propagate the error directly
            }
            Err(e) => {
                log::error!(
                    "Round {:?}: Error setting proposal in RoundState: {:?}", 
                    self.round_identifier(), e
                );
                Err(e) // Propagate other errors
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*; 
    use crate::mocks::{
        mock_final_state::MockQbftFinalState,
        mock_block_creator::MockQbftBlockCreator,
        mock_services::{MockQbftBlockImporter, MockValidatorMulticaster},
        mock_timers::MockRoundTimer,
    };
    use crate::types::{ConsensusRoundIdentifier, NodeKey, BftExtraData, AlloyBftExtraDataCodec, QbftConfig, BftExtraDataCodec};
    use crate::payload::MessageFactory;
    use alloy_primitives::{Address, B256, Bytes, U256};
    use alloy_rlp::{Error as RlpError, Encodable, Decodable};
    use std::sync::Arc;
    use std::collections::HashSet;
    use k256::ecdsa::{VerifyingKey};
    use crate::validation::{ProposalValidator, PrepareValidator, CommitValidator, ValidationContext, MessageValidatorFactory};


    // --- Mock Validators with Failure Configuration ---
    #[derive(Clone)]
    struct ConfigurableMockProposalValidator { fail_on_validate: bool, error_to_return: Option<QbftError> }
    impl ProposalValidator for ConfigurableMockProposalValidator {
        fn validate_proposal(&self, _proposal: &Proposal, context: &ValidationContext) -> Result<(), QbftError> {
            if self.fail_on_validate {
                Err(self.error_to_return.clone().unwrap_or_else(|| 
                    QbftError::ProposalInvalidAuthor { 
                        expected: context.expected_proposer, 
                        actual: _proposal.author().unwrap_or_default(),
                    }
                ))
            } else { Ok(()) }
        }
        fn validate_block_header_for_proposal(&self, _header: &QbftBlockHeader, _context: &ValidationContext) -> Result<(), QbftError> {
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
        fn validate_prepare(&self, prepare: &Prepare, _context: &ValidationContext) -> Result<(), QbftError> {
            if let Some(fail_addr) = self.fail_for_author {
                if prepare.author().map_or(false, |auth| auth == fail_addr) {
                    return Err(QbftError::ValidationError(format!("MockPrepareValidator failed as configured for author {:?}", fail_addr)));
                }
            }
            Ok(())
        }
    }

    #[derive(Clone)] // Removed Default derive here, will add custom ::new()
    struct ConfigurableMockCommitValidator { fail_on_validate: bool }
    impl CommitValidator for ConfigurableMockCommitValidator {
        fn validate_commit(&self, _commit: &Commit, _context: &ValidationContext) -> Result<(), QbftError> {
            if self.fail_on_validate { Err(QbftError::ValidationError("MockCommitValidator failed as configured".to_string())) } else { Ok(()) }
        }
    }

    #[derive(Clone, Default)]
    struct ConfigurableMockMessageValidatorFactory {
        proposal_should_fail: bool,
        proposal_error: Option<QbftError>,
        prepare_fail_for_author: Option<Address>, // Changed from prepare_should_fail
        commit_should_fail: bool,
    }

    impl ConfigurableMockMessageValidatorFactory {
        fn new() -> Self { Default::default() } // Keep default constructor

        fn set_proposal_failure(mut self, fail: bool, error: Option<QbftError>) -> Self {
            self.proposal_should_fail = fail;
            self.proposal_error = error;
            self
        }

        fn set_prepare_failure_for_author(mut self, author: Option<Address>) -> Self {
            self.prepare_fail_for_author = author;
            self
        }

        #[allow(dead_code)] // May become used later
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

    #[allow(clippy::too_many_arguments)]
    fn setup_qbft_round(
        round_id: ConsensusRoundIdentifier,
        parent_header: QbftBlockHeader,
        final_state: Arc<MockQbftFinalState>,
        block_creator: Arc<MockQbftBlockCreator>,
        block_importer: Arc<MockQbftBlockImporter>,
        message_factory: Arc<MessageFactory>,
        multicaster: Arc<MockValidatorMulticaster>,
        round_timer: Arc<MockRoundTimer>,
        extra_data_codec: Arc<dyn BftExtraDataCodec>,
        proposal_validator: Arc<dyn ProposalValidator + Send + Sync>,
        prepare_validator: Arc<dyn PrepareValidator + Send + Sync>,
        commit_validator: Arc<dyn CommitValidator + Send + Sync>,
        config: Arc<QbftConfig>,
        _mined_block_observers: Vec<Arc<dyn QbftMinedBlockObserver>>, // Parameter can be kept if new() signature is public API, but mark unused
        initial_locked_info: Option<CertifiedPrepareInfo>,
    ) -> QbftRound {
        QbftRound::new(
            round_id,
            parent_header,
            final_state as Arc<dyn QbftFinalState>,
            block_creator as Arc<dyn QbftBlockCreator>,
            block_importer as Arc<dyn QbftBlockImporter>,
            message_factory,
            multicaster as Arc<dyn ValidatorMulticaster>,
            round_timer as Arc<dyn RoundTimer>,
            extra_data_codec,
            proposal_validator,
            prepare_validator,
            commit_validator,
            config,
            _mined_block_observers, // REMOVED from struct init
            initial_locked_info,
        )
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
            number * 10, 
            Bytes::new(), 
            B256::ZERO, 
            Bytes::from_static(&[0u8; 8]), 
            None, 
        );
        let _ = header.hash(); 
        header
    }

    struct MockObserver;
    impl QbftMinedBlockObserver for MockObserver {
        fn block_imported(&self, _block: &QbftBlock) {}
    }

    #[test]
    fn test_handle_proposal_valid_from_proposer() {
        let local_node_key_arc = deterministic_node_key(1); 
        let local_address = address_from_arc_key(&local_node_key_arc); 
        
        let validators: HashSet<Address> = vec![local_address].into_iter().collect();
        
        let sequence_number = 1u64;
        let round_number = 0u32;
        let round_id = ConsensusRoundIdentifier { sequence_number, round_number };

        let mut hash_bytes = [0u8; 32];
        let val_bytes = (sequence_number - 1).to_be_bytes(); 
        hash_bytes[24..].copy_from_slice(&val_bytes); 
        let parent_hash = B256::new(hash_bytes);
        
        let parent_header = simple_parent_header(sequence_number - 1, parent_hash);

        let mock_final_state = Arc::new(MockQbftFinalState::new(local_node_key_arc.clone(), validators.clone()));

        let message_factory = Arc::new(MessageFactory::new(local_node_key_arc.clone()).unwrap());
        let mock_block_creator = Arc::new(MockQbftBlockCreator::new(Arc::new(parent_header.clone()), mock_final_state.clone(), Arc::new(AlloyBftExtraDataCodec::default())));
        let mock_block_importer = Arc::new(MockQbftBlockImporter::default());
        let mock_multicaster = Arc::new(MockValidatorMulticaster::default());
        let mock_round_timer = Arc::new(MockRoundTimer::default());
        let test_codec = testing_extradata_codec_local(); 
        let config = default_test_qbft_config();

        let msg_validator_factory = Arc::new(
            ConfigurableMockMessageValidatorFactory::new().set_proposal_failure(false, None)
        );

        let mut qbft_round = setup_qbft_round(
            round_id,
            parent_header.clone(),
            mock_final_state.clone(),
            mock_block_creator.clone(),
            mock_block_importer.clone(),
            message_factory.clone(),
            mock_multicaster.clone(),
            mock_round_timer.clone(),
            test_codec.clone(),
            msg_validator_factory.clone().create_proposal_validator(),
            msg_validator_factory.clone().create_prepare_validator(),
            msg_validator_factory.clone().create_commit_validator(),
            config.clone(),
            vec![Arc::new(MockObserver)],
            None,
        );

        let proposed_block = mock_block_creator.create_block(&parent_header, &round_id, parent_header.timestamp + 1).unwrap();
        let proposal_message = message_factory.create_proposal(round_id, proposed_block.clone(), vec![], None).unwrap();

        let result = qbft_round.handle_proposal_message(proposal_message.clone());

        assert!(result.is_ok(), "handle_proposal_message failed: {:?}", result.err());
        
        let round_state = qbft_round.round_state();
        assert!(round_state.proposal_message().is_some(), "Proposal not set in RoundState");
        assert_eq!(round_state.proposal_message().unwrap().block().hash(), proposed_block.hash(), "Proposed block mismatch");
        assert!(round_state.is_prepared(), "RoundState should be prepared after local node (validator) sends prepare.");

        let prepare_sent = mock_multicaster.prepares.lock().unwrap();
        assert_eq!(prepare_sent.len(), 1, "Expected 1 Prepare message to be sent");
        assert_eq!(prepare_sent[0].payload().digest, proposed_block.hash(), "Prepare digest mismatch");
        assert_eq!(*prepare_sent[0].round_identifier(), round_id, "Prepare round_id mismatch");
    }

    #[test]
    fn test_handle_proposal_from_non_proposer() {
        let local_node_key_arc = deterministic_node_key(1); 
        let local_address = address_from_arc_key(&local_node_key_arc);
        
        let actual_proposer_key_arc = deterministic_node_key(2); 
        let actual_proposer_address = address_from_arc_key(&actual_proposer_key_arc);

        let non_proposer_key_arc = deterministic_node_key(3); 
        let non_proposer_address = address_from_arc_key(&non_proposer_key_arc);

        let validators: HashSet<Address> = vec![local_address, actual_proposer_address].into_iter().collect();
        
        let sequence_number = 1u64;
        let round_number = 0u32;
        let round_id = ConsensusRoundIdentifier { sequence_number, round_number };

        let mut hash_bytes = [0u8; 32];
        let val_bytes = (sequence_number - 1).to_be_bytes(); 
        hash_bytes[24..].copy_from_slice(&val_bytes); 
        let parent_hash = B256::new(hash_bytes);
        let parent_header = simple_parent_header(sequence_number - 1, parent_hash);

        let mut mock_final_state_validators = validators.clone();
        mock_final_state_validators.insert(local_address);

        let mock_final_state = Arc::new(MockQbftFinalState::new(local_node_key_arc.clone(), mock_final_state_validators.clone()));

        let message_factory = Arc::new(MessageFactory::new(local_node_key_arc.clone()).unwrap());
        
        let expected_proposer_for_round = mock_final_state.get_proposer_for_round(&round_id).unwrap();

        let non_proposer_message_factory = Arc::new(MessageFactory::new(non_proposer_key_arc.clone()).unwrap());
        
        let mock_block_creator_final_state = Arc::new(MockQbftFinalState::new(actual_proposer_key_arc.clone(), validators.clone()));
        let mock_block_creator = Arc::new(MockQbftBlockCreator::new(Arc::new(parent_header.clone()), mock_block_creator_final_state, Arc::new(AlloyBftExtraDataCodec::default())));
        
        let mock_block_importer = Arc::new(MockQbftBlockImporter::default());
        let mock_multicaster = Arc::new(MockValidatorMulticaster::default());
        let mock_round_timer = Arc::new(MockRoundTimer::default());
        let test_codec = testing_extradata_codec_local(); 
        let config = default_test_qbft_config();

        let configured_error = QbftError::ProposalInvalidAuthor {
            expected: expected_proposer_for_round, 
            actual: non_proposer_address,
        };
        let factory_config = ConfigurableMockMessageValidatorFactory::new()
            .set_proposal_failure(true, Some(configured_error.clone())); 
        let msg_validator_factory = Arc::new(factory_config);
        
        let proposal_validator_mock = msg_validator_factory.clone().create_proposal_validator();
        let prepare_validator_mock = msg_validator_factory.clone().create_prepare_validator();
        let commit_validator_mock = msg_validator_factory.create_commit_validator();

        let mut qbft_round = setup_qbft_round(
            round_id,
            parent_header.clone(),
            mock_final_state.clone(), 
            mock_block_creator.clone(), 
            mock_block_importer,
            message_factory.clone(),
            mock_multicaster.clone(),
            mock_round_timer,
            test_codec,
            proposal_validator_mock, 
            prepare_validator_mock,  
            commit_validator_mock,   
            config.clone(),
            vec![Arc::new(MockObserver)],
            None, 
        );

        let proposed_block = mock_block_creator.create_block(&parent_header, &round_id, parent_header.timestamp + 1).unwrap();
        let proposal_from_non_proposer = non_proposer_message_factory.create_proposal(round_id, proposed_block.clone(), vec![], None).unwrap();

        let result = qbft_round.handle_proposal_message(proposal_from_non_proposer.clone());

        assert!(result.is_err(), "Expected handle_proposal_message to fail for non-proposer.");
        match result {
            Err(QbftError::ProposalInvalidAuthor { expected, actual }) => {
                assert_eq!(expected, expected_proposer_for_round, "Error reported wrong expected proposer");
                assert_eq!(actual, non_proposer_address, "Error reported wrong actual proposer");
            }
            Err(other_error) => {
                panic!("Expected ProposalInvalidAuthor error, got {:?}", other_error);
            }
            Ok(_) => panic!("Expected an error, but got Ok"),
        }
        
        assert!(qbft_round.round_state().proposal_message().is_none(), "Proposal should not be set in RoundState");
        assert_eq!(mock_multicaster.prepares.lock().unwrap().len(), 0, "No Prepare message should have been sent");
    }

    #[test]
    fn test_handle_proposal_invalid_signature() {
        let local_node_key_arc = deterministic_node_key(1);
        let local_address = address_from_arc_key(&local_node_key_arc);
        
        let validators: HashSet<Address> = vec![local_address].into_iter().collect();
        
        let sequence_number = 1u64;
        let round_number = 0u32;
        let round_id = ConsensusRoundIdentifier { sequence_number, round_number };

        let mut hash_bytes = [0u8; 32];
        let val_bytes = (sequence_number - 1).to_be_bytes();
        hash_bytes[24..].copy_from_slice(&val_bytes);
        let parent_hash = B256::new(hash_bytes);
        let parent_header = simple_parent_header(sequence_number - 1, parent_hash);

        let mock_final_state = Arc::new(MockQbftFinalState::new(local_node_key_arc.clone(), validators.clone()));

        let message_factory = Arc::new(MessageFactory::new(local_node_key_arc.clone()).unwrap());
        let mock_block_creator_final_state = Arc::new(MockQbftFinalState::new(local_node_key_arc.clone(), validators.clone()));
        let mock_block_creator = Arc::new(MockQbftBlockCreator::new(Arc::new(parent_header.clone()), mock_block_creator_final_state, Arc::new(AlloyBftExtraDataCodec::default())));
        let mock_block_importer = Arc::new(MockQbftBlockImporter::default());
        let mock_multicaster = Arc::new(MockValidatorMulticaster::default());
        let mock_round_timer = Arc::new(MockRoundTimer::default());
        let test_codec = testing_extradata_codec_local(); 
        let config = default_test_qbft_config();

        let error_message = "Invalid signature on proposal".to_string();
        let configured_error = QbftError::ValidationError(error_message.clone());
        
        let factory_config = ConfigurableMockMessageValidatorFactory::new()
            .set_proposal_failure(true, Some(configured_error.clone())); 
        let msg_validator_factory = Arc::new(factory_config);
        
        let proposal_validator_mock = msg_validator_factory.clone().create_proposal_validator();
        let prepare_validator_mock = msg_validator_factory.clone().create_prepare_validator();
        let commit_validator_mock = msg_validator_factory.create_commit_validator();

        let mut qbft_round = setup_qbft_round(
            round_id,
            parent_header.clone(),
            mock_final_state.clone(), 
            mock_block_creator.clone(), 
            mock_block_importer,
            message_factory.clone(), 
            mock_multicaster.clone(),
            mock_round_timer,
            test_codec,
            proposal_validator_mock, 
            prepare_validator_mock,  
            commit_validator_mock,   
            config.clone(),
            vec![Arc::new(MockObserver)],
            None, 
        );

        let proposed_block = mock_block_creator.create_block(&parent_header, &round_id, parent_header.timestamp + 1).unwrap();
        let proposal_message = message_factory.create_proposal(
            round_id,
            proposed_block.clone(),
            vec![], 
            None,   
        ).unwrap();

        let result = qbft_round.handle_proposal_message(proposal_message.clone());

        assert!(matches!(result, Err(QbftError::ValidationError(_))), "Expected QbftError::ValidationError, got {:?}", result);
        if let Err(QbftError::ValidationError(msg)) = result {
            assert_eq!(msg, error_message, "Error message mismatch");
        } else {
            panic!("Expected QbftError::ValidationError with message \"{}\", got {:?}", error_message, result);
        }
    }

    #[test]
    fn test_handle_proposal_invalid_block_header() {
        let local_node_key_arc = deterministic_node_key(1);
        let local_address = address_from_arc_key(&local_node_key_arc);
        
        let validators: HashSet<Address> = vec![local_address].into_iter().collect();
        
        let sequence_number = 1u64;
        let round_number = 0u32;
        let round_id = ConsensusRoundIdentifier { sequence_number, round_number };

        let mut hash_bytes = [0u8; 32];
        let val_bytes = (sequence_number - 1).to_be_bytes();
        hash_bytes[24..].copy_from_slice(&val_bytes);
        let parent_hash = B256::new(hash_bytes);
        let parent_header = simple_parent_header(sequence_number - 1, parent_hash);

        let mock_final_state = Arc::new(MockQbftFinalState::new(local_node_key_arc.clone(), validators.clone()));

        let message_factory = Arc::new(MessageFactory::new(local_node_key_arc.clone()).unwrap());
        let mock_block_creator_final_state = Arc::new(MockQbftFinalState::new(local_node_key_arc.clone(), validators.clone()));
        let mock_block_creator = Arc::new(MockQbftBlockCreator::new(Arc::new(parent_header.clone()), mock_block_creator_final_state, Arc::new(AlloyBftExtraDataCodec::default())));
        let mock_block_importer = Arc::new(MockQbftBlockImporter::default());
        let mock_multicaster = Arc::new(MockValidatorMulticaster::default());
        let mock_round_timer = Arc::new(MockRoundTimer::default());
        let test_codec = testing_extradata_codec_local(); 
        let config = default_test_qbft_config();

        let error_message = "Invalid block header in proposal".to_string();
        let configured_error = QbftError::ValidationError(error_message.clone());
        
        let factory_config = ConfigurableMockMessageValidatorFactory::new()
            .set_proposal_failure(true, Some(configured_error.clone())); 
        let msg_validator_factory = Arc::new(factory_config);
        
        let proposal_validator_mock = msg_validator_factory.clone().create_proposal_validator();
        let prepare_validator_mock = msg_validator_factory.clone().create_prepare_validator();
        let commit_validator_mock = msg_validator_factory.create_commit_validator();

        let mut qbft_round = setup_qbft_round(
            round_id,
            parent_header.clone(),
            mock_final_state.clone(), 
            mock_block_creator.clone(), 
            mock_block_importer,
            message_factory.clone(), 
            mock_multicaster.clone(),
            mock_round_timer,
            test_codec,
            proposal_validator_mock, 
            prepare_validator_mock,  
            commit_validator_mock,   
            config.clone(),
            vec![Arc::new(MockObserver)],
            None, 
        );

        let proposed_block = mock_block_creator.create_block(&parent_header, &round_id, parent_header.timestamp + 1).unwrap();
        let proposal_message = message_factory.create_proposal(
            round_id,
            proposed_block.clone(),
            vec![], 
            None,   
        ).unwrap();

        let result = qbft_round.handle_proposal_message(proposal_message.clone());

        assert!(matches!(result, Err(QbftError::ValidationError(_))), "Expected QbftError::ValidationError, got {:?}", result);
        if let Err(QbftError::ValidationError(msg)) = result {
            assert_eq!(msg, error_message, "Error message mismatch for block header validation.");
        }
        
        assert!(qbft_round.round_state().proposal_message().is_none(), "Proposal should not be set in RoundState after header validation failure");
        assert_eq!(mock_multicaster.prepares.lock().unwrap().len(), 0, "No Prepare message should have been sent after header validation failure");
    }

    #[test]
    fn test_handle_proposal_duplicate() {
        let local_node_key_arc = deterministic_node_key(1); 
        let local_address = address_from_arc_key(&local_node_key_arc); 
        
        let validators: HashSet<Address> = vec![local_address].into_iter().collect();
        
        let sequence_number = 1u64;
        let round_number = 0u32;
        let round_id = ConsensusRoundIdentifier { sequence_number, round_number };

        let mut hash_bytes = [0u8; 32];
        let val_bytes = (sequence_number - 1).to_be_bytes(); 
        hash_bytes[24..].copy_from_slice(&val_bytes); 
        let parent_hash = B256::new(hash_bytes);
        let parent_header = simple_parent_header(sequence_number - 1, parent_hash);

        let mock_final_state = Arc::new(MockQbftFinalState::new(local_node_key_arc.clone(), validators.clone()));

        let message_factory = Arc::new(MessageFactory::new(local_node_key_arc.clone()).unwrap());
        let mock_block_creator = Arc::new(MockQbftBlockCreator::new(Arc::new(parent_header.clone()), mock_final_state.clone(), Arc::new(AlloyBftExtraDataCodec::default())));
        let mock_block_importer = Arc::new(MockQbftBlockImporter::default());
        let mock_multicaster = Arc::new(MockValidatorMulticaster::default());
        let mock_round_timer = Arc::new(MockRoundTimer::default());
        let test_codec = testing_extradata_codec_local(); 
        let config = default_test_qbft_config();

        let msg_validator_factory = Arc::new(
            ConfigurableMockMessageValidatorFactory::new().set_proposal_failure(false, None)
        );

        let mut qbft_round = setup_qbft_round(
            round_id,
            parent_header.clone(),
            mock_final_state.clone(),
            mock_block_creator.clone(),
            mock_block_importer.clone(),
            message_factory.clone(),
            mock_multicaster.clone(),
            mock_round_timer.clone(),
            test_codec.clone(),
            msg_validator_factory.clone().create_proposal_validator(),
            msg_validator_factory.clone().create_prepare_validator(),
            msg_validator_factory.create_commit_validator(),
            config.clone(),
            vec![Arc::new(MockObserver)],
            None,
        );

        let proposed_block = mock_block_creator.create_block(&parent_header, &round_id, parent_header.timestamp + 1).unwrap();
        let proposal_message = message_factory.create_proposal(round_id, proposed_block.clone(), vec![], None).unwrap();

        let result1 = qbft_round.handle_proposal_message(proposal_message.clone());
        assert!(result1.is_ok(), "First handle_proposal_message failed: {:?}", result1.err());
        assert_eq!(mock_multicaster.prepares.lock().unwrap().len(), 1, "Expected 1 Prepare message after first proposal");

        let result2 = qbft_round.handle_proposal_message(proposal_message);

        assert!(matches!(result2, Err(QbftError::ProposalAlreadyReceived { .. })), "Expected ProposalAlreadyReceived error, got {:?}", result2);
        
        assert_eq!(mock_multicaster.prepares.lock().unwrap().len(), 1, "No additional Prepare message should be sent for duplicate proposal");
    }

    #[test]
    fn test_handle_proposal_when_round_already_prepared() {
        let local_node_key_arc = deterministic_node_key(1); 
        let local_address = address_from_arc_key(&local_node_key_arc);
        let initial_proposer_key_arc = deterministic_node_key(2); 
        let initial_proposer_address = address_from_arc_key(&initial_proposer_key_arc);

        let validators: HashSet<Address> = vec![local_address, initial_proposer_address].into_iter().collect();
        
        let sequence_number = 1u64;
        let round_number = 0u32; 
        let round_id = ConsensusRoundIdentifier { sequence_number, round_number };

        let mut hash_bytes = [0u8; 32];
        let val_bytes = (sequence_number - 1).to_be_bytes(); 
        hash_bytes[24..].copy_from_slice(&val_bytes); 
        let parent_hash = B256::new(hash_bytes);
        let parent_header = simple_parent_header(sequence_number - 1, parent_hash);

        let mock_final_state_for_qbft_round = Arc::new(MockQbftFinalState::new(local_node_key_arc.clone(), validators.clone()));
        let actual_initial_proposer = mock_final_state_for_qbft_round.get_proposer_for_round(&round_id).unwrap();
        
        let initial_message_factory_key = if actual_initial_proposer == initial_proposer_address {
            initial_proposer_key_arc.clone()
        } else if actual_initial_proposer == local_address {
            local_node_key_arc.clone()
        } else {
            panic!("Actual proposer is neither of the expected addresses.");
        };

        let initial_message_factory = Arc::new(MessageFactory::new(initial_message_factory_key.clone()).unwrap());
        assert_eq!(address_from_arc_key(&initial_message_factory_key), actual_initial_proposer, "Initial message factory key does not match determined proposer address");

        let later_message_factory = Arc::new(MessageFactory::new(local_node_key_arc.clone()).unwrap());

        let mock_block_creator_final_state = Arc::new(MockQbftFinalState::new(initial_proposer_key_arc.clone(), validators.clone()));
        let mock_block_creator = Arc::new(MockQbftBlockCreator::new(Arc::new(parent_header.clone()), mock_block_creator_final_state, Arc::new(AlloyBftExtraDataCodec::default())));
        
        let mock_block_importer = Arc::new(MockQbftBlockImporter::default());
        let mock_multicaster = Arc::new(MockValidatorMulticaster::default());
        let mock_round_timer = Arc::new(MockRoundTimer::default());
        let test_codec = testing_extradata_codec_local(); 
        let config = default_test_qbft_config();

        let msg_validator_factory = Arc::new(
            ConfigurableMockMessageValidatorFactory::new().set_proposal_failure(false, None)
        );

        let mut qbft_round = setup_qbft_round(
            round_id,
            parent_header.clone(),
            mock_final_state_for_qbft_round.clone(), 
            mock_block_creator.clone(),
            mock_block_importer.clone(),
            later_message_factory.clone(), 
            mock_multicaster.clone(),
            mock_round_timer.clone(),
            test_codec.clone(),
            msg_validator_factory.clone().create_proposal_validator(),
            msg_validator_factory.clone().create_prepare_validator(),
            msg_validator_factory.clone().create_commit_validator(),
            config.clone(),
            vec![Arc::new(MockObserver)],
            None,
        );

        let initial_proposed_block = mock_block_creator.create_block(&parent_header, &round_id, parent_header.timestamp + 1).unwrap();
        let initial_proposal_digest = initial_proposed_block.hash();
        let initial_proposal_message = initial_message_factory.create_proposal(round_id, initial_proposed_block.clone(), vec![], None).unwrap();
        
        qbft_round.round_state.set_proposal(initial_proposal_message.clone()).expect("Setting initial proposal failed");

        let prepare1 = initial_message_factory.create_prepare(round_id, initial_proposal_digest).unwrap();
        qbft_round.round_state.add_prepare(prepare1.clone()).expect("Adding prepare from initial proposer failed");
        
        let prepare2 = later_message_factory.create_prepare(round_id, initial_proposal_digest).unwrap();
        qbft_round.round_state.add_prepare(prepare2.clone()).expect("Adding prepare from local node failed");
                
        assert!(qbft_round.round_state().is_prepared(), "RoundState should be PREPARED after manual setup with 2 prepares for N=2");
        
        let initial_prepare_count = mock_multicaster.prepares.lock().unwrap().len();

        let late_proposed_block = mock_block_creator.create_block(&parent_header, &round_id, parent_header.timestamp + 2).unwrap();
        let late_proposal_message = later_message_factory.create_proposal(round_id, late_proposed_block.clone(), vec![], None).unwrap();

        let result = qbft_round.handle_proposal_message(late_proposal_message);

        assert!(matches!(result, Err(QbftError::ProposalAlreadyReceived { .. }) ), 
            "Expected ProposalAlreadyReceived error, got {:?}", result);
        
        assert_eq!(mock_multicaster.prepares.lock().unwrap().len(), initial_prepare_count, 
            "No additional Prepare messages should have been sent by QbftRound for a late proposal");
    }

    #[test]
    fn test_handle_prepare_reaches_prepared_sends_commit() {
        // Setup: 4 Validators (V1=proposer, V2=local_node, V3, V4). Quorum = 3.
        let key_v1 = deterministic_node_key(1); // Proposer
        let addr_v1 = address_from_arc_key(&key_v1);
        let key_v2 = deterministic_node_key(2); // Local node under test
        let addr_v2 = address_from_arc_key(&key_v2);
        let key_v3 = deterministic_node_key(3);
        let addr_v3 = address_from_arc_key(&key_v3);
        let key_v4 = deterministic_node_key(4);
        let addr_v4 = address_from_arc_key(&key_v4);

        let validators: HashSet<Address> = [addr_v1, addr_v2, addr_v3, addr_v4].iter().cloned().collect();
        assert_eq!(validators.len(), 4, "Should be 4 unique validators");

        let sequence_number = 1u64;
        let round_number = 0u32; // V1 will be proposer if sorted first or second by address (0 % 4 = 0)
        let round_id = ConsensusRoundIdentifier { sequence_number, round_number };

        let parent_header = simple_parent_header(sequence_number - 1, B256::random());

        // MockFinalState for QbftRound (V2's perspective)
        // It needs to know V2 is the local node.
        // Quorum calculation: F = (4-1)/3 = 1. Quorum = N-F = 4-1 = 3. (Using MockQbftFinalState's quorum_size impl)
        let mock_final_state_v2 = Arc::new(MockQbftFinalState::new(key_v2.clone(), validators.clone()));
        assert_eq!(mock_final_state_v2.quorum_size(), 3, "Quorum size should be 3 for 4 validators");

        // Determine actual proposer for round_id (V1 may not be if its address isn't first when sorted)
        let actual_proposer_addr = mock_final_state_v2.get_proposer_for_round(&round_id).unwrap();
        let proposer_key_arc = if actual_proposer_addr == addr_v1 { key_v1.clone() }
                             else if actual_proposer_addr == addr_v2 { key_v2.clone() } 
                             else if actual_proposer_addr == addr_v3 { key_v3.clone() }
                             else { key_v4.clone() }; // Should be one of them
        
        // Message Factories
        let proposer_mf = Arc::new(MessageFactory::new(proposer_key_arc.clone()).unwrap());
        let local_mf_v2 = Arc::new(MessageFactory::new(key_v2.clone()).unwrap()); // For V2's own messages (like Prepare, Commit)
        let v3_mf = Arc::new(MessageFactory::new(key_v3.clone()).unwrap());
        let v4_mf = Arc::new(MessageFactory::new(key_v4.clone()).unwrap());

        // Other Mocks
        // Block creator can use any key from the validator set for its internal final state mock
        let mock_block_creator_final_state = Arc::new(MockQbftFinalState::new(proposer_key_arc.clone(), validators.clone()));
        let mock_block_creator = Arc::new(MockQbftBlockCreator::new(Arc::new(parent_header.clone()), mock_block_creator_final_state, Arc::new(AlloyBftExtraDataCodec::default())));
        let mock_block_importer = Arc::new(MockQbftBlockImporter::default());
        let mock_multicaster_v2 = Arc::new(MockValidatorMulticaster::default());
        let mock_round_timer_v2 = Arc::new(MockRoundTimer::default());
        let test_codec = testing_extradata_codec_local(); 
        let config = default_test_qbft_config();

        // Message Validators (all succeeding)
        let msg_validator_factory = Arc::new(
            ConfigurableMockMessageValidatorFactory::new().set_proposal_failure(false, None)
        );

        let mut qbft_round_v2 = setup_qbft_round(
            round_id,
            parent_header.clone(),
            mock_final_state_v2.clone(), 
            mock_block_creator.clone(),
            mock_block_importer.clone(),
            local_mf_v2.clone(), // V2's own message factory for its QbftRound instance
            mock_multicaster_v2.clone(),
            mock_round_timer_v2.clone(),
            test_codec.clone(),
            msg_validator_factory.clone().create_proposal_validator(),
            msg_validator_factory.clone().create_prepare_validator(),
            msg_validator_factory.clone().create_commit_validator(),
            config.clone(),
            vec![Arc::new(MockObserver)],
            None, // No initial locked block
        );

        // 1. Proposer (actual_proposer) creates and sends proposal.
        let proposed_block = mock_block_creator.create_block(&parent_header, &round_id, parent_header.timestamp + 1).unwrap();
        let proposal_digest = proposed_block.hash();
        let proposal_message = proposer_mf.create_proposal(round_id, proposed_block.clone(), vec![], None).unwrap();

        // 2. V2 (local node) handles the proposal.
        // This should make V2 accept it and send its own Prepare (Prepare_V2).
        let res_handle_proposal = qbft_round_v2.handle_proposal_message(proposal_message.clone());
        assert!(res_handle_proposal.is_ok(), "V2 failed to handle proposal: {:?}", res_handle_proposal.err());
        assert_eq!(mock_multicaster_v2.prepares.lock().unwrap().len(), 1, "V2 should have sent its Prepare after proposal");
        assert!(!qbft_round_v2.round_state().is_prepared(), "Round should not be prepared yet (1/3 prepares)");
        assert!(!qbft_round_v2.commit_sent, "V2 commit_sent should be false initially");

        // 3. V3 sends Prepare_V3. V2 handles it.
        let prepare_v3 = v3_mf.create_prepare(round_id, proposal_digest).unwrap();
        let res_handle_prepare_v3 = qbft_round_v2.handle_prepare_message(prepare_v3);
        assert!(res_handle_prepare_v3.is_ok(), "V2 failed to handle Prepare_V3: {:?}", res_handle_prepare_v3.err());
        assert_eq!(res_handle_prepare_v3.unwrap(), None, "Handling Prepare_V3 should not finalize a block");
        assert!(!qbft_round_v2.round_state().is_prepared(), "Round should not be prepared yet (2/3 prepares)");
        assert!(!qbft_round_v2.commit_sent, "V2 commit_sent should still be false");
        assert_eq!(mock_multicaster_v2.commits.lock().unwrap().len(), 0, "V2 should not have sent a commit yet");

        // 4. V4 sends Prepare_V4. V2 handles it.
        let prepare_v4 = v4_mf.create_prepare(round_id, proposal_digest).unwrap();
        let res_handle_prepare_v4 = qbft_round_v2.handle_prepare_message(prepare_v4);
        assert!(res_handle_prepare_v4.is_ok(), "V2 failed to handle Prepare_V4: {:?}", res_handle_prepare_v4.err());
        assert_eq!(res_handle_prepare_v4.unwrap(), None, "Handling Prepare_V4 should not finalize a block");

        // Assertions after V2 processes Prepare_V4:
        assert!(qbft_round_v2.round_state().is_prepared(), "Round should now be prepared (3/3 prepares)");
        assert!(qbft_round_v2.locked_block.is_some(), "V2's locked_block should be set after becoming prepared");
        if let Some(locked_info) = &qbft_round_v2.locked_block {
            assert_eq!(locked_info.block.hash(), proposal_digest, "Locked block digest mismatch");
            assert_eq!(locked_info.prepares.len(), 3, "Locked block should have 3 prepares");
        }

        assert!(qbft_round_v2.commit_sent, "V2 commit_sent should be true as it should have sent its commit");
        assert_eq!(mock_multicaster_v2.commits.lock().unwrap().len(), 1, "V2 should have sent its Commit");
        if let Some(sent_commit) = mock_multicaster_v2.commits.lock().unwrap().get(0) {
            assert_eq!(sent_commit.author().unwrap(), addr_v2, "Sent commit author mismatch");
            assert_eq!(sent_commit.payload().digest, proposal_digest, "Sent commit digest mismatch");
        }
        
        assert!(!qbft_round_v2.round_state().is_committed(), "RoundState should not be committed yet (1/3 commits)");
    }

    #[test]
    fn test_handle_prepare_invalid_signature() {
        // Setup: 4 Validators (V1, V2=local_node, V3=sender of invalid prepare, V4)
        let key_v1 = deterministic_node_key(1); 
        let addr_v1 = address_from_arc_key(&key_v1);
        let key_v2 = deterministic_node_key(2); // Local node under test
        let addr_v2 = address_from_arc_key(&key_v2);
        let key_v3 = deterministic_node_key(3); // Sender of the invalid prepare
        let addr_v3 = address_from_arc_key(&key_v3);
        let key_v4 = deterministic_node_key(4); // Another validator
        let addr_v4 = address_from_arc_key(&key_v4);

        let validators: HashSet<Address> = [addr_v1, addr_v2, addr_v3, addr_v4].iter().cloned().collect();
        assert_eq!(validators.len(), 4, "HashSet of validators should contain 4 unique addresses");

        let sequence_number = 1u64;
        let round_number = 0u32;
        let round_id = ConsensusRoundIdentifier { sequence_number, round_number };
        let parent_header = simple_parent_header(sequence_number - 1, B256::random());

        let mock_final_state_v2 = Arc::new(MockQbftFinalState::new(key_v2.clone(), validators.clone()));
        // For N=4, F=(4-1)/3 = 1. Quorum (2F+1) = 3.
        assert_eq!(mock_final_state_v2.quorum_size(), 3, "Quorum size should be 3 for 4 validators with mock logic");

        // Determine actual proposer and get their key for message factory
        let proposer_keys_map = std::collections::HashMap::from([
            (addr_v1, key_v1.clone()),
            (addr_v2, key_v2.clone()),
            (addr_v3, key_v3.clone()),
            (addr_v4, key_v4.clone()),
        ]);
        let actual_proposer_addr = mock_final_state_v2.get_proposer_for_round(&round_id).unwrap();
        let proposer_key_arc = proposer_keys_map.get(&actual_proposer_addr).expect("Actual proposer not in key map").clone();
        
        let proposer_mf = Arc::new(MessageFactory::new(proposer_key_arc.clone()).unwrap());
        let local_mf_v2 = Arc::new(MessageFactory::new(key_v2.clone()).unwrap());
        let v3_mf = Arc::new(MessageFactory::new(key_v3.clone()).unwrap());

        // Block creator needs a final state; can use the proposer's key and full validator set for its internal mock final state.
        let mock_block_creator_final_state = Arc::new(MockQbftFinalState::new(proposer_key_arc.clone(), validators.clone()));
        let mock_block_creator = Arc::new(MockQbftBlockCreator::new(Arc::new(parent_header.clone()), mock_block_creator_final_state, Arc::new(AlloyBftExtraDataCodec::default())));
        let mock_block_importer = Arc::new(MockQbftBlockImporter::default());
        let mock_multicaster_v2 = Arc::new(MockValidatorMulticaster::default());
        let mock_round_timer_v2 = Arc::new(MockRoundTimer::default());
        let test_codec = testing_extradata_codec_local(); 
        let config = default_test_qbft_config();

        // Configure PrepareValidator to fail only for prepares from addr_v3
        let factory_config = ConfigurableMockMessageValidatorFactory::new()
            .set_prepare_failure_for_author(Some(addr_v3)); 
        
        let expected_error_msg_from_mock = format!("MockPrepareValidator failed as configured for author {:?}", addr_v3);

        let msg_validator_factory = Arc::new(factory_config);

        let mut qbft_round_v2 = setup_qbft_round(
            round_id,
            parent_header.clone(),
            mock_final_state_v2.clone(), 
            mock_block_creator.clone(),
            mock_block_importer.clone(),
            local_mf_v2.clone(), 
            mock_multicaster_v2.clone(),
            mock_round_timer_v2.clone(),
            test_codec.clone(),
            msg_validator_factory.clone().create_proposal_validator(), 
            msg_validator_factory.clone().create_prepare_validator(),  
            msg_validator_factory.clone().create_commit_validator(),
            config.clone(),
            vec![Arc::new(MockObserver)],
            None,
        );

        // 1. Proposer sends proposal, V2 accepts and sends its own Prepare.
        // This should succeed because V2's prepare is not from addr_v3.
        let proposed_block = mock_block_creator.create_block(&parent_header, &round_id, parent_header.timestamp + 1).unwrap();
        let proposal_digest = proposed_block.hash();
        let proposal_message = proposer_mf.create_proposal(round_id, proposed_block.clone(), vec![], None).unwrap();
        qbft_round_v2.handle_proposal_message(proposal_message.clone()).expect("V2 failed to handle proposal, but its own prepare should be valid.");
        
        let prepares_before_invalid = qbft_round_v2.round_state().get_prepare_messages().len();
        assert_eq!(prepares_before_invalid, 1, "V2 should have added its own prepare to round_state");
        // With N=4, Quorum=3. 1 prepare is not enough.
        assert!(!qbft_round_v2.round_state().is_prepared(), "Round should NOT be prepared after V2's own prepare (1/3 needed)");

        let locked_block_before = qbft_round_v2.locked_block.clone();
        let commits_sent_before = mock_multicaster_v2.commits.lock().unwrap().len();

        // 2. V3 sends a Prepare (which our mock validator will deem invalid).
        let prepare_v3_invalid = v3_mf.create_prepare(round_id, proposal_digest).unwrap();
        let result = qbft_round_v2.handle_prepare_message(prepare_v3_invalid);

        // Assertions
        assert!(matches!(result, Err(QbftError::ValidationError(_))), "Expected QbftError::ValidationError, got {:?}", result);
        if let Err(QbftError::ValidationError(msg)) = result {
            assert_eq!(msg, expected_error_msg_from_mock, "Error message mismatch for invalid prepare");
        }

        assert_eq!(qbft_round_v2.round_state().get_prepare_messages().len(), prepares_before_invalid, "Number of prepares in RoundState should not change due to invalid one");
        assert!(!qbft_round_v2.round_state().is_prepared(), "Round should not become prepared from an invalid prepare (still 1/3 needed)");
        assert_eq!(qbft_round_v2.locked_block.map(|lb| lb.block.hash()), locked_block_before.map(|lb| lb.block.hash()), "Locked block should not change");
        assert!(!qbft_round_v2.commit_sent, "V2 commit_sent should remain false");
        assert_eq!(mock_multicaster_v2.commits.lock().unwrap().len(), commits_sent_before, "V2 should not send a commit on invalid prepare");
    }

} 