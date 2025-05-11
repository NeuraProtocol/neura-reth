use crate::state::height_state::HeightState;
use crate::types::{
    QbftConfig, QbftFinalState, QbftBlockCreator, QbftBlockImporter, ValidatorMulticaster, RoundTimer,
    ConsensusRoundIdentifier, QbftBlock, QbftBlockHeader, BftExtraDataCodec, // Added BftExtraDataCodec
};
use crate::messagewrappers::{Proposal, Prepare, Commit, RoundChange};
use crate::payload::MessageFactory;
use crate::error::QbftError;
use alloy_primitives::Address;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH}; // Added SystemTime, UNIX_EPOCH
use log::{info, warn, trace};

pub struct HeightController {
    height_state: HeightState,
    parent_header: Arc<QbftBlockHeader>, // Added parent_header
    message_factory: Arc<MessageFactory>,
    validator_multicaster: Arc<dyn ValidatorMulticaster>,
    block_creator: Arc<dyn QbftBlockCreator>,
    block_importer: Arc<dyn QbftBlockImporter>,
    round_timer: Arc<dyn RoundTimer>, // For starting/cancelling round timers
    extra_data_codec: Arc<dyn BftExtraDataCodec>, // Added field
    // QbftConfig, QbftFinalState, local_address are available via height_state
}

impl HeightController {
    #[allow(clippy::too_many_arguments)] // Allow more arguments for the constructor
    pub fn new(
        sequence_number: u64,
        parent_header_for_creation: Arc<QbftBlockHeader>, // Renamed for clarity
        qbft_config: Arc<QbftConfig>,
        final_state_provider: Arc<dyn QbftFinalState>,
        local_address: Address,
        message_factory: Arc<MessageFactory>,
        validator_multicaster: Arc<dyn ValidatorMulticaster>,
        block_creator: Arc<dyn QbftBlockCreator>,
        block_importer: Arc<dyn QbftBlockImporter>,
        round_timer: Arc<dyn RoundTimer>,
        extra_data_codec: Arc<dyn BftExtraDataCodec>, // Added parameter
    ) -> Result<Self, QbftError> {
        let height_state = HeightState::new(
            sequence_number,
            qbft_config.clone(), // Arc clones pointer, not data
            final_state_provider.clone(),
            local_address,
        )?;
        
        Ok(Self {
            height_state,
            parent_header: parent_header_for_creation,
            message_factory,
            validator_multicaster,
            block_creator,
            block_importer,
            round_timer,
            extra_data_codec, // Added to struct initialization
        })
    }

    // Placeholder for the core decision-making logic
    fn check_state_and_act(&mut self) -> Result<(), QbftError> {
        info!(
            "Height {}: Checking state and acting. Current round: {}. Is complete: {}. Local Address: {:?}", 
            self.height_state.sequence_number, 
            self.height_state.current_round_number,
            self.height_state.is_complete(),
            self.height_state.local_address
        );

        if self.height_state.is_complete() {
            trace!("Height {} is complete, no further action.", self.height_state.sequence_number);
            return Ok(());
        }

        // Check for RoundChange quorum for future rounds first, as this can change the current round.
        // Collect rounds with existing state that are greater than current.
        let mut future_round_numbers: Vec<u32> = self.height_state.round_states.keys()
            .filter(|&&r| r > self.height_state.current_round_number)
            .cloned()
            .collect();
        future_round_numbers.sort_unstable(); // Process in increasing order

        for &target_future_round_num in &future_round_numbers {
            if let Some(future_round_state) = self.height_state.round_states.get(&target_future_round_num) {
                if future_round_state.has_round_change_quorum(self.height_state.round_change_min_quorum_size) {
                    info!(
                        "Height {}: RoundChange quorum met for future round {}. Current round is {}. Advancing to round {}.",
                        self.height_state.sequence_number, target_future_round_num, self.height_state.current_round_number, target_future_round_num
                    );
                    // Attempt to advance the round. start_new_round handles starting timers etc.
                    self.height_state.start_new_round(target_future_round_num)?;
                    // After advancing the round, we should re-evaluate state from the beginning of check_state_and_act.
                    // So, we return, and the next call (e.g. from message handler) will run with the new round.
                    return Ok(()); 
                }
            }
        }

        let current_round_identifier = ConsensusRoundIdentifier {
            sequence_number: self.height_state.sequence_number,
            round_number: self.height_state.current_round_number,
        };
        
        // Ensure round timer is active if we are not the proposer for the current round and height is not complete.
        // Proposer starts its own timer when it sends a proposal.
        if !self.height_state.is_complete() {
            let current_proposer_for_this_round = self.height_state.get_current_round_state().current_proposer;
            if self.height_state.local_address != current_proposer_for_this_round {
                let round_timeout_duration = self.height_state.qbft_config.message_round_timeout_ms;
                self.round_timer.start_timer(current_round_identifier, round_timeout_duration);
                trace!(
                    "Height {}, Round {}: Non-proposer. Ensured round timer is active for {}ms.",
                    current_round_identifier.sequence_number, current_round_identifier.round_number, round_timeout_duration
                );
            }
        }
        
        // Note: current_round_state is fetched within sections as needed to manage borrow lifetimes.

        // 1. Proposer Actions
        // Scope for proposer check's immutable borrow
        let should_propose = {
            let rs_check = self.height_state.get_current_round_state();
            rs_check.current_proposer == self.height_state.local_address && rs_check.proposal_message.is_none()
        };

        if should_propose {
            trace!("Height {}, Round {}: This node IS the proposer and needs to propose.", current_round_identifier.sequence_number, current_round_identifier.round_number);
            
            // Determine timestamp for the new block
            let current_system_time_seconds = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("Time went backwards or SystemTime is before UNIX_EPOCH. This should not happen.")
                .as_secs();
            let new_block_timestamp = std::cmp::max(self.parent_header.timestamp + 1, current_system_time_seconds);
            
            let new_block = self.block_creator.create_block(
                self.parent_header.as_ref(),
                &current_round_identifier, 
                new_block_timestamp
            )?;
            let proposal_message = self.message_factory.create_proposal(
                current_round_identifier, 
                new_block.clone(),
                Vec::new(),
                None
            )?;
            self.height_state.get_current_round_state_mut().set_proposal(
                proposal_message.clone()
            );
            info!(
                "Height {}, Round {}: Created and set proposal for block hash: {:?}. Broadcasting.",
                current_round_identifier.sequence_number,
                current_round_identifier.round_number,
                new_block.header.hash()
            );
            self.validator_multicaster.multicast_proposal(&proposal_message);
            let round_timeout_duration = self.height_state.qbft_config.message_round_timeout_ms;
            self.round_timer.start_timer(current_round_identifier, round_timeout_duration);
            trace!("Height {}, Round {}: Started round timer for {}ms.", current_round_identifier.sequence_number, current_round_identifier.round_number, round_timeout_duration);
        } else {
            // To provide a more specific trace, we can re-fetch and check conditions if needed, but this is simpler.
            // If not proposing, the timer started above (if applicable) handles round timeout.
            trace!("Height {}, Round {}: Not acting as proposer (either not proposer, or proposal already exists). Timer should be active if non-proposer.", current_round_identifier.sequence_number, current_round_identifier.round_number);
        }
        
        // Trace current state after potential proposer action. Uses a fresh immutable borrow.
        {
            let rs_for_trace = self.height_state.get_current_round_state();
            trace!(
                "Height {}, Round {}: Post-Proposer Action. Proposer: {:?}, Proposal Set: {}, Prepared: {}, Committed Locally: {}",
                current_round_identifier.sequence_number, current_round_identifier.round_number,
                rs_for_trace.current_proposer, rs_for_trace.proposal_message.is_some(),
                rs_for_trace.is_prepared(), rs_for_trace.has_committed_locally(&self.height_state.local_address)
            );
        }

        // 2. Send Prepare if a valid proposal exists and we haven't prepared yet for this digest
        {
            // Fresh immutable borrow for prepare logic
            let current_round_state_for_prepare = self.height_state.get_current_round_state();
            if let (Some(_proposal_msg), Some(proposed_block_digest)) =
                (&current_round_state_for_prepare.proposal_message, current_round_state_for_prepare.proposed_block_hash) {
                
                let already_prepared_this_digest = current_round_state_for_prepare
                    .prepare_messages
                    .get(&self.height_state.local_address)
                    .map_or(false, |existing_prepare| existing_prepare.payload().digest == proposed_block_digest);

                if !already_prepared_this_digest {
                    trace!(
                        "Height {}, Round {}: Valid proposal {:?} exists. This node has not sent Prepare yet. Sending Prepare.",
                        current_round_identifier.sequence_number, current_round_identifier.round_number, proposed_block_digest
                    );
                    let prepare_message = self.message_factory.create_prepare(
                        current_round_identifier, 
                        proposed_block_digest
                    )?;
                    // Mutable borrow for add_prepare, scoped within this block if possible, or ensure prior immutable borrows are dropped.
                    self.height_state.get_current_round_state_mut().add_prepare(prepare_message.clone())
                        .map_err(|e| QbftError::InternalError(format!("Failed to add self-prepare: {}", e)))?;
                    info!(
                        "Height {}, Round {}: Sent Prepare for digest {:?}.",
                        current_round_identifier.sequence_number, current_round_identifier.round_number, proposed_block_digest
                    );
                    self.validator_multicaster.multicast_prepare(&prepare_message);
                } else {
                    trace!(
                        "Height {}, Round {}: Already sent Prepare for digest {:?} in this round.",
                        current_round_identifier.sequence_number, current_round_identifier.round_number, proposed_block_digest
                    );
                }
            } else {
                trace!(
                    "Height {}, Round {}: No active proposal or proposal digest. Cannot send Prepare.", 
                    current_round_identifier.sequence_number, current_round_identifier.round_number
                );
            }
        }

        // 3. Form Prepared Certificate if prepare quorum is met and not already prepared
        let current_round_state = self.height_state.get_current_round_state(); // Immutable borrow first for checks

        if current_round_state.proposal_message.is_some() && 
           !current_round_state.is_prepared() &&
           current_round_state.has_prepare_quorum(self.height_state.prepare_quorum_size) {
            
            trace!(
                "Height {}, Round {}: Prepare quorum met. Forming prepared certificate.",
                current_round_identifier.sequence_number, current_round_identifier.round_number
            );

            // Now get mutable access to form the certificate
            match self.height_state.get_current_round_state_mut().form_prepared_certificate() {
                Ok(_) => {
                    info!(
                        "Height {}, Round {}: Successfully formed PreparedCertificate.",
                        current_round_identifier.sequence_number, current_round_identifier.round_number
                    );
                    // After forming a prepared certificate, this node should immediately send a Commit.
                    // This will be handled in the next section of check_state_and_act.
                }
                Err(e) => {
                    // Log the error, but don't necessarily halt all operations unless it's critical.
                    // QbftError::InternalError might be too generic if form_prepared_certificate provides specific errors.
                    warn!(
                        "Height {}, Round {}: Failed to form PreparedCertificate: {}. This might be a bug or race condition.",
                        current_round_identifier.sequence_number, current_round_identifier.round_number, e
                    );
                    // Depending on the error, we might want to return Err(QbftError::InternalError(e.to_string()))
                    // For now, just log and continue, as other actions might still be possible (e.g. round change due to timeout)
                }
            }
        }

        // 4. Send Commit if round is prepared and we haven't committed locally for this digest
        // Re-fetch current_round_state to ensure we see the newly formed certificate.
        let current_round_state = self.height_state.get_current_round_state(); // Immutable borrow for checks

        if current_round_state.is_prepared() {
            if let Some(prepared_block_digest) = current_round_state.proposed_block_hash {
                let already_committed_this_digest = current_round_state
                    .commit_messages
                    .get(&self.height_state.local_address)
                    .map_or(false, |existing_commit| existing_commit.payload().digest == prepared_block_digest);

                if !already_committed_this_digest {
                    trace!(
                        "Height {}, Round {}: Round is Prepared with digest {:?}. This node has not sent Commit yet. Sending Commit.",
                        current_round_identifier.sequence_number, current_round_identifier.round_number, prepared_block_digest
                    );

                    // Create Commit Seal (signature over the digest)
                    let commit_seal = self.message_factory.create_commit_seal(prepared_block_digest)?;
                    
                    // Create Commit message
                    let commit_message = self.message_factory.create_commit(
                        current_round_identifier,
                        prepared_block_digest,
                        commit_seal
                    )?;

                    // Add Commit to our own state (mutable borrow needed)
                    // Similar to add_prepare, map error from RoundState::add_commit if necessary.
                    self.height_state.get_current_round_state_mut().add_commit(commit_message.clone())
                        .map_err(|e| QbftError::InternalError(format!("Failed to add self-commit: {}", e)))?;

                    info!(
                        "Height {}, Round {}: Sent Commit for digest {:?}.",
                        current_round_identifier.sequence_number, current_round_identifier.round_number, prepared_block_digest
                    );

                    // Multicast the Commit message
                    self.validator_multicaster.multicast_commit(&commit_message); // Does not return Result

                } else {
                    trace!(
                        "Height {}, Round {}: Already sent Commit for digest {:?} in this round.",
                        current_round_identifier.sequence_number, current_round_identifier.round_number, prepared_block_digest
                    );
                }
            } else {
                // This case should ideally not happen if is_prepared() is true, as being prepared implies a proposal and thus a digest.
                warn!(
                    "Height {}, Round {}: Round is Prepared, but no proposed_block_hash found. Inconsistent state?",
                    current_round_identifier.sequence_number, current_round_identifier.round_number
                );
            }
        } else {
            trace!(
                "Height {}, Round {}: Round is not Prepared. Cannot send Commit.",
                current_round_identifier.sequence_number, current_round_identifier.round_number
            );
        }

        // 5. Check for Commit Quorum and Finalize Block
        if !self.height_state.is_complete() {
            // Re-fetch current_round_state to ensure all commits are seen
            let current_round_state = self.height_state.get_current_round_state();

            if current_round_state.has_commit_quorum(self.height_state.commit_quorum_size) {
                info!(
                    "Height {}: Commit Quorum MET in round {}. Attempting to finalize block.",
                    current_round_identifier.sequence_number, current_round_identifier.round_number
                );

                if let Some(mut block_to_finalize) = current_round_state.proposed_block.clone() {
                    let commit_seals: Vec<_> = current_round_state
                        .commit_messages
                        .values()
                        .map(|commit| commit.payload().committed_seal.clone())
                        .collect();
                    
                    trace!("Height {}, Round {}: Found {} commit seals for finalization.", current_round_identifier.sequence_number, current_round_identifier.round_number, commit_seals.len());

                    match self.extra_data_codec.decode(&block_to_finalize.header.extra_data) {
                        Ok(mut bft_extra_data) => {
                            bft_extra_data.committed_seals = commit_seals;
                            match self.extra_data_codec.encode(&bft_extra_data) {
                                Ok(updated_extra_data_bytes) => {
                                    let old_header = block_to_finalize.header.clone(); // Clone before moving
                                    block_to_finalize.header = QbftBlockHeader::new(
                                        old_header.parent_hash,
                                        old_header.ommers_hash,
                                        old_header.beneficiary,
                                        old_header.state_root,
                                        old_header.transactions_root,
                                        old_header.receipts_root,
                                        old_header.logs_bloom,
                                        old_header.difficulty,
                                        old_header.number,
                                        old_header.gas_limit,
                                        old_header.gas_used,
                                        old_header.timestamp,
                                        updated_extra_data_bytes.clone(),
                                        old_header.mix_hash,
                                        old_header.nonce.clone(),
                                    );
                                    let new_block_hash = block_to_finalize.header.hash();

                                    info!(
                                        "Height {}, Round {}: ExtraData updated. Old hash: {:?}, New hash for import: {:?}. Importing block...",
                                        current_round_identifier.sequence_number, current_round_identifier.round_number, old_header.hash(), new_block_hash
                                    );

                                    match self.block_importer.import_block(&block_to_finalize) {
                                        Ok(_) => {
                                            info!(
                                                "Height {}, Round {}: Block {:?} SUCCESSFULLY IMPORTED.",
                                                current_round_identifier.sequence_number, current_round_identifier.round_number, new_block_hash
                                            );
                                            self.height_state.committed_block = Some(block_to_finalize);
                                            self.round_timer.cancel_timer(current_round_identifier);
                                            trace!("Height {}, Round {}: Cancelled round timer.", current_round_identifier.sequence_number, current_round_identifier.round_number);
                                        }
                                        Err(e) => {
                                            warn!(
                                                "Height {}, Round {}: Failed to import block {:?}: {:?}. Height remains active.",
                                                current_round_identifier.sequence_number, current_round_identifier.round_number, new_block_hash, e
                                            );
                                        }
                                    }
                                }
                                Err(e) => {
                                    warn!("Height {}, Round {}: Failed to ENCODE BftExtraData: {:?}. Cannot finalize block.", current_round_identifier.sequence_number, current_round_identifier.round_number, e);
                                }
                            }
                        }
                        Err(e) => {
                            warn!("Height {}, Round {}: Failed to DECODE BftExtraData: {:?}. Cannot finalize block.", current_round_identifier.sequence_number, current_round_identifier.round_number, e);
                        }
                    }
                } else {
                    warn!(
                        "Height {}, Round {}: Commit Quorum met, but no proposed block in RoundState. This is unexpected.",
                        current_round_identifier.sequence_number, current_round_identifier.round_number
                    );
                }
            }
        }

        // 6. Send RoundChange if previous round timed out
        // This part needs to run even if the block was just committed, to ensure we handle scenarios
        // where a timeout might have been processed JUST before commit quorum was observed by this node.
        // However, if height is complete, no further action.
        if !self.height_state.is_complete() {
            let current_round_num = self.height_state.current_round_number;
            if current_round_num > 0 {
                let prev_round_num = current_round_num - 1;
                if let Some(prev_round_state) = self.height_state.round_states.get(&prev_round_num) {
                    if prev_round_state.timed_out {
                        // Check if we already sent a RoundChange for the *current_round_num*
                        let already_sent_rc_for_current_round = self.height_state.get_current_round_state()
                            .round_change_messages
                            .contains_key(&self.height_state.local_address);

                        if !already_sent_rc_for_current_round {
                            trace!(
                                "Height {}, Prev Round {}: Timed out. Current round is {}. Sending RoundChange.",
                                self.height_state.sequence_number, prev_round_num, current_round_num
                            );

                            let best_prior_cert_wrapper = self.height_state.get_best_prepared_certificate_from_prior_rounds(current_round_num);
                            
                            let (prm_opt, p_block_opt) = if let Some(cert_wrapper) = best_prior_cert_wrapper {
                                let prm = crate::payload::PreparedRoundMetadata { // Corrected path to PreparedRoundMetadata
                                    prepared_round: cert_wrapper.proposal_message.payload().round_identifier.round_number,
                                    prepared_block_hash: cert_wrapper.proposal_message.payload().proposed_block.hash(),
                                    signed_proposal_payload: cert_wrapper.proposal_message.clone(),
                                    prepares: cert_wrapper.prepares.iter().map(|p| p.signed_payload.clone()).collect(), // Corrected: .signed_payload is a field
                                };
                                let p_block = cert_wrapper.proposal_message.payload().proposed_block.clone();
                                (Some(prm), Some(p_block))
                            } else {
                                (None, None)
                            };

                            let target_rc_identifier = ConsensusRoundIdentifier {
                                sequence_number: self.height_state.sequence_number,
                                round_number: current_round_num,
                            };

                            let round_change_message = self.message_factory.create_round_change(
                                target_rc_identifier,
                                prm_opt,
                                p_block_opt
                            )?;

                            // Add RoundChange to current round's state
                            self.height_state.get_current_round_state_mut().add_round_change(round_change_message.clone())
                                .map_err(|e| QbftError::InternalError(format!("Failed to add self-round_change: {}", e)))?;
                            
                            info!(
                                "Height {}, Round {}: Sent RoundChange targeting this round.",
                                self.height_state.sequence_number, current_round_num
                            );

                            // Multicast RoundChange
                            self.validator_multicaster.multicast_round_change(&round_change_message);

                            // Ensure timer for the new current round is running.
                            // If this node is not the proposer for current_round_num, it needs a timeout.
                            // If it *is* the proposer, it will have started its timer when it proposed.
                            // The HeightState::start_new_round (called by handle_round_timeout) should ideally handle
                            // starting the timer for the new round if not proposer.
                            // Let's double-check if HeightController should ensure it here too, for non-proposers.
                            // The proposer logic already starts a timer. This is for non-proposers entering a new round post-timeout.
                            let current_proposer_for_new_round = self.height_state.get_current_round_state().current_proposer;
                            if self.height_state.local_address != current_proposer_for_new_round {
                                // Only start timer if not proposer, as proposer starts its own.
                                // However, is the timer already started by `HeightState::start_new_round`?
                                // Let's assume `HeightState::start_new_round` or the initial proposal flow handles this.
                                // For now, no explicit timer start here, relying on other mechanisms.
                                // This might be a point to review: ensuring timers are always active for non-finalized rounds.
                                // With the new logic at the start of check_state_and_act, this should be covered.
                                trace!(
                                    "Height {}, Round {}: Previous round timed out. New round timer should be active (proposer: {:?}).",
                                    self.height_state.sequence_number, current_round_num, current_proposer_for_new_round
                                );
                            }
                        } else {
                            trace!(
                                "Height {}, Round {}: Previous round timed out, but RoundChange already sent for current round.",
                                self.height_state.sequence_number, current_round_num
                            );
                        }
                    }
                }
            }
        }

        // Section 1 of check_state_and_act already handles evaluating RoundChange messages for future rounds.
        Ok(())
    }

    // --- Message Handlers ---
    // These will call the HeightState handlers and then trigger check_state_and_act

    pub fn handle_incoming_proposal(&mut self, proposal: Proposal) -> Result<(), QbftError> {
        self.height_state.handle_proposal_message(proposal)?;
        self.check_state_and_act()
    }

    pub fn handle_incoming_prepare(&mut self, prepare: Prepare) -> Result<(), QbftError> {
        self.height_state.handle_prepare_message(prepare)?;
        self.check_state_and_act()
    }

    pub fn handle_incoming_commit(&mut self, commit: Commit) -> Result<(), QbftError> {
        self.height_state.handle_commit_message(commit)?;
        self.check_state_and_act()
    }

    pub fn handle_incoming_round_change(&mut self, round_change: RoundChange) -> Result<(), QbftError> {
        self.height_state.handle_round_change_message(round_change)?;
        self.check_state_and_act()
    }

    pub fn handle_round_timeout(&mut self, timed_out_round_number: u32) -> Result<(), QbftError> {
        self.height_state.handle_round_timeout(timed_out_round_number)?;
        // After handling timeout, HeightState might have advanced the round.
        // check_state_and_act() will then be called. Its section 6 handles sending RoundChange if prev round timed out.
        self.check_state_and_act() 
    }
    
    // --- Accessors for external queries (optional, could be direct from HeightState if public) ---
    pub fn sequence_number(&self) -> u64 {
        self.height_state.sequence_number
    }

    pub fn is_complete(&self) -> bool {
        self.height_state.is_complete()
    }

    pub fn get_committed_block(&self) -> Option<&QbftBlock> {
        self.height_state.get_committed_block()
    }
}
