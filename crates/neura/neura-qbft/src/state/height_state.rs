use crate::state::round_state::RoundState;
use crate::types::QbftConfig;
use crate::types::QbftFinalState;
use crate::messagewrappers::{Proposal, Prepare, Commit, RoundChange, PreparedCertificateWrapper};
use crate::types::{ConsensusRoundIdentifier, QbftBlock};
use alloy_primitives::{Address, B256};
use std::collections::HashMap;
use std::sync::Arc;
use log::{info, warn, trace}; // Added for logging

pub struct HeightState {
    pub sequence_number: u64,
    pub current_round_number: u32,
    pub round_states: HashMap<u32, RoundState>,
    pub committed_block: Option<QbftBlock>,
    
    // Buffers for messages received for future rounds at this height
    pub future_proposals: HashMap<u32, Vec<Proposal>>,
    pub future_prepares: HashMap<u32, Vec<Prepare>>,
    pub future_commits: HashMap<u32, Vec<Commit>>,
    
    // Configuration and external state access
    pub qbft_config: Arc<QbftConfig>,
    pub final_state: Arc<dyn QbftFinalState>,
    pub local_address: Address, // Address of the local node

    // Validator and quorum information for this height
    pub validator_set: Vec<Address>,
    pub fault_tolerance_f: usize,       // (N-1)/3
    pub prepare_quorum_size: usize,     // 2F+1
    pub commit_quorum_size: usize,      // 2F+1
    // Quorum for round changes can vary; F+1 is a common minimum for some checks,
    // while others might require 2F+1 (e.g. for a strong certificate).
    // Let's define a general one, specific uses might calculate on the fly or use a different field.
    pub round_change_min_quorum_size: usize, // F+1 
}

impl HeightState {
    pub fn new(
        sequence_number: u64,
        qbft_config: Arc<QbftConfig>,
        final_state: Arc<dyn QbftFinalState>,
        local_address: Address,
    ) -> Result<Self, crate::error::QbftError> { // Assuming QbftError is at crate::error
        let validator_set = final_state.get_validators_for_block(sequence_number)?;
        if validator_set.is_empty() {
            return Err(crate::error::QbftError::NoValidators);
        }

        let n = validator_set.len();
        let fault_tolerance_f = (n - 1) / 3;
        let prepare_quorum_size = 2 * fault_tolerance_f + 1;
        let commit_quorum_size = 2 * fault_tolerance_f + 1;
        let round_change_min_quorum_size = fault_tolerance_f + 1;

        let initial_round_number = 0;
        let initial_round_identifier = ConsensusRoundIdentifier::new(sequence_number, initial_round_number);
        let initial_proposer = final_state.get_proposer_for_round(&initial_round_identifier)?;
        
        let initial_round_state = RoundState::new(initial_round_identifier, initial_proposer);
        let mut round_states = HashMap::new();
        round_states.insert(initial_round_number, initial_round_state);

        Ok(Self {
            sequence_number,
            current_round_number: initial_round_number,
            round_states,
            committed_block: None,
            future_proposals: HashMap::new(), // Initialize buffer
            future_prepares: HashMap::new(), // Initialize buffer
            future_commits: HashMap::new(), // Initialize buffer
            qbft_config,
            final_state,
            local_address,
            validator_set,
            fault_tolerance_f,
            prepare_quorum_size,
            commit_quorum_size,
            round_change_min_quorum_size,
        })
    }

    /// Returns an immutable reference to the current `RoundState`.
    /// Panics if the current round state is not found, which indicates an invariant violation.
    pub fn get_current_round_state(&self) -> &RoundState {
        self.round_states.get(&self.current_round_number)
            .expect("Current round state not found, invariant violation.")
    }

    /// Returns a mutable reference to the current `RoundState`.
    /// Panics if the current round state is not found, which indicates an invariant violation.
    pub fn get_current_round_state_mut(&mut self) -> &mut RoundState {
        self.round_states.get_mut(&self.current_round_number)
            .expect("Current round state not found, invariant violation.")
    }

    /// Advances the height state to a new round.
    /// This involves setting the current round number, determining the new proposer,
    /// and creating a new `RoundState` for that round.
    /// If a `RoundState` for `new_round_number` already exists, it will be replaced.
    pub fn start_new_round(&mut self, new_round_number: u32) -> Result<(), crate::error::QbftError> {
        self.current_round_number = new_round_number;

        let new_round_identifier = ConsensusRoundIdentifier::new(
            self.sequence_number, 
            new_round_number
        );

        let new_proposer = self.final_state.get_proposer_for_round(&new_round_identifier)?;
        
        let new_round_state = RoundState::new(new_round_identifier, new_proposer);
        self.round_states.insert(new_round_number, new_round_state);
        
        // Process any buffered messages for this new round
        self.process_buffered_messages_for_round(new_round_number);

        // TODO: Potentially trigger round start actions, like starting a round timer, 
        // or notifying observers. This might be handled by the caller or a controller.
        // log::info!("Height {}: Started new round {}", self.sequence_number, new_round_number);

        Ok(())
    }

    /// Processes any messages that were buffered for the given round number.
    fn process_buffered_messages_for_round(&mut self, round_number: u32) {
        // Get a mutable reference to the round state for this round number.
        // If it doesn't exist (e.g. called out of band), we can't process, so just return.
        // However, in the context of start_new_round, it should always exist.
        let round_state = match self.round_states.get_mut(&round_number) {
            Some(rs) => rs,
            None => {
                warn!(
                    "HeightState {}: Attempted to process buffered messages for round {} but no such RoundState exists.",
                    self.sequence_number, round_number
                );
                return;
            }
        };

        // Process Proposals
        if let Some(proposals) = self.future_proposals.remove(&round_number) {
            if proposals.len() > 1 {
                warn!(
                    "HeightState {}: Multiple proposals ({}) buffered for round {}. Processing only the first one found.", 
                    self.sequence_number, proposals.len(), round_number
                );
            }
            if let Some(proposal) = proposals.into_iter().next() { // Process first one if any
                info!("HeightState {}: Processing buffered proposal for round {}", self.sequence_number, round_number);
                round_state.set_proposal(proposal);
            }
        }

        // Process Prepares
        if let Some(prepares) = self.future_prepares.remove(&round_number) {
            info!(
                "HeightState {}: Processing {} buffered prepares for round {}", 
                self.sequence_number, prepares.len(), round_number
            );
            for prepare in prepares {
                if let Err(e) = round_state.add_prepare(prepare) {
                    warn!(
                        "HeightState {}: Error processing buffered prepare for round {}: {}", 
                        self.sequence_number, round_number, e
                    );
                }
            }
        }

        // Process Commits
        if let Some(commits) = self.future_commits.remove(&round_number) {
            info!(
                "HeightState {}: Processing {} buffered commits for round {}", 
                self.sequence_number, commits.len(), round_number
            );
            for commit in commits {
                if let Err(e) = round_state.add_commit(commit) {
                    warn!(
                        "HeightState {}: Error processing buffered commit for round {}: {}", 
                        self.sequence_number, round_number, e
                    );
                }
            }
        }
    }

    /// Handles an incoming Proposal message.
    /// Routes the proposal to the appropriate round state or ignores it.
    /// Assumes the proposal has undergone basic external validation (e.g., signature).
    pub fn handle_proposal_message(&mut self, proposal: Proposal) -> Result<(), crate::error::QbftError> {
        let proposal_sequence_number = proposal.round_identifier().sequence_number;
        let proposal_round_number = proposal.round_identifier().round_number;

        if proposal_sequence_number != self.sequence_number {
            trace!(
                "HeightState {}: Received proposal for different sequence number {}. Ignoring.",
                self.sequence_number,
                proposal_sequence_number
            );
            return Ok(());
        }

        if proposal_round_number == self.current_round_number {
            info!(
                "HeightState {}: Received proposal for current round {}. Applying.",
                self.sequence_number,
                self.current_round_number
            );
            let current_round = self.get_current_round_state_mut();
            current_round.set_proposal(proposal);
            // TODO: After setting proposal, logic might be needed to trigger actions,
            // e.g., if this node is the proposer, it might create and send its own proposal,
            // or if a valid proposal is received, it might validate it and then send Prepares.
            // This higher-level logic typically resides in a controller using HeightState.
        } else if proposal_round_number > self.current_round_number {
            trace!(
                "HeightState {}: Received proposal for future round {}. Current round is {}. Buffering.",
                self.sequence_number,
                proposal_round_number,
                self.current_round_number
            );
            self.future_proposals.entry(proposal_round_number).or_default().push(proposal);
        } else {
            // Proposal for a past round
            trace!(
                "HeightState {}: Received proposal for past round {}. Current round is {}. Ignoring.",
                self.sequence_number,
                proposal_round_number,
                self.current_round_number
            );
        }
        Ok(())
    }

    /// Handles an incoming Prepare message.
    /// Routes the prepare to the appropriate round state or ignores it.
    /// Assumes the prepare has undergone basic external validation.
    pub fn handle_prepare_message(&mut self, prepare: Prepare) -> Result<(), crate::error::QbftError> {
        let prepare_sequence_number = prepare.round_identifier().sequence_number;
        let prepare_round_number = prepare.round_identifier().round_number;

        if prepare_sequence_number != self.sequence_number {
            trace!(
                "HeightState {}: Received prepare for different sequence number {}. Ignoring.",
                self.sequence_number,
                prepare_sequence_number
            );
            return Ok(());
        }

        if prepare_round_number == self.current_round_number {
            let current_round = self.get_current_round_state_mut();
            match current_round.add_prepare(prepare) {
                Ok(_) => {
                    info!(
                        "HeightState {}: Added prepare to current round {}.",
                        self.sequence_number,
                        self.current_round_number
                    );
                    // TODO: After adding prepare, check if prepare quorum is met.
                    // If so, call current_round.form_prepared_certificate()
                    // and potentially broadcast Commits if this node hasn't already.
                    // This higher-level logic typically resides in a controller using HeightState.
                }
                Err(e) => {
                    warn!(
                        "HeightState {}: Failed to add prepare to current round {}: {}. Ignoring prepare.",
                        self.sequence_number,
                        self.current_round_number,
                        e
                    );
                    // Not returning an error to HeightState caller, as the HeightState itself is not broken.
                    // The RoundState handled the invalid prepare.
                }
            }
        } else if prepare_round_number > self.current_round_number {
            trace!(
                "HeightState {}: Received prepare for future round {}. Current round is {}. Buffering.",
                self.sequence_number,
                prepare_round_number,
                self.current_round_number
            );
            self.future_prepares.entry(prepare_round_number).or_default().push(prepare);
        } else {
            // Prepare for a past round
            trace!(
                "HeightState {}: Received prepare for past round {}. Current round is {}. Ignoring.",
                self.sequence_number,
                prepare_round_number,
                self.current_round_number
            );
        }
        Ok(())
    }

    /// Handles an incoming Commit message.
    /// Routes the commit to the appropriate round state or ignores it.
    /// Assumes the commit has undergone basic external validation.
    pub fn handle_commit_message(&mut self, commit: Commit) -> Result<(), crate::error::QbftError> {
        let commit_sequence_number = commit.round_identifier().sequence_number;
        let commit_round_number = commit.round_identifier().round_number;

        if commit_sequence_number != self.sequence_number {
            trace!(
                "HeightState {}: Received commit for different sequence number {}. Ignoring.",
                self.sequence_number,
                commit_sequence_number
            );
            return Ok(());
        }

        if commit_round_number == self.current_round_number {
            let current_round = self.get_current_round_state_mut();
            match current_round.add_commit(commit) {
                Ok(_) => {
                    info!(
                        "HeightState {}: Added commit to current round {}.",
                        self.sequence_number,
                        self.current_round_number
                    );

                    // Check if this commit finalizes the block for the height
                    if !self.is_complete() {
                        let round_state = self.get_current_round_state(); // Immutable borrow fine for checks
                        if round_state.has_commit_quorum(self.commit_quorum_size) {
                            if let Some(block_to_commit) = round_state.proposed_block.as_ref() {
                                info!(
                                    "HeightState {}: Commit quorum reached for round {}. Finalizing block {:?}.",
                                    self.sequence_number,
                                    self.current_round_number,
                                    block_to_commit.hash() // Assuming QbftBlock has a hash() method
                                );
                                self.committed_block = Some(block_to_commit.clone());
                                // TODO: Notify observers or controller that height is complete.
                            } else {
                                // This state should ideally be unreachable if has_commit_quorum is true,
                                // as commit quorum implies a proposal and thus a proposed_block in RoundState.
                                warn!(
                                    "HeightState {}: Commit quorum reached for round {} but no proposed block found. This is unexpected.",
                                    self.sequence_number,
                                    self.current_round_number
                                );
                            }
                        }
                    }
                }
                Err(e) => {
                    warn!(
                        "HeightState {}: Failed to add commit to current round {}: {}. Ignoring commit.",
                        self.sequence_number,
                        self.current_round_number,
                        e
                    );
                }
            }
        } else if commit_round_number > self.current_round_number {
            trace!(
                "HeightState {}: Received commit for future round {}. Current round is {}. Buffering.",
                self.sequence_number,
                commit_round_number,
                self.current_round_number
            );
            self.future_commits.entry(commit_round_number).or_default().push(commit);
        } else {
            // Commit for a past round
            trace!(
                "HeightState {}: Received commit for past round {}. Current round is {}. Ignoring.",
                self.sequence_number,
                commit_round_number,
                self.current_round_number
            );
        }
        Ok(())
    }

    /// Handles an incoming RoundChange message.
    /// Routes the message to the appropriate round state for the current height.
    /// If a RoundState for the RoundChange's target round doesn't exist, it will be created.
    /// Assumes the message has undergone basic external validation.
    pub fn handle_round_change_message(&mut self, round_change: RoundChange) -> Result<(), crate::error::QbftError> {
        let rc_sequence_number = round_change.payload().round_identifier.sequence_number;
        let rc_target_round_number = round_change.payload().round_identifier.round_number;

        if rc_sequence_number != self.sequence_number {
            trace!(
                "HeightState {}: Received RoundChange for different sequence number {}. Ignoring.",
                self.sequence_number,
                rc_sequence_number
            );
            return Ok(());
        }

        // Ensure a RoundState exists for the target round of the RoundChange.
        // If not, create it. This allows collecting RCs for rounds we haven't formally entered.
        if !self.round_states.contains_key(&rc_target_round_number) {
            info!(
                "HeightState {}: Received RoundChange for round {} which has no state yet. Creating state.",
                self.sequence_number, rc_target_round_number
            );
            let new_round_identifier = ConsensusRoundIdentifier::new(self.sequence_number, rc_target_round_number);
            let new_proposer = self.final_state.get_proposer_for_round(&new_round_identifier)?;
            let new_round_state = RoundState::new(new_round_identifier, new_proposer);
            self.round_states.insert(rc_target_round_number, new_round_state);
        }

        // Add the RoundChange message to its target round state.
        if let Some(target_round_state) = self.round_states.get_mut(&rc_target_round_number) {
            match target_round_state.add_round_change(round_change) {
                Ok(_) => {
                    info!(
                        "HeightState {}: Added RoundChange to round {}.",
                        self.sequence_number,
                        rc_target_round_number
                    );
                    // TODO: After adding RoundChange, check if round change quorum is met for rc_target_round_number.
                    // If so, and rc_target_round_number > self.current_round_number, 
                    // then self.start_new_round(rc_target_round_number) might be called.
                    // This higher-level logic typically resides in a controller using HeightState.
                }
                Err(e) => {
                    warn!(
                        "HeightState {}: Failed to add RoundChange to round {}: {}. Ignoring RoundChange.",
                        self.sequence_number,
                        rc_target_round_number,
                        e
                    );
                }
            }
        } else {
            // This case should ideally not be reached if the above logic correctly creates the round state.
            warn!(
                "HeightState {}: RoundState for target round {} of RoundChange not found after attempting creation. This is unexpected.",
                self.sequence_number, rc_target_round_number
            );
        }
        
        Ok(())
    }

    /// Examines RoundChange messages for a specific round within this height 
    /// to find the best PreparedCertificate carried within them.
    /// "Best" is determined by the highest `prepared_round` in the metadata.
    ///
    /// # Arguments
    /// * `round_number_to_examine` - The round number whose collected RoundChange messages should be inspected.
    ///
    /// # Returns
    /// An `Option<PreparedCertificateWrapper>` containing the best certificate found, or None.
    pub fn get_best_prepared_certificate_from_round_changes(
        &self, 
        round_number_to_examine: u32
    ) -> Option<PreparedCertificateWrapper> {
        let mut best_certificate_data: Option<(PreparedCertificateWrapper, u32, B256)> = None; // (Certificate, prepared_round, block_hash)

        if let Some(round_state_to_examine) = self.round_states.get(&round_number_to_examine) {
            for round_change_msg in round_state_to_examine.round_change_messages.values() {
                if let Some(metadata) = &round_change_msg.payload().prepared_round_metadata {
                    let prepares: Vec<Prepare> = metadata.prepares.iter()
                        .map(|signed_prepare_payload| Prepare::new(signed_prepare_payload.clone()))
                        .collect();

                    let current_candidate_cert = PreparedCertificateWrapper {
                        proposal_message: metadata.signed_proposal_payload.clone(),
                        prepares,
                    };
                    let current_candidate_prepared_round = metadata.prepared_round;
                    let current_candidate_block_hash = metadata.signed_proposal_payload.payload().proposed_block.hash();

                    match best_certificate_data {
                        Some((_, best_known_prepared_round, best_known_block_hash)) => {
                            if current_candidate_prepared_round > best_known_prepared_round {
                                best_certificate_data = Some((
                                    current_candidate_cert, 
                                    current_candidate_prepared_round, 
                                    current_candidate_block_hash
                                ));
                            } else if current_candidate_prepared_round == best_known_prepared_round {
                                // Tie-breaking: prefer lower block hash
                                if current_candidate_block_hash < best_known_block_hash {
                                    best_certificate_data = Some((
                                        current_candidate_cert, 
                                        current_candidate_prepared_round, 
                                        current_candidate_block_hash
                                    ));
                                }
                            }
                        }
                        None => {
                            best_certificate_data = Some((
                                current_candidate_cert, 
                                current_candidate_prepared_round, 
                                current_candidate_block_hash
                            ));
                        }
                    }
                }
            }
        }
        best_certificate_data.map(|(cert, _, _)| cert)
    }

    /// Handles a round timeout event.
    /// If the timeout is for the current round, it marks the round as timed out
    /// and advances the HeightState to the next round.
    pub fn handle_round_timeout(&mut self, timed_out_round_number: u32) -> Result<(), crate::error::QbftError> {
        if timed_out_round_number != self.current_round_number {
            info!(
                "HeightState {}: Received timeout for round {}, but current round is {}. Ignoring stale timeout.",
                self.sequence_number,
                timed_out_round_number,
                self.current_round_number
            );
            return Ok(());
        }

        warn!(
            "HeightState {}: Round {} timed out.",
            self.sequence_number,
            self.current_round_number
        );

        // Mark the current round as timed out
        self.get_current_round_state_mut().timed_out = true;

        // Advance to the next round
        let next_round_number = self.current_round_number + 1;
        info!(
            "HeightState {}: Advancing to round {} due to timeout of round {}.",
            self.sequence_number,
            next_round_number,
            self.current_round_number
        );
        self.start_new_round(next_round_number)
    }

    /// Checks if a block has been committed for the current height.
    pub fn is_complete(&self) -> bool {
        self.committed_block.is_some()
    }

    /// Returns a reference to the committed block, if one exists for this height.
    pub fn get_committed_block(&self) -> Option<&QbftBlock> {
        self.committed_block.as_ref()
    }

    /// Searches all round states up to (but not including) a specified round number 
    /// for the one with the best (highest round number) prepared certificate.
    /// Returns the PreparedCertificateWrapper if found.
    pub fn get_best_prepared_certificate_from_prior_rounds(&self, up_to_round_exclusive: u32) -> Option<PreparedCertificateWrapper> {
        let mut best_certificate: Option<PreparedCertificateWrapper> = None;
        let mut highest_prepared_round = None;

        for r in 0..up_to_round_exclusive {
            if let Some(rs) = self.round_states.get(&r) {
                if let Some(cert) = &rs.prepared_certificate {
                    // The round number for a PreparedCertificate is implicitly the round of the Proposal it contains.
                    // The certificate wrapper itself doesn't store a round number directly,
                    // but its proposal_message does.
                    let proposal_round = cert.proposal_message.payload().round_identifier.round_number;
                    
                    if highest_prepared_round.is_none() || proposal_round > highest_prepared_round.unwrap() {
                        highest_prepared_round = Some(proposal_round);
                        best_certificate = Some(cert.clone()); 
                    }
                }
            }
        }
        best_certificate
    }

    // TODO: Implement methods for advancing rounds, handling messages, timeouts, etc.
} 