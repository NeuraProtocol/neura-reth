use crate::messagewrappers::{Proposal, Prepare, Commit, RoundChange, PreparedCertificateWrapper};
use crate::types::{ConsensusRoundIdentifier, QbftBlock, Address};
use alloy_primitives::B256 as Hash;
use std::collections::{HashMap, HashSet}; // Using HashMap for messages to store by author

pub struct RoundState {
    // Identifier for this round (sequence number, round number)
    pub round_identifier: ConsensusRoundIdentifier,

    // The proposer for this specific round
    pub current_proposer: Address,

    // The proposal message received for this round. 
    // Option because a round might start without a proposal (e.g., due to timeout).
    pub proposal_message: Option<Proposal>,

    // The hash of the proposed block, if a proposal exists and is valid.
    // Used to ensure prepares and commits are for the correct block.
    pub proposed_block_hash: Option<Hash>,

    // The actual block from the proposal, stored if the proposal is accepted.
    // Option because it's only set after a valid proposal is processed.
    pub proposed_block: Option<QbftBlock>,

    // Certificate of 2F+1 Prepare messages for the proposal_message.
    // Indicates that a block is "prepared".
    pub prepared_certificate: Option<PreparedCertificateWrapper>,
    
    // Collection of valid RoundChange messages received *targeting this round_identifier*.
    // Stored by author Address to easily manage and check for duplicates/quorum.
    pub round_change_messages: HashMap<Address, RoundChange>,

    // Collection of valid Prepare messages received for the proposal_message in this round.
    // Stored by author Address.
    pub prepare_messages: HashMap<Address, Prepare>,

    // Collection of valid Commit messages received for the proposal_message in this round.
    // Stored by author Address.
    pub commit_messages: HashMap<Address, Commit>,

    // A flag to indicate if this round has timed out.
    pub timed_out: bool,

    // Might also include:
    // - earliest_round_change_target_round: Option<u32> (if tracking RCs for future rounds within this state)
    // - local_node_prepared: bool
    // - local_node_committed: bool
}

impl RoundState {
    pub fn new(round_identifier: ConsensusRoundIdentifier, current_proposer: Address) -> Self {
        RoundState {
            round_identifier,
            current_proposer,
            proposal_message: None,
            proposed_block_hash: None,
            proposed_block: None,
            prepared_certificate: None,
            round_change_messages: HashMap::new(),
            prepare_messages: HashMap::new(),
            commit_messages: HashMap::new(),
            timed_out: false,
        }
    }

    // --- Potential Methods ---

    /// Returns true if a proposal has been accepted and a prepared certificate has been formed.
    pub fn is_prepared(&self) -> bool {
        self.prepared_certificate.is_some()
    }

    /// Returns true if this node has sent a commit for the current proposal.
    /// (This might need more sophisticated tracking if we distinguish local actions)
    pub fn has_committed_locally(&self, local_address: &Address) -> bool {
        self.commit_messages.contains_key(local_address)
    }
    
    /// Returns the number of unique commit messages received.
    pub fn commit_quorum_count(&self) -> usize {
        self.commit_messages.len()
    }

    /// Returns the number of unique prepare messages received.
    pub fn prepare_quorum_count(&self) -> usize {
        self.prepare_messages.len()
    }
    
    /// Adds a received Prepare message.
    /// Returns Ok(()) if added, Err if already present from this author for this proposal.
    /// Assumes the Prepare message has already been validated externally.
    pub fn add_prepare(&mut self, prepare: Prepare) -> Result<(), &'static str> {
        // Basic check: ensure prepare is for the current proposal's digest
        if let Some(current_digest) = self.proposed_block_hash {
            if prepare.payload().proposal_digest != current_digest {
                return Err("Prepare digest does not match current proposal");
            }
            // Additional check: ensure prepare is for the current round_identifier
            if prepare.payload().round_identifier != self.round_identifier {
                return Err("Prepare round identifier does not match current round");
            }
        } else {
            // Cannot add prepare if no proposal is set yet
            return Err("Cannot add prepare, no proposal active in this round");
        }

        let author = match prepare.author() {
            Ok(addr) => addr,
            Err(_) => return Err("Could not get author from prepare message"),
        };

        if self.prepare_messages.insert(author, prepare).is_some() {
            // If insert returned Some, it means there was already a message from this author.
            // Depending on rules, this might be an error or just an update.
            // For now, let's consider it an update, though QBFT usually expects one per author.
            // log::warn!("Replaced existing prepare message from author: {:?}", author);
        }
        Ok(())
    }

    // TODO: add_commit, add_round_change, set_proposal, etc.
    // TODO: Methods to check for quorum for prepares, commits, round_changes.
    // TODO: Method to form PreparedCertificate.
} 