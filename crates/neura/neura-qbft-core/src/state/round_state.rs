use crate::messagewrappers::{Proposal, Prepare, Commit, RoundChange, PreparedCertificateWrapper};
use crate::types::{ConsensusRoundIdentifier, QbftBlock};
use alloy_primitives::{Address, B256 as Hash};
// use reth_primitives::Sealable; // Original line, commented out or removed
use std::collections::HashMap;
use log; // Ensure log is used

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
        log::debug!(
            "RoundState ({:?}): Entering add_prepare. Current proposed_block_hash: {:?}. Prepare for digest: {:?}, round: {:?}", 
            self.round_identifier, 
            self.proposed_block_hash, 
            prepare.payload().digest, 
            prepare.payload().round_identifier
        );

        if let Some(current_digest) = self.proposed_block_hash {
            if prepare.payload().digest != current_digest {
                return Err("Prepare digest does not match current proposal digest.");
            }
            if prepare.payload().round_identifier != self.round_identifier {
                return Err("Prepare round identifier does not match current round state.");
            }
        } else {
            return Err("Cannot add Prepare: No proposal set in RoundState yet.");
        }

        let author = match prepare.author() {
            Ok(addr) => addr,
            Err(_) => {
                log::error!("RoundState ({:?}): Could not get author from prepare message", self.round_identifier);
                return Err("Could not get author from prepare message")
            },
        };

        if self.prepare_messages.insert(author, prepare).is_some() {
            log::warn!("RoundState ({:?}): Replaced existing prepare message from author: {:?}", self.round_identifier, author);
        }
        Ok(())
    }

    /// Sets the proposal for this round.
    /// Stores the proposal message, block hash, and block.
    /// Assumes the Proposal message has already been validated externally.
    ///
    /// TODO: Consider behavior if a proposal is already set. Replace? Error?
    pub fn set_proposal(&mut self, proposal: Proposal) {
        log::debug!(
            "RoundState ({:?}): Entering set_proposal. Current proposed_block_hash: {:?}", 
            self.round_identifier, 
            self.proposed_block_hash
        );
        let block_hash = proposal.payload().proposed_block.header.hash();
        log::debug!("RoundState ({:?}): Calculated block_hash: {:?}", self.round_identifier, block_hash);
        let block = proposal.payload().proposed_block.clone();

        self.proposal_message = Some(proposal);
        self.proposed_block_hash = Some(block_hash);
        self.proposed_block = Some(block);
        log::debug!(
            "RoundState ({:?}): Exiting set_proposal. New proposed_block_hash: {:?}", 
            self.round_identifier, 
            self.proposed_block_hash
        );
    }

    /// Adds a received Commit message.
    /// Returns Ok(()) if added, Err if relevant checks fail or if already present from this author.
    /// Assumes the Commit message has already been validated externally (e.g., signature).
    pub fn add_commit(&mut self, commit: Commit) -> Result<(), &'static str> {
        let current_digest = match self.proposed_block_hash {
            Some(digest) => digest,
            None => return Err("Cannot add commit, no proposal active in this round"),
        };

        if commit.payload().digest != current_digest {
            return Err("Commit digest does not match current proposal");
        }

        if commit.payload().round_identifier != self.round_identifier {
            return Err("Commit round identifier does not match current round");
        }

        let author = match commit.author() {
            Ok(addr) => addr,
            Err(_) => return Err("Could not get author from commit message"),
        };

        if self.commit_messages.insert(author, commit).is_some() {
            // log::warn!("Replaced existing commit message from author: {:?}", author);
        }
        Ok(())
    }

    /// Adds a received RoundChange message.
    /// Returns Ok(()) if added, Err if relevant checks fail or if already present from this author.
    /// Assumes the RoundChange message has already been validated externally (e.g., signature).
    /// This method only stores RoundChange messages that target the current round of this RoundState.
    pub fn add_round_change(&mut self, round_change: RoundChange) -> Result<(), &'static str> {
        if round_change.payload().round_identifier.round_number != self.round_identifier.round_number {
            return Err("RoundChange message does not target the current round number");
        }
        
        if round_change.payload().round_identifier.sequence_number != self.round_identifier.sequence_number {
            return Err("RoundChange message does not target the current sequence number (height)");
        }

        let author = match round_change.author() {
            Ok(addr) => addr,
            Err(_) => return Err("Could not get author from round_change message"),
        };

        if self.round_change_messages.insert(author, round_change).is_some() {
            // log::warn!("Replaced existing round_change message from author: {:?}", author);
        }
        Ok(())
    }

    // --- Quorum Checks ---

    /// Checks if the number of unique Prepare messages meets the given threshold.
    /// The `quorum_threshold` is typically 2F+1 for prepares.
    pub fn has_prepare_quorum(&self, quorum_threshold: usize) -> bool {
        // Ensure there is a proposal before checking for prepare quorum.
        // A round cannot be prepared without a proposal.
        if self.proposal_message.is_none() {
            return false;
        }
        self.prepare_messages.len() >= quorum_threshold
    }

    /// Checks if the number of unique Commit messages meets the given threshold.
    /// The `quorum_threshold` is typically 2F+1 for commits.
    pub fn has_commit_quorum(&self, quorum_threshold: usize) -> bool {
        // Ensure the round is prepared before checking for commit quorum.
        // Commits are only valid for a prepared proposal.
        if !self.is_prepared() {
            return false;
        }
        self.commit_messages.len() >= quorum_threshold
    }

    /// Checks if the number of unique RoundChange messages (for the current round) meets the threshold.
    /// The `quorum_threshold` can vary (e.g., F+1 or 2F+1) depending on the context.
    pub fn has_round_change_quorum(&self, quorum_threshold: usize) -> bool {
        self.round_change_messages.len() >= quorum_threshold
    }

    /// Forms and stores a `PreparedCertificateWrapper` if one is not already present
    /// and a proposal exists. This method assumes that the prepare quorum has already
    /// been met by the caller.
    /// 
    /// The `PreparedCertificateWrapper` bundles the signed proposal and the collected signed prepares.
    pub fn form_prepared_certificate(&mut self) -> Result<(), &'static str> {
        if self.prepared_certificate.is_some() {
            return Err("Prepared certificate already exists for this round state.");
        }

        let current_proposal = match &self.proposal_message {
            Some(proposal) => proposal,
            None => return Err("Cannot form prepared certificate without an active proposal."),
        };

        let proposal_bft_message = (**current_proposal).clone(); 

        let prepares: Vec<Prepare> = self.prepare_messages.values().cloned().collect();

        let new_prepared_certificate = PreparedCertificateWrapper::new(proposal_bft_message, prepares);
        self.prepared_certificate = Some(new_prepared_certificate);

        Ok(())
    }

    // TODO: Method to get best prepared certificate from round change messages.
} 