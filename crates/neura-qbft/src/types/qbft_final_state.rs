use crate::types::{ConsensusRoundIdentifier, NodeKey}; // Corrected NodeKey path
use crate::types::header::QbftBlockHeader; // Corrected path
use crate::types::block_creator::QbftBlockCreator; // Corrected path
use crate::types::block::QbftBlock; // Added import for QbftBlock
use crate::error::QbftError; // Corrected path
use alloy_primitives::{Address, B256 as Hash}; // Added B256 as Hash for Hash type
use std::collections::HashSet; // For validator set
use std::sync::Arc;

// Timers - placeholders for now. These would likely involve some async runtime interaction
// or a mockable timer interface in a real implementation.
pub trait RoundTimer: Send + Sync {
    fn start_timer(&self, round: ConsensusRoundIdentifier);
    fn cancel_timer(&self, round: ConsensusRoundIdentifier);
    // fn schedule_expiry_event(round, duration) -> event_tx.send(RoundExpiry(round))
}

pub trait BlockTimer: Send + Sync {
    fn start_timer(&self, round: ConsensusRoundIdentifier, parent_timestamp_seconds: u64); // Or parent_header: &QbftBlockHeader
    fn cancel_timer(&self, round: ConsensusRoundIdentifier);
    // fn check_empty_block_expired(&self, parent_timestamp_seconds: u64, current_time_millis: u64) -> bool;
    fn get_timestamp_for_future_block(&self, round: &ConsensusRoundIdentifier, parent_timestamp_seconds: u64) -> u64;
    // fn reset_timer_for_empty_block(
    //     &self, 
    //     round: ConsensusRoundIdentifier, 
    //     parent_timestamp_seconds: u64, 
    //     current_time_millis: u64
    // );
}

// TODO: Define QbftBlockCreatorFactory trait or struct later
pub trait QbftBlockCreatorFactory: Send + Sync {
    /// Creates a block creator instance for a new block to be built upon `parent_header`.
    /// `final_state_view` provides access to necessary chain state (e.g., validators, current time via clock if included).
    fn create_block_creator(
        &self, 
        parent_header: &QbftBlockHeader, 
        final_state_view: Arc<dyn QbftFinalState> // Pass Arc if QbftBlockCreator needs to retain it
    ) -> Result<Arc<dyn QbftBlockCreator>, QbftError>; // Return a Result in case creation can fail
}

// TODO: Define ValidatorMulticaster trait later (for sending messages to validators)
pub trait ValidatorMulticaster: Send + Sync {
    fn multicast_proposal(&self, proposal: &crate::messagewrappers::Proposal);
    fn multicast_prepare(&self, prepare: &crate::messagewrappers::Prepare);
    fn multicast_commit(&self, commit: &crate::messagewrappers::Commit);
    fn multicast_round_change(&self, round_change: &crate::messagewrappers::RoundChange);
}


/// This trait defines the full data set, or context, required for many of the aspects of QBFT workflows.
/// An implementation of this trait will be provided by the integrating application (e.g., Neura-Reth).
pub trait QbftFinalState: Send + Sync {
    fn node_key(&self) -> Arc<NodeKey>;
    fn local_address(&self) -> Address;
    
    fn validators(&self) -> HashSet<Address>; // Set of current validators for the *current* state
    fn get_validators_for_block(&self, block_number: u64) -> Result<Vec<Address>, QbftError>;
    fn is_validator(&self, address: Address) -> bool;
    fn is_local_node_validator(&self) -> bool {
        self.is_validator(self.local_address())
    }

    fn quorum_size(&self) -> usize; // Calculated as 2f+1
    fn byzantine_fault_tolerance_f(&self) -> usize; // Calculated as (N-1)/3

    fn get_byzantine_fault_tolerance(&self) -> usize {
        self.byzantine_fault_tolerance_f()
    }

    // Proposer selection
    fn is_proposer_for_round(&self, proposer: Address, round: &ConsensusRoundIdentifier) -> bool;
    fn is_local_node_proposer_for_round(&self, round: &ConsensusRoundIdentifier) -> bool {
        self.is_proposer_for_round(self.local_address(), round)
    }
    fn get_proposer_for_round(&self, round: &ConsensusRoundIdentifier) -> Address;

    // Timers - these would return references to timer objects
    // fn round_timer(&self) -> Arc<dyn RoundTimer>;
    // fn block_timer(&self) -> Arc<dyn BlockTimer>;

    // Block creation factory
    // fn block_creator_factory(&self) -> Arc<dyn QbftBlockCreatorFactory>;

    // Network multicaster for sending messages to validators
    // fn validator_multicaster(&self) -> Arc<dyn ValidatorMulticaster>;

    // Clock for consistent time
    // fn clock(&self) -> Arc<dyn std::time::SystemTime>; // Or a mockable clock trait

    fn current_validators(&self) -> Vec<Address>;
    fn get_validator_node_key(&self, address: &Address) -> Option<Arc<NodeKey>>;
    fn get_block_by_hash(&self, hash: &Hash) -> Option<QbftBlock>;
    fn get_block_header(&self, hash: &Hash) -> Option<QbftBlockHeader>;
} 