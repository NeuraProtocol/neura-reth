use std::collections::HashSet;
use std::sync::Arc;
use alloy_primitives::Address;
use k256::ecdsa::SigningKey;
use rand::rngs::OsRng;

use crate::types::{QbftFinalState, NodeKey, ConsensusRoundIdentifier};
use crate::error::QbftError; // In case any method needs to return a Result compatible with other parts


pub struct MockQbftFinalState {
    local_node_key: Arc<NodeKey>,
    local_address: Address,
    validators: HashSet<Address>,
    // For simple round-robin proposer selection
    sorted_validators: Vec<Address>,
}

impl MockQbftFinalState {
    pub fn new(local_node_key: Arc<NodeKey>, validators: HashSet<Address>) -> Self {
        let local_address = Address::from_public_key(&local_node_key.verifying_key());
        let mut sorted_validators: Vec<Address> = validators.iter().cloned().collect();
        sorted_validators.sort(); // Ensure consistent order for round-robin
        
        if !validators.contains(&local_address) {
            // This mock assumes the local node is always one of the validators for simplicity.
            // In a real scenario, a node might not be a validator.
            // For mock purposes, we could add it or panic.
            // Let's panic for now to enforce test setup correctness.
            panic!("MockQbftFinalState: Local node address {:?} must be in the validator set.", local_address);
        }

        Self {
            local_node_key,
            local_address,
            validators,
            sorted_validators,
        }
    }

    /// Creates a default MockQbftFinalState with a randomly generated local key and N validators.
    /// The local node will be the first validator.
    pub fn with_static_validators(num_validators: usize, local_node_index: usize) -> Self {
        assert!(num_validators > 0, "Must have at least one validator");
        assert!(local_node_index < num_validators, "Local node index out of bounds");

        let mut keys = Vec::new();
        let mut validators_set = HashSet::new();
        let mut sorted_validators_vec = Vec::new();

        for i in 0..num_validators {
            let sk = SigningKey::random(&mut OsRng);
            let addr = Address::from_public_key(&sk.verifying_key());
            keys.push(sk);
            validators_set.insert(addr);
            sorted_validators_vec.push(addr);
        }
        sorted_validators_vec.sort(); // Consistent order

        let local_key = Arc::new(keys.remove(local_node_index));
        // Adjust sorted_validators_vec and validators_set if local_node_index removal affects them significantly for tests.
        // However, for basic QbftFinalState trait, the internal sorted_validators is what matters for proposer selection.
        // The `validators` HashSet should contain all, including the local.
        // The `local_address` is derived from `local_key`.

        let mock_state = Self::new(local_key, validators_set);
        // Overwrite sorted_validators if the one derived in new() is not what we want for predictable tests.
        // For now, new() derives sorted_validators from the passed HashSet, which is fine.
        mock_state
    }
}

impl QbftFinalState for MockQbftFinalState {
    fn node_key(&self) -> Arc<NodeKey> {
        self.local_node_key.clone()
    }

    fn local_address(&self) -> Address {
        self.local_address
    }

    fn validators(&self) -> HashSet<Address> {
        self.validators.clone()
    }

    fn is_validator(&self, address: Address) -> bool {
        self.validators.contains(&address)
    }

    // N = number of validators
    // Quorum size (Q) = 2F + 1
    // Byzantine Fault Tolerance (F) = floor((N - 1) / 3)
    // So, Q = 2 * floor((N - 1) / 3) + 1
    fn quorum_size(&self) -> usize {
        let n = self.validators.len();
        if n == 0 { return 0; }
        let f = (n - 1) / 3;
        2 * f + 1
    }

    fn Byzantine_fault_tolerance_f(&self) -> usize {
        let n = self.validators.len();
        if n == 0 { return 0; }
        (n - 1) / 3
    }

    fn is_proposer_for_round(&self, proposer: Address, round: &ConsensusRoundIdentifier) -> bool {
        if self.sorted_validators.is_empty() {
            return false; // No validators, no proposer
        }
        // Simple round-robin: Proposer_for_round_R = Validators[R % N]
        // Where N is the number of validators.
        // Besu IBFT 1.0 used: Proposer_for_round_R = Validators[(Height + R) % N]
        // Let's use (Height + R) % N for more deterministic behavior across heights.
        let n = self.sorted_validators.len();
        let proposer_index = (round.sequence_number as usize + round.round_number as usize) % n;
        self.sorted_validators[proposer_index] == proposer
    }

    fn get_proposer_for_round(&self, round: &ConsensusRoundIdentifier) -> Address {
        if self.sorted_validators.is_empty() {
            // This case should ideally not happen in a running system.
            // Return a zero address or panic. For tests, panic might be better.
            panic!("No validators available to select a proposer.");
        }
        let n = self.sorted_validators.len();
        let proposer_index = (round.sequence_number as usize + round.round_number as usize) % n;
        self.sorted_validators[proposer_index]
    }
} 