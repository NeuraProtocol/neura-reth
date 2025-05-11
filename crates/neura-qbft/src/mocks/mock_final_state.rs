use std::collections::HashSet;
use std::sync::Arc;
use alloy_primitives::Address;
use k256::ecdsa::SigningKey;
// use rand::rngs::OsRng; // Replaced with thread_rng for consistency
use std::collections::HashMap; // Added for block_headers

use crate::types::{QbftFinalState, NodeKey, ConsensusRoundIdentifier, QbftBlock, QbftBlockHeader};
use alloy_primitives::B256 as Hash;
use crate::error::QbftError; // In case any method needs to return a Result compatible with other parts


pub struct MockQbftFinalState {
    local_node_key: Arc<NodeKey>,
    local_address: Address,
    validators: HashSet<Address>,
    // For simple round-robin proposer selection
    sorted_validators: Vec<Address>,
    f_override: Option<usize>, // Added for explicit f control in tests
    block_headers: HashMap<Hash, Arc<QbftBlockHeader>>, // Added field
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
            f_override: None, // Default to None
            block_headers: HashMap::new(), // Initialize field
        }
    }

    // New constructor to allow overriding 'f'
    pub fn new_with_f_override(
        local_node_key: Arc<NodeKey>, 
        validators: HashSet<Address>, 
        f_override: usize
    ) -> Self {
        let local_address = Address::from_public_key(&local_node_key.verifying_key());
        let mut sorted_validators: Vec<Address> = validators.iter().cloned().collect();
        sorted_validators.sort(); // Ensure consistent order for round-robin
        
        if !validators.contains(&local_address) {
            panic!("MockQbftFinalState: Local node address {:?} must be in the validator set.", local_address);
        }

        Self {
            local_node_key,
            local_address,
            validators,
            sorted_validators,
            f_override: Some(f_override),
            block_headers: HashMap::new(), // Initialize field
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

        let mut rng = rand::thread_rng(); // Use thread_rng
        for _i in 0..num_validators { // _i to silence unused warning
            let sk = SigningKey::random(&mut rng); // Pass rng
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

    // Method to add known headers for testing lookups
    pub fn add_known_header(&mut self, header: Arc<QbftBlockHeader>) {
        self.block_headers.insert(header.hash(), header);
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

    fn current_validators(&self) -> Vec<Address> {
        self.sorted_validators.clone()
    }

    fn get_validator_node_key(&self, address: &Address) -> Option<Arc<NodeKey>> {
        if *address == self.local_address {
            Some(self.local_node_key.clone())
        } else {
            // This mock only knows about the local node key.
            // For a more complete mock, you might store all validator keys.
            None
        }
    }

    fn get_validators_for_block(&self, _block_number: u64) -> Result<Vec<Address>, QbftError> {
        // For simplicity, this mock returns the current set of validators for any block number.
        // A real implementation would fetch historical validator sets.
        Ok(self.sorted_validators.clone())
    }

    fn get_block_by_hash(&self, _hash: &Hash) -> Option<QbftBlock> {
        // This mock does not store blocks.
        None
    }

    fn get_block_header(&self, hash: &Hash) -> Option<QbftBlockHeader> {
        // This mock retrieves block headers stored as Arc<QbftBlockHeader>.
        // We need to clone the QbftBlockHeader from the Arc to match the trait signature.
        self.block_headers.get(hash).map(|arc_header| (**arc_header).clone())
    }

    fn is_validator(&self, address: Address) -> bool {
        self.validators.contains(&address)
    }

    fn quorum_size(&self) -> usize {
        let n = self.validators.len();
        if n == 0 { return 0; }
        let f = (n - 1) / 3;
        2 * f + 1
    }

    fn byzantine_fault_tolerance_f(&self) -> usize {
        if let Some(f_val) = self.f_override {
            return f_val;
        }
        let n = self.validators.len();
        if n == 0 { return 0; }
        (n - 1) / 3
    }

    fn is_proposer_for_round(&self, proposer: Address, round: &ConsensusRoundIdentifier) -> bool {
        if self.sorted_validators.is_empty() {
            return false; 
        }
        let n = self.sorted_validators.len();
        let proposer_index = (round.sequence_number as usize + round.round_number as usize) % n;
        self.sorted_validators[proposer_index] == proposer
    }

    fn get_proposer_for_round(&self, round: &ConsensusRoundIdentifier) -> Result<Address, QbftError> {
        if self.sorted_validators.is_empty() {
            log::error!("No validators available to select a proposer for round {:?}.", round);
            return Err(QbftError::NoValidators);
        }
        let n = self.sorted_validators.len();
        let proposer_index = (round.sequence_number as usize + round.round_number as usize) % n;
        Ok(self.sorted_validators[proposer_index])
    }
} 