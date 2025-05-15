// crates/neura-qbft/src/testing_helpers.rs
#![allow(dead_code)] // Allow unused code for these placeholders
#![allow(unused_variables)] // Allow unused variables for placeholders

use std::sync::Arc;
use rand::{thread_rng, RngCore};
use alloy_primitives::{Address, B256, Bloom};
use crate::types::{NodeKey, QbftConfig, QbftBlockHeader, BftExtraDataCodec, AlloyBftExtraDataCodec};

// Placeholder for default_config
pub fn default_config() -> Arc<QbftConfig> {
    // Create a config matching the actual QbftConfig struct fields
    Arc::new(QbftConfig {
        message_round_timeout_ms: 10000,
        max_future_block_time_seconds: 15,
        block_period_seconds: 5,
        difficulty: alloy_primitives::U256::from(1),
        nonce: alloy_primitives::Bytes::from_static(&[0x80]),
        fault_tolerance_f: 0,
        gas_limit_bound_divisor: 1024,
        min_gas_limit: 30_000_000,
    })
}

// Implementation for testing_extradata_codec
pub fn testing_extradata_codec() -> Arc<dyn BftExtraDataCodec> {
    Arc::new(AlloyBftExtraDataCodec::default())
}

// Placeholder for create_node_key
pub fn create_node_key() -> NodeKey {
    // Create with a proper RNG
    NodeKey::random(&mut thread_rng())
}

// Placeholder for deterministic_node_key
pub fn deterministic_node_key(seed: u64) -> Arc<NodeKey> {
    // TODO: Implement actual deterministic node key generation
    // This might involve seeding a PRNG or using a fixed key for testing
    Arc::new(NodeKey::random(&mut thread_rng())) // Using thread_rng for now
}

// Placeholder for deterministic_address_from_arc_key
pub fn deterministic_address_from_arc_key(key: &Arc<NodeKey>) -> Address {
    // NodeKey doesn't have an address method directly
    // We need to derive the address from the public key
    let verifying_key = key.verifying_key();
    let encoded_point = verifying_key.to_encoded_point(false);
    let public_key_bytes = encoded_point.as_bytes();
    
    // Get the keccak256 hash of the public key (without the leading 0x04 byte)
    let hash = alloy_primitives::keccak256(&public_key_bytes[1..]);
    
    // Take the last 20 bytes as the Ethereum address
    let mut address_bytes = [0u8; 20];
    address_bytes.copy_from_slice(&hash[12..32]);
    
    Address::from_slice(&address_bytes)
}

// Implementation for default_parent_header
pub fn default_parent_header(number: u64, parent_hash: B256, timestamp: u64, gas_limit: u64) -> Arc<QbftBlockHeader> {
    // Create a simple default header for testing
    let header = QbftBlockHeader::new(
        parent_hash,
        alloy_consensus::constants::EMPTY_OMMER_ROOT_HASH,
        Address::from_slice(&[0x42u8; 20]), // Default beneficiary address
        random_b256(),                      // Random state root
        random_b256(),                      // Random transactions root
        random_b256(),                      // Random receipts root
        Bloom::default(),                    // Empty logs bloom
        alloy_primitives::U256::from(1),     // Difficulty 1 (typical for non-PoW)
        number,                              // Block number from argument
        gas_limit,                           // Gas limit from argument
        0,                                   // No gas used
        timestamp,                           // Timestamp from argument
        alloy_primitives::Bytes::from_static(&[0u8; 32]), // Empty extra data
        B256::ZERO,                          // Zero mix hash
        crate::types::EMPTY_NONCE,           // Default empty nonce
        None,                                // base_fee_per_gas
    );
    
    Arc::new(header)
}

// Helper function to generate a random B256 value
fn random_b256() -> B256 {
    let mut rng = thread_rng();
    let mut bytes = [0u8; 32];
    rng.fill_bytes(&mut bytes);
    B256::from_slice(&bytes)
} 