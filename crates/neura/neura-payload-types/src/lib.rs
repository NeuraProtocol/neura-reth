use alloy_primitives::{Address, Bytes, U256, B256};
use alloy_rpc_types::eth::{Transaction as AlloyTransaction, AccessList as AlloyAccessList};
use alloy_rpc_types::TransactionTrait; // Import the trait
use reth_ethereum_engine_primitives::EthBuiltPayload;
use reth_payload_primitives::BuiltPayload;
use reth_primitives_traits::{SealedBlock, NodePrimitives};
use reth_ethereum_primitives::EthPrimitives; // For BuiltPayload trait
use alloy_eips::eip7685::Requests; // For BuiltPayload trait
use alloy_consensus::transaction::EthereumTxEnvelope;
use alloy_consensus::TxEip4844Variant;

// Potentially enable serde if the feature is active
#[cfg(feature = "serde")]
use serde::{Serialize, Deserialize};

/// Represents a full transaction, including all fields necessary for Neura.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct FullTransaction {
    pub to: Option<Address>,
    pub value: U256,
    pub input: Bytes,
    pub nonce: u64,
    pub gas_limit: u64,
    pub gas_price: Option<U256>,
    pub chain_id: Option<u64>,
    pub r: U256,
    pub s: U256,
    pub v: U256,
    pub y_parity: Option<U256>, // Represents Parity (0 for even, 1 for odd)
    pub access_list: Option<Vec<(Address, Vec<U256>)>>,
    pub transaction_type: Option<U256>,
    pub max_fee_per_gas: Option<U256>,
    pub max_priority_fee_per_gas: Option<U256>,
}

/// A trait for converting different transaction-related types to their "full" counterparts.
pub trait TransactionConverter {
    type FullType;
    fn into_full_type(self) -> Self::FullType;
}

impl TransactionConverter for AlloyTransaction {
    type FullType = FullTransaction;

    fn into_full_type(self) -> Self::FullType {
        let envelope: EthereumTxEnvelope<TxEip4844Variant> = self.inner.clone_inner(); // Assuming this gives EthereumTxEnvelope
        let signature = envelope.signature(); // Assuming this gives alloy_primitives::Signature

        FullTransaction {
            to: envelope.to(),
            value: envelope.value(),
            input: envelope.input().clone(),
            nonce: envelope.nonce(),
            gas_limit: envelope.gas_limit(),
            gas_price: envelope.gas_price().map(U256::from),
            chain_id: envelope.chain_id(),
            
            r: signature.r(),
            s: signature.s(),
            v: { if signature.v() { U256::from(1) } else { U256::from(0) } }, 
            y_parity: Some({ if signature.v() { U256::from(1) } else { U256::from(0) } }),
            
            access_list: envelope.access_list().map(|al_ref| {
                al_ref.0.iter().map(|item| {
                    let keys_u256 = item.storage_keys.iter().map(|k: &B256| U256::from_be_bytes(k.0)).collect();
                    (item.address, keys_u256)
                }).collect()
            }),
            transaction_type: Some(U256::from(envelope.tx_type() as u8)),
            max_fee_per_gas: Some(U256::from(envelope.max_fee_per_gas())),
            max_priority_fee_per_gas: envelope.max_priority_fee_per_gas().map(U256::from),
        }
    }
}

/// Wraps an EthBuiltPayload with additional Neura-specific details, like full transactions.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct NeuraBuiltPayloadWithDetails {
    pub original_payload: EthBuiltPayload,
    pub full_transactions: Vec<FullTransaction>,
}

impl NeuraBuiltPayloadWithDetails {
    pub fn new(original_payload: EthBuiltPayload, full_transactions: Vec<FullTransaction>) -> Self {
        Self { original_payload, full_transactions }
    }

    // Optional: Add direct accessors if needed, e.g., for full_transactions
    pub fn full_transactions(&self) -> &[FullTransaction] {
        &self.full_transactions
    }
}

impl BuiltPayload for NeuraBuiltPayloadWithDetails {
    type Primitives = EthPrimitives;

    fn block(&self) -> &SealedBlock<<Self::Primitives as NodePrimitives>::Block> {
        self.original_payload.block()
    }

    fn fees(&self) -> U256 {
        self.original_payload.fees()
    }

    fn requests(&self) -> Option<Requests> {
        self.original_payload.requests()
    }
} 