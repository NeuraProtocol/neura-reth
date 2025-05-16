//! Crate for Neura-specific payload types.

use alloy_primitives::{Address, Bytes, U256, TxKind};
use alloy_rpc_types::eth::{Transaction as AlloyTransaction};
use alloy_rpc_types::TransactionTrait; // Import the trait
use alloy_consensus::{TxType}; // TxKind is NOT imported from here
use reth_ethereum_engine_primitives::EthBuiltPayload;
use reth_payload_primitives::BuiltPayload;
use reth_primitives_traits::{SealedBlock, NodePrimitives};
use reth_ethereum_primitives::EthPrimitives; // For BuiltPayload trait
use alloy_eips::eip7685::Requests; // For BuiltPayload trait

// Potentially enable serde if the feature is active
#[cfg(feature = "serde")]
use serde::{Serialize, Deserialize};

/// Represents a full transaction, including all fields necessary for Neura.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct FullTransaction {
    /// The recipient address of the transaction.
    pub to: Option<Address>,
    /// The value (amount) transferred in the transaction.
    pub value: U256,
    /// The input data (calldata) of the transaction.
    pub input: Bytes,
    /// The nonce of the sender.
    pub nonce: u64,
    /// The gas limit (maximum gas) for the transaction.
    pub gas_limit: u64,
    /// The gas price for legacy transactions.
    pub gas_price: Option<U256>,
    /// The chain ID for replay protection.
    pub chain_id: Option<u64>,
    /// The R value of the transaction signature.
    pub r: U256,
    /// The S value of the transaction signature.
    pub s: U256,
    /// The V value of the transaction signature (EIP-155 adjusted).
    pub v: U256,
    /// The Y-parity of the signature (0 for even, 1 for odd).
    pub y_parity: Option<U256>,
    /// The access list for EIP-2930 transactions.
    pub access_list: Option<Vec<(Address, Vec<U256>)>>,
    /// The type of the transaction (e.g., legacy, EIP-1559).
    pub transaction_type: Option<U256>,
    /// The maximum fee per gas for EIP-1559 transactions.
    pub max_fee_per_gas: Option<U256>,
    /// The maximum priority fee per gas for EIP-1559 transactions.
    pub max_priority_fee_per_gas: Option<U256>,
}

/// A trait for converting different transaction-related types to their "full" counterparts.
pub trait TransactionConverter {
    /// The associated full type representation.
    type FullType;
    /// Converts the transaction type into its "full" representation.
    fn into_full_type(self) -> Self::FullType;
}

impl TransactionConverter for AlloyTransaction {
    type FullType = FullTransaction;

    /// Converts an `alloy_rpc_types::eth::Transaction` into a `FullTransaction`.
    fn into_full_type(self) -> Self::FullType {
        // `AlloyTransaction` (self) wraps an `inner: Recovered<EthereumTxEnvelope<Signature>>`.
        // `TransactionTrait` methods are implemented on `EthereumTxEnvelope` found at `self.inner.message`.
        // RPC-specific, processed fields (r, s, v, y_parity) are direct fields on `self`.

        let access_list_converted = self.inner.access_list().map(|al_ref| {
            al_ref.0.iter()
                .map(|item| {
                    let keys_u256 = item
                        .storage_keys
                        .iter()
                        .map(|k| U256::from_be_bytes(k.0))
                        .collect();
                    (item.address, keys_u256)
                })
                .collect()
        });

        // Use .kind() method from TransactionTrait on self.inner.message
        // TxKind is from alloy_primitives
        let to_address = if let TxKind::Call(addr) = self.inner.kind() { Some(addr) } else { None };

        // Use .tx_type() and .max_fee_per_gas() from TransactionTrait on self.inner.message
        let max_fee_val = match self.inner.tx_type() {
            TxType::Eip1559 | TxType::Eip4844 | TxType::Eip7702 => Some(U256::from(self.inner.max_fee_per_gas())),
            _ => None,
        };

        FullTransaction {
            to: to_address,
            value: self.inner.value(),
            input: self.inner.input().clone(),
            nonce: self.inner.nonce(),
            gas_limit: self.inner.gas_limit(),
            gas_price: self.inner.gas_price().map(U256::from),
            chain_id: self.inner.chain_id(),
            
            // Access signature components from self.inner.signature using methods
            r: self.inner.signature().r(), 
            s: self.inner.signature().s(), 
            // v: self.inner.signature.v(), // Previous attempt for v from sig.rs, which returns bool (y_parity)
            // For FullTransaction.v, we expect the EIP-155 adjusted V. Let's retry self.v from AlloyTransaction itself.
            // If alloy_rpc_types::Transaction v0.7.0 does not have `v` field, this will error again, and we'll need another source for it.
            // v: self.v, // This errored: no field `v` on type `alloy_rpc_types::Transaction`
            
            // Reconstruct EIP-155 `v` value
            v: {
                let y_parity_val = self.inner.signature().v() as u64;
                if let Some(chain_id) = self.inner.chain_id() {
                    U256::from(y_parity_val + 35 + chain_id * 2)
                } else {
                    // Legacy transaction (no chain_id)
                    U256::from(y_parity_val + 27)
                }
            },
            
            // y_parity is derived from signature's v() method (which returns a bool for y_parity)
            y_parity: Some(if self.inner.signature().v() { U256::from(1) } else { U256::from(0) }),
            
            access_list: access_list_converted, 
            
            transaction_type: Some(U256::from(self.inner.tx_type() as u8)),
            
            max_fee_per_gas: max_fee_val,
            max_priority_fee_per_gas: self.inner.max_priority_fee_per_gas().map(U256::from),
        }
    }
}

impl TransactionConverter for alloy_consensus::EthereumTxEnvelope<alloy_consensus::TxEip4844> {
    type FullType = FullTransaction;

    fn into_full_type(self) -> Self::FullType { // self is now EthereumTxEnvelope<TxEip4844>
        let _signer = self.recover_signer().unwrap_or_default(); // EthereumTxEnvelope directly has this if TxEnvelope trait is used
        let signature = self.signature(); // EthereumTxEnvelope directly has this if TxEnvelope trait is used

        // Access other fields using methods from TransactionTrait, which EthereumTxEnvelope implements
        let to_address = if let TxKind::Call(addr) = self.kind() { Some(addr) } else { None };

        let max_fee_val = match self.tx_type() {
            TxType::Eip1559 | TxType::Eip4844 | TxType::Eip7702 => Some(U256::from(self.max_fee_per_gas())),
            _ => None,
        };
        
        // Note: effective_gas_price might need base_fee_per_gas. 
        // If so, that needs to be passed into this function or calculated differently.
        // For now, assuming FullTransaction doesn't strictly need effective_gas_price or it's handled by the consumer.

        FullTransaction {
            to: to_address,
            value: self.value(),
            input: self.input().clone(),
            nonce: self.nonce(),
            gas_limit: self.gas_limit(),
            gas_price: self.gas_price().map(U256::from),
            chain_id: self.chain_id(),
            
            r: signature.r(),
            s: signature.s(),
            v: { // Reconstruct EIP-155 v from signature parity and chain_id
                let y_parity_val = signature.v() as u64; // signature.v() is bool
                if let Some(id) = self.chain_id() {
                    U256::from(y_parity_val + 35 + id * 2)
                } else {
                    U256::from(y_parity_val + 27)
                }
            },
            y_parity: Some(if signature.v() { U256::from(1) } else { U256::from(0) }),
            
            access_list: self.access_list().map(|al_ref| {
                al_ref.0.iter().map(|item| {
                    (item.address, item.storage_keys.iter().map(|k| U256::from_be_bytes(k.0)).collect())
                }).collect()
            }),
            
            transaction_type: Some(U256::from(self.tx_type() as u8)),
            
            max_fee_per_gas: max_fee_val,
            max_priority_fee_per_gas: self.max_priority_fee_per_gas().map(U256::from),
        }
    }
}

/// Wraps an EthBuiltPayload with additional Neura-specific details, like full transactions.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct NeuraBuiltPayloadWithDetails {
    /// The original, underlying Ethereum built payload.
    pub original_payload: EthBuiltPayload,
    /// A list of full transaction details corresponding to the transactions in the payload.
    pub full_transactions: Vec<FullTransaction>,
}

impl NeuraBuiltPayloadWithDetails {
    /// Creates a new `NeuraBuiltPayloadWithDetails` instance.
    pub fn new(original_payload: EthBuiltPayload, full_transactions: Vec<FullTransaction>) -> Self {
        Self { original_payload, full_transactions }
    }

    // Optional: Add direct accessors if needed, e.g., for full_transactions
    /// Returns a slice of the full transaction details.
    pub fn full_transactions(&self) -> &[FullTransaction] {
        &self.full_transactions
    }
}

impl BuiltPayload for NeuraBuiltPayloadWithDetails {
    type Primitives = EthPrimitives;

    /// Returns a reference to the sealed block within the original payload.
    fn block(&self) -> &SealedBlock<<Self::Primitives as NodePrimitives>::Block> {
        self.original_payload.block()
    }

    /// Returns the total fees of the original payload.
    fn fees(&self) -> U256 {
        self.original_payload.fees()
    }

    /// Returns the EIP-7685 requests from the original payload, if any.
    fn requests(&self) -> Option<Requests> {
        self.original_payload.requests()
    }
} 