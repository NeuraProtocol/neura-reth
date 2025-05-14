use neura_payload_types::{NeuraBuiltPayloadWithDetails, FullTransaction, TransactionConverter};
use reth_ethereum_payload_builder::EthereumPayloadBuilder as RethEthereumPayloadBuilder;
use reth_basic_payload_builder::PayloadBuilder;
use reth_ethereum_engine_primitives::EthPayloadBuilderAttributes;
use reth_payload_builder_primitives::PayloadBuilderError;
use reth_basic_payload_builder::{BuildArguments, BuildOutcome, MissingPayloadBehaviour, PayloadConfig};
use reth_ethereum_engine_primitives::EthBuiltPayload;
use reth_ethereum_primitives::{TransactionSigned, EthPrimitives};
use reth_transaction_pool::{TransactionPool, PoolTransaction};
use reth_storage_api::StateProviderFactory;
use reth_chainspec::{ChainSpecProvider, EthereumHardforks};
use reth_evm::ConfigureEvm;
use reth_evm_ethereum::EthEvmConfig;
use reth_primitives_traits::{Header as RethHeaderTrait, NodePrimitives, Block as RethBlockTrait, SealedBlock as RethPrimitivesSealedBlock};
use alloy_rpc_types::eth::{Transaction as AlloyTransaction, AccessList as AlloyRpcAccessList, AccessListItem as AlloyRpcAccessListItem};
use alloy_primitives::{U256, Address, Bytes, B256, U64, TxKind as AlloyCoreTxKind, Signature as AlloyCoreSignature};
use alloy_eips::eip7685::Requests;
use alloy_consensus::{
    Signed, TxLegacy, TxEip2930, TxEip1559, TxEip4844, TxEip7702, 
    TxType as AlloyCoreTxType, 
    EthereumTxEnvelope, TxEip4844Variant,
    BlobTransactionSidecar as AlloyBlobTransactionSidecar,
    SignableTransaction, 
};
use alloy_consensus::transaction::Recovered;
use alloy_rlp::Encodable;
use alloy_eips::eip2930::{AccessList as AlloyEip2930AccessList, AccessListItem as AlloyEip2930AccessListItem};
use alloy_primitives::eip4844::{Blob, KzgCommitment, KzgProof};
use std::sync::Arc;
use reth_ethereum_primitives::{Transaction as RethTransactionEnum};

/// A Neura-specific payload builder that wraps the standard Reth EthereumPayloadBuilder
/// to augment its output with `FullTransaction` details.
#[derive(Debug, Clone)]
pub struct NeuraPayloadBuilder<Pool, Client, EvmConfig = EthEvmConfig> {
    inner_builder: RethEthereumPayloadBuilder<Pool, Client, EvmConfig>,
}

impl<Pool, Client, EvmConfig> NeuraPayloadBuilder<Pool, Client, EvmConfig>
where
    Client: StateProviderFactory + ChainSpecProvider + Clone + Send + Sync + 'static,
    <Client as ChainSpecProvider>::ChainSpec: EthereumHardforks,
    Pool: TransactionPool<Transaction = Arc<reth_transaction_pool::ValidPoolTransaction<TransactionSigned>>, Consensus = TransactionSigned> + Clone + Send + Sync + 'static,
    EvmConfig: ConfigureEvm<Primitives = EthPrimitives, NextBlockEnvCtx = reth_evm::NextBlockEnvAttributes> + Clone + Send + Sync + 'static,
{
    pub fn new(
        client: Client,
        pool: Pool,
        evm_config: EvmConfig,
        builder_config: reth_ethereum_payload_builder::EthereumBuilderConfig,
    ) -> Self {
        Self {
            inner_builder: RethEthereumPayloadBuilder::new(client, pool, evm_config, builder_config),
        }
    }

    fn convert_to_full_transactions(
        &self,
        built_payload: &EthBuiltPayload,
    ) -> Vec<FullTransaction> {
        let sealed_block_concrete = built_payload.block();
        let block_header_ref: &alloy_consensus::Header = sealed_block_concrete.header();
        let envelopes_from_block: &[EthereumTxEnvelope<TransactionSigned>] = sealed_block_concrete.body(); 
        
        let base_fee_per_gas: Option<u64> = block_header_ref.base_fee_per_gas();

        envelopes_from_block
            .iter() 
            .enumerate()
            .filter_map(|(_idx, envelope)| { 
                let reth_tx_signed: TransactionSigned = match envelope {
                    EthereumTxEnvelope::Legacy(s) => TransactionSigned::from(s.clone()),
                    EthereumTxEnvelope::Eip2930(s) => TransactionSigned::from(s.clone()),
                    EthereumTxEnvelope::Eip1559(s) => TransactionSigned::from(s.clone()),
                    EthereumTxEnvelope::Eip4844(variant) => match variant {
                        TxEip4844Variant::Tx(s) => TransactionSigned::from(s.clone()),
                        _ => return None,
                    },
                    EthereumTxEnvelope::Eip7702(s) => TransactionSigned::from(s.clone()),
                    _ => return None,
                };

                let alloy_signature: AlloyCoreSignature = reth_tx_signed.signature().clone();
                let reth_tx_variant = &reth_tx_signed.transaction; 
                let tx_hash = reth_tx_signed.hash();

                let convert_reth_access_list_to_consensus =
                    |reth_al_opt: Option<&AlloyEip2930AccessList>| -> Option<AlloyEip2930AccessList> {
                        reth_al_opt.cloned()
                    };
                
                let convert_reth_tx_kind_to_consensus =
                    |reth_kind: &AlloyCoreTxKind| -> AlloyCoreTxKind {
                        *reth_kind
                    };

                let inner_tx_envelope = match reth_tx_variant {
                    RethTransactionEnum::Legacy(unsigned_tx) => {
                        let signed_tx = Signed::new_unchecked(unsigned_tx.clone(), alloy_signature, *tx_hash);
                        EthereumTxEnvelope::Legacy(signed_tx)
                    }
                    RethTransactionEnum::Eip2930(unsigned_tx) => {
                        let signed_tx = Signed::new_unchecked(unsigned_tx.clone(), alloy_signature, *tx_hash);
                        EthereumTxEnvelope::Eip2930(signed_tx)
                    }
                    RethTransactionEnum::Eip1559(unsigned_tx) => {
                        let signed_tx = Signed::new_unchecked(unsigned_tx.clone(), alloy_signature, *tx_hash);
                        EthereumTxEnvelope::Eip1559(signed_tx)
                    }
                    RethTransactionEnum::Eip4844(unsigned_tx) => {
                        let signed_tx = Signed::new_unchecked(unsigned_tx.clone(), alloy_signature, *tx_hash);
                        EthereumTxEnvelope::Eip4844(TxEip4844Variant::Tx(signed_tx))
                    }
                    RethTransactionEnum::Eip7702(unsigned_tx) => {
                        let signed_tx = Signed::new_unchecked(unsigned_tx.clone(), alloy_signature, *tx_hash);
                        EthereumTxEnvelope::Eip7702(signed_tx)
                    }
                    _ => return None,
                };
                
                let inner_recovered_tx = Recovered::new_unchecked(inner_tx_envelope.clone(), reth_tx_signed.signer());

                let calculated_effective_gas_price = {
                    let base_fee = base_fee_per_gas.map(U256::from).unwrap_or_default();
                    U256::from(reth_tx_variant.effective_gas_price(base_fee_per_gas))
                };
                
                let rpc_access_list = reth_tx_variant.access_list().map(|al_ref| {
                    AlloyRpcAccessList(
                        al_ref.0.iter().map(|item: &AlloyEip2930AccessListItem| {
                            AlloyRpcAccessListItem {
                                address: item.address,
                                storage_keys: item.storage_keys.clone(),
                            }
                        }).collect::<Vec<_>>()
                    )
                });

                let alloy_tx = AlloyTransaction {
                    inner: inner_recovered_tx,
                    effective_gas_price: Some(calculated_effective_gas_price.to::<u128>()),
                    block_hash: None,
                    block_number: None,
                    transaction_index: None,
                };

                Some(alloy_tx.into_full_type())
            })
            .collect()
    }
}

impl<Pool, Client, EvmConfig> PayloadBuilder for NeuraPayloadBuilder<Pool, Client, EvmConfig>
where
    EvmConfig: ConfigureEvm<Primitives = EthPrimitives, NextBlockEnvCtx = reth_evm::NextBlockEnvAttributes> + Clone + Send + Sync + 'static,
    Client: StateProviderFactory + ChainSpecProvider + Clone + Unpin + Send + Sync + 'static,
    <Client as ChainSpecProvider>::ChainSpec: EthereumHardforks,
    Pool: TransactionPool<Transaction = Arc<reth_transaction_pool::ValidPoolTransaction<TransactionSigned>>, Consensus = TransactionSigned> + Clone + Send + Sync + 'static,
{
    type Attributes = EthPayloadBuilderAttributes;
    type BuiltPayload = NeuraBuiltPayloadWithDetails;

    fn try_build(
        &self,
        args: reth_basic_payload_builder::BuildArguments<Self::Attributes, Self::BuiltPayload>,
    ) -> Result<reth_basic_payload_builder::BuildOutcome<Self::BuiltPayload>, PayloadBuilderError> {
        let original_best_payload_opt: Option<Arc<EthBuiltPayload>> =
            args.best_payload.as_ref().map(|neura_bp_arc| {
                Arc::new(neura_bp_arc.original_payload.clone())
            });

        let inner_args = reth_basic_payload_builder::BuildArguments {
            cached_reads: args.cached_reads,
            config: args.config, 
            cancel: args.cancel, 
            best_payload: original_best_payload_opt,
        };

        match self.inner_builder.try_build(inner_args) {
            Ok(reth_basic_payload_builder::BuildOutcome::Better { payload: eth_payload, cached_reads }) => {
                let full_transactions = self.convert_to_full_transactions(&eth_payload);
                let neura_payload = NeuraBuiltPayloadWithDetails::new((*eth_payload).clone(), full_transactions);
                Ok(reth_basic_payload_builder::BuildOutcome::Better { payload: neura_payload, cached_reads })
            }
            Ok(reth_basic_payload_builder::BuildOutcome::Aborted { fees, cached_reads }) => {
                Ok(reth_basic_payload_builder::BuildOutcome::Aborted { fees, cached_reads })
            }
            Ok(reth_basic_payload_builder::BuildOutcome::Cancelled) => Ok(reth_basic_payload_builder::BuildOutcome::Cancelled),
            Ok(reth_basic_payload_builder::BuildOutcome::Freeze(eth_payload)) => {
                let full_transactions = self.convert_to_full_transactions(&eth_payload);
                let neura_payload = NeuraBuiltPayloadWithDetails::new((*eth_payload).clone(), full_transactions);
                Ok(reth_basic_payload_builder::BuildOutcome::Freeze(neura_payload))
            }
            Err(e) => Err(e),
        }
    }

    fn on_missing_payload(
        &self,
        args: reth_basic_payload_builder::BuildArguments<Self::Attributes, Self::BuiltPayload>,
    ) -> reth_basic_payload_builder::MissingPayloadBehaviour<Self::BuiltPayload> {
         let original_best_payload_opt: Option<Arc<EthBuiltPayload>> =
            args.best_payload.as_ref().map(|neura_bp_arc| {
                Arc::new(neura_bp_arc.original_payload.clone())
            });
        let inner_args = reth_basic_payload_builder::BuildArguments {
            cached_reads: args.cached_reads,
            config: args.config.clone(),
            cancel: args.cancel.clone(),
            best_payload: original_best_payload_opt,
        };

        match self.inner_builder.on_missing_payload(inner_args) {
            MissingPayloadBehaviour::RaceEmptyPayload => MissingPayloadBehaviour::RaceEmptyPayload,
            MissingPayloadBehaviour::AwaitInProgress => MissingPayloadBehaviour::AwaitInProgress,
            MissingPayloadBehaviour::RacePayload(job_fn) => {
                MissingPayloadBehaviour::RacePayload(Box::new(move || {
                    job_fn().map(|eth_payload_arc| {
                        let full_transactions = self.convert_to_full_transactions(&eth_payload_arc);
                        NeuraBuiltPayloadWithDetails::new((*eth_payload_arc).clone(), full_transactions)
                    })
                }))
            }
        }
    }

    fn build_empty_payload(
        &self,
        config: reth_basic_payload_builder::PayloadConfig<Self::Attributes>,
    ) -> Result<Self::BuiltPayload, PayloadBuilderError> {
        match self.inner_builder.build_empty_payload(config) {
            Ok(eth_payload_arc) => {
                let full_transactions = self.convert_to_full_transactions(&eth_payload_arc);
                Ok(NeuraBuiltPayloadWithDetails::new((*eth_payload_arc).clone(), full_transactions))
            }
            Err(e) => Err(e),
        }
    }
} 