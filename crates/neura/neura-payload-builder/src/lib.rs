use neura_payload_types::{NeuraBuiltPayloadWithDetails, FullTransaction, TransactionConverter};
use reth_ethereum_payload_builder::EthereumPayloadBuilder as RethEthereumPayloadBuilder;
use reth_basic_payload_builder::PayloadBuilder;
use reth_ethereum_engine_primitives::EthPayloadBuilderAttributes;
use reth_payload_builder_primitives::PayloadBuilderError;
use reth_basic_payload_builder::{BuildArguments, BuildOutcome, MissingPayloadBehaviour, PayloadConfig, Payload as BasicPayloadStruct};
use reth_ethereum_engine_primitives::EthBuiltPayload;
use reth_ethereum_primitives::{TransactionSigned, EthPrimitives};
use reth_chainspec::EthChainSpec;
use reth_transaction_pool::{PoolTransaction, TransactionPool};
use reth_storage_api::StateProviderFactory;
use reth_chainspec::{ChainSpecProvider, EthereumHardforks};
use reth_evm::ConfigureEvm;
use reth_evm_ethereum::EthEvmConfig;
use reth_primitives_traits::{NodePrimitives, SealedHeader};
use alloy_rpc_types::eth::{Transaction as AlloyTransaction, AccessList as AlloyAccessList, AccessListItem as AlloyAccessListItem};
use alloy_primitives::{Signature as AlloySignature, U256, Address, Bytes, B256 };
use alloy_eips::eip7685::Requests;
use alloy_consensus::transaction::EthereumTxEnvelope;
use alloy_consensus::TxEip4844Variant;
use std::sync::Arc;

/// A Neura-specific payload builder that wraps the standard Reth EthereumPayloadBuilder
/// to augment its output with `FullTransaction` details.
#[derive(Debug, Clone)]
pub struct NeuraPayloadBuilder<Pool, Client, EvmConfig = EthEvmConfig> {
    inner_builder: RethEthereumPayloadBuilder<Pool, Client, EvmConfig>,
}

impl<Pool, Client, EvmConfig> NeuraPayloadBuilder<Pool, Client, EvmConfig>
where
    Client: StateProviderFactory + ChainSpecProvider<ChainSpec = EthChainSpec> + Clone + Send + Sync + 'static,
    Pool: TransactionPool<Transaction = Arc<reth_transaction_pool::ValidPoolTransaction<TransactionSigned>>> + Clone + Send + Sync + 'static,
    EvmConfig: ConfigureEvm<Primitives = EthPrimitives, NextBlockEnvCtx = reth_evm::NextBlockEnvAttributes> + Clone + Send + Sync + 'static,
    EthChainSpec: EthereumHardforks, // Ensure EthChainSpec satisfies EthereumHardforks
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

    // Placeholder: Actual conversion from EthBuiltPayload to Vec<FullTransaction> is complex
    // and involves converting reth_primitives::TransactionSigned to alloy_rpc_types::eth::Transaction
    // then using the TransactionConverter trait.
    fn convert_to_full_transactions(
        &self,
        _built_payload: &EthBuiltPayload, // Parameter not used by placeholder
    ) -> Vec<FullTransaction> {
        // TODO: Implement the actual conversion logic here.
        // This will involve:
        // 1. Iterating through transactions in _built_payload.block().transactions().
        // 2. For each reth_primitives::TransactionSigned:
        //    a. Construct a valid alloy_rpc_types::eth::Transaction.
        //       This means creating the `inner: Recovered<Signed<EthereumTxEnvelope<...>>>`
        //       and calculating `effective_gas_price` and other top-level fields.
        //    b. Call `.into_full_type()` on the created alloy_rpc_types::eth::Transaction.
        vec![] // Placeholder returns an empty vector
    }
}

impl<Pool, Client, EvmConfig> PayloadBuilder for NeuraPayloadBuilder<Pool, Client, EvmConfig>
where
    EvmConfig: ConfigureEvm<Primitives = EthPrimitives, NextBlockEnvCtx = reth_evm::NextBlockEnvAttributes> + Clone + Send + Sync + 'static,
    Client: StateProviderFactory + ChainSpecProvider<ChainSpec = EthChainSpec> + Clone + Unpin + Send + Sync + 'static,
    Pool: TransactionPool<Transaction = Arc<reth_transaction_pool::ValidPoolTransaction<TransactionSigned>>> + Clone + Send + Sync + 'static,
    EthChainSpec: EthereumHardforks,
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
            Ok(reth_basic_payload_builder::BuildOutcome::Better(inner_payload_struct)) => {
                let eth_payload_arc = inner_payload_struct.payload; // This is Arc<EthBuiltPayload>
                let full_transactions = self.convert_to_full_transactions(&eth_payload_arc);
                let neura_payload = NeuraBuiltPayloadWithDetails::new((*eth_payload_arc).clone(), full_transactions);

                let neura_payload_data = BasicPayloadStruct {
                    parent_block: inner_payload_struct.parent_block,
                    payload: Arc::new(neura_payload), // Payload struct expects Arc<P>
                    fees: inner_payload_struct.fees,
                    cached_reads: inner_payload_struct.cached_reads,
                };
                Ok(reth_basic_payload_builder::BuildOutcome::Better(neura_payload_data))
            }
            Ok(reth_basic_payload_builder::BuildOutcome::Aborted(inner_payload_struct)) => {
                let eth_payload_arc = inner_payload_struct.payload; // This is Arc<EthBuiltPayload>
                let full_transactions = self.convert_to_full_transactions(&eth_payload_arc);
                let neura_payload = NeuraBuiltPayloadWithDetails::new((*eth_payload_arc).clone(), full_transactions);
                
                let neura_payload_data = BasicPayloadStruct {
                    parent_block: inner_payload_struct.parent_block,
                    payload: Arc::new(neura_payload), // Payload struct expects Arc<P>
                    fees: inner_payload_struct.fees,
                    cached_reads: inner_payload_struct.cached_reads,
                };
                Ok(reth_basic_payload_builder::BuildOutcome::Aborted(neura_payload_data))
            }
            Ok(reth_basic_payload_builder::BuildOutcome::Cancelled) => Ok(reth_basic_payload_builder::BuildOutcome::Cancelled),
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
            reth_basic_payload_builder::MissingPayloadBehaviour::RaceEmptyPayload => reth_basic_payload_builder::MissingPayloadBehaviour::RaceEmptyPayload,
            reth_basic_payload_builder::MissingPayloadBehaviour::AwaitInProgress => reth_basic_payload_builder::MissingPayloadBehaviour::AwaitInProgress,
            reth_basic_payload_builder::MissingPayloadBehaviour::BuildBest(eth_payload_arc) => { // This is Arc<EthBuiltPayload>
                 let full_transactions = self.convert_to_full_transactions(&eth_payload_arc);
                 let neura_payload = NeuraBuiltPayloadWithDetails::new((*eth_payload_arc).clone(), full_transactions);
                 reth_basic_payload_builder::MissingPayloadBehaviour::BuildBest(Arc::new(neura_payload)) // Expects Arc<P>
            }
        }
    }

    fn build_empty_payload(
        &self,
        config: reth_basic_payload_builder::PayloadConfig<Self::Attributes>,
    ) -> Result<Self::BuiltPayload, PayloadBuilderError> {
        match self.inner_builder.build_empty_payload(config) {
            Ok(eth_payload_arc) => { // This is Arc<EthBuiltPayload>
                let full_transactions = self.convert_to_full_transactions(&eth_payload_arc);
                Ok(NeuraBuiltPayloadWithDetails::new((*eth_payload_arc).clone(), full_transactions))
            }
            Err(e) => Err(e),
        }
    }
} 