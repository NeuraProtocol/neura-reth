//! Neura-specific payload builder.

use neura_payload_types::{NeuraBuiltPayloadWithDetails, FullTransaction, TransactionConverter};
use reth_ethereum_payload_builder::EthereumPayloadBuilder as RethEthereumPayloadBuilder;
use reth_basic_payload_builder::PayloadBuilder;
use reth_ethereum_engine_primitives::EthPayloadBuilderAttributes;
use reth_payload_builder_primitives::PayloadBuilderError;
use reth_basic_payload_builder::{MissingPayloadBehaviour};
use reth_ethereum_engine_primitives::EthBuiltPayload; // For EthBuiltPayload type
use reth_ethereum_primitives::EthPrimitives; // For EvmConfig generic constraint & block header
use reth_transaction_pool::TransactionPool;
use reth_storage_api::StateProviderFactory;
use reth_chainspec::{ChainSpecProvider, EthereumHardforks};
use reth_evm::ConfigureEvm;
use reth_evm_ethereum::EthEvmConfig;

use std::sync::Arc;


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
    Pool: TransactionPool<Transaction = reth_transaction_pool::EthPooledTransaction> + Clone + Send + Sync + 'static,
    EvmConfig: ConfigureEvm<Primitives = EthPrimitives, NextBlockEnvCtx = reth_evm::NextBlockEnvAttributes> + Clone + Send + Sync + 'static,
{
    /// Creates a new instance of `NeuraPayloadBuilder`.
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

    fn convert_to_full_transactions_static(
        built_payload: &EthBuiltPayload,
    ) -> Vec<FullTransaction> {
        let sealed_block_concrete = built_payload.block();
        // let block_header_ref = sealed_block_concrete.header(); // Not used if effective_gas_price is handled in converter
        
        let envelopes_from_block: &[alloy_consensus::EthereumTxEnvelope<alloy_consensus::TxEip4844>] = 
            &sealed_block_concrete.body().transactions; 
        
        // base_fee_per_gas is not needed here if the converter handles it or if FullTransaction doesn't store effective_gas_price
        // let base_fee_per_gas: Option<u64> = block_header_ref.base_fee_per_gas;

        envelopes_from_block
            .iter()
            .filter_map(|envelope| { // envelope is &alloy_consensus::EthereumTxEnvelope<TxEip4844>
                // Directly convert the envelope, assuming TransactionConverter is impl'd for it.
                // The envelope needs to be cloned because into_full_type takes self.
                Some(TransactionConverter::into_full_type(envelope.clone()))
            })
            .collect()
    }
}

impl<Pool, Client, EvmConfig> PayloadBuilder for NeuraPayloadBuilder<Pool, Client, EvmConfig>
where
    EvmConfig: ConfigureEvm<Primitives = EthPrimitives, NextBlockEnvCtx = reth_evm::NextBlockEnvAttributes> + Clone + Send + Sync + 'static,
    Client: StateProviderFactory + ChainSpecProvider + Clone + Unpin + Send + Sync + 'static,
    <Client as ChainSpecProvider>::ChainSpec: EthereumHardforks,
    Pool: TransactionPool<Transaction = reth_transaction_pool::EthPooledTransaction> + Clone + Send + Sync + 'static,
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
            best_payload: original_best_payload_opt.map(|arc_payload| (*arc_payload).clone()),
        };

        match self.inner_builder.try_build(inner_args) {
            Ok(reth_basic_payload_builder::BuildOutcome::Better { payload: eth_payload, cached_reads }) => {
                let full_transactions = Self::convert_to_full_transactions_static(&eth_payload);
                let neura_payload = NeuraBuiltPayloadWithDetails::new(eth_payload.clone(), full_transactions);
                Ok(reth_basic_payload_builder::BuildOutcome::Better { payload: neura_payload, cached_reads })
            }
            Ok(reth_basic_payload_builder::BuildOutcome::Aborted { fees, cached_reads }) => {
                Ok(reth_basic_payload_builder::BuildOutcome::Aborted { fees, cached_reads })
            }
            Ok(reth_basic_payload_builder::BuildOutcome::Cancelled) => Ok(reth_basic_payload_builder::BuildOutcome::Cancelled),
            Ok(reth_basic_payload_builder::BuildOutcome::Freeze(eth_payload)) => {
                let full_transactions = Self::convert_to_full_transactions_static(&eth_payload);
                let neura_payload = NeuraBuiltPayloadWithDetails::new(eth_payload.clone(), full_transactions);
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
            best_payload: original_best_payload_opt.map(|arc_payload| (*arc_payload).clone()),
        };

        match self.inner_builder.on_missing_payload(inner_args) {
            MissingPayloadBehaviour::RaceEmptyPayload => MissingPayloadBehaviour::RaceEmptyPayload,
            MissingPayloadBehaviour::AwaitInProgress => MissingPayloadBehaviour::AwaitInProgress,
            MissingPayloadBehaviour::RacePayload(job_fn) => {
                MissingPayloadBehaviour::RacePayload(Box::new(move || {
                    job_fn().map(|eth_payload_arc| {
                        let full_transactions = Self::convert_to_full_transactions_static(&eth_payload_arc);
                        NeuraBuiltPayloadWithDetails::new(eth_payload_arc.clone(), full_transactions)
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
                let full_transactions = Self::convert_to_full_transactions_static(&eth_payload_arc);
                Ok(NeuraBuiltPayloadWithDetails::new(eth_payload_arc.clone(), full_transactions))
            }
            Err(e) => Err(e),
        }
    }
}