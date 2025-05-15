#![doc(html_logo_url = "https://raw.githubusercontent.com/paradigmxyz/reth/main/assets/reth-docs.png")]
#![doc(html_favicon_url = "https://avatars0.githubusercontent.com/u/97369466?s=256")]
#![doc(issue_tracker_base_url = "https://github.com/paradigmxyz/reth/issues/")]
#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]

// Neura specific types
use neura_engine_types::NeuraEngineTypes;
use neura_payload_builder::NeuraPayloadBuilder;
use neura_payload_types::NeuraBuiltPayloadWithDetails;
use neura_consensus_qbft::{QbftConsensus, RethQbftFinalState, RethRoundTimer}; // Import QBFT components

// Reth types
use reth_chainspec::{ChainSpec, EthereumHardforks};
use reth_consensus::{Consensus, FullConsensus}; // For Consensus trait and Arc<dyn FullConsensus>
use reth_errors::ConsensusError; // For the error type in FullConsensus
use reth_ethereum_payload_builder::EthereumBuilderConfig; // Using standard config for NeuraPayloadBuilder
use reth_ethereum_primitives::EthPrimitives;
use reth_evm::ConfigureEvm;
use reth_node_api::{FullNodeTypes, NodeTypes, PrimitivesTy, TxTy};
use reth_node_builder::{
    components::{ConsensusBuilder, PayloadBuilderBuilder}, // Added ConsensusBuilder
    node::NodeTypesAdapter, // To help adapt components if needed
    BuilderContext,
    ComponentsBuilder, // To build the full set of components for NeuraNode
    PayloadTypes,
    // Will also need other component builders like PoolBuilder, NetworkBuilder, ExecutorBuilder, ConsensusBuilder
    // For now, we can use the Ethereum ones as placeholders or define Neura specific ones later.
    components::{
        BasicPayloadServiceBuilder,
        EthereumConsensusBuilder, // Will be replaced
        EthereumExecutorBuilder,  // Placeholder
        EthereumNetworkBuilder,   // Placeholder
        EthereumPoolBuilder,      // Placeholder
    },
};
use reth_provider::EthStorage;
use reth_transaction_pool::{PoolTransaction, TransactionPool};
use reth_trie_db::MerklePatriciaTrie;
use std::sync::Arc; // For Arc<dyn FullConsensus>

// For placeholder NodeKey generation
use k256::SecretKey;
use rand;

// Add necessary imports for QbftConsensus::new arguments
use neura_qbft_core::{types::QbftConfig, statemachine::QbftController};
use neura_consensus_qbft::types::NodeKey as QbftNodeKey; // Alias to avoid conflict if NodeKey is also from k256

// --- NeuraNode --- 
/// Type configuration for a Neura node.
#[derive(Debug, Default, Clone, Copy)]
#[non_exhaustive]
pub struct NeuraNode;

impl NodeTypes for NeuraNode {
    type Primitives = EthPrimitives; // Using Eth primitives for now
    type ChainSpec = ChainSpec; // Standard ChainSpec for now
    type StateCommitment = MerklePatriciaTrie; // Standard Ethereum state commitment
    type Storage = EthStorage; // Standard Ethereum storage
    type Payload = NeuraEngineTypes; // Our custom Neura engine types
}

// --- NeuraPayloadService --- (replaces EthereumPayloadBuilder from reth-ethereum-node)
/// Builds the Neura payload builder.
#[derive(Clone, Default, Debug)]
#[non_exhaustive]
pub struct NeuraPayloadService;

impl<Types, Node, Pool, Evm> PayloadBuilderBuilder<Node, Pool, Evm> for NeuraPayloadService
where
    Types: NodeTypes<ChainSpec: EthereumHardforks, Primitives = EthPrimitives>,
    Node: FullNodeTypes<Types = Types>,
    Pool: TransactionPool<Transaction: PoolTransaction<Consensus = TxTy<Node::Types>>>
        + Unpin
        + 'static,
    Evm: ConfigureEvm<
            Primitives = PrimitivesTy<Types>,
            NextBlockEnvCtx = reth_evm::NextBlockEnvAttributes, // Standard for now
        > + 'static,
    Types::Payload: PayloadTypes<
        BuiltPayload = NeuraBuiltPayloadWithDetails, // Crucial: Expects our detailed payload
        PayloadAttributes = <NeuraEngineTypes as PayloadTypes>::PayloadAttributes, // From NeuraEngineTypes
        PayloadBuilderAttributes = <NeuraEngineTypes as PayloadTypes>::PayloadBuilderAttributes, // From NeuraEngineTypes
    >,
{
    type PayloadBuilder = NeuraPayloadBuilder<Pool, Node::Provider, Evm>;

    async fn build_payload_builder(
        self,
        ctx: &BuilderContext<Node>,
        pool: Pool,
        evm_config: Evm,
    ) -> eyre::Result<Self::PayloadBuilder> {
        let conf = ctx.payload_builder_config();
        Ok(NeuraPayloadBuilder::new(
            ctx.provider().clone(),
            pool,
            evm_config,
            EthereumBuilderConfig::new().with_gas_limit(conf.gas_limit()), // Uses standard config for now
        ))
    }
}

// --- NeuraQbftConsensusBuilder ---
#[derive(Debug, Default, Clone, Copy)]
#[non_exhaustive]
pub struct NeuraQbftConsensusBuilder {
    // Potentially add configuration fields for QBFT if needed here
}

impl<Node> ConsensusBuilder<Node> for NeuraQbftConsensusBuilder
where
    Node: FullNodeTypes<Types = NeuraNode>,
    // Add bounds for Node::Provider to be ProviderFactory if RethQbftFinalState needs it directly.
    // RethQbftFinalState constructor takes `ProviderFactory<NT>` where NT: ProviderNodeTypes.
    // BuilderContext<Node> gives access to `ctx.provider()` which is `Node::Provider`.
    // So `Node::Provider` must be compatible with `ProviderFactory<impl ProviderNodeTypes>`.
    // This is usually true if Node::Provider is ProviderFactory itself.
    Node::Provider: reth_provider::ProviderFactory<reth_node_api::provider::ProviderNodeTypes<
        ChainSpec = <NeuraNode as NodeTypes>::ChainSpec,
        Primitives = <NeuraNode as NodeTypes>::Primitives,
        Storage = <NeuraNode as NodeTypes>::Storage,
        StateCommitment = <NeuraNode as NodeTypes>::StateCommitment,
    >> + Clone + Unpin + 'static, 
{
    type Consensus = Arc<dyn FullConsensus<EthPrimitives, Error = ConsensusError>>;

    async fn build_consensus(self, ctx: &BuilderContext<Node>) -> eyre::Result<Self::Consensus> {
        let chain_spec = ctx.chain_spec();
        let provider_factory = ctx.provider().clone();

        // Prepare arguments for QbftConsensus::new
        let secret_key = SecretKey::random(&mut rand::thread_rng());
        let node_key_raw = QbftNodeKey::from_secret_key(secret_key);
        let node_key_arc = Arc::new(node_key_raw.clone());

        let local_address: reth_primitives::Address = {
            let verifying_key = node_key_raw.verifying_key();
            // Assuming NodeKey::verifying_key() returns a k256::VerifyingKey like type
            let uncompressed_pk_bytes = verifying_key.to_encoded_point(false).as_bytes().to_vec();
            let hash = alloy_primitives::keccak256(&uncompressed_pk_bytes[1..]);
            reth_primitives::Address::from_slice(&hash[12..])
        };

        let qbft_config_arc = Arc::new(QbftConfig::default());

        // The RethRoundTimer will be a dependency for the actual QbftController
        let _round_timer_for_controller = Arc::new(RethRoundTimer::new(ctx.task_executor().clone()));
        
        // Placeholder for the QbftController argument
        let controller_arg: Arc<QbftController> = todo!("Proper QbftController initialization needed here. It requires multiple dependencies like a final_state, block_creator_factory, block_importer, message_factory, validator_multicaster, block_timer, round_timer, extra_data_codec, message_validator_factory, etc.");

        // QbftConsensus::new expects Arc<ChainSpec>, ProviderFactory<NT>, Arc<QbftController>, Arc<QbftConfig>, Arc<NodeKey>, RethAddress
        let qbft_consensus = QbftConsensus::new(
            chain_spec.clone(), 
            provider_factory.clone(), // Corrected 2nd argument
            controller_arg,           // 3rd argument: Arc<QbftController>
            qbft_config_arc,          // 4th argument: Arc<QbftConfig>
            node_key_arc,             // 5th argument: Arc<NodeKey>
            local_address             // 6th argument: RethAddress
        );

        Ok(Arc::new(qbft_consensus))
    }
}

// --- NeuraNode Components --- 
// This is how we'd assemble a NeuraNode, similar to EthereumNode::components
impl NeuraNode {
    /// Returns a [`ComponentsBuilder`] configured for a Neura node.
    pub fn components<Node>() -> ComponentsBuilder<
        Node,
        EthereumPoolBuilder, // Placeholder, could be NeuraPoolBuilder
        BasicPayloadServiceBuilder<NeuraPayloadService>, // Uses our NeuraPayloadService
        EthereumNetworkBuilder, // Placeholder
        EthereumExecutorBuilder, // Placeholder
        NeuraQbftConsensusBuilder, // Replaced EthereumConsensusBuilder
    >
    where
        Node: FullNodeTypes<Types: NodeTypes<ChainSpec = ChainSpec, Primitives = EthPrimitives>>,
        // The Node::Types::Payload must align with what NeuraPayloadService expects.
        // Since NeuraNode defines `type Payload = NeuraEngineTypes`, and NeuraEngineTypes defines
        // BuiltPayload = NeuraBuiltPayloadWithDetails, this should align if Node::Types = NeuraNode.
        <Node::Types as NodeTypes>::Payload: PayloadTypes<
            BuiltPayload = NeuraBuiltPayloadWithDetails,
            PayloadAttributes = <NeuraEngineTypes as PayloadTypes>::PayloadAttributes,
            PayloadBuilderAttributes = <NeuraEngineTypes as PayloadTypes>::PayloadBuilderAttributes,
        >,
         // Add constraint for Node::Provider for NeuraQbftConsensusBuilder
        Node::Provider: reth_provider::ProviderFactory<reth_node_api::provider::ProviderNodeTypes<
            ChainSpec = <NeuraNode as NodeTypes>::ChainSpec,
            Primitives = <NeuraNode as NodeTypes>::Primitives,
            Storage = <NeuraNode as NodeTypes>::Storage,
            StateCommitment = <NeuraNode as NodeTypes>::StateCommitment,
        >> + Clone + Unpin + 'static,
    {
        ComponentsBuilder::default()
            .node_types::<Node>() // Important to set the node type context
            .pool(EthereumPoolBuilder::default()) // Placeholder
            .payload(BasicPayloadServiceBuilder::new(NeuraPayloadService::default())) // Use NeuraPayloadService
            .network(EthereumNetworkBuilder::default()) // Placeholder
            .executor(EthereumExecutorBuilder::default()) // Placeholder
            .consensus(NeuraQbftConsensusBuilder::default()) // Use NeuraQbftConsensusBuilder
    }
} 