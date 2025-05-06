use reth_node_api::{
    ConsensusBuilder, EngineValidatorBuilder, FullNodeComponents, FullNodeTypes, NodeTypes,
};
use reth_node_builder::BuilderContext;
use std::sync::Arc;

use crate::{
    chain_spec::QBFTChainSpec,
    consensus::QBFTConsensus,
    engine::{QBFTEngineTypes, QBFTEngineValidator},
};

/// QBFT consensus builder
#[derive(Debug, Default, Clone)]
pub struct QBFTNodeBuilder;

impl<Node> ConsensusBuilder<Node> for QBFTNodeBuilder
where
    Node: FullNodeTypes<Types: NodeTypes<ChainSpec = QBFTChainSpec>>,
{
    type Consensus = Arc<QBFTConsensus>;

    async fn build_consensus(
        self,
        ctx: &BuilderContext<Node>,
    ) -> eyre::Result<Self::Consensus> {
        let chain_spec = ctx.chain_spec().clone();
        Ok(Arc::new(QBFTConsensus::new(chain_spec)))
    }
}

/// QBFT engine validator builder
#[derive(Debug, Default, Clone)]
pub struct QBFTEngineValidatorBuilder;

impl<Node, Types> EngineValidatorBuilder<Node> for QBFTEngineValidatorBuilder
where
    Types: NodeTypes<ChainSpec = QBFTChainSpec, Payload = QBFTEngineTypes>,
    Node: FullNodeComponents<Types = Types>,
{
    type Validator = QBFTEngineValidator;

    async fn build(self, ctx: &BuilderContext<Node>) -> eyre::Result<Self::Validator> {
        let chain_spec = ctx.chain_spec().clone();
        let consensus = Arc::new(QBFTConsensus::new(chain_spec.clone()));
        Ok(QBFTEngineValidator::new(chain_spec, consensus))
    }
} 