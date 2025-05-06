#![doc(
    html_logo_url = "https://raw.githubusercontent.com/paradigmxyz/reth/main/assets/reth-docs.png",
    html_favicon_url = "https://avatars0.githubusercontent.com/u/97369466?s=256",
    issue_tracker_base_url = "https://github.com/paradigmxyz/reth/issues/"
)]
#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]

pub mod chain_spec;
pub mod consensus;
pub mod engine;
pub mod node;

pub use chain_spec::{QBFTChainSpec, QBFTConfig, RewardConfig};
pub use consensus::QBFTConsensus;
pub use engine::{QBFTEngineTypes, QBFTEngineValidator};
pub use node::{QBFTEngineValidatorBuilder, QBFTNodeBuilder};

use alloy_primitives::BlockNumber;
use reth_consensus_common::ConsensusEngine;
use reth_primitives_traits::SealedHeader;

/// QBFT consensus engine implementation
pub struct QBFTEngine {
    block_number: BlockNumber,
    block_header: SealedHeader<alloy_consensus::BlockHeader>,
    safe_block_header: Option<SealedHeader<alloy_consensus::BlockHeader>>,
    finalized_block_header: Option<SealedHeader<alloy_consensus::BlockHeader>>,
}

#[async_trait::async_trait]
impl ConsensusEngine for QBFTEngine {
    type BlockHeader = alloy_consensus::BlockHeader;

    fn block_number(&self) -> BlockNumber {
        self.block_number
    }

    fn block_header(&self) -> SealedHeader<Self::BlockHeader> {
        self.block_header.clone()
    }

    fn safe_block_header(&self) -> Option<SealedHeader<Self::BlockHeader>> {
        self.safe_block_header.clone()
    }

    fn finalized_block_header(&self) -> Option<SealedHeader<Self::BlockHeader>> {
        self.finalized_block_header.clone()
    }
} 