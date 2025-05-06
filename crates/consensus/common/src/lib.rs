//! Commonly used consensus methods.

#![doc(
    html_logo_url = "https://raw.githubusercontent.com/paradigmxyz/reth/main/assets/reth-docs.png",
    html_favicon_url = "https://avatars0.githubusercontent.com/u/97369466?s=256",
    issue_tracker_base_url = "https://github.com/paradigmxyz/reth/issues/"
)]
#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]
#![cfg_attr(not(feature = "std"), no_std)]

use alloy_primitives::BlockNumber;
use reth_primitives_traits::SealedHeader;

/// Collection of consensus validation methods.
pub mod validation;

/// Common consensus engine trait that all consensus engines must implement
#[async_trait::async_trait]
pub trait ConsensusEngine: Send + Sync {
    /// The block header type used by this consensus engine
    type BlockHeader;

    /// Get the current block number
    fn block_number(&self) -> BlockNumber;

    /// Get the current block header
    fn block_header(&self) -> SealedHeader<Self::BlockHeader>;

    /// Get the safe block header if available
    fn safe_block_header(&self) -> Option<SealedHeader<Self::BlockHeader>>;

    /// Get the finalized block header if available
    fn finalized_block_header(&self) -> Option<SealedHeader<Self::BlockHeader>>;
}
