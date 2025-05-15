#![doc(html_logo_url = "https://raw.githubusercontent.com/paradigmxyz/reth/main/assets/reth-docs.png")]
#![doc(html_favicon_url = "https://avatars0.githubusercontent.com/u/97369466?s=256")]
#![doc(issue_tracker_base_url = "https://github.com/paradigmxyz/reth/issues/")]
#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]
#![cfg_attr(not(feature = "std"), no_std)]

// extern crate alloc; // Removed

use alloy_rpc_types_engine::{ExecutionData, ExecutionPayload};
pub use alloy_rpc_types_engine::{
    ExecutionPayloadEnvelopeV2, ExecutionPayloadEnvelopeV3, ExecutionPayloadEnvelopeV4,
    ExecutionPayloadV1, PayloadAttributes as EthPayloadAttributes, // Using Eth as base for Neura
};
use reth_engine_primitives::EngineTypes; // For EngineTypes trait
use reth_payload_primitives::{BuiltPayload, PayloadTypes};
use reth_primitives_traits::{NodePrimitives, SealedBlock};
use serde::{Deserialize, Serialize};

use neura_payload_types::NeuraBuiltPayloadWithDetails;
use reth_ethereum_engine_primitives::EthPayloadBuilderAttributes; // Using Eth as base for Neura

/// Engine API types for Neura.
#[derive(Debug, Default, Clone, Deserialize, Serialize)]
#[non_exhaustive]
pub struct NeuraEngineTypes;

impl PayloadTypes for NeuraEngineTypes {
    type ExecutionData = ExecutionData; 
    type BuiltPayload = NeuraBuiltPayloadWithDetails;
    type PayloadAttributes = EthPayloadAttributes;      // Using Eth version for now
    type PayloadBuilderAttributes = EthPayloadBuilderAttributes; // Using Eth version for now

    fn block_to_payload(
        block: SealedBlock<
            <<Self::BuiltPayload as BuiltPayload>::Primitives as NodePrimitives>::Block,
        >,
    ) -> Self::ExecutionData {
        let (payload, sidecar) =
            ExecutionPayload::from_block_unchecked(block.hash(), &block.into_block());
        ExecutionData { payload, sidecar }
    }
}

impl EngineTypes for NeuraEngineTypes
{
    type ExecutionPayloadEnvelopeV1 = ExecutionPayloadV1;
    type ExecutionPayloadEnvelopeV2 = ExecutionPayloadEnvelopeV2;
    type ExecutionPayloadEnvelopeV3 = ExecutionPayloadEnvelopeV3;
    type ExecutionPayloadEnvelopeV4 = ExecutionPayloadEnvelopeV4;
}

// Removed TryFrom implementations that violated orphan rules 