use alloy_primitives::{Address, B256, U256};
use alloy_rpc_types_engine::{
    ExecutionPayload, ForkchoiceState, ForkchoiceUpdated, PayloadAttributes, PayloadStatus,
    TransitionConfiguration,
};
use async_trait::async_trait;
use reth_engine_primitives::{
    EngineTypes, EngineValidator, PayloadValidator,
};
use reth_ethereum_primitives::EthPrimitives;
use reth_payload_primitives::{
    EngineApiMessageVersion, PayloadTypes, BuiltPayload as PayloadBuiltPayload,
    PayloadBuilderAttributes, PayloadOrAttributes, EngineObjectValidationError,
    EngineApiError,
};
use reth_primitives_traits::{Block, NodePrimitives, RecoveredBlock, SealedBlock};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::{
    chain_spec::QBFTChainSpec,
    consensus::QBFTConsensus,
};

/// QBFT engine types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QBFTEngineTypes;

impl PayloadTypes for QBFTEngineTypes {
    type ExecutionData = ExecutionPayload;
    type BuiltPayload = ExecutionPayload;
    type PayloadAttributes = PayloadAttributes;
    type PayloadBuilderAttributes = PayloadAttributes;

    fn block_to_payload(
        block: SealedBlock<<EthPrimitives as NodePrimitives>::Block>,
    ) -> Self::ExecutionData {
        ExecutionPayload::from_block_unchecked(block.hash(), &block.into_block())
    }
}

impl EngineTypes for QBFTEngineTypes {
    type ExecutionPayloadEnvelopeV1 = ExecutionPayload;
    type ExecutionPayloadEnvelopeV2 = ExecutionPayload;
    type ExecutionPayloadEnvelopeV3 = ExecutionPayload;
    type ExecutionPayloadEnvelopeV4 = ExecutionPayload;
}

/// QBFT engine validator
#[derive(Debug, Clone)]
pub struct QBFTEngineValidator {
    /// Chain specification
    chain_spec: Arc<QBFTChainSpec>,
    /// Consensus engine
    consensus: Arc<QBFTConsensus>,
}

impl QBFTEngineValidator {
    /// Creates a new QBFT engine validator
    pub fn new(chain_spec: Arc<QBFTChainSpec>, consensus: Arc<QBFTConsensus>) -> Self {
        Self {
            chain_spec,
            consensus,
        }
    }
}

impl EngineValidator<QBFTEngineTypes> for QBFTEngineValidator {
    fn validate_version_specific_fields(
        &self,
        version: EngineApiMessageVersion,
        payload_or_attrs: PayloadOrAttributes<'_, QBFTEngineTypes::ExecutionData, QBFTEngineTypes::PayloadAttributes>,
    ) -> Result<(), EngineObjectValidationError> {
        // QBFT doesn't have any version-specific fields to validate
        Ok(())
    }

    fn ensure_well_formed_attributes(
        &self,
        version: EngineApiMessageVersion,
        attributes: &QBFTEngineTypes::PayloadAttributes,
    ) -> Result<(), EngineObjectValidationError> {
        // Validate timestamp
        let block_period = self.chain_spec.block_period();
        if attributes.timestamp % block_period != 0 {
            return Err(EngineObjectValidationError::InvalidParams(
                "Invalid timestamp".into(),
            ));
        }

        // Validate proposer
        let validators = self.chain_spec.validators_at_block(attributes.block_number);
        let proposer_index = (attributes.block_number % validators.len() as u64) as usize;
        let expected_proposer = validators[proposer_index];

        if attributes.suggested_fee_recipient != expected_proposer {
            return Err(EngineObjectValidationError::InvalidParams(
                "Invalid fee recipient".into(),
            ));
        }

        Ok(())
    }
}

impl PayloadValidator for QBFTEngineValidator {
    type Block = <EthPrimitives as NodePrimitives>::Block;
    type ExecutionData = ExecutionPayload;

    fn ensure_well_formed_payload(
        &self,
        payload: Self::ExecutionData,
    ) -> Result<RecoveredBlock<Self::Block>, EngineApiError> {
        // Convert the execution payload to a block
        let block = RecoveredBlock::try_from(payload)
            .map_err(|e| EngineApiError::InvalidPayload(e.to_string()))?;

        // Validate the block
        self.consensus
            .validate_block_pre_execution(&block)
            .map_err(|e| EngineApiError::InvalidPayload(e.to_string()))?;

        Ok(block)
    }
} 