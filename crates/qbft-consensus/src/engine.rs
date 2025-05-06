use alloy_primitives::{Address, B256, U256};
use alloy_rpc_types_engine::{
    ExecutionPayload, ForkchoiceState, ForkchoiceUpdated, PayloadAttributes, PayloadStatus,
    TransitionConfiguration,
};
use async_trait::async_trait;
use reth_engine_primitives::{
    EngineApiError, EngineApiMessageVersion, EngineTypes, EngineValidator, PayloadValidator,
};
use reth_ethereum_primitives::EthPrimitives;
use reth_primitives_traits::{Block, NodePrimitives, RecoveredBlock};
use std::sync::Arc;

use crate::{
    chain_spec::QBFTChainSpec,
    consensus::QBFTConsensus,
};

/// QBFT engine types
#[derive(Debug, Clone)]
pub struct QBFTEngineTypes;

impl EngineTypes for QBFTEngineTypes {
    type PayloadAttributes = PayloadAttributes;
    type ExecutionPayload = ExecutionPayload;
    type BuiltPayload = ExecutionPayload;
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

#[async_trait]
impl EngineValidator for QBFTEngineValidator {
    type Error = EngineApiError;
    type PayloadAttributes = PayloadAttributes;
    type ExecutionPayload = ExecutionPayload;
    type BuiltPayload = ExecutionPayload;

    async fn validate_payload_attributes(
        &self,
        payload_attrs: &Self::PayloadAttributes,
        version: EngineApiMessageVersion,
    ) -> Result<(), Self::Error> {
        // Validate timestamp
        let block_period = self.chain_spec.block_period();
        if payload_attrs.timestamp % block_period != 0 {
            return Err(EngineApiError::InvalidPayloadAttributes(
                "Invalid timestamp".into(),
            ));
        }

        // Validate proposer
        let validators = self.chain_spec.validators_at_block(payload_attrs.block_number);
        let proposer_index = (payload_attrs.block_number % validators.len() as u64) as usize;
        let expected_proposer = validators[proposer_index];

        if payload_attrs.suggested_fee_recipient != expected_proposer {
            return Err(EngineApiError::InvalidPayloadAttributes(
                "Invalid fee recipient".into(),
            ));
        }

        Ok(())
    }

    async fn validate_payload(
        &self,
        payload: &Self::ExecutionPayload,
        version: EngineApiMessageVersion,
    ) -> Result<(), Self::Error> {
        // Validate block number
        if payload.block_number == 0 {
            return Ok(());
        }

        // Validate timestamp
        let block_period = self.chain_spec.block_period();
        if payload.timestamp % block_period != 0 {
            return Err(EngineApiError::InvalidPayload("Invalid timestamp".into()));
        }

        // Validate proposer
        let validators = self.chain_spec.validators_at_block(payload.block_number);
        let proposer_index = (payload.block_number % validators.len() as u64) as usize;
        let expected_proposer = validators[proposer_index];

        if payload.fee_recipient != expected_proposer {
            return Err(EngineApiError::InvalidPayload("Invalid fee recipient".into()));
        }

        Ok(())
    }

    async fn validate_forkchoice_state(
        &self,
        state: &ForkchoiceState,
        version: EngineApiMessageVersion,
    ) -> Result<(), Self::Error> {
        // Validate that the head block exists
        if state.head_block_hash.is_zero() {
            return Err(EngineApiError::InvalidForkchoiceState(
                "Invalid head block hash".into(),
            ));
        }

        // Validate that the safe block exists
        if state.safe_block_hash.is_zero() {
            return Err(EngineApiError::InvalidForkchoiceState(
                "Invalid safe block hash".into(),
            ));
        }

        // Validate that the finalized block exists
        if state.finalized_block_hash.is_zero() {
            return Err(EngineApiError::InvalidForkchoiceState(
                "Invalid finalized block hash".into(),
            ));
        }

        Ok(())
    }

    async fn validate_transition_configuration(
        &self,
        config: &TransitionConfiguration,
    ) -> Result<(), Self::Error> {
        // QBFT doesn't use total difficulty, so we can skip this validation
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