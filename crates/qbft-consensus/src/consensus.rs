use alloy_consensus::BlockHeader;
use alloy_primitives::{Address, B256, U256};
use reth_consensus::{Consensus, ConsensusError, FullConsensus, HeaderValidator};
use reth_ethereum_primitives::EthPrimitives;
use reth_execution_types::BlockExecutionResult;
use reth_primitives_traits::{Block, NodePrimitives, RecoveredBlock, SealedBlock, SealedHeader};
use std::sync::Arc;

use crate::chain_spec::QBFTChainSpec;

/// QBFT consensus implementation
#[derive(Debug, Clone)]
pub struct QBFTConsensus {
    /// Chain specification
    chain_spec: Arc<QBFTChainSpec>,
}

impl QBFTConsensus {
    /// Creates a new QBFT consensus instance
    pub fn new(chain_spec: Arc<QBFTChainSpec>) -> Self {
        Self { chain_spec }
    }

    /// Validates the block header according to QBFT rules
    fn validate_qbft_header(&self, header: &SealedHeader<BlockHeader>) -> Result<(), ConsensusError> {
        // Validate block number
        if header.number() == 0 {
            return Ok(());
        }

        // Validate timestamp
        let block_period = self.chain_spec.block_period();
        if header.timestamp() % block_period != 0 {
            return Err(ConsensusError::Other(
                "Block timestamp must be a multiple of block period".into(),
            ));
        }

        // Validate validator set
        let validators = self.chain_spec.validators_at_block(header.number());
        if validators.is_empty() {
            return Err(ConsensusError::Other("No validators available".into()));
        }

        // Validate proposer
        let proposer = self.get_proposer(header);
        if !validators.contains(&proposer) {
            return Err(ConsensusError::Other("Invalid block proposer".into()));
        }

        Ok(())
    }

    /// Gets the proposer address from the block header
    fn get_proposer(&self, header: &SealedHeader<BlockHeader>) -> Address {
        // In QBFT, the proposer is determined by the block number and validator set
        let validators = self.chain_spec.validators_at_block(header.number());
        let proposer_index = (header.number() % validators.len() as u64) as usize;
        validators[proposer_index]
    }

    /// Validates the block body according to QBFT rules
    fn validate_qbft_body(
        &self,
        body: &<EthPrimitives as NodePrimitives>::BlockBody,
        header: &SealedHeader<BlockHeader>,
    ) -> Result<(), ConsensusError> {
        // Validate transactions
        for tx in body.transactions() {
            // Add any QBFT-specific transaction validation rules here
        }

        // Validate ommers (should be empty in QBFT)
        if !body.ommers().is_empty() {
            return Err(ConsensusError::Other("QBFT does not support ommers".into()));
        }

        Ok(())
    }
}

impl<B> Consensus<B> for QBFTConsensus
where
    B: Block,
{
    type Error = ConsensusError;

    fn validate_body_against_header(
        &self,
        body: &B::Body,
        header: &SealedHeader<B::Header>,
    ) -> Result<(), ConsensusError> {
        self.validate_qbft_body(body, header)
    }

    fn validate_block_pre_execution(&self, block: &SealedBlock<B>) -> Result<(), ConsensusError> {
        self.validate_qbft_header(block.header())
    }
}

impl<N> FullConsensus<N> for QBFTConsensus
where
    N: NodePrimitives,
{
    fn validate_block_post_execution(
        &self,
        block: &RecoveredBlock<N::Block>,
        result: &BlockExecutionResult<N::Receipt>,
    ) -> Result<(), ConsensusError> {
        // Validate state changes according to QBFT rules
        // This could include checking validator rewards, state transitions, etc.
        Ok(())
    }
}

impl<H> HeaderValidator<H> for QBFTConsensus
where
    H: BlockHeader,
{
    fn validate_header(&self, header: &SealedHeader<H>) -> Result<(), ConsensusError> {
        self.validate_qbft_header(header)
    }

    fn validate_header_against_parent(
        &self,
        header: &SealedHeader<H>,
        parent: &SealedHeader<H>,
    ) -> Result<(), ConsensusError> {
        // Validate block number
        if header.number() != parent.number() + 1 {
            return Err(ConsensusError::Other("Invalid block number".into()));
        }

        // Validate timestamp
        let block_period = self.chain_spec.block_period();
        if header.timestamp() <= parent.timestamp() {
            return Err(ConsensusError::Other("Invalid block timestamp".into()));
        }
        if (header.timestamp() - parent.timestamp()) % block_period != 0 {
            return Err(ConsensusError::Other(
                "Block timestamp must be a multiple of block period".into(),
            ));
        }

        // Validate parent hash
        if header.parent_hash() != parent.hash() {
            return Err(ConsensusError::Other("Invalid parent hash".into()));
        }

        Ok(())
    }

    fn validate_header_with_total_difficulty(
        &self,
        header: &H,
        total_difficulty: U256,
    ) -> Result<(), ConsensusError> {
        // QBFT doesn't use total difficulty, so we can skip this validation
        Ok(())
    }
} 