use std::sync::Arc;
use alloy_primitives::{Address, Bytes, B256, U256, Bloom, FixedBytes};
use crate::types::{ConsensusRoundIdentifier, QbftBlock, QbftBlockHeader, QbftBlockCreator, QbftBlockCreatorFactory, QbftFinalState, BftExtraData, AlloyBftExtraDataCodec, BftExtraDataCodec};
use crate::error::QbftError;

// --- MockQbftBlockCreator ---
pub struct MockQbftBlockCreator {
    parent_header: Arc<QbftBlockHeader>,
    final_state: Arc<dyn QbftFinalState>, // To get current validators for extra_data
    extra_data_codec: Arc<dyn BftExtraDataCodec>, // To encode extra_data
}

impl MockQbftBlockCreator {
    pub fn new(parent_header: Arc<QbftBlockHeader>, final_state: Arc<dyn QbftFinalState>, extra_data_codec: Arc<dyn BftExtraDataCodec>) -> Self {
        Self { parent_header, final_state, extra_data_codec }
    }
}

impl QbftBlockCreator for MockQbftBlockCreator {
    fn create_block(
        &self,
        // parent_header is already stored in self, but API asks for it. For mock, we can ignore the passed one if it matches self.
        _parent_header_arg: &QbftBlockHeader, 
        round_identifier: &ConsensusRoundIdentifier,
        timestamp_seconds: u64,
    ) -> Result<QbftBlock, QbftError> {
        let new_block_number = self.parent_header.number + 1;
        
        let validators: Vec<Address> = self.final_state.validators().into_iter().collect();
        // For a mock, committed_seals would be empty at creation time.
        let bft_extra_data = BftExtraData {
            vanity_data: Bytes::from_static(&[0u8; 32]), // 32 bytes of zeros
            validators, // Current validator set from final_state
            committed_seals: Vec::new(), // Empty for new block proposal
            round_number: round_identifier.round_number, // Round number for this block
        };
        let extra_data_bytes = self.extra_data_codec.encode(&bft_extra_data)?;

        let mock_header = QbftBlockHeader::new(
            self.parent_header.hash(),         // parent_hash
            B256::ZERO,                       // ommers_hash (typically zero for PoA/QBFT)
            self.final_state.local_address(), // beneficiary (proposer)
            B256::random(),                   // state_root (mock)
            B256::random(),                   // transactions_root (mock, for empty block)
            B256::random(),                   // receipts_root (mock, for empty block)
            Bloom::default(),                 // logs_bloom (empty)
            U256::from(1),                    // difficulty (typically 1 for PoA)
            new_block_number,                 // number
            30_000_000,                       // gas_limit (a common value)
            0,                                // gas_used (empty block)
            timestamp_seconds,                // timestamp
            extra_data_bytes,                 // extra_data
            B256::ZERO,                       // mix_hash (typically zero for PoA)
            FixedBytes::from_static(&[0u8; 8]).into(), // nonce (typically zero for PoA, must be 8 bytes)
        );

        let mock_block = QbftBlock::new(
            mock_header,
            Vec::new(), // empty transactions
            Vec::new(), // empty ommers
        );
        
        log::debug!("MockQbftBlockCreator: Created block for height {}, round {}, timestamp {}. Hash: {:?}", 
            new_block_number, round_identifier.round_number, timestamp_seconds, mock_block.hash());

        Ok(mock_block)
    }
}

// --- MockQbftBlockCreatorFactory ---
#[derive(Default)] // Allow easy creation if no specific state needed for factory itself
pub struct MockQbftBlockCreatorFactory {
    // If the factory needs to hold some state or config (e.g. which codec to use), add here.
    // For this mock, we'll assume AlloyBftExtraDataCodec is used implicitly by MockQbftBlockCreator.
    extra_data_codec: Arc<dyn BftExtraDataCodec>, 
}

impl MockQbftBlockCreatorFactory {
    pub fn new() -> Self {
        Self { extra_data_codec: Arc::new(AlloyBftExtraDataCodec) } // Default to Alloy codec
    }

    pub fn with_codec(codec: Arc<dyn BftExtraDataCodec>) -> Self {
        Self { extra_data_codec: codec }
    }
}

impl QbftBlockCreatorFactory for MockQbftBlockCreatorFactory {
    fn create_block_creator(
        &self, 
        parent_header: &QbftBlockHeader, 
        final_state_view: Arc<dyn QbftFinalState>
    ) -> Result<Arc<dyn QbftBlockCreator>, QbftError> {
        Ok(Arc::new(MockQbftBlockCreator::new(
            Arc::new(parent_header.clone()), // Clone parent_header for Arc ownership
            final_state_view, 
            self.extra_data_codec.clone()
        )))
    }
} 