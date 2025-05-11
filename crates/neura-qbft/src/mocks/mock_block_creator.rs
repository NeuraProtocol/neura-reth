use std::sync::Arc;
use alloy_primitives::{Address, Bytes, B256, U256, Bloom};
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
        
        let validators: Vec<Address> = self.final_state.current_validators();
        let bft_extra_data = BftExtraData {
            vanity_data: Bytes::from_static(&[0u8; 32]), 
            validators, 
            committed_seals: Vec::new(), 
            round_number: round_identifier.round_number, 
        };
        let extra_data_bytes = self.extra_data_codec.encode(&bft_extra_data)?;

        let mock_header = QbftBlockHeader::new(
            self.parent_header.hash(),         
            B256::ZERO,                       
            self.final_state.local_address(), 
            B256::ZERO,                   // state_root (mock) - Changed from random
            B256::ZERO,                   // transactions_root (mock) - Changed from random
            B256::ZERO,                   // receipts_root (mock) - Changed from random
            Bloom::default(),                 
            U256::from(1),                    
            new_block_number,                 
            30_000_000,                       
            0,                                
            timestamp_seconds,                
            extra_data_bytes,                 
            B256::ZERO,                       
            Bytes::from_static(&[0u8; 8]), // nonce (8-byte zero array, as QbftBlockHeader::new asserts len 8)
        );

        let mock_block = QbftBlock::new(
            mock_header,
            Vec::new(), 
            Vec::new(), 
        );
        
        log::debug!("MockQbftBlockCreator: Created block for height {}, round {}, timestamp {}. Hash: {:?}", 
            new_block_number, round_identifier.round_number, timestamp_seconds, mock_block.hash());

        Ok(mock_block)
    }
}

// --- MockQbftBlockCreatorFactory ---
pub struct MockQbftBlockCreatorFactory {
    extra_data_codec: Arc<dyn BftExtraDataCodec>, 
}

impl MockQbftBlockCreatorFactory {
    pub fn new() -> Self {
        Self { extra_data_codec: Arc::new(AlloyBftExtraDataCodec::default()) } // AlloyBftExtraDataCodec is Default
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
            Arc::new(parent_header.clone()), 
            final_state_view, 
            self.extra_data_codec.clone()
        )))
    }
} 