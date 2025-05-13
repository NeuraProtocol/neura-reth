//! QBFT consensus implementation for Reth.

// Standard imports
use std::sync::Arc;
use std::collections::{HashMap, HashSet}; // Added HashMap for RethRoundTimer
use std::time::Duration; // For timer

// Reth imports
use reth_consensus::{ConsensusError,HeaderValidator};
use reth_consensus_common::validation::validate_header_gas;
use alloy_primitives::{
    Address as RethAddress, BlockNumber, B256, U256, // Removed Bytes
};
use alloy_consensus::{EMPTY_OMMER_ROOT_HASH};
use alloy_eips::BlockHashOrNumber as AlloyBlockHashOrNumber; // Re-adding for get_block_by_hash
use reth_primitives::{SealedBlock, SealedHeader}; // Removed BlockId from here
use reth_primitives_traits::{
    NodePrimitives, BlockHeader as RethPrimitivesBlockHeaderTrait, 
    BlockBody as RethPrimitivesBlockBodyTrait, GotExpected, // Use SealedHeader from traits - NOTE: SealedHeader is already imported from reth_primitives, so this line can be simplified if only SealedHeader was intended from traits.
    Block as RethPrimitivesBlockTrait, // Re-adding for get_block_by_hash
};
use reth_chainspec::ChainSpec;
use reth_provider::{
    ProviderError,
    ProviderFactory, HeaderProvider, // Keep these direct imports
    BlockNumReader, // BlockReader was unused after commenting out get_block_by_hash
    BlockReader, // Re-adding for get_block_by_hash
};
use reth_provider::providers::ProviderNodeTypes;
use reth_node_builder::NodeTypesWithDB;

// Core QBFT imports
use neura_qbft_core::{
    types::{
        QbftConfig, QbftFinalState, QbftBlockHeader, BftExtraDataCodec, ConsensusRoundIdentifier,
        NodeKey, RoundTimer, AlloyBftExtraDataCodec, QbftBlock, SignedData,
    },
    messagewrappers::{Proposal, BftMessage},
    validation::{ValidationContext, ProposalValidator},
    payload::{ProposalPayload}, // Removed unused MessageFactory
    statemachine::QbftController,
    error::QbftError,
};

// Tokio for async operations (timers)
use tokio::sync::mpsc;
use tokio::task::{AbortHandle}; // Removed unused: JoinHandle
use tracing::{debug, trace, warn};
use std::sync::Mutex;
use thiserror::Error;
use alloy_consensus::BlockHeader as AlloyConsensusBlockHeader; // Added for number()
use std::fmt;

#[cfg(test)]
mod test_utils; // MOVED and ADDED: Declare test_utils module here for crate visibility during tests

#[derive(Debug, Error)]
pub enum QbftConsensusError {
    #[error("Provider error: {0}")]
    Provider(#[from] ProviderError),
    #[error("QBFT core error: {0}")]
    QbftCore(#[from] QbftError),
    #[error("Header validation failed: {0}")]
    Validation(String),
    #[error("Consensus Error: {0}")]
    RethConsensus(#[from] ConsensusError),
    #[error("Internal error: {0}")]
    Internal(String),
    #[error("Failed to convert reth header to qbft header: {0}")]
    HeaderConversion(String),
}

/// Adapter struct to implement `neura_qbft_core::types::QbftFinalState` using Reth's provider.
#[derive(Debug)]
#[allow(dead_code)]
pub struct RethQbftFinalState<NT: NodeTypesWithDB + ProviderNodeTypes> {
    provider_factory: ProviderFactory<NT>,
    node_key: Arc<NodeKey>,
    local_address: RethAddress,
    extra_data_codec: Arc<AlloyBftExtraDataCodec>,
    config: Arc<QbftConfig>,
}

impl<NT: NodeTypesWithDB + ProviderNodeTypes> RethQbftFinalState<NT> {
    pub fn new(
        provider_factory: ProviderFactory<NT>,
        node_key: Arc<NodeKey>,
        local_address: RethAddress,
        extra_data_codec: Arc<AlloyBftExtraDataCodec>,
        config: Arc<QbftConfig>,
    ) -> Self {
        Self {
            provider_factory,
            node_key,
            local_address,
            extra_data_codec,
            config,
        }
    }
}

fn convert_reth_header_to_qbft<H: RethPrimitivesBlockHeaderTrait>(reth_header: &H) -> QbftBlockHeader {
    QbftBlockHeader::new(
        reth_header.parent_hash(),
        reth_header.ommers_hash(),
        reth_header.beneficiary(),
        reth_header.state_root(),
        reth_header.transactions_root(),
        reth_header.receipts_root(),
        reth_header.logs_bloom(),
        reth_header.difficulty(),
        reth_header.number(),
        reth_header.gas_limit(),
        reth_header.gas_used(),
        reth_header.timestamp(),
        reth_header.extra_data().clone(),
        reth_header.mix_hash().unwrap_or_default(), // Use unwrap_or_default for Option<B256>
        reth_header.nonce().unwrap_or_default().into(), // Convert Option<FixedBytes<8>> to FixedBytes<8> then to Bytes
        reth_header.base_fee_per_gas().map(U256::from),
    )
}

fn map_provider_to_qbft_error(err: ProviderError) -> QbftError {
    QbftError::InternalError(format!("Reth Provider Error: {}", err))
}

impl<NT: NodeTypesWithDB + ProviderNodeTypes + Clone + Send + Sync + 'static>
    QbftFinalState for RethQbftFinalState<NT>
where
    neura_qbft_core::types::block::Transaction: From<<NT::Primitives as reth_primitives_traits::NodePrimitives>::SignedTx>,
    <NT::Primitives as reth_primitives_traits::NodePrimitives>::SignedTx: Clone,
{
    fn node_key(&self) -> Arc<NodeKey> {
        Arc::clone(&self.node_key)
    }

    fn local_address(&self) -> RethAddress {
        self.local_address
    }

    fn validators(&self) -> HashSet<RethAddress> {
        self.current_validators().into_iter().collect()
    }

    fn get_validators_for_block(&self, block_number: BlockNumber) -> Result<Vec<RethAddress>, QbftError> {
        let provider = self.provider_factory.provider().map_err(map_provider_to_qbft_error)?;
        let header = provider.header_by_number(block_number).map_err(map_provider_to_qbft_error)?
            .ok_or_else(|| QbftError::InternalError(format!("Header not found for block {}", block_number)))?;
        
        let bft_extra_data = self.extra_data_codec.decode(&header.extra_data())
            .map_err(|e| QbftError::InternalError(format!("Failed to decode BFT extra data for block {}: {:?}", block_number, e)))?;
        Ok(bft_extra_data.validators.into_iter().collect())
    }

    fn is_validator(&self, address: RethAddress) -> bool {
        self.validators().contains(&address)
    }

    fn quorum_size(&self) -> usize {
        let f = self.byzantine_fault_tolerance_f();
        2 * f + 1
    }

    fn byzantine_fault_tolerance_f(&self) -> usize {
        let n = self.validators().len();
        if n == 0 { // Avoid division by zero or underflow if n=0 although validators should not be empty.
            return 0;
        }
        (n - 1) / 3
    }

    fn is_proposer_for_round(&self, proposer: RethAddress, round: &ConsensusRoundIdentifier) -> bool {
        match self.get_proposer_for_round(round) {
            Ok(expected_proposer) => expected_proposer == proposer,
            Err(e) => {
                warn!(
                    target: "consensus::qbft::final_state",
                    "Error getting expected proposer for round {:?}: {:?}. Assuming not proposer.",
                    round, e
                );
                false
            }
        }
    }

    fn current_validators(&self) -> Vec<RethAddress> {
        // Try to get best_block_number and then sealed_header using UFCS
        match <ProviderFactory<NT> as BlockNumReader>::best_block_number(&self.provider_factory) { 
            Ok(latest_block_num) => {
                match <ProviderFactory<NT> as HeaderProvider>::sealed_header(&self.provider_factory, latest_block_num) { 
                    Ok(Some(latest_sealed_header)) => {
                        match self.get_validators_for_block(latest_sealed_header.number()) {
                            Ok(validators_vec) => validators_vec,
                            Err(e) => {
                                warn!(
                                    target: "consensus::qbft::final_state",
                                    "Failed to get validators for block {}: {:?}. Returning empty current validators.",
                                    latest_sealed_header.number(),
                                    e
                                );
                                Vec::new()
                            }
                        }
                    }
                    Ok(None) => {
                        warn!(target: "consensus::qbft::final_state", "Latest sealed header not found for block number {}. Returning empty current validators.", latest_block_num);
                        Vec::new()
                    }
                    Err(e) => {
                        warn!(
                            target: "consensus::qbft::final_state",
                            "Provider error fetching sealed header for block {}: {:?}. Returning empty current validators.",
                            latest_block_num, e
                        );
                        Vec::new()
                    }
                }
            }
            Err(e) => {
                warn!(
                    target: "consensus::qbft::final_state",
                    "Provider error fetching best block number: {:?}. Returning empty current validators.",
                    e
                );
                Vec::new()
            }
        }
    }

    fn get_validator_node_key(&self, address: &RethAddress) -> Option<Arc<NodeKey>> {
        if *address == self.local_address {
            Some(Arc::clone(&self.node_key))
        } else {
            warn!(
                target: "consensus::qbft::final_state",
                "Requested NodeKey for a non-local address: {}. This is not currently supported beyond the local node's key.",
                address
            );
            None
        }
    }

    fn get_block_by_hash(&self, hash: &B256) -> Option<QbftBlock> {
        match self.provider_factory.provider() {
            Ok(provider) => {
                match provider.block(AlloyBlockHashOrNumber::Hash(*hash)) { 
                    Ok(Some(reth_block_unsealed)) => { 
                        let qbft_header = convert_reth_header_to_qbft(reth_block_unsealed.header());

                        let qbft_transactions: Vec<neura_qbft_core::types::block::Transaction> =
                            reth_block_unsealed.body().transactions().iter().map(|reth_tx_signed| {
                                (*reth_tx_signed).clone().into()
                            }).collect();

                        // TODO: Fix ommers retrieval. For now, returning empty ommers.
                        let qbft_ommers: Vec<QbftBlockHeader> = Vec::new(); 
                        /*
                        let qbft_ommers: Vec<QbftBlockHeader> = 
                            <<NT as NodeTypes>::Primitives as NodePrimitives>::Block as RethPrimitivesBlockTrait>::ommers(&reth_block_unsealed)
                            .iter()
                            .map(|reth_ommer_header| convert_reth_header_to_qbft(reth_ommer_header))
                            .collect();
                        */
                        
                        Some(QbftBlock::new(qbft_header, qbft_transactions, qbft_ommers))
                    }
                    Ok(None) => None, // Block not found
                    Err(e) => {
                        warn!(
                            target: "consensus::qbft::final_state",
                            "Provider error fetching block by hash {}: {:?}",
                            hash, e
                        );
                        None
                    }
                }
            }
            Err(e) => {
                warn!(
                    target: "consensus::qbft::final_state",
                    "Error getting provider in get_block_by_hash: {:?}",
                    e
                );
                None
            }
        }
    }

    fn get_block_header(&self, block_hash: &B256) -> Option<QbftBlockHeader> {
        match self.provider_factory.provider() {
            Ok(main_provider) => {
                match main_provider.header(block_hash) {
                    Ok(Some(header)) => {
                        Some(convert_reth_header_to_qbft(&header))
                    }
                    Ok(None) => None,
                    Err(e) => {
                        warn!("Error fetching header in RethQbftFinalState: {:?}", e);
                        None
                    }
                }
            }
            Err(e) => {
                warn!("Error getting provider in RethQbftFinalState: {:?}", e);
                None
            }
        }
    }

    fn get_proposer_for_round(&self, round_id: &ConsensusRoundIdentifier) -> Result<RethAddress, QbftError> {
        if round_id.sequence_number == 0 {
            return Err(QbftError::InternalError("Cannot determine proposer for genesis block sequence (0)".to_string()));
        }
        let parent_number = round_id.sequence_number.saturating_sub(1);
        let parent_validators = self.get_validators_for_block(parent_number)?;
        if parent_validators.is_empty() {
            return Err(QbftError::InternalError(format!("No validators found for parent block {}", parent_number)));
        }
        let mut sorted_validators = parent_validators;
        sorted_validators.sort();
        let proposer_index = (round_id.sequence_number + round_id.round_number as u64) % sorted_validators.len() as u64;
        Ok(sorted_validators[proposer_index as usize])
    }
}

/// Adapter for QBFT RoundTimer.
#[derive(Debug)]
pub struct RethRoundTimer {
    round_event_tx: mpsc::Sender<ConsensusRoundIdentifier>,
    active_timers: Arc<Mutex<HashMap<ConsensusRoundIdentifier, AbortHandle>>>,
}

impl RethRoundTimer {
    pub fn new(round_event_tx: mpsc::Sender<ConsensusRoundIdentifier>) -> Self {
        Self {
            round_event_tx,
            active_timers: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl RoundTimer for RethRoundTimer {
    fn start_timer(&self, round: ConsensusRoundIdentifier, timeout_ms: u64) {
        let mut active_timers_guard = self.active_timers.lock().expect("Failed to lock active_timers for start");

        if let Some(existing_timer_handle) = active_timers_guard.remove(&round) {
            existing_timer_handle.abort();
            debug!(target: "consensus::qbft::timer", "RethRoundTimer: Aborted existing timer for round {:?} before starting new one.", round);
        }

        let tx_clone = self.round_event_tx.clone();
        let active_timers_clone = Arc::clone(&self.active_timers);

        let task = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(timeout_ms)).await;
            
            if !tx_clone.is_closed() {
                if let Err(e) = tx_clone.send(round).await {
                    warn!(target: "consensus::qbft::timer", "RethRoundTimer: Failed to send round timeout event for round {:?}: {:?}", round, e);
                }
            }
            
            let mut guard = active_timers_clone.lock().expect("Failed to lock active_timers for removal");
            guard.remove(&round); 
            debug!(target: "consensus::qbft::timer", "RethRoundTimer: Timer task completed for round {:?}, handle removed.", round);
        });

        active_timers_guard.insert(round, task.abort_handle());
        debug!(target: "consensus::qbft::timer", "RethRoundTimer: Started timer for round {:?} with timeout {}ms", round, timeout_ms);
    }

    fn cancel_timer(&self, round: ConsensusRoundIdentifier) {
        if let Some(timer_handle) = self.active_timers.lock().expect("Failed to lock active_timers for cancel").remove(&round) {
            timer_handle.abort();
            debug!(target: "consensus::qbft::timer", "RethRoundTimer: Cancelled timer for round {:?}. Handle removed from map.", round);
        } else {
            trace!(target: "consensus::qbft::timer", "RethRoundTimer: No active timer found to cancel for round {:?}.", round);
        }
    }
}

/// Implements the Reth `Consensus` trait for QBFT.
#[allow(dead_code)]
pub struct QbftConsensus<NT: NodeTypesWithDB + ProviderNodeTypes> {
    chainspec: Arc<ChainSpec>,
    provider_factory: ProviderFactory<NT>,
    controller: Arc<QbftController>,
    config: Arc<QbftConfig>,
    final_state_adapter: Arc<RethQbftFinalState<NT>>,
    extra_data_codec: Arc<AlloyBftExtraDataCodec>,
}

// Manual Debug implementation for QbftConsensus
impl<NT: NodeTypesWithDB + ProviderNodeTypes> fmt::Debug for QbftConsensus<NT> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("QbftConsensus")
            .field("chainspec", &self.chainspec)
            .field("provider_factory", &"ProviderFactory { ... }")
            .field("controller", &"Arc<QbftController> { ... }")
            .field("config", &self.config)
            .field("final_state_adapter", &self.final_state_adapter)
            .field("extra_data_codec", &self.extra_data_codec)
            .finish()
    }
}

impl<NT: NodeTypesWithDB + ProviderNodeTypes + Clone + Send + Sync + 'static> QbftConsensus<NT> {
    /// Creates a new instance of QbftConsensus.
    pub fn new(
        chainspec: Arc<ChainSpec>,
        provider_factory: ProviderFactory<NT>,
        controller: Arc<QbftController>,
        config: Arc<QbftConfig>,
        node_key: Arc<NodeKey>,
        local_address: RethAddress,
    ) -> Self {
        let extra_data_codec = Arc::new(AlloyBftExtraDataCodec::default());
        let final_state_adapter = Arc::new(RethQbftFinalState::new(
            provider_factory.clone(),
            node_key,
            local_address,
            Arc::clone(&extra_data_codec),
            Arc::clone(&config),
        ));
        
        Self {
            chainspec,
            provider_factory,
            controller,
            config,
            final_state_adapter,
            extra_data_codec,
        }
    }
}

// First, implement HeaderValidator
impl<NT> reth_consensus::HeaderValidator<<NT::Primitives as NodePrimitives>::BlockHeader> for QbftConsensus<NT>
where
    NT: NodeTypesWithDB + ProviderNodeTypes + Send + Sync + 'static,
    NT::Primitives: NodePrimitives,
    <NT::Primitives as NodePrimitives>::BlockHeader: RethPrimitivesBlockHeaderTrait + Send + Sync + 'static + Clone,
{
    fn validate_header(
        &self,
        header: &SealedHeader<<NT::Primitives as NodePrimitives>::BlockHeader>,
    ) -> Result<(), reth_consensus::ConsensusError> {
        if header.difficulty() != self.config.difficulty {
             return Err(reth_consensus::ConsensusError::Other(format!(
                "Invalid QBFT difficulty. Expected: {}, Got: {}",
                self.config.difficulty, header.difficulty()
            )));
        }
        
        let qbft_block_header = convert_reth_header_to_qbft(header.header());

        // QBFT Nonce check (must be 0, represented as 8 zero bytes)
        // QbftBlockHeader::new ensures nonce is 8 bytes. Here we check it's all zeros.
        if qbft_block_header.nonce != alloy_primitives::Bytes::from_static(&[0u8; 8]) {
            return Err(reth_consensus::ConsensusError::Other(format!(
                "Invalid QBFT nonce. Expected 8 zero bytes, Got: {:?}",
                qbft_block_header.nonce
            )));
        }

        // Basic Extra Data decode check using the stored codec
        if let Err(e) = self.extra_data_codec.decode(&qbft_block_header.extra_data) {
            return Err(reth_consensus::ConsensusError::Other(format!(
                "Failed to decode QBFT BftExtraData from header {}: {}",
                header.hash(), e
            )));
        }

        // Remove the old TODO and warning
        // // TODO: Re-enable QBFT core header validation. Method validate_header_for_proposal not found or signature mismatch.
        // // self.controller.validate_header_for_proposal(&_qbft_header, Arc::clone(&self.final_state_adapter))
        // //     .map_err(|e| reth_consensus::ConsensusError::Other(format!("QBFT Core error: {}", e)))?;
        // warn!(target: "consensus::qbft", "QBFT core header validation (validate_header_for_proposal) is currently disabled for header {}.", header.hash());

        debug!(target: "consensus::qbft", "Validated QBFT header (standalone checks): {}", header.hash());
        Ok(())
    }

    fn validate_header_against_parent(
        &self,
        header: &SealedHeader<<NT::Primitives as NodePrimitives>::BlockHeader>,
        parent: &SealedHeader<<NT::Primitives as NodePrimitives>::BlockHeader>,
    ) -> Result<(), reth_consensus::ConsensusError> {
        if header.number() != parent.number() + 1 {
            return Err(reth_consensus::ConsensusError::ParentBlockNumberMismatch {
                block_number: header.number(),
                parent_block_number: parent.number(),
            });
        }
        if header.timestamp() <= parent.timestamp() {
            return Err(reth_consensus::ConsensusError::TimestampIsInPast {
                timestamp: header.timestamp(),
                parent_timestamp: parent.timestamp(),
            });
        }
        
        validate_header_gas(header.header()).map_err(|e| reth_consensus::ConsensusError::Other(format!("Gas validation error: {:?}", e)))?;

        debug!(target: "consensus::qbft", "Validated QBFT header {} against parent {}", header.hash(), parent.hash());
        Ok(())
    }
}

// Second, implement Consensus
impl<NT> reth_consensus::Consensus<<NT::Primitives as NodePrimitives>::Block> for QbftConsensus<NT>
where
    NT: NodeTypesWithDB + ProviderNodeTypes + Send + Sync + 'static,
    NT::Primitives: NodePrimitives,
    <NT::Primitives as NodePrimitives>::Block: reth_primitives_traits::Block<
        Header = <NT::Primitives as NodePrimitives>::BlockHeader,
        Body = <NT::Primitives as NodePrimitives>::BlockBody,
    >,
    <NT::Primitives as NodePrimitives>::BlockHeader: RethPrimitivesBlockHeaderTrait + Clone + Send + Sync + 'static,
    <NT::Primitives as NodePrimitives>::BlockBody: RethPrimitivesBlockBodyTrait + Clone + Send + Sync + 'static,
    neura_qbft_core::types::block::Transaction: From<<NT::Primitives as NodePrimitives>::SignedTx>,
{
    type Error = QbftConsensusError;

    fn validate_body_against_header(
        &self,
        body: &<NT::Primitives as NodePrimitives>::BlockBody, 
        header: &SealedHeader<<NT::Primitives as NodePrimitives>::BlockHeader>,
    ) -> Result<(), Self::Error> {
        // QBFT doesn't use ommers, so verify ommers hash is empty
        if header.ommers_hash() != EMPTY_OMMER_ROOT_HASH {
            return Err(QbftConsensusError::RethConsensus(reth_consensus::ConsensusError::BodyOmmersHashDiff(
                reth_primitives_traits::GotExpectedBoxed(Box::new(GotExpected::new(header.ommers_hash(), EMPTY_OMMER_ROOT_HASH)))
            )));
        }

        // Verify transactions root matches header
        let tx_root = body.calculate_tx_root();
        if tx_root != header.transactions_root() {
            return Err(QbftConsensusError::RethConsensus(reth_consensus::ConsensusError::BodyTransactionRootDiff(
                reth_primitives_traits::GotExpectedBoxed(Box::new(GotExpected::new(tx_root, header.transactions_root())))
            )));
        }

        // QBFT-specific: Allow empty blocks if not genesis
        if body.transactions().is_empty() && header.number() != 0 {
            debug!(target: "consensus::qbft", "Empty block allowed for non-genesis block {}", header.number());
        }

        debug!(target: "consensus::qbft", "Validated QBFT block body against header: {}", header.hash());
        Ok(())
    }

    fn validate_block_pre_execution(
        &self,
        block: &SealedBlock<<NT::Primitives as NodePrimitives>::Block>,
    ) -> Result<(), Self::Error> {
        // Get the sealed header using sealed_header()
        let sealed_header = block.sealed_header();
        
        // First validate the header
        self.validate_header(sealed_header)?;

        // Convert to QBFT header for core validation
        let qbft_header = convert_reth_header_to_qbft(sealed_header.header());
        
        // Create validation context for QBFT core validation
        let current_sequence = sealed_header.number();
        let current_round = 0; // For now, we assume round 0 for block validation
        let validators = self.final_state_adapter.get_validators_for_block(current_sequence)
            .map_err(|e| QbftConsensusError::QbftCore(e))?;
        
        let parent_header = self.final_state_adapter.get_block_header(&sealed_header.parent_hash())
            .ok_or_else(|| QbftConsensusError::Validation("Parent header not found".to_string()))?;
        
        let expected_proposer = self.final_state_adapter.get_proposer_for_round(&ConsensusRoundIdentifier {
            sequence_number: current_sequence,
            round_number: current_round,
        }).map_err(|e| QbftConsensusError::QbftCore(e))?;

        let context = ValidationContext::new(
            current_sequence,
            current_round,
            validators.into_iter().collect(),
            Arc::new(parent_header),
            self.final_state_adapter.clone() as Arc<dyn QbftFinalState>,
            Arc::new(AlloyBftExtraDataCodec::default()), // Use a default codec for now
            Arc::clone(&self.config),
            None, // No accepted proposal digest for block validation
            expected_proposer,
        );

        // Convert transactions to the expected type for QbftBlock
        let qbft_transactions: Vec<neura_qbft_core::types::block::Transaction> = block.body().transactions().iter().cloned().map(|tx| tx.into()).collect();

        // Create a proposal for validation
        let proposal_payload = ProposalPayload::new(
            ConsensusRoundIdentifier { sequence_number: current_sequence, round_number: current_round },
            QbftBlock::new(qbft_header.clone(), qbft_transactions, Vec::new()),
        );
        let signed_data = SignedData::sign(proposal_payload, &self.final_state_adapter.node_key()).map_err(QbftConsensusError::QbftCore)?;
        let bft_message = BftMessage::new(signed_data);
        let proposal = Proposal::new(
            bft_message,
            qbft_header,
            Vec::new(), // No round change proofs for block validation
            None, // No prepared certificate for block validation
        );

        // Get the proposal validator from the controller and context
        let proposal_validator = neura_qbft_core::validation::ProposalValidatorImpl::new(
            self.controller.message_validator_factory(),
            self.controller.round_change_message_validator_factory(),
            self.config.clone(),
        );

        proposal_validator.validate_proposal(&proposal, &context)
            .map_err(|e| QbftConsensusError::QbftCore(e))?;

        // Validate body against header
        self.validate_body_against_header(block.body(), sealed_header)?;
        
        debug!(target: "consensus::qbft", "Validated QBFT block (pre-execution): {}", block.hash());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::*; 

    use neura_qbft_core::{
        mocks::{ 
            MockQbftFinalState, MockQbftBlockCreatorFactory, MockQbftBlockImporter,
            MockValidatorMulticaster, MockBlockTimer, MockMessageValidatorFactory,
            MockRoundChangeMessageValidatorFactory,
        },
        statemachine::QbftController, 
        types::{QbftConfig, NodeKey, AlloyBftExtraDataCodec, ConsensusRoundIdentifier}, 
        payload::MessageFactory as TestMessageFactory, 
    };
    use reth_provider::test_utils::MockNodeTypesWithDB; // MockNodeTypesWithDB is used directly
    use reth_chainspec::MAINNET; // MAINNET is used directly
    use reth_stages::test_utils::{TestStageDB};
    use k256::SecretKey; 
    use rand_08::thread_rng; 
    use alloy_primitives::{keccak256, B256, U256, Bytes}; // REMOVED: FixedBytes
    use std::collections::HashSet; 
    use alloy_consensus::{Header as AlloyConsensusHeader, Sealable, EMPTY_OMMER_ROOT_HASH, constants::{EMPTY_RECEIPTS, EMPTY_TRANSACTIONS}}; 
    use reth_primitives::SealedHeader; // Used in test_get_block_by_hash_empty_body
    use reth_primitives::{BlockBody as RethBlockBody, SealedBlock as RethSealedBlock}; // ADDED specific imports
    use reth_consensus::Consensus; // ADDED: Consensus trait for validate_block_pre_execution
    use alloy_eips::eip4895::Withdrawals; // ADDED: For block body

    // Test for QbftConsensus::new()
    #[test]
    fn test_qbft_consensus_new() {
        let chainspec = MAINNET.clone();
        let test_db_for_consensus = TestStageDB::default();
        let provider_factory = test_db_for_consensus.factory.clone();

        let mut config = QbftConfig::default();
        config.fault_tolerance_f = 0;
        let config_arc = Arc::new(config);

        let mut rng = thread_rng();
        let secret_key = SecretKey::random(&mut rng);
        let node_key = Arc::new(NodeKey::from(secret_key));
        let local_address = {
            let verifying_key = node_key.verifying_key();
            let uncompressed_pk_bytes = verifying_key.to_encoded_point(false).as_bytes().to_vec();
            let hash = keccak256(&uncompressed_pk_bytes[1..]);
            RethAddress::from_slice(&hash[12..])
        };

        let (round_event_tx, _round_event_rx) = mpsc::channel(10);
        let round_timer_for_controller = Arc::new(RethRoundTimer::new(round_event_tx.clone()));

        let local_address_for_mock_final_state = { // Derive address for the mock
            let verifying_key = node_key.verifying_key();
            let uncompressed_pk_bytes = verifying_key.to_encoded_point(false).as_bytes().to_vec();
            let hash = keccak256(&uncompressed_pk_bytes[1..]);
            RethAddress::from_slice(&hash[12..])
        };
        let mut mock_validators = HashSet::new();
        mock_validators.insert(local_address_for_mock_final_state);
        mock_validators.insert(RethAddress::random()); // Add another random validator

        let final_state_for_controller = Arc::new(MockQbftFinalState::new(
            node_key.clone(),
            mock_validators, // Use the updated validator set
        ));
        
        let block_creator_factory = Arc::new(MockQbftBlockCreatorFactory::new());
        let block_importer = Arc::new(MockQbftBlockImporter::new());
        let controller_extra_data_codec = Arc::new(AlloyBftExtraDataCodec::default());
        let message_factory = Arc::new(TestMessageFactory::new(node_key.clone()).expect("Test MessageFactory creation failed"));
        let validator_multicaster = Arc::new(MockValidatorMulticaster::new());
        let block_timer = Arc::new(MockBlockTimer::new(config_arc.block_period_seconds));
        let message_validator_factory = Arc::new(MockMessageValidatorFactory::new());
        let rc_message_validator_factory = Arc::new(MockRoundChangeMessageValidatorFactory::new());

        let _controller = Arc::new(QbftController::new(
            final_state_for_controller,
            block_creator_factory,
            block_importer,
            message_factory,
            validator_multicaster,
            block_timer,
            round_timer_for_controller,
            controller_extra_data_codec,
            message_validator_factory,
            rc_message_validator_factory,
            Vec::new(),
            config_arc.clone(),
        ));

        let consensus = QbftConsensus::<MockNodeTypesWithDB>::new(
            chainspec.clone(),
            provider_factory.clone(),
            _controller.clone(),
            config_arc.clone(),
            node_key.clone(),
            local_address,
        );

        assert_eq!(consensus.chainspec.chain, MAINNET.chain);
        assert!(Arc::ptr_eq(&consensus.config, &config_arc));
        assert!(Arc::ptr_eq(&consensus.controller, &_controller));
    }

    // Test for RethRoundTimer functionality through QbftController
    #[tokio::test]
    async fn test_reth_round_timer_integration() {
        let config = Arc::new(QbftConfig::default());
        let (round_event_tx, mut round_event_rx) = mpsc::channel(10);
        let round_timer_arc = Arc::new(RethRoundTimer::new(round_event_tx));

        let mut rng = thread_rng();
        let secret_key_timer_test = SecretKey::random(&mut rng);
        let node_key_for_controller_deps = Arc::new(NodeKey::from(secret_key_timer_test.clone()));
        
        let local_address_for_timer_mock_final_state = { // Derive address for the mock
            let verifying_key = node_key_for_controller_deps.verifying_key();
            let uncompressed_pk_bytes = verifying_key.to_encoded_point(false).as_bytes().to_vec();
            let hash = keccak256(&uncompressed_pk_bytes[1..]);
            RethAddress::from_slice(&hash[12..])
        };
        let mut timer_mock_validators = HashSet::new();
        timer_mock_validators.insert(local_address_for_timer_mock_final_state);
        // Optionally add more random validators if needed for the test's logic
        // timer_mock_validators.insert(RethAddress::random());


        let final_state_for_controller_timer_test = Arc::new(MockQbftFinalState::new(
            node_key_for_controller_deps.clone(),
            timer_mock_validators, // Use the updated validator set
        ));

        let block_creator_factory_timer_test = Arc::new(MockQbftBlockCreatorFactory::new());
        let block_importer_timer_test = Arc::new(MockQbftBlockImporter::new());
        let controller_extra_data_codec_timer_test = Arc::new(AlloyBftExtraDataCodec::default());
        let message_factory_timer_test = Arc::new(TestMessageFactory::new(node_key_for_controller_deps).expect("Test MessageFactory creation failed for timer test"));
        let validator_multicaster_timer_test = Arc::new(MockValidatorMulticaster::new());
        let block_timer_timer_test = Arc::new(MockBlockTimer::new(config.block_period_seconds));
        let message_validator_factory_timer_test = Arc::new(MockMessageValidatorFactory::new());
        let rc_message_validator_factory_timer_test = Arc::new(MockRoundChangeMessageValidatorFactory::new());

        let _controller = Arc::new(QbftController::new(
            final_state_for_controller_timer_test,
            block_creator_factory_timer_test,
            block_importer_timer_test,
            message_factory_timer_test,
            validator_multicaster_timer_test,
            block_timer_timer_test,
            round_timer_arc.clone(),
            controller_extra_data_codec_timer_test,
            message_validator_factory_timer_test,
            rc_message_validator_factory_timer_test,
            Vec::new(),
            config.clone(),
        ));

        let timer_to_test = round_timer_arc;

        let round_id_fire = ConsensusRoundIdentifier { sequence_number: 1, round_number: 0 };
        timer_to_test.start_timer(round_id_fire, 20); 

        match tokio::time::timeout(Duration::from_millis(50), round_event_rx.recv()).await {
            Ok(Some(received_round_id)) => assert_eq!(received_round_id, round_id_fire),
            Ok(None) => panic!("Timer event channel closed unexpectedly"),
            Err(_) => panic!("Timer event not received within timeout"),
        }

        let round_id_cancel = ConsensusRoundIdentifier { sequence_number: 1, round_number: 1 };
        timer_to_test.start_timer(round_id_cancel, 100);
        tokio::time::sleep(Duration::from_millis(10)).await; 
        timer_to_test.cancel_timer(round_id_cancel);
        tokio::time::sleep(Duration::from_millis(120)).await; 
        
        match round_event_rx.try_recv() {
            Ok(received_round_id) => panic!("Received event for cancelled timer: {:?}", received_round_id),
            Err(mpsc::error::TryRecvError::Empty) => { /* Expected */ }
            Err(e) => panic!("Error checking for cancelled timer event: {:?}", e),
        }

        let round_id_restart = ConsensusRoundIdentifier { sequence_number: 2, round_number: 0 };
        timer_to_test.start_timer(round_id_restart, 200); 
        tokio::time::sleep(Duration::from_millis(10)).await;
        timer_to_test.start_timer(round_id_restart, 30);  

        match tokio::time::timeout(Duration::from_millis(60), round_event_rx.recv()).await {
            Ok(Some(received_round_id)) => assert_eq!(received_round_id, round_id_restart),
            Ok(None) => panic!("Restarted timer event channel closed"),
            Err(_) => panic!("Restarted timer event not received (expected shorter one)"),
        }
    }

    mod reth_qbft_final_state_tests {
        use super::*; // Pulls from the parent `tests` module.
        
        #[test]
        fn test_new_and_basic_getters() {
            // Use the new setup function correctly
            let (final_state_obj, _initial_validators, _config, _codec, _test_db) =
                setup_test_final_state_components(1); // e.g., 1 initial validator

            // To get node_key and local_address for assertion, we need to re-derive them or store them
            // For simplicity here, let's assume we are testing the internal consistency of RethQbftFinalState
            // by calling its own getters. We can't directly compare with the ones from setup_test_final_state_components
            // without returning them specifically or re-generating, which might be flaky if rng is involved.
            
            // Retrieve from final_state itself to check consistency.
            let _node_key_from_state = final_state_obj.node_key();
            let _local_address_from_state = final_state_obj.local_address();
            // Assertions can be tricky without having the original node_key/local_address easily available
            // from the setup function's return. For now, just ensure they don't panic.
            // A more robust test would involve returning these from setup_test_final_state_components or having
            // a way to deterministically generate them if needed for direct comparison.
        }

        #[test]
        fn test_get_validator_node_key() {
            let (final_state_obj, _initial_validators, _config, _codec, _test_db) =
                setup_test_final_state_components(1);

            let local_address = final_state_obj.local_address();
            let local_node_key_arc = final_state_obj.node_key();

            let fetched_node_key_option = final_state_obj.get_validator_node_key(&local_address);
            
            // Commenting out the Arc strong count check as it can be fragile
            /*
            assert_eq!(
                fetched_node_key_option.as_ref().map(|arc_nk| Arc::strong_count(arc_nk)), 
                Some(Arc::strong_count(&local_node_key_arc) + 1), 
                "Should return the local node key for the local address"
            );
            */
            assert_eq!(fetched_node_key_option.unwrap().verifying_key(), local_node_key_arc.verifying_key(), "Verifying keys should match");

            let (_random_key, random_address) = generate_unique_node_key_and_address();
            let random_node_key_result = final_state_obj.get_validator_node_key(&random_address);
            assert_eq!(random_node_key_result, None, "Should return None for a non-local address");
        }

        #[test]
        fn test_get_validators_for_block() {
            let (final_state, initial_validators, qbft_config, codec, test_db) =
                setup_test_final_state_components(3); 

            let genesis_sealed_header: SealedHeader = test_db.factory.sealed_header(0).unwrap().expect("Genesis header should exist");

            let header1_validators =
                vec![initial_validators[0], initial_validators[1], final_state.local_address()];
            let header1_number = 1;
            let actual_h1_intrinsic_difficulty = qbft_config.difficulty + U256::from(100);
            let header1 = create_sealed_header_with_validators(
                header1_number,
                genesis_sealed_header.hash(),
                &header1_validators,
                &codec,
                &qbft_config,
                actual_h1_intrinsic_difficulty,
            );

            test_db.insert_headers_with_td(vec![&header1]).unwrap();

            let result = final_state.get_validators_for_block(header1.number);
            assert!(result.is_ok(), "Expected Ok, got {:?}", result);
            let fetched_validator_addrs = result.unwrap();

            assert_eq!(
                fetched_validator_addrs.len(),
                header1_validators.len(),
                "Validator count mismatch"
            );
            for addr_expected in &header1_validators {
                assert!(
                    fetched_validator_addrs.contains(addr_expected),
                    "Missing validator {:?} for block {}",
                    addr_expected,
                    header1.number
                );
            }

            let non_existent_block_number: BlockNumber = 99;
            let result_non_existent = final_state.get_validators_for_block(non_existent_block_number);
            assert!(result_non_existent.is_err());
            match result_non_existent.unwrap_err() {
                QbftError::InternalError(msg) if msg.contains(&format!("Header not found for block {}", non_existent_block_number)) => {},
                e => panic!("Expected QbftError::InternalError with header not found, got {:?}", e),
            }
        }

        #[test]
        fn test_current_validators() {
            let (final_state, expected_genesis_validators_vec, _qbft_config, _codec, _test_db) =
                setup_test_final_state_components(3); 

            // Due to difficulties in advancing TestStageDB's best_block_number reliably past genesis in tests,
            // this test currently verifies that current_validators() returns genesis validators when best_block_number is 0.
            // TODO: Revisit this test to cover non-genesis current_validators if TestStageDB behavior is better understood or an alternative is used.

            let best_block_num = final_state.provider_factory.provider().unwrap().best_block_number().unwrap();
            assert_eq!(best_block_num, 0, "Expected best_block_number to be 0 (genesis) in this test setup");

            let expected_genesis_validators_set: HashSet<RethAddress> = 
                expected_genesis_validators_vec.into_iter().collect();

            let current_validator_addrs_vec = final_state.current_validators();
            let current_validator_addrs_set: HashSet<RethAddress> = 
                current_validator_addrs_vec.into_iter().collect();
            
            assert_eq!(
                current_validator_addrs_set.len(),
                expected_genesis_validators_set.len(),
                "Validator set size mismatch with QBFT genesis validators"
            );
            assert_eq!(
                current_validator_addrs_set,
                expected_genesis_validators_set,
                "Current validators do not match expected QBFT genesis validators"
            );
        }

        #[test]
        fn test_validators_method() {
            let (final_state, expected_genesis_validators_vec, _qbft_config, _codec, _test_db) =
                setup_test_final_state_components(4); // Use a different number for variety

            // As with test_current_validators, this relies on best_block_number being 0 (genesis)
            let best_block_num = final_state.provider_factory.provider().unwrap().best_block_number().unwrap();
            assert_eq!(best_block_num, 0, "Expected best_block_number to be 0 (genesis) in this test setup");

            let expected_genesis_validators_set: HashSet<RethAddress> = 
                expected_genesis_validators_vec.into_iter().collect();

            let returned_validators_set = final_state.validators();
            
            assert_eq!(
                returned_validators_set.len(),
                expected_genesis_validators_set.len(),
                "Validator set size mismatch"
            );
            assert_eq!(
                returned_validators_set,
                expected_genesis_validators_set,
                "validators() did not return the expected QBFT genesis validators"
            );
        }

        #[test]
        fn test_is_validator() {
            let (final_state, initial_validators, _config, _codec, _test_db) =
                setup_test_final_state_components(3);

            // Check that all initial validators (from genesis) are recognized
            for validator_addr in &initial_validators {
                assert!(
                    final_state.is_validator(*validator_addr),
                    "Expected {:?} to be a validator",
                    validator_addr
                );
            }

            // Check a non-validator address
            let (_key, non_validator_address) = generate_unique_node_key_and_address();
            assert!(
                !initial_validators.contains(&non_validator_address),
                "Test setup error: generated non_validator_address is actually in the initial set"
            );
            assert!(
                !final_state.is_validator(non_validator_address),
                "Expected {:?} not to be a validator",
                non_validator_address
            );
            
            // Test with an empty validator set (edge case, though current_validators guards against this for genesis)
            // To truly test this, we'd need a way to force current_validators to return empty or mock it.
            // For now, relying on the fact that setup_test_final_state_components always creates validators.
        }

        #[test]
        fn test_byzantine_fault_tolerance_and_quorum_size() {
            // Test case 1: Standard N=4, F=1, Q=3
            let (final_state_n4, _, _, _, _) = setup_test_final_state_components(4);
            assert_eq!(final_state_n4.validators().len(), 4, "N=4: Validator count mismatch");
            assert_eq!(final_state_n4.byzantine_fault_tolerance_f(), 1, "N=4: F calculation incorrect");
            assert_eq!(final_state_n4.quorum_size(), 3, "N=4: Quorum size calculation incorrect");

            // Test case 2: N=7, F=2, Q=5
            let (final_state_n7, _, _, _, _) = setup_test_final_state_components(7);
            assert_eq!(final_state_n7.validators().len(), 7, "N=7: Validator count mismatch");
            assert_eq!(final_state_n7.byzantine_fault_tolerance_f(), 2, "N=7: F calculation incorrect");
            assert_eq!(final_state_n7.quorum_size(), 5, "N=7: Quorum size calculation incorrect");
            
            // Test case 3: N=1, F=0, Q=1 (Minimum validators for a non-trivial network)
            let (final_state_n1, _, _, _, _) = setup_test_final_state_components(1);
            assert_eq!(final_state_n1.validators().len(), 1, "N=1: Validator count mismatch");
            assert_eq!(final_state_n1.byzantine_fault_tolerance_f(), 0, "N=1: F calculation incorrect");
            assert_eq!(final_state_n1.quorum_size(), 1, "N=1: Quorum size calculation incorrect");

            // Test case 4: N=0 (Edge case, though our setup ensures at least 1 for local_address)
            // To truly test N=0, we'd need to mock `validators()` to return an empty set.
            // The current implementation of `byzantine_fault_tolerance_f` returns 0 if n=0.
            // And `setup_test_final_state_components` always adds the local node, so `num_initial_validators = 0`
            // would result in 1 validator. We'll rely on direct logic review for N=0 or mock if crucial later.
            // For instance, if we called with setup_test_final_state_components(0), it would effectively be N=1.
        }

        #[test]
        fn test_get_proposer_for_round() {
            let num_genesis_validators = 4;
            let (final_state, mut genesis_validators, qbft_config, codec, test_db) =
                setup_test_final_state_components(num_genesis_validators);
            
            genesis_validators.sort(); // Ensure consistent ordering for proposer selection

            let genesis_sealed_header = test_db.factory.sealed_header(0).unwrap().expect("Genesis header missing");

            // Test proposer for sequence 1 (uses genesis validators)
            // Round 0: (SeqNumber + RoundNumber) % NumValidators = (1 + 0) % 4 = 1
            let round_id_s1_r0 = ConsensusRoundIdentifier { sequence_number: 1, round_number: 0 };
            let proposer_s1_r0 = final_state.get_proposer_for_round(&round_id_s1_r0).unwrap();
            assert_eq!(proposer_s1_r0, genesis_validators[1 % num_genesis_validators]);
            assert!(final_state.is_proposer_for_round(proposer_s1_r0, &round_id_s1_r0));

            // Round 1: (1 + 1) % 4 = 2
            let round_id_s1_r1 = ConsensusRoundIdentifier { sequence_number: 1, round_number: 1 };
            let proposer_s1_r1 = final_state.get_proposer_for_round(&round_id_s1_r1).unwrap();
            assert_eq!(proposer_s1_r1, genesis_validators[2 % num_genesis_validators]);
            assert!(final_state.is_proposer_for_round(proposer_s1_r1, &round_id_s1_r1));
            
            // Round 4 (wraps around): (1 + 4) % 4 = 1
            let round_id_s1_r4 = ConsensusRoundIdentifier { sequence_number: 1, round_number: 4 };
            let proposer_s1_r4 = final_state.get_proposer_for_round(&round_id_s1_r4).unwrap();
            assert_eq!(proposer_s1_r4, genesis_validators[1 % num_genesis_validators]);
            assert!(final_state.is_proposer_for_round(proposer_s1_r4, &round_id_s1_r4));

            // Test with a non-validator for a round
            let non_validator_for_s1_r0 = genesis_validators[0 % num_genesis_validators]; // Proposer is index 1
            if num_genesis_validators > 1 { // Avoid panic if only one validator
                 assert_ne!(non_validator_for_s1_r0, proposer_s1_r0);
                 assert!(!final_state.is_proposer_for_round(non_validator_for_s1_r0, &round_id_s1_r0));
            }


            // Test for sequence 0 (should error)
            let round_id_s0_r0 = ConsensusRoundIdentifier { sequence_number: 0, round_number: 0 };
            assert!(final_state.get_proposer_for_round(&round_id_s0_r0).is_err());

            // Test for a block where parent validators might be different (Block 2, uses validators from Block 1)
            let mut block1_validators = vec![RethAddress::random(), RethAddress::random(), final_state.local_address()];
            block1_validators.sort();
            let num_block1_validators = block1_validators.len();

            let header1 = create_sealed_header_with_validators(
                1, // block number
                genesis_sealed_header.hash(), // parent hash
                &block1_validators,
                &codec,
                &qbft_config,
                qbft_config.difficulty + U256::from(100), // difficulty for block 1
            );
            test_db.insert_headers_with_td(std::iter::once(&header1)).unwrap();
            
            // Proposer for sequence 2, round 0: (SeqNumber + RoundNumber) % NumValidators = (2 + 0) % num_block1_validators
            let round_id_s2_r0 = ConsensusRoundIdentifier { sequence_number: 2, round_number: 0 };
            let proposer_s2_r0 = final_state.get_proposer_for_round(&round_id_s2_r0).unwrap();
            assert_eq!(proposer_s2_r0, block1_validators[(2 + 0) % num_block1_validators]);
            assert!(final_state.is_proposer_for_round(proposer_s2_r0, &round_id_s2_r0));
        }

        #[test]
        fn test_get_block_header() {
            let (final_state, initial_validators, qbft_config, codec, test_db) =
                setup_test_final_state_components(1);

            let genesis_sealed_header = test_db.factory.sealed_header(0).unwrap().expect("Genesis header missing");

            // Test with genesis header
            let qbft_genesis_header_opt = final_state.get_block_header(&genesis_sealed_header.hash());
            assert!(qbft_genesis_header_opt.is_some(), "QBFT Genesis header not found by hash");
            let qbft_genesis_header = qbft_genesis_header_opt.unwrap();
            assert_eq!(qbft_genesis_header.number, 0, "Genesis header number mismatch");
            assert_eq!(qbft_genesis_header.parent_hash, genesis_sealed_header.parent_hash(), "Genesis parent_hash mismatch");

            // Create and insert another header
            let header1_validators = vec![initial_validators[0], RethAddress::random()];
             let header1 = create_sealed_header_with_validators(
                1, // block number
                genesis_sealed_header.hash(), // parent hash
                &header1_validators,
                &codec,
                &qbft_config,
                qbft_config.difficulty,
            );
            test_db.insert_headers_with_td(std::iter::once(&header1)).unwrap();
            
            let qbft_header1_opt = final_state.get_block_header(&header1.hash());
            assert!(qbft_header1_opt.is_some(), "QBFT Header1 not found by hash");
            let qbft_header1 = qbft_header1_opt.unwrap();
            assert_eq!(qbft_header1.number, header1.number, "Header1 number mismatch");
            assert_eq!(qbft_header1.parent_hash, header1.parent_hash(), "Header1 parent_hash mismatch");
            assert_eq!(qbft_header1.difficulty, header1.difficulty(), "Header1 difficulty mismatch");

            // Test with a non-existent hash
            let non_existent_hash = B256::random();
            let non_existent_header_opt = final_state.get_block_header(&non_existent_hash);
            assert!(non_existent_header_opt.is_none(), "Expected None for non-existent header hash");
        }

        #[test]
        fn test_get_block_by_hash_empty_body() {
            let (final_state, _initial_validators, qbft_config, _codec, test_db) =
                setup_test_final_state_components(1);

            let genesis_sealed_header: SealedHeader = test_db.factory.sealed_header(0).unwrap().expect("Genesis header missing");
            
            let qbft_block_opt = final_state.get_block_by_hash(&genesis_sealed_header.hash());
            assert!(qbft_block_opt.is_some(), "QBFT Genesis block not found by hash");
            
            let qbft_block = qbft_block_opt.unwrap();

            assert_eq!(qbft_block.header.number, 0, "Block number mismatch");
            assert_eq!(qbft_block.header.parent_hash, genesis_sealed_header.parent_hash(), "Parent hash mismatch");
            assert_eq!(qbft_block.header.difficulty, qbft_config.difficulty, "Difficulty mismatch");
            assert_eq!(qbft_block.header.transactions_root, EMPTY_TRANSACTIONS, "Genesis transactions_root mismatch");

            assert!(qbft_block.body_transactions.is_empty(), "Expected empty transactions for default genesis");
            assert!(qbft_block.body_ommers.is_empty(), "Expected empty ommers as per current implementation");

            let non_existent_hash = B256::random();
            let non_existent_block_opt = final_state.get_block_by_hash(&non_existent_hash);
            assert!(non_existent_block_opt.is_none(), "Expected None for non-existent block hash");
        }
    }

    mod qbft_consensus_tests {
        use super::*; 

        #[test]
        fn test_validate_header_valid() {
            let (consensus, _node_key, local_address, config, _test_db, _final_state_adapter) = 
                setup_qbft_consensus_for_test(); 
            
            let validators = vec![local_address]; 
            let extra_data_codec = AlloyBftExtraDataCodec::default();

            let valid_header = create_sealed_header_with_validators( 
                1, 
                B256::random(), 
                &validators,
                &extra_data_codec,
                &config,
                config.difficulty, 
            );
            
            assert!(consensus.validate_header(&valid_header).is_ok());
        }

        #[test]
        fn test_validate_header_invalid_difficulty() {
            let (consensus, _node_key, local_address, config, _test_db, _final_state_adapter) = 
                setup_qbft_consensus_for_test(); 
            
            let validators = vec![local_address];
            let extra_data_codec = AlloyBftExtraDataCodec::default();
            let invalid_difficulty = config.difficulty + U256::from(1);

            let header_wrong_difficulty = create_sealed_header_with_validators( 
                1,
                B256::random(),
                &validators,
                &extra_data_codec,
                &config,
                invalid_difficulty, 
            );
            
            let result = consensus.validate_header(&header_wrong_difficulty);
            assert!(result.is_err());
            if let Err(ConsensusError::Other(msg)) = result {
                assert!(msg.contains("Invalid QBFT difficulty"));
            } else {
                panic!("Expected ConsensusError::Other for difficulty mismatch, got {:?}", result);
            }
        }

        #[test]
        fn test_validate_header_invalid_nonce() {
            let (consensus, _node_key, local_address, config, _test_db, _final_state_adapter) = 
                setup_qbft_consensus_for_test(); 
            
            let validators = vec![local_address];
            let extra_data_codec = AlloyBftExtraDataCodec::default();

            let header_with_bad_nonce_alloy = AlloyConsensusHeader {
                number: 1,
                parent_hash: B256::random(),
                ommers_hash: EMPTY_OMMER_ROOT_HASH,
                beneficiary: RethAddress::random(),
                state_root: B256::random(),
                transactions_root: EMPTY_TRANSACTIONS,
                receipts_root: EMPTY_RECEIPTS,
                logs_bloom: Default::default(),
                difficulty: config.difficulty,
                gas_limit: 30_000_000,
                gas_used: 0,
                timestamp: 1,
                extra_data: { // Valid extra data
                    let bft_extra = neura_qbft_core::types::BftExtraData {
                        vanity_data: Bytes::from_static(&[0u8; 32]),
                        validators: validators.clone(),
                        committed_seals: Vec::new(),
                        round_number: 0,
                    };
                    extra_data_codec.encode(&bft_extra).unwrap()
                },
                mix_hash: Default::default(),
                nonce: alloy_primitives::FixedBytes([0,0,0,0,0,0,0,1]), // Non-zero nonce!
                base_fee_per_gas: Some(1_000_000_000),
                withdrawals_root: None,
                blob_gas_used: None,
                excess_blob_gas: None,
                parent_beacon_block_root: None,
                requests_hash: None,
            };
            
            let sealed_bad_nonce_header = header_with_bad_nonce_alloy.seal_slow();
            let (header_part, hash_part) = sealed_bad_nonce_header.into_parts();
            let reth_sealed_bad_nonce_header = SealedHeader::new(header_part, hash_part);

            let result = consensus.validate_header(&reth_sealed_bad_nonce_header);
            assert!(result.is_err());
            if let Err(ConsensusError::Other(msg)) = result {
                assert!(msg.contains("Invalid QBFT nonce"));
            } else {
                panic!("Expected ConsensusError::Other for nonce mismatch, got {:?}", result);
            }
        }

        #[test]
        fn test_validate_header_invalid_extra_data() {
            let (consensus, _node_key, _local_address, config, _test_db, _final_state_adapter) = 
                setup_qbft_consensus_for_test(); 

            let invalid_extra_data = Bytes::from_static(&[1, 2, 3, 4]); 

            let header_with_bad_extra_alloy = AlloyConsensusHeader {
                number: 1,
                parent_hash: B256::random(),
                ommers_hash: EMPTY_OMMER_ROOT_HASH,
                beneficiary: RethAddress::random(),
                state_root: B256::random(),
                transactions_root: EMPTY_TRANSACTIONS,
                receipts_root: EMPTY_RECEIPTS,
                logs_bloom: Default::default(),
                difficulty: config.difficulty,
                gas_limit: 30_000_000,
                gas_used: 0,
                timestamp: 1,
                extra_data: invalid_extra_data, // Invalid
                mix_hash: Default::default(),
                nonce: alloy_primitives::FixedBytes::ZERO, // Correct nonce
                base_fee_per_gas: Some(1_000_000_000),
                withdrawals_root: None,
                blob_gas_used: None,
                excess_blob_gas: None,
                parent_beacon_block_root: None,
                requests_hash: None,
            };

            let sealed_bad_extra_header = header_with_bad_extra_alloy.seal_slow();
            let (header_part, hash_part) = sealed_bad_extra_header.into_parts();
            let reth_sealed_bad_extra_header = SealedHeader::new(header_part, hash_part);
            
            let result = consensus.validate_header(&reth_sealed_bad_extra_header);
            assert!(result.is_err());
             if let Err(ConsensusError::Other(msg)) = result {
                assert!(msg.contains("Failed to decode QBFT BftExtraData"));
            } else {
                panic!("Expected ConsensusError::Other for extra data decode error, got {:?}", result);
            }
        }

        #[test]
        fn test_validate_header_against_parent_valid() {
            let (consensus, _node_key, local_address, config, _test_db, _final_state_adapter) = 
                setup_qbft_consensus_for_test();
            
            let validators = vec![local_address];
            let extra_data_codec = AlloyBftExtraDataCodec::default();

            let parent_header = create_sealed_header_with_validators(
                1, // block_number
                B256::random(), // parent_hash (can be random for this test)
                &validators,
                &extra_data_codec,
                &config,
                config.difficulty,
            );

            let current_header = create_sealed_header_with_validators(
                2, // block_number = parent + 1
                parent_header.hash(), // parent_hash
                &validators, 
                &extra_data_codec,
                &config,
                config.difficulty, 
                // Gas limit will be default from create_sealed_header_with_validators
                // Timestamp will be block_number * 1, so 2 > 1
            );
            
            let result = consensus.validate_header_against_parent(&current_header, &parent_header);
            assert!(result.is_ok(), "Expected valid header against parent, got {:?}", result);
        }

        #[test]
        fn test_validate_header_against_parent_block_number_mismatch() {
            let (consensus, _node_key, local_address, config, _test_db, _final_state_adapter) = 
                setup_qbft_consensus_for_test();
            
            let validators = vec![local_address];
            let extra_data_codec = AlloyBftExtraDataCodec::default();

            let parent_header = create_sealed_header_with_validators(
                1, 
                B256::random(), 
                &validators,
                &extra_data_codec,
                &config,
                config.difficulty,
            );

            let current_header_wrong_num = create_sealed_header_with_validators(
                3, // block_number != parent + 1
                parent_header.hash(), 
                &validators, 
                &extra_data_codec,
                &config,
                config.difficulty, 
            );
            
            let result = consensus.validate_header_against_parent(&current_header_wrong_num, &parent_header);
            assert!(result.is_err());
            match result.unwrap_err() {
                ConsensusError::ParentBlockNumberMismatch { .. } => {}, // Expected
                e => panic!("Expected ParentBlockNumberMismatch, got {:?}", e),
            }
        }

        #[test]
        fn test_validate_header_against_parent_timestamp_in_past() {
            let (consensus, _node_key, local_address, config, _test_db, _final_state_adapter) = 
                setup_qbft_consensus_for_test();
            
            let validators = vec![local_address];
            let extra_data_codec = AlloyBftExtraDataCodec::default();

            // Parent header with timestamp based on its number (e.g., 2)
            let parent_header_ts_2 = create_sealed_header_with_validators(
                2, 
                B256::random(), 
                &validators,
                &extra_data_codec,
                &config,
                config.difficulty,
            );

            // Current header (number 3) but with an earlier or same timestamp as parent_header_ts_2
            // We need to manually create the alloy header to set a custom timestamp
            let bft_extra_data = neura_qbft_core::types::BftExtraData {
                vanity_data: Bytes::from_static(&[0u8; 32]),
                validators: validators.clone(),
                committed_seals: Vec::new(),
                round_number: 0u32,
            };
            let extra_data_bytes = extra_data_codec.encode(&bft_extra_data).unwrap();

            let current_alloy_header_bad_ts = AlloyConsensusHeader {
                number: 3, // parent_header_ts_2.number + 1
                parent_hash: parent_header_ts_2.hash(),
                ommers_hash: EMPTY_OMMER_ROOT_HASH,
                beneficiary: RethAddress::random(),
                state_root: B256::random(),
                transactions_root: EMPTY_TRANSACTIONS,
                receipts_root: EMPTY_RECEIPTS,
                logs_bloom: Default::default(),
                difficulty: config.difficulty,
                gas_limit: 30_000_000, // from create_sealed_header_with_validators
                gas_used: 0,
                timestamp: parent_header_ts_2.timestamp(), // Timestamp same as parent's
                extra_data: extra_data_bytes,
                mix_hash: Default::default(),
                nonce: alloy_primitives::FixedBytes::ZERO, 
                base_fee_per_gas: Some(1_000_000_000), 
                withdrawals_root: None,
                blob_gas_used: None,
                excess_blob_gas: None,
                parent_beacon_block_root: None,
                requests_hash: None,
            };
            let sealed_current_bad_ts = current_alloy_header_bad_ts.seal_slow();
            let (h_part, h_hash) = sealed_current_bad_ts.into_parts();
            let current_header_bad_ts = SealedHeader::new(h_part, h_hash);
            
            let result = consensus.validate_header_against_parent(&current_header_bad_ts, &parent_header_ts_2);
            assert!(result.is_err());
            match result.unwrap_err() {
                ConsensusError::TimestampIsInPast { .. } => {}, // Expected
                e => panic!("Expected TimestampIsInPast, got {:?}", e),
            }
        }

        #[test]
        fn test_validate_header_against_parent_gas_limit_invalid() {
            // This test relies on reth_consensus_common::validation::validate_header_gas
            // We create a header that should fail that validation by setting gas_used > gas_limit.
            let (consensus, _node_key, local_address, config, _test_db, _final_state_adapter) = 
                setup_qbft_consensus_for_test();
            
            let validators = vec![local_address];
            let extra_data_codec = AlloyBftExtraDataCodec::default();

            let parent_header = create_sealed_header_with_validators(
                1, 
                B256::random(), 
                &validators,
                &extra_data_codec,
                &config,
                config.difficulty,
            );

            let bft_extra_data = neura_qbft_core::types::BftExtraData {
                vanity_data: Bytes::from_static(&[0u8; 32]),
                validators: validators.clone(),
                committed_seals: Vec::new(),
                round_number: 0u32,
            };
            let extra_data_bytes = extra_data_codec.encode(&bft_extra_data).unwrap();

            let current_alloy_header_bad_gas = AlloyConsensusHeader {
                number: 2, 
                parent_hash: parent_header.hash(),
                ommers_hash: EMPTY_OMMER_ROOT_HASH,
                beneficiary: RethAddress::random(),
                state_root: B256::random(),
                transactions_root: EMPTY_TRANSACTIONS,
                receipts_root: EMPTY_RECEIPTS,
                logs_bloom: Default::default(),
                difficulty: config.difficulty,
                gas_limit: 100, // Gas limit
                gas_used: 200,  // MODIFIED: gas_used > gas_limit
                timestamp: parent_header.timestamp() + 1,
                extra_data: extra_data_bytes,
                mix_hash: Default::default(),
                nonce: alloy_primitives::FixedBytes::ZERO, 
                base_fee_per_gas: Some(1_000_000_000), 
                withdrawals_root: None,
                blob_gas_used: None,
                excess_blob_gas: None,
                parent_beacon_block_root: None,
                requests_hash: None,
            };
            let sealed_current_bad_gas = current_alloy_header_bad_gas.seal_slow();
            let (h_part, h_hash) = sealed_current_bad_gas.into_parts();
            let current_header_bad_gas = SealedHeader::new(h_part, h_hash);

            let result = consensus.validate_header_against_parent(&current_header_bad_gas, &parent_header);
            assert!(result.is_err(), "Expected an error due to gas_used > gas_limit");
            // The error from validate_header_gas is wrapped in ConsensusError::Other
            match result.unwrap_err() {
                ConsensusError::Other(s) => {
                    assert!(s.contains("Gas validation error"), "Error message prefix mismatch: {}", s);
                    // The specific error from validate_header_gas is HeaderGasUsedExceedsGasLimit
                    // which gets wrapped. The debug format of HeaderGasUsedExceedsGasLimit will be in the string.
                    assert!(s.contains("HeaderGasUsedExceedsGasLimit"), "Specific error type mismatch: {}", s);
                }, 
                e => panic!("Expected ConsensusError::Other for gas validation, got {:?}", e),
            }
        }

        #[test]
        fn test_validate_block_pre_execution_valid() {
            let (consensus, _node_key, local_address, qbft_config, test_db, final_state_adapter) = 
                setup_qbft_consensus_for_test();

            let validators = vec![local_address];
            let extra_data_codec = AlloyBftExtraDataCodec::default();

            let parent_sealed_header = create_sealed_header_with_validators(
                0, // block_number for genesis-like parent
                B256::ZERO, // parent_hash for genesis
                &validators,
                &extra_data_codec,
                &qbft_config,
                qbft_config.difficulty,
            );

            test_db.insert_headers_with_td(std::iter::once(&parent_sealed_header)).unwrap();

            // Calculate expected proposer for block 1, round 0
            let block_number = 1;
            let current_round: u32 = 0;
            let expected_proposer = final_state_adapter
                .get_proposer_for_round(&ConsensusRoundIdentifier {
                    sequence_number: block_number,
                    round_number: current_round,
                })
                .expect("Failed to get expected proposer for block 1, round 0");
            
            let current_alloy_header = AlloyConsensusHeader {
                number: block_number,
                parent_hash: parent_sealed_header.hash(),
                ommers_hash: EMPTY_OMMER_ROOT_HASH,
                beneficiary: expected_proposer, // SET BENEFICIARY
                state_root: B256::random(), // Placeholder
                transactions_root: EMPTY_TRANSACTIONS, // For an empty block body
                receipts_root: EMPTY_RECEIPTS,     // For an empty block body
                logs_bloom: Default::default(),
                difficulty: qbft_config.difficulty,
                gas_limit: 30_000_000,
                gas_used: 0,
                timestamp: parent_sealed_header.timestamp() + 1,
                extra_data: test_utils::create_valid_bft_extra_data_bytes(&validators, &extra_data_codec, 0),
                mix_hash: Default::default(),
                nonce: alloy_primitives::FixedBytes::ZERO, 
                base_fee_per_gas: Some(1_000_000_000), 
                withdrawals_root: None, // Assuming no withdrawals for simplicity
                blob_gas_used: None,
                excess_blob_gas: None,
                parent_beacon_block_root: None,
                requests_hash: None,
            };
            let sealed_alloy_header = current_alloy_header.seal_slow();
            let (header_part, header_hash) = sealed_alloy_header.into_parts(); // header_part is alloy_consensus::Header for block 1
            
            // Create and insert the SealedHeader for block 1 into the DB
            let reth_block1_sealed_header = SealedHeader::new(header_part.clone(), header_hash);
            test_db.insert_headers_with_td(std::iter::once(&reth_block1_sealed_header)).unwrap();

            let block_body = RethBlockBody { 
                transactions: Vec::new(),
                ommers: Vec::new(), // QBFT has empty ommers
                withdrawals: Some(Withdrawals(Vec::new())), // Match header's withdrawals_root
            };

            // Construct RethSealedBlock using seal_parts
            let sealed_block = RethSealedBlock::seal_parts(
                header_part,           // Pass the unsealed alloy_consensus::Header for block 1
                block_body             // Takes BlockBody
            );
            
            // Ensure mock proposal validator is set to pass (default in setup)
            // consensus.core_validator is QbftBlockValidator which wraps MockProposalValidator

            let result = consensus.validate_block_pre_execution(&sealed_block);
            assert!(result.is_ok(), "Expected valid block pre-execution, got {:?}", result);
        }

        #[test]
        fn test_validate_block_pre_execution_core_validator_fails_other() {
            let (consensus, _node_key, local_address, qbft_config, test_db, _final_state_adapter) = 
                setup_qbft_consensus_for_test();

            let validators = vec![local_address]; // Keep validators simple for this test
            let extra_data_codec = AlloyBftExtraDataCodec::default();

            let parent_sealed_header = create_sealed_header_with_validators(
                0, B256::ZERO, &validators, &extra_data_codec, &qbft_config, qbft_config.difficulty,
            );
            test_db.insert_headers_with_td(std::iter::once(&parent_sealed_header)).unwrap();

            let block_number = 1;
            // Attempt to trigger "Round in block extra_data mismatch"
            let alloy_header_block1 = AlloyConsensusHeader {
                number: block_number,
                parent_hash: parent_sealed_header.hash(),
                ommers_hash: EMPTY_OMMER_ROOT_HASH,
                beneficiary: RethAddress::random(),
                state_root: B256::random(),
                transactions_root: EMPTY_TRANSACTIONS,
                receipts_root: EMPTY_RECEIPTS,
                logs_bloom: Default::default(),
                difficulty: qbft_config.difficulty,
                gas_limit: 30_000_000,
                gas_used: 0,
                timestamp: parent_sealed_header.timestamp() + 1,
                extra_data: test_utils::create_valid_bft_extra_data_bytes(&validators, &extra_data_codec, 1), // Round 1, context expects 0
                mix_hash: Default::default(),
                nonce: alloy_primitives::FixedBytes::ZERO, 
                base_fee_per_gas: Some(1_000_000_000), 
                withdrawals_root: None, 
                blob_gas_used: None,
                excess_blob_gas: None,
                parent_beacon_block_root: None,
                requests_hash: None,
            };
            let sealed_alloy_header_b1 = alloy_header_block1.seal_slow();
            let (header_part_b1, header_hash_b1) = sealed_alloy_header_b1.into_parts();
            
            let reth_b1_sealed_header = SealedHeader::new(header_part_b1.clone(), header_hash_b1);
            test_db.insert_headers_with_td(std::iter::once(&reth_b1_sealed_header)).unwrap();

            let block_body_b1 = RethBlockBody { transactions: Vec::new(), ommers: Vec::new(), withdrawals: Some(Withdrawals(Vec::new())) };
            let sealed_block_b1 = RethSealedBlock::seal_parts(header_part_b1, block_body_b1);
            
            let result = consensus.validate_block_pre_execution(&sealed_block_b1);
            // Parent hash check is now expected to pass.
            // The intended validation failure for this test is the round mismatch.
            match result {
                Err(QbftConsensusError::QbftCore(QbftError::ValidationError(msg))) if msg.contains("Round in block extra_data mismatch") => {
                    // This is the expected error.
                }
                Ok(_) => panic!("Expected core validation error (Round in block extra_data mismatch), but got Ok"),
                Err(e) => panic!("Expected QbftError::ValidationError for round mismatch, but got other error: {:?}", e),
            }
        }

        #[test]
        fn test_validate_block_pre_execution_body_tx_root_mismatch() {
            let (consensus, _node_key, local_address, qbft_config, test_db, final_state_adapter) = 
                setup_qbft_consensus_for_test();

            let validators = vec![local_address];
            let extra_data_codec = AlloyBftExtraDataCodec::default();

            let parent_sealed_header = create_sealed_header_with_validators(
                0, B256::ZERO, &validators, &extra_data_codec, &qbft_config, qbft_config.difficulty,
            );
            test_db.insert_headers_with_td(std::iter::once(&parent_sealed_header)).unwrap();

            let block_number = 1;
            let current_round: u32 = 0;
            let expected_proposer = final_state_adapter
                .get_proposer_for_round(&ConsensusRoundIdentifier {
                    sequence_number: block_number,
                    round_number: current_round,
                })
                .expect("Failed to get expected proposer for block 1, round 0");

            let alloy_header_block1 = AlloyConsensusHeader {
                number: block_number,
                parent_hash: parent_sealed_header.hash(),
                ommers_hash: EMPTY_OMMER_ROOT_HASH,
                beneficiary: expected_proposer, // SET BENEFICIARY
                state_root: B256::random(),
                transactions_root: B256::random(), // Set a specific, non-empty tx_root in header
                receipts_root: EMPTY_RECEIPTS, 
                logs_bloom: Default::default(),
                difficulty: qbft_config.difficulty,
                gas_limit: 30_000_000,
                gas_used: 0,
                timestamp: parent_sealed_header.timestamp() + 1,
                extra_data: test_utils::create_valid_bft_extra_data_bytes(&validators, &extra_data_codec, 0),
                mix_hash: Default::default(),
                nonce: alloy_primitives::FixedBytes::ZERO, 
                base_fee_per_gas: Some(1_000_000_000), 
                withdrawals_root: None, 
                blob_gas_used: None,
                excess_blob_gas: None,
                parent_beacon_block_root: None,
                requests_hash: None,
            };
            let sealed_alloy_header_b1 = alloy_header_block1.seal_slow();
            let (header_part_b1, header_hash_b1) = sealed_alloy_header_b1.into_parts();
            
            let reth_b1_sealed_header = SealedHeader::new(header_part_b1.clone(), header_hash_b1);
            test_db.insert_headers_with_td(std::iter::once(&reth_b1_sealed_header)).unwrap();

            let block_body_b1 = RethBlockBody { transactions: Vec::new(), ommers: Vec::new(), withdrawals: Some(Withdrawals(Vec::new())) };
            let sealed_block_b1 = RethSealedBlock::seal_parts(header_part_b1, block_body_b1);
            
            let result = consensus.validate_block_pre_execution(&sealed_block_b1);
            // Now that parent hash and beneficiary are correct, the next expected error is BodyTransactionRootDiff.
            match result {
                Err(QbftConsensusError::RethConsensus(ConsensusError::BodyTransactionRootDiff(_))) => {
                    // This is the expected error now.
                }
                Ok(_) => panic!("Expected BodyTransactionRootDiff, but got Ok"),
                Err(e) => panic!("Expected BodyTransactionRootDiff, but got other error: {:?}", e),
            }
        }

        #[test]
        fn test_validate_body_against_header_valid() {
            let (consensus, _node_key, local_address, qbft_config, _test_db, _final_state_adapter) = 
                setup_qbft_consensus_for_test();

            let validators = vec![local_address];
            let extra_data_codec = AlloyBftExtraDataCodec::default();

            let header = create_sealed_header_with_validators(
                1, B256::random(), &validators, &extra_data_codec, &qbft_config, qbft_config.difficulty,
            ); 

            let body = RethBlockBody { // Body matches default header roots
                transactions: Vec::new(),
                ommers: Vec::new(),
                withdrawals: None,
            };

            let result = consensus.validate_body_against_header(&body, &header);
            assert!(result.is_ok(), "Expected valid body against header, got {:?}", result);
        }

        #[test]
        fn test_validate_body_against_header_ommers_mismatch() {
            let (consensus, _node_key, local_address, qbft_config, _test_db, _final_state_adapter) = 
                setup_qbft_consensus_for_test();
            let validators = vec![local_address];
            let extra_data_codec = AlloyBftExtraDataCodec::default();

            let alloy_header_with_ommers = AlloyConsensusHeader {
                ommers_hash: B256::random(), // Non-empty ommers hash
                transactions_root: EMPTY_TRANSACTIONS, // Keep tx_root matching for this test
                number: 1,
                parent_hash: B256::random(), 
                beneficiary: RethAddress::random(),
                state_root: B256::random(),
                receipts_root: EMPTY_RECEIPTS, 
                logs_bloom: Default::default(),
                difficulty: qbft_config.difficulty,
                gas_limit: 30_000_000,
                gas_used: 0,
                timestamp: 1,
                extra_data: test_utils::create_valid_bft_extra_data_bytes(&validators, &extra_data_codec, 0),
                mix_hash: Default::default(),
                nonce: alloy_primitives::FixedBytes::ZERO, 
                base_fee_per_gas: Some(1_000_000_000), 
                withdrawals_root: None, 
                blob_gas_used: None,
                excess_blob_gas: None,
                parent_beacon_block_root: None,
                requests_hash: None,
            };
            let sealed_alloy_h = alloy_header_with_ommers.seal_slow();
            let (h_part, h_hash) = sealed_alloy_h.into_parts();
            let header = SealedHeader::new(h_part, h_hash);

            let body = RethBlockBody { // Body implies empty ommers (calculate_ommers_root would be EMPTY_OMMER_ROOT_HASH)
                transactions: Vec::new(),
                ommers: Vec::new(),
                withdrawals: None,
            };

            let result = consensus.validate_body_against_header(&body, &header);
            assert!(matches!(result, Err(QbftConsensusError::RethConsensus(ConsensusError::BodyOmmersHashDiff(_)))));
        }

        #[test]
        fn test_validate_body_against_header_tx_root_mismatch() {
            let (consensus, _node_key, local_address, qbft_config, _test_db, _final_state_adapter) = 
                setup_qbft_consensus_for_test();
            let validators = vec![local_address];
            let extra_data_codec = AlloyBftExtraDataCodec::default();

            let alloy_header_with_tx = AlloyConsensusHeader {
                ommers_hash: EMPTY_OMMER_ROOT_HASH, // Keep ommers matching
                transactions_root: B256::random(),  // Non-empty tx root in header
                number: 1,
                parent_hash: B256::random(), 
                beneficiary: RethAddress::random(),
                state_root: B256::random(),
                receipts_root: EMPTY_RECEIPTS, 
                logs_bloom: Default::default(),
                difficulty: qbft_config.difficulty,
                gas_limit: 30_000_000,
                gas_used: 0,
                timestamp: 1,
                extra_data: test_utils::create_valid_bft_extra_data_bytes(&validators, &extra_data_codec, 0),
                mix_hash: Default::default(),
                nonce: alloy_primitives::FixedBytes::ZERO, 
                base_fee_per_gas: Some(1_000_000_000), 
                withdrawals_root: None, 
                blob_gas_used: None,
                excess_blob_gas: None,
                parent_beacon_block_root: None,
                requests_hash: None,
            };
            let sealed_alloy_h = alloy_header_with_tx.seal_slow();
            let (h_part, h_hash) = sealed_alloy_h.into_parts();
            let header = SealedHeader::new(h_part, h_hash);

            let body = RethBlockBody { // Body has empty txs, so its root will be EMPTY_TRANSACTIONS
                transactions: Vec::new(),
                ommers: Vec::new(),
                withdrawals: None,
            };

            let result = consensus.validate_body_against_header(&body, &header);
            assert!(matches!(result, Err(QbftConsensusError::RethConsensus(ConsensusError::BodyTransactionRootDiff(_)))));
        }

        #[test]
        fn test_validate_body_against_header_empty_block_non_genesis() {
            let (consensus, _node_key, local_address, qbft_config, _test_db, _final_state_adapter) = 
                setup_qbft_consensus_for_test();
            let validators = vec![local_address];
            let extra_data_codec = AlloyBftExtraDataCodec::default();

            let header = create_sealed_header_with_validators(
                1, // Non-genesis block number
                B256::random(), &validators, &extra_data_codec, &qbft_config, qbft_config.difficulty,
            );

            let body = RethBlockBody { // Empty body
                transactions: Vec::new(),
                ommers: Vec::new(),
                withdrawals: None,
            };
            // This combination should be Ok as empty non-genesis blocks are allowed
            let result = consensus.validate_body_against_header(&body, &header);
            assert!(result.is_ok(), "Expected Ok for empty non-genesis block, got {:?}", result);
        }

        #[test]
        fn test_validate_body_against_header_empty_block_genesis() {
            let (consensus, _node_key, local_address, qbft_config, _test_db, _final_state_adapter) = 
                setup_qbft_consensus_for_test();
            let validators = vec![local_address];
            let extra_data_codec = AlloyBftExtraDataCodec::default();

            let header = create_sealed_header_with_validators(
                0, // Genesis block number
                B256::random(), &validators, &extra_data_codec, &qbft_config, qbft_config.difficulty,
            );

            let body = RethBlockBody { // Empty body
                transactions: Vec::new(),
                ommers: Vec::new(),
                withdrawals: None,
            };
            // This combination should also be Ok (current logic `header.number() != 0` for special handling is fine)
            let result = consensus.validate_body_against_header(&body, &header);
            assert!(result.is_ok(), "Expected Ok for empty genesis block, got {:?}", result);
        }

    }

    mod reth_round_timer_tests {
        use super::*;
        use tokio::sync::mpsc;
        use tokio::time::{sleep, timeout, Duration};
        use neura_qbft_core::types::{ConsensusRoundIdentifier, RoundTimer};

        #[tokio::test]
        async fn test_reth_round_timer_start_and_fire() {
            let (tx, mut rx): (mpsc::Sender<ConsensusRoundIdentifier>, mpsc::Receiver<ConsensusRoundIdentifier>) = mpsc::channel(10);
            let timer = RethRoundTimer::new(tx);
            let round_id = ConsensusRoundIdentifier { sequence_number: 1, round_number: 0 };
            
            timer.start_timer(round_id, 50); // 50 ms timeout

            match timeout(Duration::from_millis(100), rx.recv()).await {
                Ok(Some(received_round_id)) => {
                    assert_eq!(received_round_id, round_id, "Timer fired for the correct round");
                }
                Ok(None) => panic!("Timer event channel closed unexpectedly"),
                Err(_) => panic!("Timer did not fire within the expected time"),
            }
        }

        #[tokio::test]
        async fn test_reth_round_timer_cancel() {
            let (tx, mut rx): (mpsc::Sender<ConsensusRoundIdentifier>, mpsc::Receiver<ConsensusRoundIdentifier>) = mpsc::channel(10);
            let timer = RethRoundTimer::new(tx);
            let round_id = ConsensusRoundIdentifier { sequence_number: 2, round_number: 0 };

            timer.start_timer(round_id, 100); // 100 ms timeout
            sleep(Duration::from_millis(10)).await; // Let it start
            timer.cancel_timer(round_id);
            sleep(Duration::from_millis(150)).await; // Wait well past original timeout

            match rx.try_recv() {
                Ok(received_round_id) => {
                    panic!("Timer fired for {:?} despite being cancelled", received_round_id);
                }
                Err(mpsc::error::TryRecvError::Empty) => {
                    // Expected: Timer was cancelled and did not fire
                }
                Err(e) => panic!("Error receiving from timer channel: {:?}", e),
            }
        }

        #[tokio::test]
        async fn test_reth_round_timer_restart_replaces_old() {
            let (tx, mut rx): (mpsc::Sender<ConsensusRoundIdentifier>, mpsc::Receiver<ConsensusRoundIdentifier>) = mpsc::channel(10);
            let timer = RethRoundTimer::new(tx);
            let round_id = ConsensusRoundIdentifier { sequence_number: 3, round_number: 0 };

            timer.start_timer(round_id, 200); // Original long timeout
            sleep(Duration::from_millis(10)).await;
            timer.start_timer(round_id, 50); // Restart with shorter timeout

            // Should fire based on the shorter timeout
            match timeout(Duration::from_millis(100), rx.recv()).await {
                Ok(Some(received_round_id)) => {
                    assert_eq!(received_round_id, round_id, "Timer fired for the correct round after restart");
                }
                Ok(None) => panic!("Timer event channel closed unexpectedly after restart"),
                Err(_) => panic!("Timer did not fire within the expected time after restart (expected shorter one)"),
            }

            // Ensure it doesn't fire again for the old, longer timeout
            sleep(Duration::from_millis(250)).await; // Wait past original long timeout
            match rx.try_recv() {
                Ok(received_round_id) => {
                    panic!("Timer fired again for {:?} for the old, longer timeout", received_round_id);
                }
                Err(mpsc::error::TryRecvError::Empty) => {
                    // Expected
                }
                Err(e) => panic!("Error receiving from timer channel after long wait: {:?}", e),
            }
        }

        #[tokio::test]
        async fn test_reth_round_timer_multiple_independent_timers() {
            let (tx, mut rx): (mpsc::Sender<ConsensusRoundIdentifier>, mpsc::Receiver<ConsensusRoundIdentifier>) = mpsc::channel(30); // Increased channel capacity
            let timer = RethRoundTimer::new(tx);

            let round_id_a = ConsensusRoundIdentifier { sequence_number: 10, round_number: 0 };
            let round_id_b = ConsensusRoundIdentifier { sequence_number: 10, round_number: 1 };
            let round_id_c = ConsensusRoundIdentifier { sequence_number: 11, round_number: 0 };

            timer.start_timer(round_id_a, 60); // Fires second
            timer.start_timer(round_id_b, 30); // Fires first
            timer.start_timer(round_id_c, 90); // Fires third

            let mut received_events = Vec::new();

            // Expect B, then A, then C based on timeouts
            match timeout(Duration::from_millis(50), rx.recv()).await {
                Ok(Some(id)) => received_events.push(id),
                _ => panic!("Timer B did not fire or channel closed"),
            }
            assert_eq!(received_events.last().unwrap(), &round_id_b);

            match timeout(Duration::from_millis(50), rx.recv()).await { // Remaining 10ms for A + 30ms buffer
                Ok(Some(id)) => received_events.push(id),
                _ => panic!("Timer A did not fire or channel closed"),
            }
            assert_eq!(received_events.last().unwrap(), &round_id_a);

            match timeout(Duration::from_millis(50), rx.recv()).await { // Remaining 30ms for C + 30ms buffer
                Ok(Some(id)) => received_events.push(id),
                _ => panic!("Timer C did not fire or channel closed"),
            }
            assert_eq!(received_events.last().unwrap(), &round_id_c);

            assert_eq!(received_events.len(), 3, "Incorrect number of timer events received");
            // Order check
            assert_eq!(received_events, vec![round_id_b, round_id_a, round_id_c]);
        }

        #[tokio::test]
        async fn test_reth_round_timer_rapid_manipulation() {
            let (tx, mut rx): (mpsc::Sender<ConsensusRoundIdentifier>, mpsc::Receiver<ConsensusRoundIdentifier>) = mpsc::channel(10);
            let timer = RethRoundTimer::new(tx);
            let round_id = ConsensusRoundIdentifier { sequence_number: 20, round_number: 0 };

            // Start, quickly cancel, restart with short, then long, then short again
            timer.start_timer(round_id, 500);
            timer.cancel_timer(round_id);
            timer.start_timer(round_id, 30); // This one should fire
            timer.start_timer(round_id, 600); // This should be cancelled by the next
            timer.start_timer(round_id, 40);  // This one should effectively replace the 600ms one and fire

            match timeout(Duration::from_millis(70), rx.recv()).await {
                Ok(Some(received_round_id)) => {
                    assert_eq!(received_round_id, round_id, "Timer fired for the correct round after rapid manipulation");
                }
                Ok(None) => panic!("Timer event channel closed unexpectedly during rapid manipulation"),
                Err(_) => panic!("Timer did not fire within the expected time after rapid manipulation (expected ~40ms)"),
            }

            // Ensure no other timers fire
            sleep(Duration::from_millis(700)).await;
            match rx.try_recv() {
                Ok(received_round_id) => {
                    panic!("Unexpected timer event {:?} fired after rapid manipulation sequence", received_round_id);
                }
                Err(mpsc::error::TryRecvError::Empty) => { /* Expected */ }
                Err(e) => panic!("Error checking channel after rapid manipulation: {:?}", e),
            }
        }

        #[tokio::test]
        async fn test_reth_round_timer_sender_dropped() {
            let (_tx, rx): (mpsc::Sender<ConsensusRoundIdentifier>, mpsc::Receiver<ConsensusRoundIdentifier>) = mpsc::channel(10);
            let timer = RethRoundTimer::new(_tx.clone()); // Clone _tx for the first timer instance
            let round_id = ConsensusRoundIdentifier { sequence_number: 30, round_number: 0 };

            timer.start_timer(round_id, 20);

            // Drop the receiver for the first timer
            drop(rx);

            // Allow time for the timer to fire and attempt to send.
            // The task inside start_timer should complete silently or log a warning, but not panic.
            sleep(Duration::from_millis(50)).await;

            // Now, create a new channel and a new timer instance for the second part of the test.
            let (new_tx, mut rx2): (mpsc::Sender<ConsensusRoundIdentifier>, mpsc::Receiver<ConsensusRoundIdentifier>) = mpsc::channel(10);
            let timer2 = RethRoundTimer::new(new_tx);

            // Start a new timer on the new timer instance for the same round_id.
            // This should not be affected by the first timer whose receiver was dropped.
            timer2.start_timer(round_id, 30);

            match timeout(Duration::from_millis(60), rx2.recv()).await {
                Ok(Some(received_round_id)) => {
                    assert_eq!(received_round_id, round_id, "New timer should fire after original sender was dropped");
                }
                Ok(None) => panic!("New timer channel closed unexpectedly"),
                Err(_) => panic!("New timer did not fire after original sender was dropped"),
            }
        }
    }
} 