//! QBFT consensus implementation for Reth.

// Standard imports
use std::sync::Arc;
use std::collections::{HashMap, HashSet}; // Added HashMap for RethRoundTimer
use std::time::Duration; // For timer

// Reth imports
use reth_consensus::{ConsensusError,HeaderValidator};
use reth_consensus_common::validation::validate_header_gas;
use alloy_primitives::{
    Address as RethAddress, BlockNumber, B256, Bytes, // Removed Sealable
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
        EMPTY_OMMER_ROOT_HASH, // QBFT doesn't use ommers in the same way, parent ommers hash is fixed.
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
        reth_header.extra_data().clone(), // extra_data() returns &Bytes
        reth_header.mix_hash().unwrap_or_default(), // Use unwrap_or_default for Option<B256>
        Bytes::copy_from_slice(reth_header.nonce().unwrap_or_default().as_slice()), // Handle Option<FixedBytes<8>>
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
    use neura_qbft_core::{
        mocks::{
            MockQbftFinalState, MockQbftBlockCreatorFactory, MockQbftBlockImporter,
            MockValidatorMulticaster, MockBlockTimer, MockMessageValidatorFactory,
            MockRoundChangeMessageValidatorFactory,
        },
        statemachine::QbftController,
        types::{QbftConfig, NodeKey, AlloyBftExtraDataCodec}, 
    };
    use reth_chainspec::MAINNET;
    use reth_provider::test_utils::MockNodeTypesWithDB;
    use reth_stages::test_utils::{TestStageDB, StorageKind};
    use k256::SecretKey;
    use rand_08::thread_rng;
    use alloy_primitives::keccak256;
    use std::collections::HashSet;
    use neura_qbft_core::payload::MessageFactory as TestMessageFactory;
    use reth_primitives::{
        BlockBody as RethBlockBody, Header as RethPrimitivesHeader, 
        TransactionSigned, SealedBlock as RethSealedBlock
    };
    

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
        use reth_stages::test_utils::TestStageDB;
        use k256::SecretKey;
        use alloy_primitives::U256;
        use std::iter;
        use alloy_consensus::Sealable;
        use alloy_consensus::constants::{EMPTY_RECEIPTS, EMPTY_TRANSACTIONS};
        use alloy_primitives::B256;
        use alloy_consensus::EMPTY_OMMER_ROOT_HASH;
        use alloy_eips::eip4895::Withdrawals;
        // Imports like RethBlockBody, RethPrimitivesHeader, TransactionSigned, RethSealedBlock
        // will be brought in by `use super::*;`

        // Helper to generate a unique NodeKey and corresponding RethAddress for testing
        fn generate_unique_node_key_and_address() -> (Arc<NodeKey>, RethAddress) {
            let mut rng = thread_rng();
            let secret_key = SecretKey::random(&mut rng);
            let node_key = Arc::new(NodeKey::from(secret_key));
            let verifying_key = node_key.verifying_key();
            let uncompressed_pk_bytes = verifying_key.to_encoded_point(false).as_bytes().to_vec();
            let hash = keccak256(&uncompressed_pk_bytes[1..]);
            let local_address = RethAddress::from_slice(&hash[12..]);
            (node_key, local_address)
        }

        fn default_qbft_config_for_test() -> Arc<QbftConfig> {
            Arc::new(QbftConfig {
                difficulty: U256::from(1), // Default difficulty for QBFT blocks
                block_period_seconds: 1, 
                message_round_timeout_ms: 2000, // Corrected field name and value type (ms)
                ..Default::default()
            })
        }

        fn default_extra_data_codec_for_test() -> Arc<AlloyBftExtraDataCodec> {
            Arc::new(AlloyBftExtraDataCodec::default())
        }

        // Corrected setup_test_final_state_components
        fn setup_test_final_state_components(
            num_initial_validators: usize,
        ) -> (
            RethQbftFinalState<MockNodeTypesWithDB>,
            Vec<RethAddress>, // initial_validators (these will be in the custom genesis)
            Arc<QbftConfig>,
            Arc<AlloyBftExtraDataCodec>,
            TestStageDB,
        ) {
            let test_db = TestStageDB::default(); // Still useful for its factory
            let config = default_qbft_config_for_test();
            let extra_data_codec = default_extra_data_codec_for_test();
            let (node_key, local_address) = generate_unique_node_key_and_address();

            // Create initial validators for the QBFT genesis block
            let mut qbft_genesis_validators: Vec<RethAddress> = iter::repeat_with(|| generate_unique_node_key_and_address().1)
                .take(num_initial_validators.saturating_sub(1)) 
                .collect();
            qbft_genesis_validators.push(local_address); // Ensure local node is a validator

            // Create BftExtraData for QBFT genesis
            let bft_extra_data_for_genesis = neura_qbft_core::types::BftExtraData {
                vanity_data: Bytes::from_static(&[0u8; 32]),
                validators: qbft_genesis_validators.clone(),
                committed_seals: Vec::new(),
                round_number: 0u32,
            };
            let qbft_genesis_extra_data_bytes = extra_data_codec.encode(&bft_extra_data_for_genesis).unwrap();

            // Create the QBFT genesis header (block 0)
            let qbft_genesis_alloy_header = alloy_consensus::Header {
                number: 0,
                parent_hash: B256::ZERO, // Genesis parent hash
                ommers_hash: EMPTY_OMMER_ROOT_HASH,
                beneficiary: RethAddress::random(), // Can be arbitrary for genesis
                state_root: B256::random(),      // Typically post-genesis state root
                transactions_root: EMPTY_TRANSACTIONS, 
                receipts_root: EMPTY_RECEIPTS,         
                logs_bloom: Default::default(),
                difficulty: config.difficulty, // Use QBFT config difficulty
                gas_limit: MAINNET.genesis_header().gas_limit, // Borrow from MAINNET or set custom
                gas_used: 0,
                timestamp: 0, // Genesis timestamp
                extra_data: qbft_genesis_extra_data_bytes,
                mix_hash: Default::default(),
                nonce: alloy_primitives::FixedBytes::ZERO, // QBFT nonce
                base_fee_per_gas: Some(MAINNET.genesis_header().base_fee_per_gas.unwrap_or(1_000_000_000)),
                withdrawals_root: None,
                blob_gas_used: None,
                excess_blob_gas: None,
                parent_beacon_block_root: None,
                requests_hash: None, 
            };

            let alloy_sealed_qbft_genesis = qbft_genesis_alloy_header.seal_slow();
            let (header_part, hash_part) = alloy_sealed_qbft_genesis.into_parts();
            let _reth_sealed_qbft_genesis_header = 
                reth_primitives_traits::SealedHeader::new(header_part.clone(), hash_part);
            
            let qbft_genesis_body = RethBlockBody {
                transactions: Vec::<TransactionSigned>::new(),
                ommers: Vec::<RethPrimitivesHeader>::new(),
                withdrawals: Option::<Withdrawals>::None, // Use Vec<reth_primitives::Withdrawal>
            };

            // Use header_part (alloy_consensus::Header) for seal_parts
            let qbft_genesis_sealed_block = RethSealedBlock::seal_parts(header_part, qbft_genesis_body);

            test_db.insert_blocks(
                std::iter::once(&qbft_genesis_sealed_block), 
                StorageKind::Database(None) 
            )
                .expect("Failed to insert QBFT genesis block into test_db");

            let provider_factory_from_test_db = test_db.factory.clone();

            let final_state = RethQbftFinalState::new(
                provider_factory_from_test_db,
                node_key.clone(),
                local_address,
                extra_data_codec.clone(), // Use the same codec used for encoding
                config.clone(),
            );
            (final_state, qbft_genesis_validators, config, extra_data_codec, test_db)
        }

        // Corrected create_sealed_header_with_validators
        fn create_sealed_header_with_validators(
            block_number: BlockNumber,
            parent_hash: B256,
            validators_slice: &[RethAddress], // Changed to slice
            extra_data_codec: &AlloyBftExtraDataCodec,
            _qbft_config: &QbftConfig, // Added qbft_config, though not used in current body
            difficulty: U256,        // Not an Option anymore
        ) -> SealedHeader {
            use neura_qbft_core::types::BftExtraData;
            use alloy_primitives::Sealable;

            let bft_extra_data = BftExtraData {
                vanity_data: Bytes::from_static(&[0u8; 32]),
                validators: validators_slice.to_vec(), // Convert slice to Vec
                committed_seals: Vec::new(),
                round_number: 0u32,
            };
            let extra_data_bytes = extra_data_codec.encode(&bft_extra_data).unwrap();

            let alloy_header = alloy_consensus::Header {
                number: block_number,
                extra_data: extra_data_bytes,
                parent_hash, // Use directly
                ommers_hash: EMPTY_OMMER_ROOT_HASH,
                beneficiary: RethAddress::random(),
                state_root: B256::random(),
                transactions_root: B256::random(),
                receipts_root: B256::random(),
                logs_bloom: Default::default(),
                difficulty, // Use directly
                gas_limit: 30_000_000, // Example gas limit
                gas_used: 0,
                timestamp: block_number * 1, // Simple timestamp progression
                mix_hash: Default::default(),
                nonce: alloy_primitives::FixedBytes::ZERO, // Corrected: Use FixedBytes::ZERO for [0u8; 8]
                base_fee_per_gas: Some(1_000_000_000), // Example base fee
                withdrawals_root: None,
                blob_gas_used: None,
                excess_blob_gas: None,
                parent_beacon_block_root: None,
                requests_hash: None,
            };

            let sealed_alloy_header = alloy_header.seal_slow();
            let (header_part, hash_part) = sealed_alloy_header.into_parts();
            reth_primitives_traits::SealedHeader::new(header_part.clone(), hash_part)
        }

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

            let genesis_sealed_header = test_db.factory.sealed_header(0).unwrap().expect("Genesis header missing");
            
            // For this test, we'll assume the genesis block in TestStageDB has an empty body
            // (which is typical for a default TestStageDB genesis).
            // We need to ensure our get_block_by_hash can handle this.

            let qbft_block_opt = final_state.get_block_by_hash(&genesis_sealed_header.hash());
            assert!(qbft_block_opt.is_some(), "QBFT Genesis block not found by hash");
            
            let qbft_block = qbft_block_opt.unwrap();

            // Verify header details
            assert_eq!(qbft_block.header.number, 0, "Block number mismatch");
            assert_eq!(qbft_block.header.parent_hash, genesis_sealed_header.parent_hash(), "Parent hash mismatch");
            assert_eq!(qbft_block.header.difficulty, qbft_config.difficulty, "Difficulty mismatch");
            // ... (add more header field checks if necessary, e.g., roots if TestStageDB populates them meaningfully for genesis)
            assert_eq!(qbft_block.header.transactions_root, EMPTY_TRANSACTIONS, "Genesis transactions_root mismatch");


            // Verify body (transactions and ommers)
            assert!(qbft_block.body_transactions.is_empty(), "Expected empty transactions for default genesis");
            assert!(qbft_block.body_ommers.is_empty(), "Expected empty ommers as per current implementation");

            // Test with a non-existent hash
            let non_existent_hash = B256::random();
            let non_existent_block_opt = final_state.get_block_by_hash(&non_existent_hash);
            assert!(non_existent_block_opt.is_none(), "Expected None for non-existent block hash");
        }
    }
} 