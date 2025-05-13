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
use alloy_consensus::EMPTY_OMMER_ROOT_HASH;
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
use std::fmt; // For manual Debug impl

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
    use reth_provider::test_utils::{create_test_provider_factory, MockNodeTypesWithDB};
    use k256::SecretKey;
    use rand_08::thread_rng;
    use alloy_primitives::keccak256;
    use std::collections::HashSet;
    use neura_qbft_core::payload::MessageFactory as TestMessageFactory; // Alias for clarity in tests

    // Test for QbftConsensus::new()
    #[test]
    fn test_qbft_consensus_new() {
        let chainspec = MAINNET.clone(); // Changed from Arc::new(MAINNET.clone())
        let provider_factory = create_test_provider_factory();
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

        let final_state_for_controller = Arc::new(MockQbftFinalState::new(
            node_key.clone(),
            vec![RethAddress::random(), RethAddress::random()].into_iter().collect::<HashSet<_>>(),
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
        
        let final_state_for_controller_timer_test = Arc::new(MockQbftFinalState::new(
            node_key_for_controller_deps.clone(),
            vec![RethAddress::random()].into_iter().collect::<HashSet<_>>(),
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
} 