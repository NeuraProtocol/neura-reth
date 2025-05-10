use crate::types::{ConsensusRoundIdentifier, SignedData, QbftBlock};
use alloy_primitives::Address;
use crate::messagewrappers::{RoundChange, BftMessage};
use crate::payload::{RoundChangePayload, PreparePayload, ProposalPayload};
use crate::validation::RoundChangeMessageValidator;
use crate::error::QbftError;
use std::collections::HashMap;
use std::cmp::Ordering;
use alloy_primitives::{B256 as Hash};

/// Information about a block that has a valid prepared certificate,
/// gathered from RoundChange messages.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertifiedPrepareInfo {
    pub block: QbftBlock,
    pub original_signed_proposal: BftMessage<ProposalPayload>,
    pub prepares: Vec<SignedData<PreparePayload>>,
    pub prepared_round: u32,
}

/// Manages RoundChange messages and determines the best CertifiedPrepareInfo.
pub struct RoundChangeManager {
    // TargetRound -> Author -> RoundChangeMessage
    round_change_messages: HashMap<ConsensusRoundIdentifier, HashMap<Address, RoundChange>>,
    // Stores the best CertifiedPrepareInfo seen for a given block hash from round change messages
    // Key: Block Hash. Value: The CertifiedPrepareInfo.
    known_prepared_certificates: HashMap<Hash, CertifiedPrepareInfo>,
    round_change_quorum_size: usize, // Number of distinct round change messages needed (f+1)
    validator: RoundChangeMessageValidator,
}

impl RoundChangeManager {
    pub fn new(round_change_quorum_size: usize, validator: RoundChangeMessageValidator) -> Self {
        Self {
            round_change_messages: HashMap::new(),
            known_prepared_certificates: HashMap::new(),
            round_change_quorum_size,
            validator,
        }
    }

    pub fn add_round_change_message(&mut self, message: RoundChange) -> Result<bool, QbftError> {
        let author = message.author()?;
        let target_round = *message.round_identifier();

        if !self.validator.validate(&message)? {
            log::warn!(
                "RoundChange from {:?} for target {:?} failed validation. Discarding.",
                author, target_round
            );
            return Err(QbftError::ValidationError("Invalid RoundChange message due to validator rules".into()));
        }

        let round_messages = self.round_change_messages.entry(target_round).or_default();
        if round_messages.contains_key(&author) {
            log::debug!(
                "Duplicate RoundChange from {:?} for target {:?} already processed. Discarding.",
                author, target_round
            );
            return Ok(false); 
        }
        round_messages.insert(author, message.clone());

        let rc_payload_data = message.payload();
            
        if let (Some(ref metadata), Some(ref block)) = (&rc_payload_data.prepared_round_metadata, &rc_payload_data.prepared_block) {
            if metadata.prepared_block_hash == block.hash() {
                let cert_info = CertifiedPrepareInfo {
                    block: block.clone(),
                    original_signed_proposal: metadata.signed_proposal_payload.clone(),
                    prepares: metadata.prepares.clone(),
                    prepared_round: metadata.prepared_round,
                };
                let block_hash = block.hash();
                match self.known_prepared_certificates.entry(block_hash) {
                    std::collections::hash_map::Entry::Occupied(mut entry) => {
                        if cert_info.prepared_round > entry.get().prepared_round {
                            entry.insert(cert_info);
                        }
                    }
                    std::collections::hash_map::Entry::Vacant(entry) => {
                        entry.insert(cert_info);
                    }
                }
            } else {
                log::warn!(
                    "RoundChange from {:?} for target {:?} has inconsistent prepared block hash ({:?}) and metadata hash ({:?}). Ignoring prepared info.", 
                    author, target_round, block.hash(), metadata.prepared_block_hash
                );
            }
        }
        Ok(true) 
    }

    fn best_certificate_from_known(&self) -> Option<&CertifiedPrepareInfo> {
        self.known_prepared_certificates.values().max_by(|a, b| {
            match a.prepared_round.cmp(&b.prepared_round) {
                Ordering::Equal => {
                    a.block.hash().cmp(&b.block.hash())
                }
                other => other,
            }
        })
    }
    
    pub fn get_round_change_messages_for_target_round(&self, target_round: &ConsensusRoundIdentifier) -> Option<Vec<RoundChange>> {
        self.round_change_messages.get(target_round).map(|map| map.values().cloned().collect())
    }
    
    pub fn has_sufficient_round_changes(&self, target_round: &ConsensusRoundIdentifier) -> bool {
        self.round_change_messages
            .get(target_round)
            .map_or(false, |messages| messages.len() >= self.round_change_quorum_size)
    }

    pub fn get_round_change_artifacts(&self, target_round: &ConsensusRoundIdentifier) -> RoundChangeArtifacts {
        let round_changes_payloads = self.get_round_change_messages_for_target_round(target_round)
            .unwrap_or_default()
            .into_iter()
            .map(|rc_wrapper| rc_wrapper.bft_message().signed_payload.clone())
            .collect();

        let best_prepared_certificate = self.best_certificate_from_known().cloned();

        RoundChangeArtifacts::new(round_changes_payloads, best_prepared_certificate)
    }
}

/// Artifacts gathered from RoundChange messages for a specific target round.
#[derive(Clone, Debug, Default)]
pub struct RoundChangeArtifacts {
    round_changes: Vec<SignedData<RoundChangePayload>>,
    best_prepared_certificate: Option<CertifiedPrepareInfo>,
}

impl RoundChangeArtifacts {
    pub fn new(
        round_changes: Vec<SignedData<RoundChangePayload>>, 
        best_prepared_certificate: Option<CertifiedPrepareInfo>
    ) -> Self {
        Self { round_changes, best_prepared_certificate }
    }

    pub fn round_changes(&self) -> &Vec<SignedData<RoundChangePayload>> {
        &self.round_changes
    }

    pub fn best_prepared_certificate(&self) -> Option<&CertifiedPrepareInfo> {
        self.best_prepared_certificate.as_ref()
    }
} 