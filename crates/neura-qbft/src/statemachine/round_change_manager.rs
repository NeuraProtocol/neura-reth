use crate::types::{ConsensusRoundIdentifier, SignedData};
use alloy_primitives::Address;
use crate::messagewrappers::RoundChange;
use crate::payload::RoundChangePayload;
use crate::statemachine::round_state::PreparedCertificate; // Used by RoundChangeArtifacts
use crate::validation::RoundChangeMessageValidator; // Corrected import
use crate::error::QbftError;

use std::collections::HashMap;

/// Holds the artifacts from a collection of RoundChange messages that justify a round transition.
#[derive(Debug, Clone)]
pub struct RoundChangeArtifacts {
    /// The collection of RoundChange messages that triggered this.
    round_changes: Vec<SignedData<RoundChangePayload>>,
    /// The best PreparedCertificate found among the round_changes, if any.
    best_prepared_certificate: Option<PreparedCertificate>,
}

impl RoundChangeArtifacts {
    pub fn new(
        round_changes: Vec<SignedData<RoundChangePayload>>,
        best_prepared_certificate: Option<PreparedCertificate>,
    ) -> Self {
        Self { round_changes, best_prepared_certificate }
    }

    pub fn round_changes(&self) -> &Vec<SignedData<RoundChangePayload>> {
        &self.round_changes
    }

    pub fn best_prepared_certificate(&self) -> Option<&PreparedCertificate> {
        self.best_prepared_certificate.as_ref()
    }

    /// Creates RoundChangeArtifacts from a collection of validated RoundChange *wrappers*.
    /// It finds the RoundChange with the highest prepared round (if any) to determine the best certificate.
    pub fn try_create(validated_round_changes: &[RoundChange]) -> Option<Self> {
        if validated_round_changes.is_empty() {
            return None;
        }

        let best_prepared_cert_candidate = validated_round_changes.iter()
            .filter_map(|rc_wrapper| {
                rc_wrapper.prepared_block().as_ref().and_then(|block| { 
                    rc_wrapper.payload().prepared_round_metadata.as_ref().map(|metadata| {
                        PreparedCertificate::new(
                            (**block).clone(),
                            metadata.prepares.clone(),
                            metadata.prepared_round,
                        )
                    })
                })
            })
            .max_by(|a, b| a.prepared_round.cmp(&b.prepared_round));
        
        let signed_payloads = validated_round_changes.iter()
            .map(|rc_wrapper| rc_wrapper.bft_message().signed_payload.clone())
            .collect();

        Some(Self::new(signed_payloads, best_prepared_cert_candidate))
    }
}


/// Manages RoundChange messages for a given block height.
struct RoundChangeStatus {
    // Maps validator address to the RoundChange message they sent for this target round.
    received_messages: HashMap<Address, RoundChange>, 
    quorum_size: usize,
    actioned: bool, // True if a certificate has been created from this status
}

impl RoundChangeStatus {
    fn new(quorum_size: usize) -> Self {
        Self { received_messages: HashMap::new(), quorum_size, actioned: false }
    }

    fn add_message(&mut self, msg: RoundChange) -> Result<bool, QbftError> {
        if self.actioned {
            return Ok(false); // Already actioned, no change
        }
        let author = msg.author()?;
        // Only add if new or different (though QBFT spec implies one RC per validator per target round)
        // For simplicity, allow overwrite if it's somehow re-validated and different, though unlikely.
        self.received_messages.insert(author, msg);
        Ok(self.has_quorum())
    }

    fn has_quorum(&self) -> bool {
        self.received_messages.len() >= self.quorum_size
    }

    fn can_create_certificate(&self) -> bool {
        self.has_quorum() && !self.actioned
    }

    /// Consumes the status to create artifacts if quorum is met.
    fn try_create_artifacts(mut self) -> Option<RoundChangeArtifacts> {
        if self.can_create_certificate() {
            self.actioned = true;
            let collected_messages: Vec<RoundChange> = self.received_messages.into_values().collect();
            RoundChangeArtifacts::try_create(&collected_messages)
        } else {
            None
        }
    }
}

pub struct RoundChangeManager {
    // Cache of RoundChangeStatus, keyed by the target round identifier.
    round_change_cache: HashMap<ConsensusRoundIdentifier, RoundChangeStatus>,
    // Quorum required for a specific round to be considered ready for change (e.g., 2f+1).
    round_specific_quorum: usize, 
    // Quorum for early round change (e.g., f+1 messages for *any* future round).
    early_round_change_f_plus_1_quorum: usize, 
    // Validator for incoming RoundChange messages for the current height.
    message_validator: RoundChangeMessageValidator, // Placeholder
    // For logging purposes, tracks the latest target round seen from each validator.
    latest_round_seen_from_validator: HashMap<Address, ConsensusRoundIdentifier>,
}

impl RoundChangeManager {
    pub fn new(
        round_specific_quorum: usize, 
        early_round_change_f_plus_1_quorum: usize, 
        message_validator: RoundChangeMessageValidator
    ) -> Self {
        Self {
            round_change_cache: HashMap::new(),
            round_specific_quorum,
            early_round_change_f_plus_1_quorum,
            message_validator,
            latest_round_seen_from_validator: HashMap::new(),
        }
    }

    /// Appends a received RoundChange message.
    /// Returns RoundChangeArtifacts if a full quorum for a specific target round is met.
    pub fn append_round_change_message(&mut self, msg: RoundChange) -> Result<Option<RoundChangeArtifacts>, QbftError> {
        if !self.message_validator.validate(&msg)? { // Placeholder validation
            log::warn!("Received invalid RoundChange message: {:?}", msg);
            return Err(QbftError::ValidationError("Invalid RoundChange message".into()));
        }

        let target_round_id = *msg.round_identifier();
        let author = msg.author()?;

        // Update latest seen round for this validator
        if let Some(existing_seen_round) = self.latest_round_seen_from_validator.get_mut(&author) {
            if target_round_id.round_number > existing_seen_round.round_number || 
               (target_round_id.round_number == existing_seen_round.round_number && 
                msg.payload().prepared_round_metadata.is_some() && existing_seen_round.round_number == target_round_id.round_number && 
                msg.payload().prepared_round_metadata.as_ref().map_or(0, |m| m.prepared_round) > 
                self.round_change_cache.get(&target_round_id).and_then(|rs| rs.received_messages.get(&author)).and_then(|prev_msg| prev_msg.payload().prepared_round_metadata.as_ref()).map_or(0, |m|m.prepared_round) 
               )
            {
                *existing_seen_round = target_round_id;
            }
        } else {
            self.latest_round_seen_from_validator.insert(author, target_round_id);
        }

        let status_entry = self.round_change_cache
            .entry(target_round_id)
            .or_insert_with(|| RoundChangeStatus::new(self.round_specific_quorum));
        
        if status_entry.add_message(msg)? {
            // Quorum met for this specific target_round_id, try to create artifacts
            // To avoid borrow checker issues with consuming from cache, we remove, try_create, then re-insert if not fully actioned.
            if status_entry.can_create_certificate() { // Check again before removing
                 let status = self.round_change_cache.remove(&target_round_id).unwrap(); // Safe unwrap
                 if let Some(artifacts) = status.try_create_artifacts() {
                     return Ok(Some(artifacts));
                 } // If try_create_artifacts returned None (e.g. couldn't make cert), status is consumed.
            }
        }
        Ok(None)
    }

    /// Checks if an early round change (f+1) condition is met for any future round.
    /// Returns the lowest future round number that meets this f+1 condition.
    pub fn lowest_future_round_with_early_quorum(&self, current_round_number: u32, current_sequence_number: u64) -> Option<u32> {
        let mut future_round_counts: HashMap<u32, usize> = HashMap::new();
        
        for (_validator, round_id) in &self.latest_round_seen_from_validator {
            if round_id.sequence_number == current_sequence_number && round_id.round_number > current_round_number {
                *future_round_counts.entry(round_id.round_number).or_insert(0) += 1;
            }
        }

        future_round_counts.into_iter()
            .filter(|(_round, count)| *count >= self.early_round_change_f_plus_1_quorum)
            .map(|(round, _count)| round)
            .min()
    }

    /// Discards cached round change messages for rounds prior to the given one.
    pub fn discard_rounds_prior_to(&mut self, completed_round_identifier: &ConsensusRoundIdentifier) {
        self.round_change_cache.retain(|round_id, _status| 
            round_id.sequence_number > completed_round_identifier.sequence_number || 
            (round_id.sequence_number == completed_round_identifier.sequence_number && 
             round_id.round_number > completed_round_identifier.round_number)
        );
        // Also prune latest_round_seen_from_validator if necessary, though it's less critical for memory.
    }
} 