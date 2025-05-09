use std::sync::Arc;
use crate::messagewrappers::{Commit, Proposal};
use crate::types::QbftFinalState;
use crate::error::QbftError;
use alloy_primitives::{B256 as Hash, Address, Signature as AlloySignature};

pub struct CommitValidator {
    final_state: Arc<dyn QbftFinalState>,
    expected_proposal_digest: Hash,
}

impl CommitValidator {
    pub fn new(
        final_state: Arc<dyn QbftFinalState>,
        accepted_proposal: &Proposal, // Pass the accepted proposal to set context
    ) -> Self {
        Self {
            final_state,
            expected_proposal_digest: accepted_proposal.block().hash(),
        }
    }

    pub fn validate_commit(&self, commit: &Commit) -> Result<bool, QbftError> {
        let author_address = commit.author()?;
        let payload = commit.payload();

        // 1. Author is a current validator
        if !self.final_state.is_validator(author_address) {
            log::warn!("Commit from non-validator {:?}. Ignoring.", author_address);
            return Ok(false);
        }

        // 2. Commit message's digest matches the accepted proposal's digest
        if payload.digest != self.expected_proposal_digest {
            log::warn!(
                "Commit digest {:?} does not match expected proposal digest {:?}. Author: {:?}", 
                payload.digest, self.expected_proposal_digest, author_address
            );
            return Ok(false);
        }

        // 3. Validate committed_seal: 
        // It must be a signature by `author_address` over `payload.digest`.
        // `payload.digest` is already a hash (B256), so it's used as a prehashed message for recovery.
        let seal_signer_address = match payload.committed_seal.recover_address_from_prehash(&payload.digest) {
            Ok(address) => address,
            Err(e) => {
                log::warn!(
                    "Failed to recover signer from committed_seal. Commit author: {:?}, Digest: {:?}, Error: {}", 
                    author_address, payload.digest, e
                );
                return Ok(false); // Recovery failed, so seal is invalid
            }
        };

        if seal_signer_address != author_address {
            log::warn!(
                "Committed_seal in Commit from {:?} was not signed by them. Seal signed by: {:?}, Expected: {:?}", 
                author_address, seal_signer_address, author_address
            );
            return Ok(false);
        }

        // 4. Outer signature of Commit (SignedData<CommitPayload>) is validated by commit.author() implicitly during its call.

        log::debug!("Commit from {:?} for digest {:?} passed validation.", author_address, payload.digest);
        Ok(true)
    }
} 