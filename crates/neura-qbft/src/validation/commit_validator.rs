use crate::messagewrappers::Commit;
use crate::validation::ValidationContext; // Assuming ValidationContext is re-exported by validation/mod.rs
use crate::error::QbftError;
use crate::payload::QbftPayload; // Added import
use alloy_primitives::B256;
// Add other necessary imports if the actual validation logic needs them

pub trait CommitValidator: Send + Sync {
    fn validate_commit(&self, commit: &Commit, context: &ValidationContext) -> Result<(), QbftError>;
}

#[derive(Default)] 
pub struct CommitValidatorImpl;

impl CommitValidatorImpl {
    pub fn new() -> Self {
        // TODO: This might take dependencies like QbftConfig later.
        Self::default()
    }
}

impl CommitValidator for CommitValidatorImpl { 
    fn validate_commit(&self, commit: &Commit, context: &ValidationContext) -> Result<(), QbftError> { 
        // Check 1: Commit message's RoundIdentifier must match the ValidationContext's current round and sequence.
        let payload_round_identifier = commit.payload().round_identifier();
        if payload_round_identifier.sequence_number != context.current_sequence_number ||
           payload_round_identifier.round_number != context.current_round_number {
            log::warn!(
                "Invalid Commit: Payload round identifier {:?} does not match context round identifier {:?}/{:?}",
                payload_round_identifier, context.current_sequence_number, context.current_round_number
            );
            return Err(QbftError::MessageRoundMismatch { 
                message_type: "Commit".to_string(),
                expected_sequence: context.current_sequence_number,
                expected_round: context.current_round_number,
                actual_sequence: payload_round_identifier.sequence_number,
                actual_round: payload_round_identifier.round_number,
            });
        }

        // Check 2: Commit message's digest must match the ValidationContext's accepted_proposal_digest.
        let commit_digest = commit.payload().digest; // This is a B256 Hash
        if context.accepted_proposal_digest.is_none() {
            log::error!("Invalid Commit: ValidationContext has no accepted_proposal_digest for round {:?}/{:?}. This should not happen if a proposal was accepted.",
                context.current_sequence_number, context.current_round_number
            );
            return Err(QbftError::InternalError("Context missing accepted proposal digest for Commit validation".to_string()));
        }
        if Some(commit_digest) != context.accepted_proposal_digest {
            log::warn!(
                "Invalid Commit: Digest {:?} does not match accepted proposal digest {:?} for round {:?}/{:?}",
                commit_digest, context.accepted_proposal_digest, context.current_sequence_number, context.current_round_number
            );
            return Err(QbftError::CommitDigestMismatch);
        }

        // Check 3: Author of the Commit message must be one of the current_validators.
        let author = commit.author()?; // This is an Address
        if !context.current_validators.contains(&author) {
            log::warn!(
                "Invalid Commit: Author {:?} is not in the current validator set for round {:?}/{:?}. Validators: {:?}",
                author, context.current_sequence_number, context.current_round_number, context.current_validators
            );
            return Err(QbftError::NotAValidator { sender: author });
        }

        // Check 4: Validate the committed_seal signature.
        // `committed_seal` is `RlpSignature` which wraps `alloy_primitives::Signature`.
        // `RlpSignature` implements `Deref<Target = alloy_primitives::Signature>`.
        let committed_seal_ref = &commit.payload().committed_seal; 
        let digest_b256: B256 = commit_digest; // commit_digest is already B256

        match committed_seal_ref.recover_address_from_prehash(&digest_b256) {
            Ok(recovered_address_for_seal) => {
                if recovered_address_for_seal != author {
                    log::warn!(
                        "Invalid Commit: Commit seal signature recovery produced address {:?} which does not match author {:?} for round {:?}/{:?}",
                        recovered_address_for_seal,
                        author,
                        context.current_sequence_number, 
                        context.current_round_number
                    );
                    return Err(QbftError::InvalidSignature { sender: author }); 
                }
                // If recovery matches author, the signature is valid for that author over the digest.
            }
            Err(e) => {
                log::warn!(
                    "Invalid Commit: Failed to recover address from commit seal signature for claimed author {:?} and digest {:?}: {}. Round {:?}/{:?}", 
                    author, digest_b256, e, context.current_sequence_number, context.current_round_number
                );
                return Err(QbftError::CryptoError(format!("Commit seal signature recovery failed: {}", e)));
            }
        }
        
        Ok(())
    }
} 
