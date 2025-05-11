// crates/neura-qbft/src/validation/mod.rs

// Declare submodules. These should correspond to .rs files in the validation/ directory.
pub mod message_validator_factory;         // For MessageValidatorFactory trait and Impl
pub mod round_change_message_validator_factory; // For RoundChangeMessageValidatorFactory trait and Impl
pub mod proposal_validator;                // For ProposalValidator trait, Impl, and ValidationContext
pub mod prepare_validator;                 // For PrepareValidator trait, Impl
pub mod commit_validator;                  // For CommitValidator trait, Impl
pub mod round_change_message_validator;  // For RoundChangeMessageValidator trait, Impl

// TODO: Declare other validator modules as they are created:
// pub mod round_change_message_validator;  // For RoundChangeMessageValidator trait, Impl


// --- Re-export key traits and structs from the submodules ---

// From proposal_validator.rs
// ValidationContext is now defined and used internally by RoundState after refactor, or passed directly to validator methods.
// It's defined in proposal_validator.rs but might not need to be pub use from validation::mod if not directly constructed outside.
// For now, keeping its re-export to see if other modules directly use validation::ValidationContext.
pub use proposal_validator::{ValidationContext, ProposalValidator, ProposalValidatorImpl};

// From prepare_validator.rs
pub use prepare_validator::{PrepareValidator, PrepareValidatorImpl};

// From commit_validator.rs
pub use commit_validator::{CommitValidator, CommitValidatorImpl};

// From round_change_message_validator.rs
pub use round_change_message_validator::{RoundChangeMessageValidator, RoundChangeMessageValidatorImpl};

// From factory modules.
pub use message_validator_factory::{MessageValidatorFactory, MessageValidatorFactoryImpl};
pub use round_change_message_validator_factory::{RoundChangeMessageValidatorFactory, RoundChangeMessageValidatorFactoryImpl};

// TODO: Re-export other validator traits AND their Impl structs as they are defined in their modules:
// pub use round_change_message_validator::{RoundChangeMessageValidator, RoundChangeMessageValidatorImpl};

// All other definitions (structs, traits, impls, use statements for them) 
// should be within their respective submodule files, not directly in this mod.rs.
 