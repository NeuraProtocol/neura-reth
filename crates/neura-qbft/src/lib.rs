// crates/neura-qbft/src/lib.rs

pub mod error;
pub mod statemachine;
pub mod types;
pub mod messagedata;
pub mod messagewrappers;
pub mod payload;
pub mod validation;
pub mod mocks;

// Re-export key types for easier use, similar to how a prelude might work.
// We will populate this as we define the types.

// pub use error::QbftError;
// pub use types::ConsensusRoundIdentifier; // Example


// TODO: Consider adding a general QbftConfig struct here or in types/ 