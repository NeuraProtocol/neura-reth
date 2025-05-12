// This file declares the modules within the tests directory.

// Declare modules for specific validator tests
mod proposal_validator_tests;
mod prepare_validator_tests;
mod commit_validator_tests;
mod round_change_message_validator_tests;

// Declare a module for common test helpers
pub mod common_helpers; // Made public so other test modules can use it 