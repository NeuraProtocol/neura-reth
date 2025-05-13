# QBFT Consensus Implementation Plan

## Overview

This document outlines the implementation plan for QBFT (Quorum Byzantine Fault Tolerance) consensus in the Reth Ethereum client. QBFT is an enterprise-grade consensus protocol designed for private networks with immediate finality.

The purpose of this application is to make reference to the Java application in the neura-chain folder (which is a fork of Besu), research how QBFT consensus was implemented in this application (relevant because Besu is also an Ethereum client which has been modified to allow QBFT consensus when enabled) and implement this into a new crate for neura-qbft in rust. as much as possible you should avoid making changes to base functionality and code outside of the create implemented for neuro-qbft. Please look at the cargo.toml file in the root of the neura-reth to see what libraries or other crates have been used and as much as possible do research to understand those before implementation.

Once the implementation is complete, the QBFT consensus module will be integrated with Reth's node builder architecture to allow easy switching between consensus mechanisms (PoW, PoA, QBFT) through configuration.

## Agent Personality

Your personality is that you are a top level Rust developer you are methodical when you Know that the answer is clear and easy you move forward with implementation.That there are sometimes issues with the IDE You are part of, any time there seems to be a deviation between the changes you have proposed and the code that is written then you will pause and wait for further input. It should not be expected that the user manually will change code to fix problems however it is acceptable to template the Implementation with todos To get the basic structure down first and then come back to it in subsequent rounds.

Development should be done Carefully and tested in between changes and when you believe that there is a good point at which code should be committed I when the application successfully builds or a significant part of work is done then please pause and wait for the user to commit the changes before proceeding.

It should also be Kept in mind That The application should be kept as close as possible to the source so that upstream changes can be merged easily.

These instructions for your personality are not complete and may may be modified So you should come back and check the agent personality every time you start a new run to see if there have been new changes.

The below sections of this implementation plan which consists of completed work current status, integration plan and summary should be updated as necessary during the development process.

## Current Status & Completed Work

**Phase 0: Planning and Initial Setup - COMPLETED**

- Detailed implementation plan drafted and reviewed.
- Workspace and dependencies understood.

**Phase 1: Research and Foundation (Understanding Besu's QBFT) - COMPLETED**

- **Deep Dive into Besu's QBFT:**
  - Analyzed QBFT implementation in `neura-chain` (Besu fork) Java codebase.
  - Focused on core logic in `neura-chain/consensus/qbft-core/` and adaptor classes in `neura-chain/consensus/qbft/adaptor/`.
  - Key Java classes and their roles identified across `statemachine/`, `validation/`, `types/`, `messagedata/`, `messagewrappers/`, `payload/` directories.
  - Studied the official QBFT specification (entethalliance.github.io) and EIP-650.
- **Library/Crate Review:**
  - Relevant dependencies from `neura-reth` root `Cargo.toml` (e.g., `alloy-primitives`, `k256`) incorporated into `neura_qbft_core`.

**Phase 2: Crate Scaffolding and Core Logic (`neura_qbft_core` crate) - IN PROGRESS (Core Structures & RLP Testing Implemented, Validation & State Machine Logic Next)**

1. **Create `neura_qbft_core` Crate: - COMPLETED**
    - Set up the new crate at `crates/neura-qbft` (package name `neura_qbft_core`).
    - Defined initial module structure (e.g., `error.rs`, `lib.rs`, and submodules for `types`, `payload`, `messagewrappers`, `statemachine`, `validation`).
    - Managed dependencies in `crates/neura-qbft/Cargo.toml` and resolved workspace dependency issues.

2. **Define Core Data Structures & Translate Java Logic: - LARGELY COMPLETED (Compiles with Warnings)**
    - Implemented Rust structs and enums for QBFT messages, payloads, types, and state machine components, translating logic from Besu's Java implementation.
        - `error.rs`: `QbftError` enum.
        - `types/`: `ConsensusRoundIdentifier`, `QbftBlockHeader`, `QbftBlock`, `SignedData<T>`, `BftExtraData`, `BftExtraDataCodec`, `NodeKey`, `RlpSignature`, placeholder traits (`QbftFinalState`, `RoundTimer`, etc.).
        - `messagedata/`: Message type codes.
        - `payload/`: `QbftPayload` trait, payload structs (`ProposalPayload`, `PreparePayload`, `CommitPayload`, `RoundChangePayload`, `PreparedRoundMetadata`), `MessageFactory`.
        - `messagewrappers/`: `BftMessage<P>`, message wrapper structs (`Proposal`, `Prepare`, `Commit`, `RoundChange`), `PreparedCertificateWrapper`.
        - `statemachine/`: `PreparedCertificate` (struct), `RoundState`, `QbftRound`, `RoundChangeManager`, `QbftBlockHeightManager`, `QbftController`, `QbftMinedBlockObserver` trait.
        - `validation/`: Placeholder validator traits and factory traits, concrete validator structs (`ProposalValidator`, etc.) and factory implementations.
    - Addressed RLP encoding/decoding using `alloy-rlp` derives and manual implementations where necessary.
    - Implemented ECDSA signature creation and recovery logic.
    - **Current State:** The `neura_qbft_core` crate compiles successfully without errors or warnings. All core message types and payloads have RLP serialization/deserialization unit tests. Key functionalities like `SignedData` and `MessageFactory` also have initial unit tests. The validation module structure (validators, factories) has been refactored and placeholder implementations are in place.

**Date: 2024-05-16 - Addressing Build Warnings and Refining State Machine**
    ***Build Status:** The `neura_qbft_core` crate compiles with several `dead_code` warnings in `qbft_round.rs`, `qbft_block_height_manager.rs`, and `qbft_controller.rs`.
    *   **Analysis & Plan for Warnings:**
        *`QbftRound`: Unused fields (`locked_block`, `proposal_sent`, `prepare_sent`) and methods (`get_block_to_propose`, etc.) related to an alternative proposal flow will be marked with `#[allow(dead_code)]`. The integration of `locked_block` into the main proposal path is noted as a future task. The `final_state` field usage via `RoundState` is considered acceptable.
        *   `QbftBlockHeightManager`: Redundant `round_change_message_validator` field, `round_timeout_count` field, and `send_round_change_message` method will be removed. A missing link where `QbftRound` should signal block finalization to `QbftBlockHeightManager` (to use `process_round_state_change`) will be addressed by modifying `QbftRound::import_block_to_chain` to return the imported block, which `QbftBlockHeightManager` will then use.
        *`QbftController`: Redundant `create_height_manager` helper method will be removed.
    *   **Progress:** Actively working on applying these changes to resolve warnings and improve code structure. - **COMPLETED**

**Date: 2024-05-17 - Integrated Locked Block Handling & Achieved Clean Build**
    ***Build Status:** The `neura_qbft_core` crate now compiles without any errors or warnings.
    *   **Locked Block Integration:**
        *Modified `QbftRound` to store `locked_block` as `Option<CertifiedPrepareInfo>`.
        *   Updated `QbftRound::new` to accept initial locked info.
        *Enhanced proposal logic in `QbftRound::create_and_propose_block` and `QbftRound::start_round_with_prepared_artifacts` to prioritize proposing a locked block or a better block from round change certificates.
        *   `QbftRound::handle_prepare_message` now updates `self.locked_block` with a `CertifiedPrepareInfo` when the round state becomes prepared.
        *Changed `QbftBlockHeightManager.locked_block` to `Option<CertifiedPrepareInfo>`.
        *   Added `QbftRound::locked_info()` getter.
        *Updated `QbftBlockHeightManager::advance_to_new_round` to retrieve `locked_info` from the outgoing round, update its own `locked_block`, and pass it to the new `QbftRound`.
        *   `QbftBlockHeightManager::process_round_state_change` now clears its `locked_block` upon block finalization for the height.
    *   **Overall:** The core mechanism for handling locked blocks and re-proposals, along with their propagation between round and height managers, is now in place. - **COMPLETED**

**Date: 2024-05-19 - RLP Testing Completed**
    ***Build Status:** The `neura_qbft_core` crate compiles without any errors or warnings.
    *   **RLP Testing:** Completed unit tests for RLP serialization and deserialization for all core QBFT message types and their payloads (`ProposalPayload`, `Proposal`, `PreparePayload`, `Prepare`, `CommitPayload`, `Commit`, `RoundChangePayload`, `RoundChange`). `MessageFactory` and `SignedData` also have foundational tests.
    *   **Next Focus:** Message Validation Logic.

**Date: 2024-05-20 - Validation Module Refactoring Completed & Clean Build**
    ***Build Status:** The `neura_qbft_core` crate compiles without any errors or warnings.
    *   **Validation Module:**
        *Successfully refactored the validation module into individual validator files (`proposal_validator.rs`, `prepare_validator.rs`, `commit_validator.rs`, `round_change_message_validator.rs`) and their respective factory files (`message_validator_factory.rs`, `round_change_message_validator_factory.rs`).
        *   Each validator file defines its specific trait (e.g., `ProposalValidator`) and a placeholder `Impl` struct (e.g., `ProposalValidatorImpl`).
        *`validation/mod.rs` correctly declares all submodules and re-exports necessary items.
        *   `ValidationContext` struct has been defined in `proposal_validator.rs` and is used across relevant validators and state machine components.
        *Resolved all linter errors and warnings related to imports, struct/trait definitions, and method signatures across the validation module and its consumers (e.g., `qbft_block_height_manager.rs`, `qbft_round.rs`, `round_state.rs`).
        *   The old monolithic `message_validator.rs` has been deleted.
    ***Next Focus:** Implementing the actual validation rules within each validator `Impl` struct.
    *   **Update (Current):** `ProposalValidatorImpl` has been significantly implemented with comprehensive unit tests. The core validation logic and unit tests for `PrepareValidatorImpl` are also now complete. The primary focus is now shifting to implementing `CommitValidatorImpl` and its unit tests.

**Date: 2024-05-21 - `round_change_message_validator_tests.rs` Passing**
    ***Build Status:** The `neura_qbft_core` crate compiles with numerous warnings (mostly unused code), but all tests within `validation::tests::commit_validator_tests.rs` and `validation::tests::round_change_message_validator_tests.rs` are now passing.
    *   **Validation Module:**
        *   All core validation logic for Proposal, Prepare, Commit, and RoundChange messages is implemented.
        *   Extensive unit tests for CommitValidator and RoundChangeMessageValidator have been debugged and are now passing. This involved fixing issues related to:
            *   Incorrect error variants being returned or asserted.
            *   Panics during test setup (e.g., premature validation in constructors).
            *   Missing parent headers in mock state causing panics during proposer calculation.
            *   Incorrect proposer calculation logic used in tests compared to the mock implementation.
            *   Mistakes in wrapping inner validation errors (e.g., Proposal/Prepare errors within RoundChange validation).
            *   Mismatches between expected and actual error message strings in assertions.
            *   Borrow checker errors related to test setup.
    ***Current Focus:** All `neura_qbft_core` tests are passing. Next is to decide on addressing warnings or proceeding to state machine implementation.

**Date: 2024-05-22 - `neura_qbft_core` All Tests Passing & Warnings Reduced**
    ***Build Status:*** All tests in the `neura_qbft_core` crate are passing. Compiler warnings have been addressed, reducing them from 37 to 8 (remaining warnings are for unused helper functions in test code, which can be addressed later or as part of a general cleanup pass).
    *   **Validation Module:**
        *   All core validation logic for Proposal, Prepare, Commit, and RoundChange messages is implemented and tested.
        *   Unit tests for `CommitValidator`, `RoundChangeMessageValidator`, `ProposalValidator`, and `PrepareValidator` are passing.
        *   Corrected error variants, fixed panics during test setup, and resolved issues with mock final state providing necessary parent headers.
        *   Addressed numerous borrow checker errors and logic issues within the tests and validator implementations.
        *   Refined assertions to match exact error messages and variants.
    *   **Types & Payloads:**
        *   Core data structures (`SignedData`, `QbftBlockHeader`, `CommitPayload`, `RoundChangePayload`, etc.) are stable and used throughout the tests.
        *   RLP encoding/decoding for these types is implicitly tested via the validation logic that relies on correct message construction and parsing.

**Date: 2024-05-22 - `neura_consensus_qbft` Initial Implementation**
    ***Build Status:** The `neura_consensus_qbft` crate compiles with a few `dead_code` warnings, which have been addressed with `#[allow(dead_code)]` attributes.
    *   **Core Implementation:**
        *   Successfully implemented `QbftConsensus` struct with `HeaderValidator` and `Consensus` trait implementations.
        *   Implemented `RethQbftFinalState` adapter for QBFT state management.
        *   Implemented `RethRoundTimer` for handling round timeouts.
        *   Fixed type resolution issues with `SealedBlock` and `SealedHeader` in validation methods.
        *   Added proper error handling with `QbftConsensusError`.
    *   **Next Focus:** Integration with `neura_qbft_core` components and implementation of remaining QBFT consensus logic.

### Next Steps:

1. **Complete `neura_consensus_qbft` Implementation:**
    *   **Current Focus:** Implement remaining QBFT consensus logic:
        *   Complete the `validate_body_against_header` implementation.
        *   Implement block proposal and validation logic.
        *   Integrate with `neura_qbft_core`'s message handling and state machine.
        *   Add proper error handling and logging.
    *   **Testing:**
        *   Add unit tests for `QbftConsensus` and its components.
        *   Test integration with `neura_qbft_core` components.
        *   Verify proper error handling and edge cases.

2. **Integration with Reth Node Builder:**
    *   Create QBFT-specific configuration types.
    *   Implement node builder integration for QBFT consensus.
    *   Add configuration validation and error handling.

3. **Block Import and Finalization:**
    *   Implement block import logic for QBFT consensus.
    *   Add proper finalization handling.
    *   Integrate with Reth's block processing pipeline.

4. **Testing and Documentation:**
    *   Add comprehensive tests for the entire QBFT consensus implementation.
    *   Document the implementation details and configuration options.
    *   Add examples and usage instructions.

## Next Steps

**Continue Phase 2: Crate Scaffolding and Core Logic (`neura_qbft_core` crate)**

1. **Resolve Build Warnings & Refine State Machine Connections:** - **COMPLETED**
    - Apply the planned changes to address the `dead_code` warnings. - **COMPLETED**
    - Ensure `QbftRound` correctly signals block finalization to `QbftBlockHeightManager`. - **COMPLETED**
    - Integrate `locked_block` handling into the main proposal flow in `QbftRound` and `QbftBlockHeightManager`. - **COMPLETED**

2. **Refine Validator Logic (Message Validation Logic):** - **COMPLETED**
    - The structural refactoring of the validation module (individual validators, factories, `ValidationContext`) is complete.
    - `ProposalValidatorImpl` is now largely implemented with extensive tests.
    - The core validation logic for `PrepareValidatorImpl` is implemented, and its unit tests are passing.
    - `CommitValidatorImpl` is implemented, and its unit tests are passing.
    - `RoundChangeMessageValidatorImpl` is implemented, and its unit tests are passing after significant debugging.

3. **Verify Crate-Level Test Suite:** - **COMPLETED**
    - **Immediate Next Step:** Run all tests for the `neura_qbft_core` crate (`cargo test -p neura_qbft_core --lib | cat`) to ensure no regressions or previously unnoticed failures exist in other test suites (e.g., `prepare_validator_tests`, `proposal_validator_tests`, state machine tests). - **COMPLETED (All tests passing)**
    - Analyze and address any failures found in the full crate test run. - **COMPLETED (No failures found)**

4. **Address Compiler Warnings (Optional):** - **PENDING DECISION**
    - Manually review and fix the remaining compiler warnings (unused imports, variables, functions).

5. **Implement QBFT State Machine Logic (Continued):** - **NEXT MAJOR STEP**
    - Flesh out the internal logic of methods within `QbftRound`, `QbftBlockHeightManager`, and `QbftController`. This involves:
        - Handling incoming messages (Proposals, Prepares, Commits, RoundChanges) by dispatching them to the appropriate round and state.
        - Implementing the state transition logic within `RoundState` and `QbftRound` based on message validation and quorum achievement.
        - Managing round timeouts and initiating round changes.
        - Handling block proposal creation and re-proposal logic (including use of `PreparedCertificateWrapper`).
        - Interacting with placeholder traits for block creation, validation, and networking (`QbftBlockCreator`, `QbftBlockImporter`, `ValidatorMulticaster`, `RoundTimer`, `BlockTimer`).
    - Address `// TODO:` comments within the `neura_qbft_core` codebase.

6. **Complete Placeholder Trait Definitions:**
    - Solidify the definitions of traits in `types/qbft_final_state.rs` and elsewhere (e.g., `QbftFinalState`, `RoundTimer`, `BlockTimer`, `QbftBlockCreatorFactory`, `ValidatorMulticaster`, `QbftBlockImporter`, `QbftMinedBlockObserver`). Ensure they accurately represent the interactions needed with the external Reth environment.

7. **Comprehensive Unit & Integration Testing for `neura_qbft_core`:**
    - Write unit tests for all critical components:
        - RLP serialization/deserialization of all message types and payloads. - **COMPLETED**
        - `MessageFactory` operations. - **COMPLETED (Initial Tests)**
        - Signature creation and verification in `SignedData`. - **COMPLETED**
        - Individual validator logic. - **COMPLETED (All validator test suites passing)**
        - `RoundState` transitions.
        - `QbftRound` message handling and state changes.
        - `RoundChangeManager` logic.
    - Develop integration tests within the crate to test interactions between these components (e.g., a sequence of messages leading to a prepared or committed state).

**Phase 3: Adapter Layer (`neura_qbft_adapter` or similar crate - New Crate)**

1. **Create Adapter Crate:**
    - Set up a new crate (e.g., `crates/neura-qbft-adapter`) that depends on `neura_qbft_core` and relevant Reth crates.
2. **Implement `neura_qbft_core` Traits:**
    - Provide concrete implementations for the traits defined in `neura_qbft_core` (e.g., `QbftFinalState`, timers, block creator, multicaster, block importer) by bridging them to Reth's functionalities (database access, networking, block processing).
    - Example: `RethQbftFinalState` would implement `QbftFinalState` by querying Reth's state. `RethValidatorMulticaster` would use Reth's P2P layer.

**Phase 4: Integration with Reth**

1. **Consensus Abstraction Layer:**
    - Implement Reth's `Consensus` trait (or equivalent) using the `QbftController` from `neura_qbft_core` and the adapter components from `neura_qbft_adapter`.
2. **Node Builder Integration:**
    - Modify Reth's `NodeBuilder` to allow selection and instantiation of the QBFT consensus engine.
    - Handle QBFT-specific configurations.
3. **Block Import and Finalization:**
    - Integrate QBFT block validation and import into Reth's block processing pipeline.
    - Ensure that blocks finalized by QBFT are correctly marked and handled by the client.

**Phase 5: Advanced Features & End-to-End Testing**

1. **Implement Advanced QBFT Features (if any pending):**
    - E.g., dynamic validator updates if specified and not yet covered.
2. **End-to-End Testing:**
    - Set up local test networks with multiple Reth nodes running QBFT.
    - Test block production, finality, and round changes in a multi-node environment.
    - Test scenarios like validator failures and network partitions.
3. **Configuration and CLI:**
    - Add configuration options for enabling and tuning QBFT.
4. **Benchmarking and Optimization:**
    - Identify and address any performance bottlenecks.

**Phase 6: Documentation and Finalization**

1. **Code Documentation:**
    - Add comprehensive Rustdoc comments to all public APIs in `neura_qbft_core` and the adapter crate.
2. **User Documentation:**
    - Update documentation on how to configure and run a Reth node with QBFT consensus.
3. **Update `IMPLEMENTATION_PLAN.md`:**
    - Mark completed sections and update the overall status throughout the project.

## References

- [EIP-650: Istanbul Byzantine Fault Tolerance](https://github.com/ethereum/EIPs/issues/650)
- [Hyperledger Besu QBFT Documentation](https://besu.hyperledger.org/en/stable/HowTo/Configure/Consensus-Protocols/QBFT/)
- [QBFT Consensus Protocol Specification](https://entethalliance.github.io/client-spec/qbft_spec.html)

## Resources

- [QBFT Blockchain Consensus Protocol Specification v1](https://entethalliance.github.io/client-spec/qbft_spec.html)
- [Hyperledger Besu QBFT Implementation](https://github.com/hyperledger/besu)
- [GoQuorum QBFT Documentation](https://docs.goquorum.consensys.io/configure-and-manage/configure/consensus-protocols/qbft)

## Summary

The project aims to integrate QBFT consensus into Reth. The `neura_qbft_core` crate, encapsulating the core QBFT logic, now successfully compiles (with warnings) and **passes all its unit tests**, including all individual validator test suites (`ProposalValidator`, `PrepareValidator`, `CommitValidator`, `RoundChangeMessageValidator`). This marks the completion of the core validation logic implementation and its initial verification. The next decision point is whether to address compiler warnings or proceed directly to implementing the QBFT state machine logic. Subsequent phases will focus on completing the state machine behaviors, creating an adapter layer to bridge `neura_qbft_core` with Reth's systems, integrating it into the Reth client, and performing end-to-end testing.
