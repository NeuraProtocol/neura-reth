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

*   Detailed implementation plan drafted and reviewed.
*   Workspace and dependencies understood.

**Phase 1: Research and Foundation (Understanding Besu's QBFT) - COMPLETED**

*   **Deep Dive into Besu's QBFT:**
    *   Analyzed QBFT implementation in `neura-chain` (Besu fork) Java codebase.
    *   Focused on core logic in `neura-chain/consensus/qbft-core/` and adaptor classes in `neura-chain/consensus/qbft/adaptor/`.
    *   Key Java classes and their roles identified across `statemachine/`, `validation/`, `types/`, `messagedata/`, `messagewrappers/`, `payload/` directories.
    *   Studied the official QBFT specification (entethalliance.github.io) and EIP-650.
*   **Library/Crate Review:**
    *   Relevant dependencies from `neura-reth` root `Cargo.toml` (e.g., `alloy-primitives`, `k256`) incorporated into `neura_qbft_core`.

**Phase 2: Core Crates Implementation**

1.  **`neura_qbft_core` Crate - COMPLETED**
    *   **Crate Setup & Module Structure:** Completed.
    *   **Core Data Structures & Logic Translation:** Completed. Includes QBFT messages, payloads, types, state machine components. RLP encoding/decoding and ECDSA logic implemented.
    *   **Validation Module:** All core validation logic (Proposal, Prepare, Commit, RoundChange) implemented and unit tested. Refactored into individual validator files.
    *   **State Machine Logic:**
        *   `QbftRound` (`statemachine/qbft_round.rs`): Core message handlers (`handle_proposal_message`, `handle_prepare_message`, `handle_commit_message`, `import_block_to_chain`) and message sending (`send_prepare`, `send_commit`) implemented and unit tested.
        *   `QbftBlockHeightManager` (`statemachine/qbft_block_height_manager.rs`): Message/event handlers (`handle_round_change_message`, `handle_round_timeout_event`, `handle_block_timer_expiry`, and handlers for proposals, prepares, commits) implemented and unit tested. Logic for advancing rounds also implemented.
        *   `QbftController` (`statemachine/qbft_controller.rs`): Reviewed; manages `QbftBlockHeightManager` instances, dispatches messages/timer events.
    *   **RLP Testing:** Comprehensive unit tests for RLP serialization/deserialization of all core QBFT message types and payloads completed.
    *   **Service Trait Definitions (`types/`):** Definitions for `QbftBlockCreator` & `QbftBlockCreatorFactory`, `QbftBlockImporter`, `ValidatorMulticaster`, `RoundTimer` & `BlockTimer` reviewed and deemed sufficiently defined.
    *   **Build Status:** Compiles without errors or actionable warnings. All unit tests passing.

2.  **`neura_consensus_qbft` Crate (Initial Reth Integration Layer) - IN PROGRESS**
    *   **Crate Setup & Dependencies:** Completed. Resolved `Cargo.toml` issues, including workspace dependency for `reth-node-api`.
    *   **Module Structure:** Basic `lib.rs`, `consensus.rs`, `error.rs`, `services.rs` created and cleaned up.
        *   `consensus.rs`: Now an empty module placeholder, as main `QbftConsensus<NT>` struct and trait implementations are in `lib.rs`.
        *   `error.rs`: `QbftConsensusError` enum defined, correctly using `reth_consensus::ConsensusError`.
    *   **Core Trait Implementations (in `lib.rs`):**
        *   `QbftConsensus<NT>` struct defined.
        *   Implemented `reth_consensus::HeaderValidator` trait.
        *   Implemented `reth_consensus::Consensus` trait (methods `validate_block_pre_execution`, `validate_body_against_header`).
        *   `RethQbftFinalState<NT>`: Adapter struct implementing `neura_qbft_core::types::QbftFinalState` using Reth's provider. All methods implemented and unit tested.
        *   `RethRoundTimer`: Adapter struct implementing `neura_qbft_core::types::RoundTimer` using Tokio. All methods implemented and unit tested.
    *   **Build Status:** Compiles without errors or warnings. All unit tests reported as passing. Linter warnings resolved.

3.  **Implement QBFT State Machine Logic (`neura_qbft_core`):** - **IN PROGRESS (QbftRound core logic complete, QbftBlockHeightManager next)**
    *   Flesh out the internal logic of methods within `QbftRound`, `QbftBlockHeightManager`, and `QbftController`.
    *   **`QbftRound` Core Logic & Testing (Execution Client Focus):** - **COMPLETED**
        *   Implemented `handle_proposal_message`, `handle_prepare_message`, `handle_commit_message`, `send_prepare`, `send_commit`, `import_block_to_chain`.
        *   Integrated locked block handling.
        *   Comprehensive unit tests for `QbftRound` completed and passing.
    *   **Next:** Implement and test `QbftBlockHeightManager` message handlers and event processing.

4.  **Complete Placeholder Trait Definitions (`neura_qbft_core`):**
    *   Solidify the definitions of traits in `types/` (e.g., `QbftBlockCreatorFactory`, `ValidatorMulticaster`, `QbftBlockImporter`, `QbftMinedBlockObserver`). Ensure they accurately represent the interactions needed with the external Reth environment. This will be refined as state machine and adapter implementations progress.

5.  **Comprehensive Unit & Integration Testing for `neura_qbft_core` State Machine:**
    *   Write unit tests for all critical state machine components:
        *   `RoundState` transitions.
        *   `QbftRound` message handling and state changes (largely covered).
        *   `RoundChangeManager` logic.
        *   `QbftBlockHeightManager` event and message handling.
    *   Develop integration tests within `neura_qbft_core` to test interactions between state machine components (e.g., a sequence of messages leading to round changes, block production across heights).

**Phase 3: Adapter Layer (`neura_consensus_qbft` - Completing Implementations)**

*   This phase now focuses on completing the implementations within `neura_consensus_qbft` that bridge `neura_qbft_core` traits to Reth components, beyond the already completed `RethQbftFinalState` and `RethRoundTimer`.
1.  **Implement Remaining `neura_qbft_core` Service Traits:**
    *   Provide concrete implementations in `neura_consensus_qbft/src/services.rs` for:
        *   `BlockTimer` (as `RethBlockTimer`): **COMPLETED**. Uses Tokio tasks and event sender.
        *   `QbftBlockCreatorFactory` and `QbftBlockCreator` (as `RethBlockCreatorFactory` and `RethBlockCreator`): **COMPLETED** for creating empty blocks. Correctly formats `BftExtraData`.
        *   `QbftBlockImporter` (as `RethQbftBlockImporter`): **IN PROGRESS**.
            *   Helper function `qbft_block_to_reth_sealed_block` **COMPLETED**: Correctly converts `QbftBlock` to `reth_primitives::SealedBlock` (handles nonce, empty transactions/ommers, sealing).
            *   Main `import_block` method is a **STUB**. Next step is to implement actual block execution and chain update logic using `BlockExecutorFactory` and `ProviderFactory`.
        *   `ValidatorMulticaster` (using Reth's P2P layer/network service).
        *   `QbftMinedBlockObserver` (if needed, or integrate its logic directly).
    *   **Build Status:** Compiles without errors or warnings. All unit tests reported as passing. Linter warnings resolved.

**Phase 4: Integration with Reth Node**

1.  **Consensus Engine Integration:**
    *   Ensure the `QbftConsensus<NT>` struct in `neura_consensus_qbft/src/lib.rs` correctly utilizes the `QbftController` from `neura_qbft_core` and the fully implemented service adapters (from Phase 3) to drive the consensus process.
2.  **Node Builder Integration:**
    *   Modify Reth's `NodeBuilder` to allow selection and instantiation of the QBFT consensus engine.
    *   Handle QBFT-specific configurations (e.g., genesis validators, block period).
3.  **Block Import and Finalization Hooks:**
    *   Integrate QBFT block validation and import into Reth's block processing pipeline.
    *   Ensure that blocks finalized by QBFT are correctly marked and handled by the client.
    *   Handle message passing from the network to the `QbftController`.

**Phase 5: Advanced Features & End-to-End Testing**

1.  **Implement Advanced QBFT Features (if any pending):**
    *   E.g., dynamic validator updates if specified and not yet covered.
2.  **End-to-End Testing:**
    *   Set up local test networks with multiple Reth nodes running QBFT.
    *   Test block production, finality, and round changes in a multi-node environment.
    *   Test scenarios like validator failures and network partitions.
3.  **Configuration and CLI:**
    *   Add configuration options for enabling and tuning QBFT.
4.  **Benchmarking and Optimization:**
    *   Identify and address any performance bottlenecks.

**Phase 6: Documentation and Finalization**

1.  **Code Documentation:**
    *   Add comprehensive Rustdoc comments to all public APIs.
2.  **User Documentation:**
    *   Update documentation on how to configure and run a Reth node with QBFT consensus.
3.  **Update `IMPLEMENTATION_PLAN.md`:**
    *   Mark completed sections and update the overall status throughout the project.

## References

- [EIP-650: Istanbul Byzantine Fault Tolerance](https://github.com/ethereum/EIPs/issues/650)
- [Hyperledger Besu QBFT Documentation](https://besu.hyperledger.org/en/stable/HowTo/Configure/Consensus-Protocols/QBFT/)
- [QBFT Consensus Protocol Specification](https://entethalliance.github.io/client-spec/qbft_spec.html)

## Summary

The project aims to integrate QBFT consensus into Reth, with an initial focus on an execution client capable of syncing with Besu QBFT nodes, deferring full validator functionality.

**`neura_qbft_core` Crate:** This crate is now **COMPLETED**. It encapsulates the core QBFT data structures, validation logic, RLP encoding, and the state machine (`QbftRound`, `QbftBlockHeightManager`, `QbftController`). All service trait definitions in `types/` have been reviewed. The crate compiles without errors or warnings, and all unit tests are passing.

**`neura_consensus_qbft` Crate:** This crate is **IN PROGRESS** and adapts `neura_qbft_core` to Reth's interfaces.
*   It includes foundational implementations for `QbftConsensus<NT>` (implementing `reth_consensus::Consensus` and `reth_consensus::HeaderValidator`), with methods currently stubbed.
*   Service implementations in `services.rs`:
    *   `RethQbftFinalState<NT>`: Completed and tested.
    *   `RethRoundTimer`: Completed and tested.
    *   `RethBlockTimer`: Completed and tested.
    *   `RethBlockCreatorFactory` and `RethBlockCreator`: Implemented and tested for creating empty blocks with correct `BftExtraData`.
    *   `RethQbftBlockImporter`: The `qbft_block_to_reth_sealed_block` function is complete and correctly converts QBFT blocks to Reth's `SealedBlock`. The main `import_block` method is a stub.
*   The crate compiles without errors or warnings, and all unit tests are reported as passing.

The immediate next step is to implement the block execution and chain update logic within the `import_block` method of `RethQbftBlockImporter` in the `neura_consensus_qbft` crate.