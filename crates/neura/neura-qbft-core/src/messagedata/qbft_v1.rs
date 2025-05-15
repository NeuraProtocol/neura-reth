// crates/neura-qbft/src/messagedata/qbft_v1.rs

// Corresponds to QbftV1.java
// Defines the P2P message codes for QBFT version 1 messages.

pub const PROPOSAL: u8 = 0x00;
pub const PREPARE: u8 = 0x01;
pub const COMMIT: u8 = 0x02;
pub const ROUND_CHANGE: u8 = 0x03;

// As in Java's QbftV1.MESSAGE_SPACE - indicates the number of distinct message types.
// Not strictly needed for encoding/decoding but good for context if we build
// P2P handling logic that uses this.
pub const MESSAGE_SPACE: usize = 4;

// It can also be useful to have a way to get a string name for these codes,
// similar to `messageName` in `Istanbul100SubProtocol.java`.

pub fn message_name(code: u8) -> &'static str {
    match code {
        PROPOSAL => "Proposal",
        PREPARE => "Prepare",
        COMMIT => "Commit",
        ROUND_CHANGE => "RoundChange",
        _ => "<Invalid/Unknown QBFT Message Code>",
    }
} 