use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use crate::types::{ConsensusRoundIdentifier, RoundTimer, BlockTimer, QbftBlockHeader};

// --- MockRoundTimer ---
#[derive(Default, Clone)] // Clone needed if Arc<MockRoundTimer> is cloned
pub struct MockRoundTimer {
    // Store active timers. In a real system, these would have associated expiry times.
    // For a mock, we just track which ones are "active".
    active_round_timers: Arc<Mutex<HashSet<ConsensusRoundIdentifier>>>,
}

impl MockRoundTimer {
    pub fn new() -> Self {
        Self { active_round_timers: Arc::new(Mutex::new(HashSet::new())) }
    }

    // Test utility to check if a timer for a round is active
    pub fn is_timer_active(&self, round: &ConsensusRoundIdentifier) -> bool {
        self.active_round_timers.lock().unwrap().contains(round)
    }

    // Test utility to get all active timers
    pub fn get_active_timers(&self) -> HashSet<ConsensusRoundIdentifier> {
        self.active_round_timers.lock().unwrap().clone()
    }

    // Test utility to manually clear a timer (e.g. for simulating expiry and re-check)
    // In a real system, expiry would trigger an event. Here, tests manage it.
    pub fn clear_timer(&self, round: &ConsensusRoundIdentifier) {
        self.active_round_timers.lock().unwrap().remove(round);
    }
}

impl RoundTimer for MockRoundTimer {
    fn start_timer(&self, round: ConsensusRoundIdentifier) {
        log::debug!("MockRoundTimer: Starting timer for round {:?}", round);
        self.active_round_timers.lock().unwrap().insert(round);
    }

    fn cancel_timer(&self, round: ConsensusRoundIdentifier) {
        log::debug!("MockRoundTimer: Cancelling timer for round {:?}", round);
        self.active_round_timers.lock().unwrap().remove(&round);
    }
}

// --- MockBlockTimer ---
#[derive(Default, Clone)]
pub struct MockBlockTimer {
    // Store active block timers, similar to round timers for this mock.
    active_block_timers: Arc<Mutex<HashSet<ConsensusRoundIdentifier>>>,
    // Configurable minimum block period for get_timestamp_for_future_block
    min_block_period_seconds: u64,
}

impl MockBlockTimer {
    pub fn new(min_block_period_seconds: u64) -> Self {
        Self {
            active_block_timers: Arc::new(Mutex::new(HashSet::new())),
            min_block_period_seconds,
        }
    }
    // Test utility similar to MockRoundTimer could be added if needed.
}

impl BlockTimer for MockBlockTimer {
    fn start_timer(&self, round: ConsensusRoundIdentifier, _parent_timestamp_seconds: u64) {
        log::debug!("MockBlockTimer: Starting timer for round {:?} (parent_ts: {})", round, _parent_timestamp_seconds);
        self.active_block_timers.lock().unwrap().insert(round);
    }

    fn cancel_timer(&self, round: ConsensusRoundIdentifier) {
        log::debug!("MockBlockTimer: Cancelling timer for round {:?}", round);
        self.active_block_timers.lock().unwrap().remove(&round);
    }

    fn get_timestamp_for_future_block(&self, _round: &ConsensusRoundIdentifier, parent_timestamp_seconds: u64) -> u64 {
        // Simple mock logic: parent_timestamp + configured min_block_period_seconds
        // A real implementation might consider current time or slot-based timing.
        let future_ts = parent_timestamp_seconds + self.min_block_period_seconds;
        log::debug!("MockBlockTimer: get_timestamp_for_future_block for round {:?} (parent: {}) -> {}", _round, parent_timestamp_seconds, future_ts);
        future_ts
    }
} 