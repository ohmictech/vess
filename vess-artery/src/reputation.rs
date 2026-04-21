//! Peer reputation tracking with latency and reliability scoring.
//!
//! Every interaction with a peer is recorded. The reputation score
//! combines:
//!
//! - **Latency**: Exponential moving average (EMA) of round-trip times.
//! - **Reliability**: Success rate over recent interactions.
//!
//! Peers are ranked by a composite score:
//!
//! ```text
//! score = reliability × (1.0 / (1.0 + latency_ms / 1000.0))
//! ```
//!
//! Higher is better. A fast, reliable peer scores ~1.0; a slow, flaky
//! peer scores close to 0.
//!
//! The reputation table is persisted across restarts and restored from
//! the artery snapshot.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Smoothing factor for the exponential moving average of latency.
/// α = 0.3 means recent samples weigh ~30%, history ~70%.
const LATENCY_EMA_ALPHA: f64 = 0.3;

/// Maximum number of recent interactions tracked per peer.
const INTERACTION_WINDOW: u64 = 100;

/// A single peer's reputation record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerReputation {
    /// Exponential moving average of round-trip latency in milliseconds.
    pub latency_ema_ms: f64,
    /// Number of successful interactions in the current window.
    pub successes: u64,
    /// Number of failed interactions in the current window.
    pub failures: u64,
    /// Total lifetime interactions (for display/diagnostics).
    pub total_interactions: u64,
    /// Unix timestamp of last successful interaction.
    pub last_seen: u64,
}

impl PeerReputation {
    fn new() -> Self {
        Self {
            latency_ema_ms: 0.0,
            successes: 0,
            failures: 0,
            total_interactions: 0,
            last_seen: 0,
        }
    }

    /// Record a successful interaction with measured latency.
    pub fn record_success(&mut self, latency_ms: f64) {
        self.total_interactions += 1;
        self.successes += 1;

        // Update EMA.
        if self.total_interactions == 1 {
            self.latency_ema_ms = latency_ms;
        } else {
            self.latency_ema_ms =
                LATENCY_EMA_ALPHA * latency_ms + (1.0 - LATENCY_EMA_ALPHA) * self.latency_ema_ms;
        }

        self.last_seen = now_unix();

        // Decay window: if total exceeds window, scale both down.
        self.decay_window();
    }

    /// Record a failed interaction (timeout, error, bad response).
    pub fn record_failure(&mut self) {
        self.total_interactions += 1;
        self.failures += 1;
        self.decay_window();
    }

    /// Composite reputation score in [0.0, 1.0].
    ///
    /// `reliability × (1.0 / (1.0 + latency_ms / 1000.0))`
    pub fn score(&self) -> f64 {
        let total = self.successes + self.failures;
        if total == 0 {
            return 0.5; // Unknown peer — neutral score.
        }
        let reliability = self.successes as f64 / total as f64;
        let latency_factor = 1.0 / (1.0 + self.latency_ema_ms / 1000.0);
        reliability * latency_factor
    }

    /// Decay the interaction window to prevent ancient history from dominating.
    fn decay_window(&mut self) {
        let total = self.successes + self.failures;
        if total > INTERACTION_WINDOW {
            // Halve both counters to gradually forget old data.
            self.successes /= 2;
            self.failures /= 2;
        }
    }
}

/// Maximum number of peers tracked in the reputation table.
/// Prevents unbounded memory growth from Sybil flooding.
const MAX_TRACKED_PEERS: usize = 50_000;

/// Tracks reputation for all known peers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReputationTable {
    peers: HashMap<[u8; 32], PeerReputation>,
}

impl Default for ReputationTable {
    fn default() -> Self {
        Self::new()
    }
}

impl ReputationTable {
    /// Create an empty reputation table.
    pub fn new() -> Self {
        Self {
            peers: HashMap::new(),
        }
    }

    /// If the table is at capacity, evict the lowest-scored peer.
    fn maybe_evict(&mut self) {
        if self.peers.len() < MAX_TRACKED_PEERS {
            return;
        }
        // Find the peer with the worst score.
        if let Some((&worst_id, _)) = self.peers.iter().min_by(|(_, a), (_, b)| {
            a.score()
                .partial_cmp(&b.score())
                .unwrap_or(std::cmp::Ordering::Equal)
        }) {
            self.peers.remove(&worst_id);
        }
    }

    /// Record a successful interaction with a peer.
    pub fn record_success(&mut self, peer_id: [u8; 32], latency_ms: f64) {
        if !self.peers.contains_key(&peer_id) {
            self.maybe_evict();
        }
        self.peers
            .entry(peer_id)
            .or_insert_with(PeerReputation::new)
            .record_success(latency_ms);
    }

    /// Record a failed interaction with a peer.
    pub fn record_failure(&mut self, peer_id: [u8; 32]) {
        if !self.peers.contains_key(&peer_id) {
            self.maybe_evict();
        }
        self.peers
            .entry(peer_id)
            .or_insert_with(PeerReputation::new)
            .record_failure();
    }

    /// Get the reputation for a specific peer, if tracked.
    pub fn get(&self, peer_id: &[u8; 32]) -> Option<&PeerReputation> {
        self.peers.get(peer_id)
    }

    /// Return peer IDs sorted by score (best first).
    pub fn ranked_peers(&self) -> Vec<([u8; 32], f64)> {
        let mut ranked: Vec<([u8; 32], f64)> = self
            .peers
            .iter()
            .map(|(&id, rep)| (id, rep.score()))
            .collect();
        ranked.sort_by(|(_, a), (_, b)| b.partial_cmp(a).unwrap_or(std::cmp::Ordering::Equal));
        ranked
    }

    /// Select up to `k` peers from `candidates`, preferring higher-scored peers.
    ///
    /// Candidates not in the table get a neutral score of 0.5.
    /// The `age_factors` slice (same length as `candidates`) applies a
    /// churn penalty: recently-created node IDs are deprioritised so
    /// Sybil ID rotation gives reduced influence during probation.
    /// If `age_factors` is empty, no penalty is applied (backwards compat).
    /// Returns indices into `candidates` sorted by descending composite score.
    pub fn select_best_with_age(
        &self,
        candidates: &[[u8; 32]],
        k: usize,
        age_factors: &[f64],
    ) -> Vec<usize> {
        let mut scored: Vec<(usize, f64)> = candidates
            .iter()
            .enumerate()
            .map(|(i, id)| {
                let rep_score = self.peers.get(id).map_or(0.5, |r| r.score());
                let age_f = age_factors.get(i).copied().unwrap_or(1.0);
                (i, rep_score * age_f)
            })
            .collect();
        scored.sort_by(|(_, a), (_, b)| b.partial_cmp(a).unwrap_or(std::cmp::Ordering::Equal));
        scored.into_iter().take(k).map(|(i, _)| i).collect()
    }

    /// Select up to `k` peers from `candidates`, preferring higher-scored peers.
    ///
    /// Candidates not in the table get a neutral score of 0.5.
    /// Returns indices into `candidates` sorted by descending score.
    pub fn select_best(&self, candidates: &[[u8; 32]], k: usize) -> Vec<usize> {
        self.select_best_with_age(candidates, k, &[])
    }

    /// Number of tracked peers.
    pub fn len(&self) -> usize {
        self.peers.len()
    }

    /// Whether the table is empty.
    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }

    /// Export all records for persistence.
    pub fn export(&self) -> Vec<([u8; 32], PeerReputation)> {
        self.peers.iter().map(|(&k, v)| (k, v.clone())).collect()
    }

    /// Import records from persistence.
    pub fn import(&mut self, records: Vec<([u8; 32], PeerReputation)>) {
        for (id, rep) in records {
            self.peers.insert(id, rep);
        }
    }
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_peer_has_neutral_score() {
        let table = ReputationTable::new();
        let peer: [u8; 32] = [0x01; 32];
        assert!(table.get(&peer).is_none());
    }

    #[test]
    fn success_increases_score() {
        let mut table = ReputationTable::new();
        let peer: [u8; 32] = [0x01; 32];

        table.record_success(peer, 50.0);
        table.record_success(peer, 40.0);
        table.record_success(peer, 45.0);

        let rep = table.get(&peer).unwrap();
        assert!(rep.score() > 0.8);
        assert_eq!(rep.successes, 3);
        assert_eq!(rep.failures, 0);
    }

    #[test]
    fn failure_decreases_score() {
        let mut table = ReputationTable::new();
        let peer: [u8; 32] = [0x01; 32];

        table.record_success(peer, 50.0);
        table.record_failure(peer);
        table.record_failure(peer);

        let rep = table.get(&peer).unwrap();
        // 1 success / 3 total = 0.33 reliability
        assert!(rep.score() < 0.5);
    }

    #[test]
    fn high_latency_lowers_score() {
        let mut table = ReputationTable::new();
        let fast: [u8; 32] = [0x01; 32];
        let slow: [u8; 32] = [0x02; 32];

        table.record_success(fast, 10.0);
        table.record_success(slow, 5000.0);

        let fast_score = table.get(&fast).unwrap().score();
        let slow_score = table.get(&slow).unwrap().score();
        assert!(fast_score > slow_score);
    }

    #[test]
    fn select_best_prefers_high_score() {
        let mut table = ReputationTable::new();
        let good: [u8; 32] = [0x01; 32];
        let bad: [u8; 32] = [0x02; 32];
        let unknown: [u8; 32] = [0x03; 32];

        // Good peer: fast, reliable.
        for _ in 0..10 {
            table.record_success(good, 20.0);
        }
        // Bad peer: slow, unreliable.
        for _ in 0..5 {
            table.record_failure(bad);
        }
        table.record_success(bad, 3000.0);

        let candidates = [bad, good, unknown];
        let best = table.select_best(&candidates, 2);

        // Good peer (index 1) should be first.
        assert_eq!(best[0], 1);
    }

    #[test]
    fn ranking_order() {
        let mut table = ReputationTable::new();
        let a: [u8; 32] = [0x01; 32];
        let b: [u8; 32] = [0x02; 32];
        let c: [u8; 32] = [0x03; 32];

        for _ in 0..10 {
            table.record_success(a, 10.0);
        }
        for _ in 0..10 {
            table.record_success(b, 100.0);
        }
        for _ in 0..5 {
            table.record_failure(c);
        }

        let ranked = table.ranked_peers();
        assert_eq!(ranked.len(), 3);
        // a (fast+reliable) > b (slow+reliable) > c (unreliable)
        assert_eq!(ranked[0].0, a);
        assert_eq!(ranked[1].0, b);
        assert_eq!(ranked[2].0, c);
    }

    #[test]
    fn export_import_roundtrip() {
        let mut table = ReputationTable::new();
        let peer: [u8; 32] = [0x01; 32];
        table.record_success(peer, 50.0);
        table.record_success(peer, 40.0);

        let exported = table.export();
        let mut restored = ReputationTable::new();
        restored.import(exported);

        let rep = restored.get(&peer).unwrap();
        assert_eq!(rep.successes, 2);
        assert_eq!(rep.failures, 0);
    }

    #[test]
    fn window_decay_prevents_unbounded_growth() {
        let mut table = ReputationTable::new();
        let peer: [u8; 32] = [0x01; 32];

        for _ in 0..200 {
            table.record_success(peer, 30.0);
        }

        let rep = table.get(&peer).unwrap();
        // Window decay should have kicked in.
        assert!(rep.successes < 200);
        // But score should still be high (all successes).
        assert!(rep.score() > 0.9);
    }
}
