//! Gossip utilities for peer selection and rate limiting.
//!
//! Provides XOR-distance based peer selection (Kademlia-style) and
//! per-peer rate limiting for gossip message forwarding.

use serde::{Deserialize, Serialize};

/// Configuration for the gossip protocol.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GossipConfig {
    /// Number of nearest neighbours to forward messages to.
    /// Higher K = more overlap = stronger consistency.
    /// Default: 6 (similar to Kademlia's K=20 scaled for smaller networks).
    pub k_neighbors: usize,

    /// Maximum hop count for gossip propagation.
    /// Each relay decrements this counter; at 0 the message is not forwarded.
    pub max_hops: u8,
}

impl Default for GossipConfig {
    fn default() -> Self {
        Self {
            k_neighbors: 6,
            max_hops: 3,
        }
    }
}

/// XOR-distance between two 32-byte node IDs.
///
/// Used for Kademlia-style nearest-neighbour selection and DHT routing.
pub fn xor_distance(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut result = [0u8; 32];
    for i in 0..32 {
        result[i] = a[i] ^ b[i];
    }
    result
}

/// Compare two XOR distances (byte-array comparison, MSB first).
///
/// Returns `std::cmp::Ordering` suitable for sorting peers by closeness.
pub fn compare_distance(d1: &[u8; 32], d2: &[u8; 32]) -> std::cmp::Ordering {
    d1.cmp(d2)
}

/// Select the K nearest peers from a list, measured by XOR distance to a target.
///
/// Returns indices into `peer_ids` sorted by ascending distance.
pub fn k_nearest(target: &[u8; 32], peer_ids: &[[u8; 32]], k: usize) -> Vec<usize> {
    let mut indexed: Vec<(usize, [u8; 32])> = peer_ids
        .iter()
        .enumerate()
        .map(|(i, id)| (i, xor_distance(target, id)))
        .collect();

    indexed.sort_by(|(_, d1), (_, d2)| compare_distance(d1, d2));
    indexed.into_iter().take(k).map(|(i, _)| i).collect()
}

/// Number of additional random peers to include in each gossip round
/// beyond the K-nearest. Breaks positional Sybil attacks: an attacker
/// can populate the XOR neighbourhood but cannot predict which random
/// peers also receive the message. Set to 4 so that even a 20% colluding
/// cartel cannot reliably partition gossip paths.
pub const RANDOM_FAN_OUT: usize = 4;

/// Wider fan-out for ownership claims and ownership genesis.
///
/// Ownership claims are critical for double-spend resolution — if a claim
/// only reaches the K-nearest DHT nodes, a network partition could leave
/// parts of the network unaware of a transfer. Doubling the random
/// fan-out ensures claims propagate to more diverse network regions.
pub const OWNERSHIP_FAN_OUT: usize = 8;

/// Compute a dynamic random fan-out that scales with estimated network
/// size.  At small scales (< 1 000 nodes) this returns the hardcoded
/// `base` value.  For larger networks it grows as
/// `min(base + ceil(ln(N) / ln(100)), max_fan)` to ensure gossip
/// coverage keeps pace with network growth.
pub fn dynamic_fan_out(estimated_network_size: usize, base: usize, max_fan: usize) -> usize {
    if estimated_network_size <= 1_000 {
        return base;
    }
    let log_ratio = ((estimated_network_size as f64).ln() / 100_f64.ln()).ceil() as usize;
    base.saturating_add(log_ratio).min(max_fan)
}

/// Select R random peer indices that are NOT in the `exclude` set.
///
/// Uses Fisher-Yates partial shuffle for O(R) performance.
pub fn random_fan_out(total_peers: usize, exclude: &[usize], r: usize) -> Vec<usize> {
    use rand::seq::SliceRandom;
    let candidates: Vec<usize> = (0..total_peers).filter(|i| !exclude.contains(i)).collect();
    if candidates.is_empty() {
        return Vec::new();
    }
    let mut rng = rand::thread_rng();
    let mut shuffled = candidates;
    shuffled.shuffle(&mut rng);
    shuffled.into_iter().take(r).collect()
}

/// Per-peer rate limiter using a sliding window counter.
///
/// Limits the number of messages accepted from any single peer within
/// a configurable time window. Prevents gossip flood attacks.
/// Tracks consecutive rate-limit violations ("strikes") per peer
/// to support automatic banishment of persistent abusers.
pub struct PeerRateLimiter {
    /// Maximum messages per window per peer.
    pub max_per_window: u32,
    /// Window duration in seconds.
    pub window_secs: u64,
    /// Peer → (count, window_start_timestamp).
    counters: HashMap<[u8; 32], (u32, u64)>,
    /// Peer → consecutive rate-limit violation count ("strikes").
    strikes: HashMap<[u8; 32], u32>,
    /// Maximum tracked peers (prevents memory growth from Sybils).
    max_peers: usize,
    /// Number of consecutive violations before a peer is flagged for banishment.
    pub strike_threshold: u32,
}

use std::collections::HashMap;

impl PeerRateLimiter {
    /// Create a new rate limiter.
    pub fn new(max_per_window: u32, window_secs: u64) -> Self {
        Self {
            max_per_window,
            window_secs,
            counters: HashMap::new(),
            strikes: HashMap::new(),
            max_peers: 10_000,
            strike_threshold: 3,
        }
    }

    /// Default: 200 messages per 10-second window per peer, banish after 3 strikes.
    pub fn with_defaults() -> Self {
        Self::new(200, 10)
    }

    /// Check if a message from `peer_id` should be accepted.
    /// Returns `true` if allowed, `false` if rate-limited.
    ///
    /// When a peer is rate-limited, its strike counter increments.
    /// A successful (allowed) message resets the strike counter.
    pub fn allow(&mut self, peer_id: &[u8; 32]) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let allowed = if let Some((count, window_start)) = self.counters.get_mut(peer_id) {
            if now.saturating_sub(*window_start) >= self.window_secs {
                // Window expired — reset.
                *count = 1;
                *window_start = now;
                true
            } else if *count >= self.max_per_window {
                false
            } else {
                *count += 1;
                true
            }
        } else {
            // New peer — enforce global cap.
            if self.counters.len() >= self.max_peers {
                // Evict oldest entries (peers with oldest window_start).
                let oldest = self
                    .counters
                    .iter()
                    .min_by_key(|(_, (_, ws))| *ws)
                    .map(|(k, _)| *k);
                if let Some(k) = oldest {
                    self.counters.remove(&k);
                }
            }
            self.counters.insert(*peer_id, (1, now));
            true
        };

        if allowed {
            // Good behavior resets strikes.
            self.strikes.remove(peer_id);
        } else {
            let strikes = self.strikes.entry(*peer_id).or_insert(0);
            *strikes = strikes.saturating_add(1);
        }
        allowed
    }

    /// Returns the current strike count for a peer.
    pub fn strikes(&self, peer_id: &[u8; 32]) -> u32 {
        self.strikes.get(peer_id).copied().unwrap_or(0)
    }

    /// Returns `true` if the peer has exceeded the strike threshold.
    pub fn should_banish(&self, peer_id: &[u8; 32]) -> bool {
        self.strikes(peer_id) >= self.strike_threshold
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xor_distance_self_is_zero() {
        let id = [0x42; 32];
        assert_eq!(xor_distance(&id, &id), [0u8; 32]);
    }

    #[test]
    fn k_nearest_selects_closest() {
        let target = [0x00; 32];
        let mut close = [0x00; 32];
        close[31] = 1; // distance = 1
        let far = [0xFF; 32]; // distance = max

        let peers = vec![far, close];
        let nearest = k_nearest(&target, &peers, 1);
        assert_eq!(nearest, vec![1]); // index 1 is closer
    }

    #[test]
    fn random_fan_out_excludes_k_nearest() {
        let exclude = vec![0, 2, 4];
        let result = random_fan_out(6, &exclude, 2);
        assert_eq!(result.len(), 2);
        for idx in &result {
            assert!(!exclude.contains(idx));
        }
    }

    #[test]
    fn random_fan_out_caps_at_available() {
        // Only 1 peer not excluded → at most 1 returned even though r=3
        let exclude = vec![0, 1, 2, 3];
        let result = random_fan_out(5, &exclude, 3);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0], 4);
    }

    #[test]
    fn random_fan_out_empty_when_all_excluded() {
        let exclude = vec![0, 1, 2];
        let result = random_fan_out(3, &exclude, 2);
        assert!(result.is_empty());
    }

    #[test]
    fn dynamic_fan_out_stays_at_base_for_small_networks() {
        assert_eq!(dynamic_fan_out(100, 4, 12), 4);
        assert_eq!(dynamic_fan_out(1_000, 4, 12), 4);
    }

    #[test]
    fn dynamic_fan_out_grows_with_network_size() {
        let f_10k = dynamic_fan_out(10_000, 4, 12);
        let f_1m = dynamic_fan_out(1_000_000, 4, 12);
        assert!(f_10k > 4, "should grow beyond base at 10K nodes");
        assert!(f_1m > f_10k, "should grow further at 1M nodes");
        assert!(f_1m <= 12, "should not exceed max_fan");
    }
}
