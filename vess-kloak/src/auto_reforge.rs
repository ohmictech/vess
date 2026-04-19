//! Bill consolidation scheduler.
//!
//! Identifies bills that can be consolidated (e.g. five D1s → one D5)
//! to keep the billfold compact. Bills never expire, so there is no
//! freshness-based reforging.

use std::collections::BTreeMap;
use vess_foundry::{Denomination, VessBill};

/// A group of bills that can be consolidated into a higher denomination.
#[derive(Debug, Clone)]
pub struct ConsolidationCandidate {
    /// Indices into the billfold of the bills to consolidate.
    pub indices: Vec<usize>,
    /// The target denomination after consolidation.
    pub target_denomination: Denomination,
}

/// Scheduler that identifies bills eligible for consolidation.
pub struct ConsolidationScheduler;

impl ConsolidationScheduler {
    /// Create a new consolidation scheduler.
    pub fn new() -> Self {
        Self
    }

    /// Scan bills and find groups that can be consolidated.
    ///
    /// For each denomination present, checks whether N bills of that
    /// denomination can form a valid higher 1-2-5 denomination
    /// (i.e. `N × value` is itself a valid denomination).
    pub fn scan(&self, bills: &[VessBill]) -> Vec<ConsolidationCandidate> {
        let mut by_denom: BTreeMap<Denomination, Vec<usize>> = BTreeMap::new();
        for (i, b) in bills.iter().enumerate() {
            by_denom.entry(b.denomination).or_default().push(i);
        }

        let mut candidates = Vec::new();
        for (&source, indices) in &by_denom {
            let src_val = source.value();

            // Try grouping 2..=count bills of this denomination.
            for count in 2..=indices.len() {
                if let Some(target_val) = src_val.checked_mul(count as u64) {
                    if Denomination::is_valid(target_val) {
                        if let Some(target) = Denomination::from_value(target_val) {
                            candidates.push(ConsolidationCandidate {
                                indices: indices[..count].to_vec(),
                                target_denomination: target,
                            });
                        }
                    }
                }
            }
        }

        candidates
    }

    /// Quick check: are any consolidations possible?
    pub fn has_candidates(&self, bills: &[VessBill]) -> bool {
        !self.scan(bills).is_empty()
    }
}

impl Default for ConsolidationScheduler {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_bill(denom: Denomination) -> VessBill {
        VessBill {
            denomination: denom,
            digest: [0xBB; 32],
            created_at: 12345,
            stealth_id: [0xCC; 32],
            dht_index: 0,
            mint_id: rand::random(),
            chain_tip: rand::random(),
            chain_depth: 0,
        }
    }

    #[test]
    fn no_consolidation_for_single_bills() {
        let scheduler = ConsolidationScheduler::new();
        let bills = vec![make_bill(Denomination::D10), make_bill(Denomination::D5)];

        assert!(!scheduler.has_candidates(&bills));
    }

    #[test]
    fn five_d1_can_consolidate_to_d5() {
        let scheduler = ConsolidationScheduler::new();
        let bills: Vec<VessBill> = (0..5).map(|_| make_bill(Denomination::D1)).collect();

        let candidates = scheduler.scan(&bills);
        assert!(!candidates.is_empty());
        // Should find at least the D5 consolidation.
        assert!(candidates.iter().any(|c| c.target_denomination == Denomination::D5));
    }

    #[test]
    fn two_d1_can_consolidate_to_d2() {
        let scheduler = ConsolidationScheduler::new();
        let bills: Vec<VessBill> = (0..2).map(|_| make_bill(Denomination::D1)).collect();

        let candidates = scheduler.scan(&bills);
        assert!(candidates.iter().any(|c| c.target_denomination == Denomination::D2));
    }
}
