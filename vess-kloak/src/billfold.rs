//! BillFold — a collection of owned Vess bills.
//!
//! The billfold is the wallet's primary data structure. It stores bills,
//! tracks total balance, and provides query methods for denomination
//! breakdown. Bills are stored permanently in the DHT and never expire.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use vess_foundry::{Denomination, VessBill};

/// ML-DSA-65 spend credentials for a bill, indexed by mint_id.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpendCredential {
    pub spend_vk: Vec<u8>,
    pub spend_sk: Vec<u8>,
}

/// A wallet's collection of Vess bills.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BillFold {
    bills: Vec<VessBill>,
    /// Mint IDs of bills currently in-flight or limbo.
    /// Reserved bills are excluded from selection but still owned.
    /// The sender can release them on retraction.
    #[serde(default)]
    reserved: HashSet<[u8; 32]>,
    /// Unix timestamp (seconds) when each bill was reserved.
    /// Used to auto-release after the limbo TTL expires.
    #[serde(default)]
    reserve_times: HashMap<[u8; 32], u64>,
    /// ML-DSA-65 spend credentials keyed by mint_id.
    /// Required to sign ownership transfers.
    #[serde(default)]
    spend_credentials: HashMap<[u8; 32], SpendCredential>,
}

impl BillFold {
    /// Create an empty billfold.
    pub fn new() -> Self {
        Self {
            bills: Vec::new(),
            reserved: HashSet::new(),
            reserve_times: HashMap::new(),
            spend_credentials: HashMap::new(),
        }
    }

    /// Add a bill to the billfold.
    /// Returns `false` (and does not store) if a bill with the same
    /// mint_id already exists — prevents duplicates from multi-path
    /// broadcast.
    pub fn deposit(&mut self, bill: VessBill) -> bool {
        if self.bills.iter().any(|b| b.mint_id == bill.mint_id) {
            return false;
        }
        self.bills.push(bill);
        true
    }

    /// Add a bill with its spend credentials in one call.
    pub fn deposit_with_credentials(
        &mut self,
        bill: VessBill,
        cred: SpendCredential,
    ) -> bool {
        let mint_id = bill.mint_id;
        if self.deposit(bill) {
            self.spend_credentials.insert(mint_id, cred);
            true
        } else {
            false
        }
    }

    /// Remove a bill by mint_id. Returns the removed bill if found.
    /// Also removes any stored spend credentials.
    pub fn withdraw(&mut self, mint_id: &[u8; 32]) -> Option<VessBill> {
        if let Some(pos) = self.bills.iter().position(|b| &b.mint_id == mint_id) {
            self.spend_credentials.remove(mint_id);
            Some(self.bills.remove(pos))
        } else {
            None
        }
    }

    /// Look up spend credentials for a bill by mint_id.
    pub fn get_credentials(&self, mint_id: &[u8; 32]) -> Option<&SpendCredential> {
        self.spend_credentials.get(mint_id)
    }

    /// Total value of all bills in the billfold.
    pub fn balance(&self) -> u64 {
        self.bills.iter().map(|b| b.denomination.value()).sum()
    }

    /// Number of bills.
    pub fn count(&self) -> usize {
        self.bills.len()
    }

    /// All bills as a slice.
    pub fn bills(&self) -> &[VessBill] {
        &self.bills
    }

    /// Mutable access to all bills.
    pub fn bills_mut(&mut self) -> &mut Vec<VessBill> {
        &mut self.bills
    }

    /// Bills of a specific denomination.
    pub fn bills_of(&self, denom: Denomination) -> Vec<&VessBill> {
        self.bills
            .iter()
            .filter(|b| b.denomination == denom)
            .collect()
    }

    /// Count of bills per denomination.
    pub fn denomination_breakdown(&self) -> Vec<(Denomination, usize)> {
        let mut counts: std::collections::BTreeMap<Denomination, usize> =
            std::collections::BTreeMap::new();
        for b in &self.bills {
            *counts.entry(b.denomination).or_insert(0) += 1;
        }
        counts.into_iter().collect()
    }

    /// Whether the billfold has enough total value to cover an amount.
    pub fn can_afford(&self, amount: u64) -> bool {
        self.balance() >= amount
    }

    // ── Reservation (limbo / in-flight) ──────────────────────────

    /// Reserve mint_ids (bills are in-flight or limbo).
    /// Reserved bills remain in the billfold but are excluded from selection.
    /// `now` is the current Unix timestamp in seconds.
    pub fn reserve(&mut self, mint_ids: &[[u8; 32]], now: u64) {
        for mid in mint_ids {
            self.reserved.insert(*mid);
            self.reserve_times.insert(*mid, now);
        }
    }

    /// Release reserved mint_ids (sender retracted or bill claimed).
    pub fn release(&mut self, mint_ids: &[[u8; 32]]) {
        for mid in mint_ids {
            self.reserved.remove(mid);
            self.reserve_times.remove(mid);
        }
    }

    /// Release all reservations older than `ttl_secs`.
    /// Returns the mint_ids that were released.
    pub fn release_expired(&mut self, ttl_secs: u64, now: u64) -> Vec<[u8; 32]> {
        let expired: Vec<[u8; 32]> = self
            .reserve_times
            .iter()
            .filter(|(_, &ts)| now.saturating_sub(ts) > ttl_secs)
            .map(|(mid, _)| *mid)
            .collect();
        for mid in &expired {
            self.reserved.remove(mid);
            self.reserve_times.remove(mid);
        }
        expired
    }

    /// Bills available for spending (excludes reserved).
    pub fn available_bills(&self) -> Vec<&VessBill> {
        self.bills
            .iter()
            .filter(|b| !self.reserved.contains(&b.mint_id))
            .collect()
    }

    /// Available balance (excludes reserved bills).
    pub fn available_balance(&self) -> u64 {
        self.available_bills()
            .iter()
            .map(|b| b.denomination.value())
            .sum()
    }

    /// Number of reserved bills.
    pub fn reserved_count(&self) -> usize {
        self.reserved.len()
    }

    /// Check if a mint_id is reserved.
    pub fn is_reserved(&self, mint_id: &[u8; 32]) -> bool {
        self.reserved.contains(mint_id)
    }

    /// Read-only access to the reserved set.
    pub fn reserved_set(&self) -> &HashSet<[u8; 32]> {
        &self.reserved
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_bill(denom: Denomination, _age_secs: u64) -> VessBill {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        VessBill {
            denomination: denom,
            digest: [0xBB; 32],
            created_at: now,
            stealth_id: [0xCC; 32],
            dht_index: 0,
            mint_id: rand::random(),
            chain_tip: rand::random(),
            chain_depth: 0,
        }
    }

    #[test]
    fn balance_and_count() {
        let mut bf = BillFold::new();
        bf.deposit(test_bill(Denomination::D10, 0));
        bf.deposit(test_bill(Denomination::D5, 0));
        bf.deposit(test_bill(Denomination::D1, 0));

        assert_eq!(bf.balance(), 16);
        assert_eq!(bf.count(), 3);
    }

    #[test]
    fn withdraw_by_mint_id() {
        let mut bf = BillFold::new();
        let bill = test_bill(Denomination::D20, 0);
        let mint_id = bill.mint_id;

        bf.deposit(bill);
        assert_eq!(bf.count(), 1);

        let removed = bf.withdraw(&mint_id).unwrap();
        assert_eq!(removed.denomination, Denomination::D20);
        assert_eq!(bf.count(), 0);
    }

    #[test]
    fn denomination_breakdown() {
        let mut bf = BillFold::new();
        bf.deposit(test_bill(Denomination::D5, 0));
        bf.deposit(test_bill(Denomination::D5, 0));
        bf.deposit(test_bill(Denomination::D10, 0));

        let breakdown = bf.denomination_breakdown();
        assert!(breakdown.contains(&(Denomination::D5, 2)));
        assert!(breakdown.contains(&(Denomination::D10, 1)));
    }
}
