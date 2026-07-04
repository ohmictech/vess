use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use vess_foundry::Vess;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct SpendCredential {
    pub spend_vk: Vec<u8>,
    pub spend_sk: Vec<u8>,
}

impl std::fmt::Debug for SpendCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SpendCredential(<redacted>)")
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct BillFold {
    bills: Vec<Vess>,
    #[serde(default)] reserved: HashSet<[u8; 32]>,
    #[serde(default)] reserve_times: HashMap<[u8; 32], u64>,
    #[serde(skip_serializing, default)] spend_credentials: HashMap<[u8; 32], SpendCredential>,
}

impl Clone for BillFold {
    fn clone(&self) -> Self {
        Self { bills: self.bills.clone(), reserved: self.reserved.clone(), reserve_times: self.reserve_times.clone(), spend_credentials: self.spend_credentials.clone() }
    }
}

impl BillFold {
    pub fn new() -> Self { Self { bills: Vec::new(), reserved: HashSet::new(), reserve_times: HashMap::new(), spend_credentials: HashMap::new() } }

    pub fn deposit(&mut self, bill: Vess) -> bool {
        let id = bill.compute_vess_id();
        if self.bills.iter().any(|b| b.compute_vess_id() == id) { return false; }
        self.bills.push(bill); true
    }

    pub fn deposit_with_credentials(&mut self, bill: Vess, cred: SpendCredential) -> bool {
        let id = bill.compute_vess_id();
        if self.deposit(bill) { self.spend_credentials.insert(id, cred); true } else { false }
    }

    pub fn withdraw(&mut self, mint_id: &[u8; 32]) -> Option<Vess> {
        if let Some(pos) = self.bills.iter().position(|b| &b.compute_vess_id() == mint_id) {
            self.spend_credentials.remove(mint_id);
            Some(self.bills.remove(pos))
        } else { None }
    }

    pub fn get_credentials(&self, mint_id: &[u8; 32]) -> Option<&SpendCredential> { self.spend_credentials.get(mint_id) }
    pub fn any_credential(&self) -> Option<&SpendCredential> { self.spend_credentials.values().next() }

    pub fn balance(&self) -> u64 { self.bills.iter().map(|b| b.amount).sum() }
    pub fn count(&self) -> usize { self.bills.len() }
    pub fn bills(&self) -> &[Vess] { &self.bills }
    pub fn bills_mut(&mut self) -> &mut Vec<Vess> { &mut self.bills }

    pub fn can_afford(&self, amount: u64) -> bool { self.spendable_balance() >= amount }

    pub fn reserve(&mut self, mint_ids: &[[u8; 32]], now: u64) {
        for mid in mint_ids { self.reserved.insert(*mid); self.reserve_times.insert(*mid, now); }
    }

    pub fn release(&mut self, mint_ids: &[[u8; 32]]) {
        for mid in mint_ids { self.reserved.remove(mid); self.reserve_times.remove(mid); }
    }

    pub fn release_expired(&mut self, ttl_secs: u64, now: u64) -> Vec<[u8; 32]> {
        let expired: Vec<[u8; 32]> = self.reserve_times.iter().filter(|(_, &ts)| now.saturating_sub(ts) > ttl_secs).map(|(mid, _)| *mid).collect();
        for mid in &expired { self.reserved.remove(mid); self.reserve_times.remove(mid); }
        expired
    }

    pub fn available_bills(&self) -> Vec<&Vess> { self.bills.iter().filter(|b| !self.reserved.contains(&b.compute_vess_id())).collect() }

    pub fn available_balance(&self) -> u64 { self.available_bills().iter().map(|b| b.amount).sum() }

    pub fn spendable_balance(&self) -> u64 {
        self.available_bills().into_iter().filter(|b| self.spend_credentials.contains_key(&b.compute_vess_id())).map(|b| b.amount).sum()
    }

    pub fn watch_only_balance(&self) -> u64 {
        self.available_bills().into_iter().filter(|b| !self.spend_credentials.contains_key(&b.compute_vess_id())).map(|b| b.amount).sum()
    }

    pub fn reserved_count(&self) -> usize { self.reserved.len() }
    pub fn is_reserved(&self, mint_id: &[u8; 32]) -> bool { self.reserved.contains(mint_id) }
    pub fn reserved_set(&self) -> &HashSet<[u8; 32]> { &self.reserved }
    pub fn export_credentials(&self) -> &HashMap<[u8; 32], SpendCredential> { &self.spend_credentials }
    pub fn import_credentials(&mut self, creds: HashMap<[u8; 32], SpendCredential>) { self.spend_credentials.extend(creds); }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn test_bill(amount: u64) -> Vess {
        Vess { amount, epoch: 0, nonce: 0, initial_pk: [0u8; 32], owner_vk: vec![], prev_sig: vec![], chain_depth: 0, consumed: vec![], change_sig: vec![], chain_tip: [0u8; 32], digest: [0u8; 32], created_at: 0, stealth_id: [0u8; 32], dht_index: 0 }
    }

    #[test] fn balance_and_count() { let mut bf = BillFold::new(); bf.deposit(test_bill(10)); bf.deposit(test_bill(5)); bf.deposit(test_bill(1)); assert_eq!(bf.balance(), 16); assert_eq!(bf.count(), 3); }

    #[test] fn withdraw() { let mut bf = BillFold::new(); let bill = test_bill(20); let id = bill.compute_vess_id(); bf.deposit(bill); assert_eq!(bf.count(), 1); let r = bf.withdraw(&id).unwrap(); assert_eq!(r.amount, 20); assert_eq!(bf.count(), 0); }

    #[test] fn spendable_vs_watchonly() {
        let mut bf = BillFold::new();
        let wo = test_bill(10); let sp = test_bill(5); let sp_id = sp.compute_vess_id();
        bf.deposit(wo);
        bf.deposit_with_credentials(sp, SpendCredential { spend_vk: vec![1; 64], spend_sk: vec![2; 64] });
        assert_eq!(bf.available_balance(), 15); assert_eq!(bf.spendable_balance(), 5); assert_eq!(bf.watch_only_balance(), 10);
    }
}