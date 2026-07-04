//! Coin selection — largest-first for Vess UTXOs.
use anyhow::{anyhow, Result};
use vess_foundry::Vess;

pub struct SelectionResult {
    pub send_indices: Vec<usize>,
    pub total_selected: u64,
    pub target_amount: u64,
    pub change: u64,
}

pub fn select_bills(bills: &[Vess], amount: u64) -> Result<SelectionResult> {
    select_bills_filtered(bills, amount, &[])
}

pub fn select_bills_filtered(bills: &[Vess], amount: u64, reserved: &[[u8; 32]]) -> Result<SelectionResult> {
    if amount == 0 { return Err(anyhow!("zero amount")); }
    let reserved_set: std::collections::HashSet<[u8; 32]> = reserved.iter().copied().collect();
    let mut available: Vec<(usize, u64)> = (0..bills.len())
        .filter(|&i| !reserved_set.contains(&bills[i].compute_vess_id()))
        .map(|i| (i, bills[i].amount))
        .collect();
    available.sort_by(|a, b| b.1.cmp(&a.1)); // largest first

    let total: u64 = available.iter().map(|(_, v)| v).sum();
    if total < amount { return Err(anyhow!("insufficient: {total} < {amount}")); }

    let mut selected = Vec::new();
    let mut running = 0u64;
    for (idx, val) in &available {
        if running >= amount { break; }
        selected.push(*idx);
        running += val;
    }

    // Drop unnecessary small bills
    selected.sort_by(|&a, &b| bills[a].amount.cmp(&bills[b].amount));
    let mut optimized = selected.clone();
    for &idx in &selected {
        let without: u64 = optimized.iter().filter(|&&i| i != idx).map(|&i| bills[i].amount).sum();
        if without >= amount { optimized.retain(|&i| i != idx); }
    }

    Ok(SelectionResult {
        total_selected: optimized.iter().map(|&i| bills[i].amount).sum(),
        target_amount: amount,
        change: running.saturating_sub(amount),
        send_indices: optimized,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn bill(amount: u64) -> Vess {
        Vess { amount, epoch: 0, nonce: 0, initial_pk: [0u8; 32], owner_vk: vec![], prev_sig: vec![], chain_depth: 0, consumed: vec![], change_sig: vec![], chain_tip: [0u8; 32], digest: [0u8; 32], created_at: 0, stealth_id: [0u8; 32], dht_index: 0 }
    }
    #[test] fn exact_match() { let b = vec![bill(10), bill(5)]; let r = select_bills(&b, 15).unwrap(); assert_eq!(r.total_selected, 15); assert_eq!(r.change, 0); }
    #[test] fn overpay() { let b = vec![bill(20)]; let r = select_bills(&b, 15).unwrap(); assert_eq!(r.total_selected, 20); assert_eq!(r.change, 5); }
    #[test] fn insufficient() { assert!(select_bills(&[bill(5)], 10).is_err()); }
    #[test] fn zero_fails() { assert!(select_bills(&[bill(5)], 0).is_err()); }
}