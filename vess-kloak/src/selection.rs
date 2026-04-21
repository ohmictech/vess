//! Denomination-selection algorithm for payments.
//!
//! Given a target amount and a billfold, selects the optimal combination
//! of bills to cover the amount with minimal waste (change + excess bill
//! count). Uses randomized branch-and-bound inspired by Bitcoin Core's
//! coin selection, falling back to greedy largest-first when the random
//! search doesn't find an improvement within a budget of iterations.
//!
//! # Waste Metric
//!
//! `waste = change + BILL_COST * bill_count`
//!
//! This penalizes both leftover change (which requires a reforge) and
//! using too many individual bills (which increases proof size on the wire).

use anyhow::{anyhow, Result};
use vess_foundry::{Denomination, VessBill};

/// Cost per additional bill in the selection (in denomination units).
/// Higher values prefer fewer, larger bills.
const BILL_COST: u64 = 1;

/// Maximum random branch-and-bound iterations before falling back to greedy.
const BNB_MAX_ITERATIONS: usize = 1_000;

/// The result of bill selection for a payment.
#[derive(Debug, Clone)]
pub struct SelectionResult {
    /// Bills to send (indices into the billfold).
    pub send_indices: Vec<usize>,
    /// Total value of selected bills.
    pub total_selected: u64,
    /// The target payment amount.
    pub target_amount: u64,
    /// Change amount (total_selected - target_amount).
    /// If > 0, the sender must reforge to split off change.
    pub change: u64,
    /// Suggested change denominations (largest-first).
    pub change_denominations: Vec<Denomination>,
}

/// Select bills from a slice to cover `amount` Vess.
///
/// Prefers exact matches. If none exists, selects the combination
/// with the least overpay. Returns indices into the `bills` slice.
pub fn select_bills(bills: &[VessBill], amount: u64) -> Result<SelectionResult> {
    select_bills_filtered(bills, amount, &[])
}

/// Select bills, excluding any whose mint_id appears in `reserved`.
///
/// 1. Randomized branch-and-bound: shuffles bills and explores inclusion/
///    exclusion, pruning branches whose remaining capacity can't improve
///    on the best solution found so far. Runs up to `BNB_MAX_ITERATIONS`.
/// 2. If BnB doesn't find a solution better than greedy, falls back to
///    greedy largest-first with post-optimization (drop unnecessary bills).
///
/// The "best" solution minimizes `waste = change + BILL_COST * bill_count`.
pub fn select_bills_filtered(
    bills: &[VessBill],
    amount: u64,
    reserved: &[[u8; 32]],
) -> Result<SelectionResult> {
    if amount == 0 {
        return Err(anyhow!("cannot select bills for zero amount"));
    }

    // Build set of available indices (exclude reserved).
    let reserved_set: std::collections::HashSet<[u8; 32]> = reserved.iter().copied().collect();
    let available: Vec<usize> = (0..bills.len())
        .filter(|&i| !reserved_set.contains(&bills[i].mint_id))
        .collect();

    let total: u64 = available
        .iter()
        .map(|&i| bills[i].denomination.value())
        .sum();
    if total < amount {
        return Err(anyhow!("insufficient funds: need {amount}, have {total}"));
    }

    // Try randomized branch-and-bound first.
    let bnb_result = bnb_select(bills, &available, amount);

    // Always compute greedy as a fallback / comparison baseline.
    let greedy_result = greedy_select(bills, &available, amount)?;

    let best = match bnb_result {
        Some(bnb) if waste(bills, &bnb, amount) <= waste(bills, &greedy_result, amount) => bnb,
        _ => greedy_result,
    };

    let total_selected: u64 = best.iter().map(|&i| bills[i].denomination.value()).sum();
    let change = total_selected - amount;
    let change_denominations = decompose_amount(change);

    Ok(SelectionResult {
        send_indices: best,
        total_selected,
        target_amount: amount,
        change,
        change_denominations,
    })
}

/// Waste metric: change amount + per-bill overhead.
fn waste(bills: &[VessBill], selected: &[usize], amount: u64) -> u64 {
    let total: u64 = selected
        .iter()
        .map(|&i| bills[i].denomination.value())
        .sum();
    let change = total.saturating_sub(amount);
    change + selected.len() as u64 * BILL_COST
}

/// Randomized branch-and-bound coin selection.
///
/// Shuffles the available bills, then performs a depth-first search where
/// each bill is either included or excluded. Prunes branches where:
/// - Including the current bill would overshoot by more than the best
///   solution's waste.
/// - The remaining capacity (sum of unconsidered bills) can't reach the
///   target even if all are included.
fn bnb_select(bills: &[VessBill], available: &[usize], target: u64) -> Option<Vec<usize>> {
    use rand::seq::SliceRandom;

    let mut rng = rand::thread_rng();
    let mut order: Vec<usize> = available.to_vec();
    order.shuffle(&mut rng);

    // Suffix sums: remaining[i] = sum of values from order[i..].
    let n = order.len();
    let mut remaining = vec![0u64; n + 1];
    for i in (0..n).rev() {
        remaining[i] = remaining[i + 1] + bills[order[i]].denomination.value();
    }

    let mut best: Option<Vec<usize>> = None;
    let mut best_waste = u64::MAX;

    // Stack-based DFS: (depth, current_sum, current_selection).
    let mut stack: Vec<(usize, u64, Vec<usize>)> = vec![(0, 0, Vec::new())];
    let mut iterations = 0usize;

    while let Some((depth, sum, sel)) = stack.pop() {
        iterations += 1;
        if iterations > BNB_MAX_ITERATIONS {
            break;
        }

        if sum >= target {
            let w = (sum - target) + sel.len() as u64 * BILL_COST;
            if w < best_waste {
                best_waste = w;
                best = Some(sel);
            }
            continue;
        }

        if depth >= n {
            continue; // exhausted all bills without reaching target
        }

        // Prune: even including everything remaining can't reach target.
        if sum + remaining[depth] < target {
            continue;
        }

        let bill_idx = order[depth];
        let bill_val = bills[bill_idx].denomination.value();

        // Branch: exclude this bill.
        stack.push((depth + 1, sum, sel.clone()));

        // Branch: include this bill (only if it could improve on best).
        let new_sum = sum + bill_val;
        let min_possible_waste = if new_sum >= target {
            (new_sum - target) + (sel.len() as u64 + 1) * BILL_COST
        } else {
            (sel.len() as u64 + 1) * BILL_COST // optimistic: exact match downstream
        };
        if min_possible_waste < best_waste {
            let mut sel_inc = sel;
            sel_inc.push(bill_idx);
            stack.push((depth + 1, new_sum, sel_inc));
        }
    }

    best
}

/// Greedy largest-first selection with post-optimization.
fn greedy_select(bills: &[VessBill], available: &[usize], amount: u64) -> Result<Vec<usize>> {
    let mut indices: Vec<usize> = available.to_vec();
    indices.sort_by(|&a, &b| {
        bills[b]
            .denomination
            .value()
            .cmp(&bills[a].denomination.value())
    });

    let mut selected = Vec::new();
    let mut running = 0u64;

    for &idx in &indices {
        if running >= amount {
            break;
        }
        selected.push(idx);
        running += bills[idx].denomination.value();
    }

    if running < amount {
        return Err(anyhow!("selection logic error: should be unreachable"));
    }

    // Drop unnecessary small bills (smallest first).
    selected.sort_by(|&a, &b| {
        bills[a]
            .denomination
            .value()
            .cmp(&bills[b].denomination.value())
    });

    let mut optimized = selected.clone();
    for &idx in &selected {
        let without: u64 = optimized
            .iter()
            .filter(|&&i| i != idx)
            .map(|&i| bills[i].denomination.value())
            .sum();
        if without >= amount {
            optimized.retain(|&i| i != idx);
        }
    }

    Ok(optimized)
}

/// Decompose an amount into valid 1-2-5 denominations (greedy largest-first).
///
/// Works for any amount within the u64 range.
/// Returns denominations sorted largest-first.
pub fn decompose_amount(mut amount: u64) -> Vec<Denomination> {
    if amount == 0 {
        return Vec::new();
    }

    let series = Denomination::series_up_to(amount);
    let mut result = Vec::new();
    for d in &series {
        let v = d.value();
        while amount >= v {
            result.push(*d);
            amount -= v;
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use vess_foundry::VessBill;

    fn bill(denom: Denomination) -> VessBill {
        VessBill {
            denomination: denom,
            digest: [0xBB; 32],
            created_at: 1000,
            stealth_id: [0xCC; 32],
            dht_index: 0,
            mint_id: rand::random(),
            chain_tip: rand::random(),
            chain_depth: 0,
        }
    }

    #[test]
    fn exact_match() {
        let bills = vec![bill(Denomination::D10), bill(Denomination::D5)];
        let result = select_bills(&bills, 15).unwrap();
        assert_eq!(result.total_selected, 15);
        assert_eq!(result.change, 0);
    }

    #[test]
    fn overpay_with_change() {
        let bills = vec![bill(Denomination::D20)];
        let result = select_bills(&bills, 15).unwrap();
        assert_eq!(result.total_selected, 20);
        assert_eq!(result.change, 5);
        assert_eq!(result.change_denominations, vec![Denomination::D5]);
    }

    #[test]
    fn prefers_exact_over_overpay() {
        let bills = vec![
            bill(Denomination::D1),
            bill(Denomination::D5),
            bill(Denomination::D10),
            bill(Denomination::D20),
        ];
        let result = select_bills(&bills, 15).unwrap();
        // BnB should find the exact D10+D5 match rather than overpaying with D20.
        assert_eq!(result.total_selected, 15);
        assert_eq!(result.change, 0);
    }

    #[test]
    fn insufficient_funds() {
        let bills = vec![bill(Denomination::D5)];
        assert!(select_bills(&bills, 10).is_err());
    }

    #[test]
    fn decompose_standard() {
        let d = decompose_amount(37);
        let sum: u64 = d.iter().map(|x| x.value()).sum();
        assert_eq!(sum, 37);
        // 37 = 20 + 10 + 5 + 2
        assert_eq!(
            d,
            vec![
                Denomination::D20,
                Denomination::D10,
                Denomination::D5,
                Denomination::D2,
            ]
        );
    }

    #[test]
    fn decompose_zero() {
        assert!(decompose_amount(0).is_empty());
    }

    #[test]
    fn select_for_zero_fails() {
        let bills = vec![bill(Denomination::D5)];
        assert!(select_bills(&bills, 0).is_err());
    }
}
