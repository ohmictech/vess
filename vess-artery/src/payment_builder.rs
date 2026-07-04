//! Payment builder — create change transactions (consume inputs, produce outputs).
use std::sync::{Arc, Mutex};
use vess_foundry::Vess;
use crate::node_runner::NodeState;

pub fn build_payment(
    state: &Arc<Mutex<NodeState>>,
    amount: u64,
    recipient_vk: &[u8],
) -> Result<(Vess, Option<Vess>), String> {
    let (consumed_ids, total, initial_pk, epoch) = {
        let s = state.lock().unwrap();
        let sender_vk = s.wallet_vk.as_ref().ok_or("no wallet key")?;
        let owner_hash = vess_foundry::spend_auth::vk_hash(sender_vk);
        let mut mine: Vec<Vess> = s.store.iter()
            .filter(|v| v.owner_vk_hash() == owner_hash)
            .cloned().collect();
        mine.sort_by_key(|v| std::cmp::Reverse(v.amount));
        let mut total = 0u64;
        let mut ids = Vec::new();
        for v in &mine {
            if total >= amount { break; }
            total += v.amount;
            ids.push(v.compute_vess_id());
        }
        if total < amount { return Err(format!("insufficient: {total} < {amount}")); }
        (ids, total, mine[0].initial_pk, s.current_epoch)
    };

    let change_amount = total - amount;

    let payment = Vess {
        amount, epoch: 0, nonce: 0, initial_pk,
        owner_vk: recipient_vk.to_vec(), prev_sig: Vec::new(), chain_depth: 0,
        consumed: consumed_ids.clone(), change_sig: Vec::new(),
        chain_tip: [0u8; 32], digest: [0u8; 32],
        created_at: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs(),
        stealth_id: [0u8; 32], dht_index: 0,
    };

    let change = if change_amount > 0 {
        Some(Vess {
            amount: change_amount, epoch: 0, nonce: 0, initial_pk,
            owner_vk: { let s = state.lock().unwrap(); s.wallet_vk.clone().unwrap_or_default() },
            prev_sig: Vec::new(), chain_depth: 0,
            consumed: consumed_ids.clone(), change_sig: Vec::new(),
            chain_tip: [0u8; 32], digest: [0u8; 32],
            created_at: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs(),
            stealth_id: [0u8; 32], dht_index: 0,
        })
    } else { None };

    let mut outputs = vec![payment.clone()];
    if let Some(ref c) = change { outputs.push(c.clone()); }
    let commitment = Vess::change_commitment(&consumed_ids, &outputs);
    let sig = {
        let s = state.lock().unwrap();
        let sk = s.wallet_sk.as_ref().ok_or("no wallet secret")?;
        vess_foundry::spend_auth::sign_spend(sk, &commitment).map_err(|e| format!("sign: {e}"))?
    };

    let mut signed_payment = payment;
    signed_payment.change_sig = sig.clone();
    let signed_change = change.map(|mut c| { c.change_sig = sig; c });

    {
        let mut s = state.lock().unwrap();
        s.store.consume(&consumed_ids, epoch);
    }

    Ok((signed_payment, signed_change))
}