//! Payment builder — create transfers with ephemeral DKSAP keypairs.
//!
//! Each Vess on the network has a UNIQUE ephemeral ML-DSA-65 keypair.
//! The sender generates this keypair, embeds the secret key encrypted
//! in the payment payload, and the recipient decrypts it to gain
//! spend authority. No wallet permanent key is ever revealed on-chain.
use std::sync::{Arc, Mutex};
use vess_foundry::Vess;
use crate::node_runner::ArteryState;

/// A freshly-built payment with ephemeral keys.
pub struct BuiltPayment {
    /// Payment Vess (to recipient, with ephemeral owner_vk).
    pub payment: Vess,
    /// Ephemeral spend SK for the payment Vess (encrypt this for the recipient).
    pub payment_sk: Vec<u8>,
    /// Change Vess (back to sender, with ephemeral owner_vk), if any.
    pub change: Option<Vess>,
    /// Ephemeral spend SK for the change Vess.
    pub change_sk: Option<Vec<u8>>,
}

/// Build a payment: select inputs we have credentials for, create outputs
/// with fresh ephemeral keypairs, sign the change commitment.
pub fn build_payment_ephemeral(
    state: &Arc<Mutex<ArteryState>>,
    amount: u64,
) -> Result<BuiltPayment, String> {
    let (consumed_ids, total, initial_pk) = {
        let s = state.lock().unwrap();
        // Find bills we have spend credentials for (our wallet owns these)
        let mut mine: Vec<Vess> = s.store.iter()
            .filter(|v| s.spend_credentials.contains_key(&v.compute_vess_id()))
            .cloned().collect();
        mine.sort_by_key(|v| std::cmp::Reverse(v.amount));

        let mut total = 0u64;
        let mut ids = Vec::new();
        for v in &mine {
            if total >= amount { break; }
            total += v.amount;
            ids.push(v.compute_vess_id());
        }
        if total < amount {
            return Err(format!("insufficient: {total} < {amount}"));
        }
        (ids, total, mine[0].initial_pk)
    };

    let change_amount = total.saturating_sub(amount);

    // Generate fresh ephemeral keypairs for payment and change
    let (payment_vk, payment_sk) = vess_foundry::spend_auth::generate_spend_keypair();
    let (change_vk, change_sk) = if change_amount > 0 {
        let (vk, sk) = vess_foundry::spend_auth::generate_spend_keypair();
        (Some(vk), Some(sk))
    } else {
        (None, None)
    };

    let payment = Vess {
        amount, epoch: 0, nonce: 0, initial_pk,
        owner_vk: payment_vk, prev_sig: Vec::new(), chain_depth: 0,
        consumed: consumed_ids.clone(), change_sig: Vec::new(),
        chain_tip: [0u8; 32], digest: [0u8; 32],
        created_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs(),
        stealth_id: [0u8; 32], dht_index: 0,
    };

    let change = change_amount.checked_sub(0).and_then(|_| {
        change_vk.map(|vk| Vess {
            amount: change_amount, epoch: 0, nonce: 0, initial_pk,
            owner_vk: vk, prev_sig: Vec::new(), chain_depth: 0,
            consumed: consumed_ids.clone(), change_sig: Vec::new(),
            chain_tip: [0u8; 32], digest: [0u8; 32],
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs(),
            stealth_id: [0u8; 32], dht_index: 0,
        })
    });

    // Sign the batch commitment with one of the input spend keys
    let input_sk = {
        let s = state.lock().unwrap();
        s.spend_credentials.get(&consumed_ids[0])
            .map(|(_, sk, _)| sk.clone())
            .ok_or("no spend credential for input")?
    };
    let mut outputs = vec![payment.clone()];
    if let Some(ref c) = change { outputs.push(c.clone()); }
    let commitment = Vess::change_commitment(&consumed_ids, &outputs);
    let sig = vess_foundry::spend_auth::sign_spend(&input_sk, &commitment)
        .map_err(|e| format!("sign: {e}"))?;

    let mut signed_payment = payment;
    signed_payment.change_sig = sig.clone();
    let signed_change = change.map(|mut c| { c.change_sig = sig; c });

    Ok(BuiltPayment {
        payment: signed_payment,
        payment_sk,
        change: signed_change,
        change_sk,
    })
}
