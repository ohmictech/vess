//! Onion routing — 3-hop DKSAP-layered payment forwarding with ChaCha20-Poly1305 AEAD.

use anyhow::{Context, Result};
use vess_protocol::{OnionLayer, OnionPayload, OnionRoute, Payment};

pub fn build_onion_route(
    payment: Payment,
    shard_key: [u8; 32],
    entry_key: &[u8; 32],
    middle_key: &[u8; 32],
    exit_key: &[u8; 32],
) -> Result<OnionRoute> {
    let exit_layer = encrypt_layer(exit_key, shard_key, &OnionPayload::Deliver {
        payment: payment.clone(), shard_key,
    })?;
    let middle_layer = encrypt_layer(middle_key, shard_key, &OnionPayload::Forward {
        inner: Box::new(exit_layer),
    })?;
    let entry_layer = encrypt_layer(entry_key, shard_key, &OnionPayload::Forward {
        inner: Box::new(middle_layer),
    })?;
    Ok(OnionRoute { outer: entry_layer })
}

fn encrypt_layer(
    relay_key: &[u8; 32],
    next_hop: [u8; 32],
    payload: &OnionPayload,
) -> Result<OnionLayer> {
    let plaintext = serde_json::to_vec(payload).context("serialize onion payload")?;
    let enc_key = blake3::derive_key("vess-onion-v1", relay_key);
    let blob = vess_sovereign::persistence::EncryptedBlob::encrypt(&plaintext, &enc_key)
        .context("onion AEAD encrypt")?;
    Ok(OnionLayer {
        next_hop,
        ct_scan: relay_key.to_vec(),
        ct_spend: relay_key.to_vec(),
        view_tag: enc_key[0],
        nonce: blob.nonce,
        ciphertext: blob.ciphertext,
    })
}

pub fn try_decrypt_onion_layer(
    layer: &OnionLayer,
    relay_key: &[u8; 32],
) -> Option<(OnionPayload, [u8; 32])> {
    let enc_key = blake3::derive_key("vess-onion-v1", relay_key);
    if layer.view_tag != enc_key[0] { return None; }
    let blob = vess_sovereign::persistence::EncryptedBlob {
        ciphertext: layer.ciphertext.clone(),
        nonce: layer.nonce,
    };
    let plaintext = blob.decrypt(&enc_key).ok()?;
    let payload: OnionPayload = serde_json::from_slice(&plaintext).ok()?;
    Some((payload, layer.next_hop))
}

pub enum OnionAction {
    Forward(OnionRoute),
    Deliver { payment: Payment, shard_key: [u8; 32] },
    Drop,
}

pub fn process_onion_route(route: &OnionRoute, relay_key: &[u8; 32]) -> OnionAction {
    match try_decrypt_onion_layer(&route.outer, relay_key) {
        Some((OnionPayload::Forward { inner }, _)) => OnionAction::Forward(OnionRoute { outer: *inner }),
        Some((OnionPayload::Deliver { payment, shard_key }, _)) => OnionAction::Deliver { payment, shard_key },
        None => OnionAction::Drop,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn onion_round_trip() {
        let ek1 = [0x11u8; 32]; let ek2 = [0x22u8; 32]; let ek3 = [0x33u8; 32];
        let payment = Payment {
            payment_id: [0x42; 32], stealth_payload: vec![0x99; 100], view_tag: 0,
            stealth_id: [0x11; 32], created_at: 12345, bill_count: 1,
            mailbox_key: None, direct_receipt_tag_hash: None, hash_lock: None,
        };
        let route = build_onion_route(payment, [0x77; 32], &ek1, &ek2, &ek3).expect("build");
        let a1 = process_onion_route(&route, &ek1);
        assert!(matches!(a1, OnionAction::Forward(_)));
        if let OnionAction::Forward(inner) = a1 {
            let a2 = process_onion_route(&inner, &ek2);
            assert!(matches!(a2, OnionAction::Forward(_)));
            if let OnionAction::Forward(inner2) = a2 {
                assert!(matches!(process_onion_route(&inner2, &ek3), OnionAction::Deliver { .. }));
            }
        }
    }

    #[test]
    fn wrong_key_drops() {
        let ek1 = [0x11; 32]; let ek2 = [0x22; 32]; let ek3 = [0x33; 32];
        let route = build_onion_route(
            Payment { payment_id: [0;32], stealth_payload: vec![], view_tag: 0,
                stealth_id: [0;32], created_at: 0, bill_count: 0,
                mailbox_key: None, direct_receipt_tag_hash: None, hash_lock: None },
            [0;32], &ek1, &ek2, &ek3,
        ).expect("build");
        assert!(matches!(process_onion_route(&route, &[0xFF;32]), OnionAction::Drop));
    }
}
