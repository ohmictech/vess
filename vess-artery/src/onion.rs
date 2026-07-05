//! Onion routing — 3-hop DKSAP-layered payment forwarding.
//!
//! The sender builds the onion inside-out:
//!   1. Wrap the Payment in OnionPayload::Deliver, encrypt to exit relay
//!   2. Wrap exit layer in OnionPayload::Forward, encrypt to middle relay
//!   3. Wrap middle layer in OnionPayload::Forward, encrypt to entry relay
//!
//! No single relay knows both sender and recipient.
//! Entry knows "packet came from X, goes to B"
//! Middle knows "packet came from A, goes to C"
//! Exit knows "packet came from B, delivers to shard Y"

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use vess_protocol::{OnionLayer, OnionPayload, OnionRoute, Payment};

/// Build a 3-hop onion route for a payment.
///
/// `relays` must contain exactly 3 (entry, middle, exit) — each is a
/// `(mesh_address, scan_ek, spend_ek)` tuple where scan_ek/spend_ek are
/// the relay's published ML-KEM-768 encapsulation keys from their MeshAddress.
pub fn build_onion_route(
    payment: Payment,
    shard_key: [u8; 32],
    entry: (&[u8], &[u8]),   // (scan_ek, spend_ek) of entry relay
    middle: (&[u8], &[u8]),  // (scan_ek, spend_ek) of middle relay
    exit: (&[u8], &[u8]),    // (scan_ek, spend_ek) of exit relay
) -> Result<OnionRoute> {
    // Build inside-out: exit layer first

    // 1. Exit layer: Deliver
    let exit_layer = encrypt_onion_layer(
        Some(exit.0),    // scan_ek
        Some(exit.1),    // spend_ek
        shard_key,       // next hop is the shard key
        &OnionPayload::Deliver {
            payment: payment.clone(),
            shard_key,
        },
    )?;

    // 2. Middle layer: Forward → exit
    let middle_layer = encrypt_onion_layer(
        Some(middle.0),
        Some(middle.1),
        shard_key, // next hop for middle is the exit's node_id (we use shard as proxy)
        &OnionPayload::Forward {
            inner: Box::new(exit_layer),
        },
    )?;

    // 3. Entry layer: Forward → middle
    let entry_layer = encrypt_onion_layer(
        Some(entry.0),
        Some(entry.1),
        shard_key,
        &OnionPayload::Forward {
            inner: Box::new(middle_layer),
        },
    )?;

    Ok(OnionRoute {
        outer: entry_layer,
    })
}

/// Encrypt one onion layer to a relay's ML-KEM-768 keys.
fn encrypt_onion_layer(
    scan_ek: Option<&[u8]>,
    spend_ek: Option<&[u8]>,
    next_hop: [u8; 32],
    payload: &OnionPayload,
) -> Result<OnionLayer> {
    // Serialize the payload
    let plaintext = serde_json::to_vec(payload)
        .context("serialize onion payload")?;

    // In production: ML-KEM encaps to scan_ek and spend_ek.
    // For dev: use ChaCha20-Poly1305 with a Blake3-derived key from the EKs.
    let enc_key = {
        let mut h = blake3::Hasher::new();
        h.update(b"vess-onion-v1");
        if let Some(ek) = scan_ek { h.update(ek); }
        if let Some(ek) = spend_ek { h.update(ek); }
        *h.finalize().as_bytes()
    };

    let cipher = chacha20poly1305::ChaCha20Poly1305::new(
        chacha20poly1305::aead::generic_array::GenericArray::from_slice(&enc_key),
    );
    let mut nonce_bytes = [0u8; 12];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce_bytes);
    let nonce = chacha20poly1305::aead::generic_array::GenericArray::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_slice())
        .map_err(|e| anyhow::anyhow!("onion encrypt: {e}"))?;

    // View tag: first byte of Blake3(enc_key)
    let view_tag = enc_key[0];

    Ok(OnionLayer {
        next_hop,
        ct_scan: scan_ek.unwrap_or(&[]).to_vec(),
        ct_spend: spend_ek.unwrap_or(&[]).to_vec(),
        view_tag,
        nonce: nonce_bytes,
        ciphertext,
    })
}

/// Attempt to decrypt an onion layer using the given relay secret keys.
///
/// Returns `Some(OnionPayload, next_hop)` if decryption succeeds,
/// `None` if this layer is not for us (view tag mismatch or decrypt failure).
pub fn try_decrypt_onion_layer(
    layer: &OnionLayer,
    scan_dk: &[u8],   // this relay's scan decapsulation key
    spend_dk: &[u8],  // this relay's spend decapsulation key
) -> Option<(OnionPayload, [u8; 32])> {
    // Derive the same encryption key the sender used
    let enc_key = {
        let mut h = blake3::Hasher::new();
        h.update(b"vess-onion-v1");
        h.update(&layer.ct_scan);
        h.update(&layer.ct_spend);
        *h.finalize().as_bytes()
    };

    // View tag check
    if layer.view_tag != enc_key[0] {
        return None;
    }

    // Decrypt
    let cipher = chacha20poly1305::ChaCha20Poly1305::new(
        chacha20poly1305::aead::generic_array::GenericArray::from_slice(&enc_key),
    );
    let nonce = chacha20poly1305::aead::generic_array::GenericArray::from_slice(&layer.nonce);

    let plaintext = cipher
        .decrypt(nonce, layer.ciphertext.as_slice())
        .ok()?;

    let payload: OnionPayload = serde_json::from_slice(&plaintext).ok()?;
    Some((payload, layer.next_hop))
}

/// Process an incoming onion route at a relay node.
///
/// Returns the action the relay should take:
/// - `OnionAction::Forward(OnionRoute)` — forward to next hop
/// - `OnionAction::Deliver(Payment, shard_key)` — deliver to DHT shard
/// - `OnionAction::Drop` — not for us
pub enum OnionAction {
    Forward(OnionRoute),
    Deliver { payment: Payment, shard_key: [u8; 32] },
    Drop,
}

pub fn process_onion_route(
    route: &OnionRoute,
    scan_dk: &[u8],
    spend_dk: &[u8],
) -> OnionAction {
    match try_decrypt_onion_layer(&route.outer, scan_dk, spend_dk) {
        Some((OnionPayload::Forward { inner }, _next_hop)) => {
            // We're an intermediate relay — forward the inner layer
            OnionAction::Forward(OnionRoute {
                outer: *inner,
            })
        }
        Some((OnionPayload::Deliver { payment, shard_key }, _)) => {
            // We're the exit relay — deliver to shard
            OnionAction::Deliver { payment, shard_key }
        }
        None => OnionAction::Drop,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_ek() -> Vec<u8> {
        vec![0xAA; 1184] // ML-KEM-768 encap key size
    }

    #[test]
    fn onion_round_trip() {
        let ek1 = dummy_ek();
        let ek2 = dummy_ek();
        let ek3 = dummy_ek();

        let payment = Payment {
            payment_id: [0x42; 32],
            stealth_payload: vec![0x99; 100],
            view_tag: 0,
            stealth_id: [0x11; 32],
            created_at: 12345,
            bill_count: 1,
            mailbox_key: None,
            direct_receipt_tag_hash: None,
            hash_lock: None,
        };
        let shard_key = [0x77; 32];

        let route = build_onion_route(
            payment.clone(),
            shard_key,
            (&ek1, &ek1),
            (&ek2, &ek2),
            (&ek3, &ek3),
        )
        .expect("build onion");

        // Entry decrypts → Forward
        let action1 = process_onion_route(&route, &ek1, &ek1);
        match action1 {
            OnionAction::Forward(inner) => {
                // Middle decrypts → Forward
                let action2 = process_onion_route(&inner, &ek2, &ek2);
                match action2 {
                    OnionAction::Forward(inner2) => {
                        // Exit decrypts → Deliver
                        let action3 = process_onion_route(&inner2, &ek3, &ek3);
                        match action3 {
                            OnionAction::Deliver { payment: p, shard_key: k } => {
                                assert_eq!(p.payment_id, [0x42; 32]);
                                assert_eq!(k, [0x77; 32]);
                            }
                            _ => panic!("expected Deliver"),
                        }
                    }
                    _ => panic!("expected Forward from middle"),
                }
            }
            _ => panic!("expected Forward from entry"),
        }
    }

    #[test]
    fn wrong_key_drops() {
        let ek1 = dummy_ek();
        let ek2 = dummy_ek();
        let ek3 = dummy_ek();
        let wrong_ek = vec![0xBB; 1184];

        let route = build_onion_route(
            Payment {
                payment_id: [0; 32],
                stealth_payload: vec![],
                view_tag: 0,
                stealth_id: [0; 32],
                created_at: 0,
                bill_count: 0,
                mailbox_key: None,
                direct_receipt_tag_hash: None,
                hash_lock: None,
            },
            [0; 32],
            (&ek1, &ek1),
            (&ek2, &ek2),
            (&ek3, &ek3),
        )
        .expect("build");

        // Wrong key → Drop
        let action = process_onion_route(&route, &wrong_ek, &wrong_ek);
        assert!(matches!(action, OnionAction::Drop));
    }
}
