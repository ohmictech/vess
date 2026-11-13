//! Domain-separated hashing. Every preimage starts with exactly one domain string.

use std::sync::OnceLock;

use blake3::Hasher;

use crate::constants::PROTOCOL_VERSION;
use crate::types::{AccountId, Hash, PublicKey};

pub const DOM_CHAIN_ID: &[u8] = b"VESS-CHAIN-ID-V1";
pub const DOM_ACCOUNT: &[u8] = b"VESS-ACCOUNT-V1";
pub const DOM_TRANSFER: &[u8] = b"VESS-TRANSFER-V1";
pub const DOM_STATE_UPDATE: &[u8] = b"VESS-STATE-UPDATE-V1";
pub const DOM_TRANSACTION_ID: &[u8] = b"VESS-TRANSACTION-ID-V1";
pub const DOM_BLOCK_POW: &[u8] = b"VESS-BLOCK-HEADER-POW-V1";
pub const DOM_BLOCK_ID: &[u8] = b"VESS-BLOCK-ID-V1";
pub const DOM_TX_LEAF: &[u8] = b"VESS-TX-LEAF-V1";
pub const DOM_TX_NODE: &[u8] = b"VESS-TX-NODE-V1";
pub const DOM_TX_ROOT: &[u8] = b"VESS-TX-ROOT-V1";
pub const DOM_STATE_ROOT: &[u8] = b"VESS-STATE-ROOT-V1";
pub const DOM_STATE_LEAF: &[u8] = b"VESS-STATE-LEAF-V1";
pub const DOM_STATE_NODE: &[u8] = b"VESS-STATE-NODE-V1";
pub const DOM_NETWORK_FRAME: &[u8] = b"VESS-NETWORK-FRAME-V1";
pub const DOM_RPC_FRAME: &[u8] = b"VESS-RPC-FRAME-V1";
pub const DOM_DEV_FEE_ACCOUNT: &[u8] = b"VESS-DEV-FEE-ACCOUNT-V1";

/// `BLAKE3(domain || part_0 || part_1 || ...)`.
pub fn tagged(domain: &[u8], parts: &[&[u8]]) -> Hash {
    let mut h = Hasher::new();
    h.update(domain);
    for part in parts {
        h.update(part);
    }
    *h.finalize().as_bytes()
}

pub fn chain_id(network: u8) -> Hash {
    tagged(DOM_CHAIN_ID, &[&[network]])
}

/// The burn address a development fee account must never point at.
///
/// This is `BLAKE3("VESS-DEV-FEE-ACCOUNT-V1")`, which is *not* the hash of any ML-DSA public key: no
/// key is known to hash to it, so fees credited there are unspendable. `DEV_FEE_ACCOUNT` in
/// `constants.rs` holds a real account id and a test asserts it is not this value, so a careless edit
/// cannot silently route every fee into a hole.
pub fn dev_fee_placeholder_account() -> AccountId {
    tagged(DOM_DEV_FEE_ACCOUNT, &[])
}

pub fn account_id(public_key: &PublicKey) -> AccountId {
    tagged(DOM_ACCOUNT, &[public_key.as_slice()])
}

/// Transaction identity.
pub fn transaction_id(kind: u8, unsigned_body: &[u8]) -> Hash {
    tagged(DOM_TRANSACTION_ID, &[&[kind], unsigned_body])
}

pub fn block_id(header_bytes: &[u8; crate::constants::BLOCK_HEADER_BYTES]) -> Hash {
    tagged(DOM_BLOCK_ID, &[header_bytes])
}

pub fn pow_hash(header_bytes: &[u8; crate::constants::BLOCK_HEADER_BYTES]) -> Hash {
    tagged(DOM_BLOCK_POW, &[header_bytes])
}

fn tx_merkle(ids: &[Hash]) -> Hash {
    if ids.is_empty() {
        return [0u8; 32];
    }
    let mut level: Vec<Hash> = ids.iter().map(|id| tagged(DOM_TX_LEAF, &[id])).collect();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            if pair.len() == 2 {
                next.push(tagged(DOM_TX_NODE, &[&pair[0], &pair[1]]));
            } else {
                next.push(pair[0]);
            }
        }
        level = next;
    }
    level[0]
}

pub fn tx_root(ids: &[Hash]) -> Hash {
    debug_assert!(u32::try_from(ids.len()).is_ok());
    let count = (ids.len() as u32).to_be_bytes();
    let merkle = tx_merkle(ids);
    tagged(DOM_TX_ROOT, &[&count, &merkle])
}

pub fn empty_tx_root() -> Hash {
    tx_root(&[])
}

pub fn state_leaf(key: &Hash, value: &[u8]) -> Hash {
    tagged(DOM_STATE_LEAF, &[key, value])
}

pub fn state_node(left: &Hash, right: &Hash) -> Hash {
    tagged(DOM_STATE_NODE, &[left, right])
}

pub fn state_root(account_root: &Hash) -> Hash {
    let version = PROTOCOL_VERSION.to_be_bytes();
    tagged(DOM_STATE_ROOT, &[&version, account_root])
}

/// `DEFAULT[d]` for `d` in `0..=256`: the root of an empty subtree of height `d`.
pub fn default_hashes() -> &'static [Hash] {
    static DEFAULTS: OnceLock<Vec<Hash>> = OnceLock::new();
    DEFAULTS.get_or_init(|| {
        let mut out = Vec::with_capacity(257);
        out.push([0u8; 32]);
        for d in 0..256 {
            let prev = out[d];
            out.push(state_node(&prev, &prev));
        }
        out
    })
}

/// The account ID of a zero-filled public key, used only as a placeholder.
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_dev_fee_account_is_a_real_account_not_the_burn_placeholder() {
        let dev = crate::constants::DEV_FEE_ACCOUNT;
        assert_ne!(dev, dev_fee_placeholder_account());
        assert_ne!(dev, [0u8; 32]);
    }

    #[test]
    fn domains_are_distinct() {
        let domains = [
            DOM_ACCOUNT,
            DOM_TRANSFER,
            DOM_STATE_UPDATE,
            DOM_TRANSACTION_ID,
            DOM_BLOCK_POW,
            DOM_BLOCK_ID,
            DOM_TX_ROOT,
            DOM_STATE_ROOT,
            DOM_STATE_LEAF,
            DOM_STATE_NODE,
        ];
        for (i, a) in domains.iter().enumerate() {
            for b in domains.iter().skip(i + 1) {
                assert_ne!(a, b);
            }
        }
    }

    #[test]
    fn account_id_is_domain_separated() {
        let pk = [7u8; 1952];
        let id = account_id(&pk);
        assert_eq!(id, tagged(DOM_ACCOUNT, &[pk.as_slice()]));
        assert_ne!(id, tagged(DOM_TRANSFER, &[pk.as_slice()]));
        assert_eq!(id.len(), 32);
    }

    #[test]
    fn empty_root_matches_zero_merkle() {
        let empty = tx_root(&[]);
        let count = 0u32.to_be_bytes();
        assert_eq!(empty, tagged(DOM_TX_ROOT, &[&count, &[0u8; 32]]));
    }

    #[test]
    fn tx_root_depends_on_order_and_count() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        assert_ne!(tx_root(&[a, b]), tx_root(&[b, a]));
        assert_ne!(tx_root(&[a]), tx_root(&[a, b]));
        assert_ne!(tx_root(&[a]), tx_root(&[b]));
    }

    #[test]
    fn odd_node_is_promoted_not_duplicated() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        let c = [3u8; 32];
        let leaf = |x: &Hash| tagged(DOM_TX_LEAF, &[x]);
        let node = |l: &Hash, r: &Hash| tagged(DOM_TX_NODE, &[l, r]);
        // [a,b,c] => node(node(a,b), c)
        let expected = node(&node(&leaf(&a), &leaf(&b)), &leaf(&c));
        let count = 3u32.to_be_bytes();
        assert_eq!(
            tx_root(&[a, b, c]),
            tagged(DOM_TX_ROOT, &[&count, &expected])
        );
    }

    #[test]
    fn default_hashes_are_nested() {
        let d = default_hashes();
        assert_eq!(d.len(), 257);
        assert_eq!(d[0], [0u8; 32]);
        for i in 0..256 {
            assert_eq!(d[i + 1], state_node(&d[i], &d[i]));
        }
        assert_ne!(d[256], [0u8; 32]);
    }

    #[test]
    fn chain_ids_differ_per_network() {
        assert_ne!(chain_id(0), chain_id(1));
        assert_ne!(chain_id(1), chain_id(2));
    }
}
