//! 256-level sparse Merkle tree with published default-subtree hashes.
//!
//! Path bit for level `d` is bit `255 - d` of the key, most-significant first. Empty subtrees
//! collapse to `DEFAULT[height]`, so the tree costs nothing for absent accounts.

use std::collections::{BTreeMap, HashMap};

use vess_core::Hash;
use vess_core::hash::{default_hashes, state_leaf, state_node};

pub const DEPTH: usize = 256;

/// Keep only the top `depth` bits of `key`.
fn mask_key(key: &Hash, depth: usize) -> Hash {
    debug_assert!(depth <= DEPTH);
    let mut out = [0u8; 32];
    let full = depth / 8;
    let rem = depth % 8;
    out[..full].copy_from_slice(&key[..full]);
    if rem > 0 {
        out[full] = key[full] & (0xFFu8 << (8 - rem));
    }
    out
}

/// Flip path bit `depth` of `key`.
fn flip_bit(key: &Hash, depth: usize) -> Hash {
    let mut out = *key;
    out[depth / 8] ^= 0x80u8 >> (depth % 8);
    out
}

#[derive(Debug, Clone, Default)]
pub struct SparseMerkle {
    leaves: BTreeMap<Hash, Vec<u8>>,
    /// Non-default internal nodes, keyed by (depth, path prefix).
    memo: HashMap<(u16, Hash), Hash>,
}

impl SparseMerkle {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    pub fn get(&self, key: &Hash) -> Option<&[u8]> {
        self.leaves.get(key).map(|v| v.as_slice())
    }

    pub fn iter(&self) -> impl Iterator<Item = (&Hash, &Vec<u8>)> {
        self.leaves.iter()
    }

    pub fn insert(&mut self, key: Hash, value: Vec<u8>) {
        self.leaves.insert(key, value);
        self.recompute_path(&key);
    }

    pub fn remove(&mut self, key: &Hash) -> Option<Vec<u8>> {
        let old = self.leaves.remove(key);
        if old.is_some() {
            self.recompute_path(key);
        }
        old
    }

    pub fn root(&self) -> Hash {
        self.node_hash(0, &[0u8; 32])
    }

    fn node_hash(&self, depth: usize, prefix: &Hash) -> Hash {
        let defaults = default_hashes();
        if depth == DEPTH {
            match self.leaves.get(prefix) {
                Some(value) => state_leaf(prefix, value),
                None => defaults[0],
            }
        } else {
            *self
                .memo
                .get(&(depth as u16, *prefix))
                .unwrap_or(&defaults[DEPTH - depth])
        }
    }

    fn recompute_path(&mut self, key: &Hash) {
        let defaults = default_hashes();
        for depth in (0..DEPTH).rev() {
            // The left child is the depth+1 node whose path bit `depth` is 0.
            let left_prefix = mask_key(key, depth);
            let right_prefix = flip_bit(&left_prefix, depth);
            let left = self.node_hash(depth + 1, &left_prefix);
            let right = self.node_hash(depth + 1, &right_prefix);
            let empty = defaults[DEPTH - (depth + 1)];
            let hash = if left == empty && right == empty {
                defaults[DEPTH - depth]
            } else {
                state_node(&left, &right)
            };

            let slot = (depth as u16, mask_key(key, depth));
            if hash == defaults[DEPTH - depth] {
                self.memo.remove(&slot);
            } else {
                self.memo.insert(slot, hash);
            }
        }
    }

    /// 256 sibling hashes, top level first.
    pub fn proof(&self, key: &Hash) -> Vec<Hash> {
        let mut out = Vec::with_capacity(DEPTH);
        for depth in 0..DEPTH {
            let sibling = flip_bit(&mask_key(key, depth + 1), depth);
            out.push(self.node_hash(depth + 1, &sibling));
        }
        out
    }

    /// Fold `proof` up from `value` (or emptiness) and compare with `root`.
    pub fn verify_proof(root: &Hash, key: &Hash, value: Option<&[u8]>, proof: &[Hash]) -> bool {
        if proof.len() != DEPTH {
            return false;
        }
        let defaults = default_hashes();
        let mut node = match value {
            Some(v) => state_leaf(key, v),
            None => defaults[0],
        };
        for depth in (0..DEPTH).rev() {
            let sibling = &proof[depth];
            node = if key[depth / 8] & (0x80u8 >> (depth % 8)) == 0 {
                state_node(&node, sibling)
            } else {
                state_node(sibling, &node)
            };
        }
        node == *root
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(byte: u8) -> Hash {
        let mut k = [0u8; 32];
        k[0] = byte;
        k
    }

    /// Independent root computation: recurse from the top, pruning empty subtrees, without
    /// touching the incremental memo.
    fn naive_node(tree: &SparseMerkle, depth: usize, prefix: &Hash) -> Hash {
        let defaults = default_hashes();
        let occupied = tree.leaves.keys().any(|k| mask_key(k, depth) == *prefix);
        if !occupied {
            return defaults[DEPTH - depth];
        }
        if depth == DEPTH {
            return state_leaf(prefix, tree.leaves.get(prefix).unwrap());
        }
        let left = mask_key(prefix, depth + 1);
        let right = flip_bit(&left, depth);
        state_node(
            &naive_node(tree, depth + 1, &left),
            &naive_node(tree, depth + 1, &right),
        )
    }

    fn naive_root(tree: &SparseMerkle) -> Hash {
        naive_node(tree, 0, &[0u8; 32])
    }

    #[test]
    fn incremental_root_matches_naive_recomputation() {
        let mut tree = SparseMerkle::new();
        tree.insert(key(1), vec![1]);
        assert_eq!(tree.root(), naive_root(&tree), "one key");
        tree.insert(key(2), vec![2]);
        assert_eq!(tree.root(), naive_root(&tree), "two keys");
        tree.insert([0xFFu8; 32], vec![3]);
        assert_eq!(tree.root(), naive_root(&tree), "three keys");
        tree.remove(&key(2));
        assert_eq!(tree.root(), naive_root(&tree), "after removal");
    }

    #[test]
    fn empty_tree_root_is_default_256() {
        let tree = SparseMerkle::new();
        assert_eq!(tree.root(), default_hashes()[DEPTH]);
        assert_eq!(tree.len(), 0);
        assert!(tree.is_empty());
    }

    #[test]
    fn insert_update_remove_roundtrip() {
        let empty = default_hashes()[DEPTH];
        let mut tree = SparseMerkle::new();

        tree.insert(key(1), vec![1]);
        let after_one = tree.root();
        assert_ne!(after_one, empty);
        assert_eq!(tree.get(&key(1)), Some(&[1u8][..]));

        tree.insert(key(1), vec![2]);
        let after_update = tree.root();
        assert_ne!(after_update, after_one);

        assert_eq!(tree.remove(&key(1)), Some(vec![2]));
        assert_eq!(tree.root(), empty);
        assert_eq!(tree.remove(&key(1)), None);
        assert_eq!(tree.root(), empty);
    }

    #[test]
    fn independent_of_insertion_order() {
        let mut a = SparseMerkle::new();
        a.insert(key(1), vec![1]);
        a.insert(key(2), vec![2]);
        a.insert([0xFFu8; 32], vec![3]);

        let mut b = SparseMerkle::new();
        b.insert([0xFFu8; 32], vec![3]);
        b.insert(key(2), vec![2]);
        b.insert(key(1), vec![1]);

        assert_eq!(a.root(), b.root());
    }

    #[test]
    fn inclusion_and_non_inclusion_proofs_verify() {
        let mut tree = SparseMerkle::new();
        tree.insert(key(1), vec![1]);
        tree.insert(key(2), vec![2]);
        let root = tree.root();

        let p = tree.proof(&key(1));
        assert_eq!(p.len(), DEPTH);
        assert!(SparseMerkle::verify_proof(&root, &key(1), Some(&[1]), &p));
        assert!(!SparseMerkle::verify_proof(&root, &key(1), Some(&[9]), &p));
        assert!(!SparseMerkle::verify_proof(&root, &key(1), None, &p));

        let absent = tree.proof(&key(3));
        assert!(SparseMerkle::verify_proof(&root, &key(3), None, &absent));
        assert!(!SparseMerkle::verify_proof(
            &root,
            &key(3),
            Some(&[3]),
            &absent
        ));
    }

    #[test]
    fn proofs_do_not_cross_keys() {
        let mut tree = SparseMerkle::new();
        tree.insert(key(1), vec![1]);
        tree.insert(key(2), vec![2]);
        let root = tree.root();
        let p1 = tree.proof(&key(1));
        assert!(!SparseMerkle::verify_proof(&root, &key(2), Some(&[1]), &p1));
    }

    #[test]
    fn keys_sharing_long_prefixes_stay_distinct() {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        // Differ only in the final bit.
        b[31] = 0x01;
        let mut tree = SparseMerkle::new();
        tree.insert(a, vec![1]);
        tree.insert(b, vec![2]);
        assert_eq!(tree.len(), 2);
        let root = tree.root();
        assert!(SparseMerkle::verify_proof(
            &root,
            &a,
            Some(&[1]),
            &tree.proof(&a)
        ));
        assert!(SparseMerkle::verify_proof(
            &root,
            &b,
            Some(&[2]),
            &tree.proof(&b)
        ));
        a[31] = 0x02;
        assert!(SparseMerkle::verify_proof(&root, &a, None, &tree.proof(&a)));
    }

    #[test]
    fn mask_and_flip_helpers() {
        let k = [0xFFu8; 32];
        assert_eq!(mask_key(&k, 0), [0u8; 32]);
        assert_eq!(mask_key(&k, 8)[0], 0xFF);
        assert_eq!(mask_key(&k, 8)[1], 0x00);
        assert_eq!(mask_key(&k, 4)[0], 0xF0);
        assert_eq!(mask_key(&k, 256), k);
        assert_eq!(flip_bit(&[0u8; 32], 0)[0], 0x80);
        assert_eq!(flip_bit(&[0u8; 32], 255)[31], 0x01);
    }
}
