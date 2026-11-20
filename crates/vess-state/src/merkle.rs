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

/// One account's proven value, as `from_proofs` takes it: `(id, leaf value or absence, siblings)`.
pub type ProofEntry = (Hash, Option<Vec<u8>>, Vec<(u8, Hash)>);

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
        // A witness may have pinned this leaf as somebody else's sibling; the leaf itself is now
        // authoritative.
        self.memo.remove(&(DEPTH as u16, key));
        self.recompute_path(&key);
    }

    pub fn remove(&mut self, key: &Hash) -> Option<Vec<u8>> {
        let old = self.leaves.remove(key);
        if old.is_some() {
            self.memo.remove(&(DEPTH as u16, *key));
            self.recompute_path(key);
        }
        old
    }

    pub fn root(&self) -> Hash {
        self.node_hash(0, &[0u8; 32])
    }

    fn node_hash(&self, depth: usize, prefix: &Hash) -> Hash {
        let defaults = default_hashes();
        // Supplied nodes win at every level, including `DEPTH` where a witness may pin a leaf that
        // is not one of the leaves we hold.
        if let Some(hash) = self.memo.get(&(depth as u16, mask_key(prefix, depth))) {
            return *hash;
        }
        if depth == DEPTH {
            return match self.leaves.get(&mask_key(prefix, depth)) {
                Some(value) => state_leaf(prefix, value),
                None => defaults[0],
            };
        }
        // Not a fork, so nothing is stored: either the subtree is empty, or it is a unary chain
        // whose hash follows from the single leaf beneath it. Folding from that leaf is one seek
        // plus at most 256 hashes, which beats descending level by level.
        match self.single_leaf_under(depth, prefix) {
            Some((leaf_key, value)) => {
                let mut node = state_leaf(&leaf_key, value);
                for level in (depth..DEPTH).rev() {
                    let sibling = defaults[DEPTH - (level + 1)];
                    node = if leaf_key[level / 8] & (0x80u8 >> (level % 8)) == 0 {
                        state_node(&node, &sibling)
                    } else {
                        state_node(&sibling, &node)
                    };
                }
                node
            }
            None if !self.occupied(depth, prefix) => defaults[DEPTH - depth],
            None => {
                // Two or more leaves but no stored fork: only reachable if an invariant broke, so
                // compute it honestly rather than returning a default.
                let left_prefix = mask_key(prefix, depth);
                let right_prefix = flip_bit(&left_prefix, depth);
                state_node(
                    &self.node_hash(depth + 1, &left_prefix),
                    &self.node_hash(depth + 1, &right_prefix),
                )
            }
        }
    }

    /// The one account under `depth` bits of `prefix`, if exactly one lives there.
    fn single_leaf_under(&self, depth: usize, prefix: &Hash) -> Option<(Hash, &Vec<u8>)> {
        let masked = mask_key(prefix, depth);
        let mut range = self.leaves.range(masked..);
        let (key, value) = range.next()?;
        if mask_key(key, depth) != masked {
            return None;
        }
        match range.next() {
            Some((next, _)) if mask_key(next, depth) == masked => None,
            _ => Some((*key, value)),
        }
    }

    /// Whether any account lives under `depth` bits of `prefix`. One `BTreeMap` seek.
    fn occupied(&self, depth: usize, prefix: &Hash) -> bool {
        let masked = mask_key(prefix, depth);
        match self.leaves.range(masked..).next() {
            Some((key, _)) => mask_key(key, depth) == masked,
            None => false,
        }
    }

    fn recompute_path(&mut self, key: &Hash) {
        let defaults = default_hashes();
        // Walk up from the leaf, carrying the hash we just computed for the occupied side. Only
        // *forking* nodes (both children non-empty) are stored: a unary chain is fully determined by
        // the one leaf beneath it, so keeping a node for every level of it made the tree cost
        // O(accounts x 256) entries — about 19 KB of RAM per account — for no information. Now a
        // stored node means "two live subtrees meet here", and `node_hash` walks the unary stretches
        // it skips. The root is unchanged: an absent child is exactly `DEFAULT[height]`, which is
        // what the full tree would have hashed anyway.
        let mut occupied = if self.leaves.contains_key(key) {
            state_leaf(key, &self.leaves[key])
        } else {
            defaults[0]
        };
        for depth in (0..DEPTH).rev() {
            // The left child is the depth+1 node whose path bit `depth` is 0.
            let left_prefix = mask_key(key, depth);
            let right_prefix = flip_bit(&left_prefix, depth);
            let goes_left = key[depth / 8] & (0x80u8 >> (depth % 8)) == 0;
            let sibling = self.node_hash(
                depth + 1,
                if goes_left {
                    &right_prefix
                } else {
                    &left_prefix
                },
            );
            let (left, right) = if goes_left {
                (occupied, sibling)
            } else {
                (sibling, occupied)
            };
            let empty = defaults[DEPTH - (depth + 1)];
            let hash = if left == empty && right == empty {
                defaults[DEPTH - depth]
            } else {
                state_node(&left, &right)
            };

            let slot = (depth as u16, left_prefix);
            if left != empty && right != empty {
                self.memo.insert(slot, hash);
            } else {
                self.memo.remove(&slot);
            }
            occupied = hash;
        }
    }

    /// Number of stored internal nodes. Only forking nodes are kept, so this stays proportional to
    /// the number of accounts rather than to accounts x depth.
    pub fn internal_node_count(&self) -> usize {
        self.memo.len()
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

    /// Only the non-default siblings on the path to `key`, ascending by depth.
    ///
    /// A default sibling is implied, not stored, so this is about `log2(accounts)` entries rather
    /// than 256 — the difference between 8 KB and ~700 bytes per account at a million accounts.
    pub fn compact_proof(&self, key: &Hash) -> Vec<(u8, Hash)> {
        let defaults = default_hashes();
        let mut out = Vec::new();
        for depth in 0..DEPTH {
            let sibling = flip_bit(&mask_key(key, depth + 1), depth);
            let hash = self.node_hash(depth + 1, &sibling);
            if hash != defaults[DEPTH - (depth + 1)] {
                out.push((depth as u8, hash));
            }
        }
        out
    }

    /// Fold `siblings` up from `value` (or emptiness) and compare with `root`.
    ///
    /// Every listed depth must be on the path, and every non-default sibling must be listed, so a
    /// truncated or padded proof fails rather than silently folding to a different root.
    pub fn verify_compact_proof(
        root: &Hash,
        key: &Hash,
        value: Option<&[u8]>,
        siblings: &[(u8, Hash)],
    ) -> bool {
        let defaults = default_hashes();
        let mut node = match value {
            Some(value) => state_leaf(key, value),
            None => defaults[0],
        };
        let mut next = siblings.len();
        let mut last_depth: Option<usize> = None;
        for depth in (0..DEPTH).rev() {
            let sibling = match siblings.get(next.wrapping_sub(1)) {
                Some((listed, hash)) if *listed as usize == depth => {
                    // Depths must strictly descend, so no level is claimed twice.
                    if last_depth.is_some_and(|last| last <= depth) {
                        return false;
                    }
                    last_depth = Some(depth);
                    next -= 1;
                    *hash
                }
                _ => defaults[DEPTH - (depth + 1)],
            };
            node = if key[depth / 8] & (0x80u8 >> (depth % 8)) == 0 {
                state_node(&node, &sibling)
            } else {
                state_node(&sibling, &node)
            };
        }
        next == 0 && node == *root
    }

    /// Build a partial tree from witness proofs: the leaves they cover plus the sibling nodes they
    /// carry.
    ///
    /// The result knows only the accounts in `proofs`, but its `root()` equals the full tree's
    /// whenever those proofs are complete for their keys, because every node on their paths is
    /// supplied by a proof or implied by `DEFAULT`. Applying a block to it therefore yields the same
    /// state root as applying it to the whole state.
    pub fn from_proofs(proofs: &[ProofEntry]) -> SparseMerkle {
        let mut leaves = BTreeMap::new();
        let mut memo = HashMap::new();
        for (key, value, siblings) in proofs {
            if let Some(value) = value {
                leaves.insert(*key, value.clone());
            }
            for (depth, hash) in siblings {
                // The sibling at `depth` is the node at `depth + 1` on the other side of the path.
                // At `depth == 255` that is a leaf-level node, so the memo is consulted at `DEPTH`
                // too; see `node_hash`.
                let level = *depth as usize;
                let prefix = flip_bit(&mask_key(key, level + 1), level);
                memo.insert(((level as u16) + 1, mask_key(&prefix, level + 1)), *hash);
            }
        }
        SparseMerkle { leaves, memo }
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

    fn scattered(index: u16) -> Hash {
        let mut k = [0u8; 32];
        k[0..2].copy_from_slice(&index.to_be_bytes());
        k[31] = (index.wrapping_mul(37)) as u8;
        k
    }

    /// Only forking nodes are kept: a compressed binary tree over N leaves has exactly N-1 of them,
    /// where the uncompressed form stored one entry per (account, level) — ~236 per account.
    #[test]
    fn only_forking_nodes_are_stored() {
        let mut tree = SparseMerkle::new();
        for index in 0..120u16 {
            tree.insert(scattered(index), vec![index as u8]);
        }
        assert_eq!(tree.len(), 120);
        assert_eq!(tree.internal_node_count(), tree.len() - 1);
        assert_eq!(tree.root(), naive_root(&tree));

        // Churn must keep the count exact and the root identical.
        for index in 0..60u16 {
            tree.remove(&scattered(index));
        }
        assert_eq!(tree.internal_node_count(), tree.len() - 1);
        assert_eq!(tree.root(), naive_root(&tree));

        for index in 1_000..1_060u16 {
            tree.insert(scattered(index), vec![index as u8]);
        }
        assert_eq!(tree.internal_node_count(), tree.len() - 1);
        assert_eq!(tree.root(), naive_root(&tree));
    }

    #[test]
    fn compact_proofs_are_logarithmic_and_verify() {
        let mut tree = SparseMerkle::new();
        for index in 0..120u16 {
            tree.insert(scattered(index), vec![index as u8, 0xAA]);
        }
        let root = tree.root();
        for index in [0u16, 37, 119] {
            let key = scattered(index);
            let value = tree.get(&key).map(|v| v.to_vec());
            let proof = tree.compact_proof(&key);
            // 120 accounts means at most ~8 forking levels plus the leaf, never 256.
            assert!(proof.len() <= 12, "{} siblings", proof.len());
            assert!(SparseMerkle::verify_compact_proof(
                &root,
                &key,
                value.as_deref(),
                &proof
            ));
            // Padding, truncation and a swapped hash must all fail.
            let mut padded = proof.clone();
            padded.push((255u8, [7u8; 32]));
            assert!(!SparseMerkle::verify_compact_proof(
                &root,
                &key,
                value.as_deref(),
                &padded
            ));
            if !proof.is_empty() {
                let mut truncated = proof.clone();
                truncated.remove(0);
                assert!(!SparseMerkle::verify_compact_proof(
                    &root,
                    &key,
                    value.as_deref(),
                    &truncated
                ));
                let mut tampered = proof.clone();
                tampered[0].1[0] ^= 1;
                assert!(!SparseMerkle::verify_compact_proof(
                    &root,
                    &key,
                    value.as_deref(),
                    &tampered
                ));
            }
        }
    }

    /// A partial tree built only from proofs must produce the full tree's root, and must keep doing
    /// so after an account is added — which is exactly what stateless block execution needs.
    #[test]
    fn a_tree_rebuilt_from_proofs_has_the_same_root() {
        let mut full = SparseMerkle::new();
        for index in 0..80u16 {
            full.insert(scattered(index), vec![index as u8]);
        }
        let root = full.root();
        let touched = [scattered(3), scattered(40), scattered(500)];
        let proofs: Vec<ProofEntry> = touched
            .iter()
            .map(|key| {
                (
                    *key,
                    full.get(key).map(|v| v.to_vec()),
                    full.compact_proof(key),
                )
            })
            .collect();

        let partial = SparseMerkle::from_proofs(&proofs);
        assert_eq!(partial.root(), root, "same root from proofs alone");

        // Mutate the touched accounts identically in both trees.
        for key in touched {
            full.insert(key, vec![0xFF]);
        }
        let mut partial = SparseMerkle::from_proofs(&proofs);
        for key in touched {
            partial.insert(key, vec![0xFF]);
        }
        assert_eq!(partial.root(), full.root());
    }

    #[test]
    fn proofs_still_verify_against_a_compressed_tree() {
        let mut tree = SparseMerkle::new();
        for index in 0..120u16 {
            tree.insert(scattered(index), vec![index as u8, 0xAA]);
        }
        let root = tree.root();
        for index in [0u16, 1, 59, 119] {
            let key = scattered(index);
            let value = tree.get(&key).map(|v| v.to_vec());
            let proof = tree.proof(&key);
            assert_eq!(proof.len(), DEPTH);
            assert!(SparseMerkle::verify_proof(
                &root,
                &key,
                value.as_deref(),
                &proof
            ));
        }
        // An absent account proves non-inclusion.
        let absent = scattered(5_000);
        assert!(SparseMerkle::verify_proof(
            &root,
            &absent,
            None,
            &tree.proof(&absent)
        ));
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
