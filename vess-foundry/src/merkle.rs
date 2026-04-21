//! Blake3-based Merkle tree for trace and scratchpad commitments.
//!
//! The tree commits to a sequence of fixed-size leaf entries. Each leaf is
//! hashed with Blake3 and the tree is built bottom-up with domain-separated
//! internal nodes.

use blake3::Hasher;

/// A domain separator mixed into internal node hashes to prevent
/// second-preimage attacks across leaf / internal levels.
const INTERNAL_PREFIX: &[u8] = b"vess-merkle-node";
const LEAF_PREFIX: &[u8] = b"vess-merkle-leaf";

/// A Merkle tree over byte-slice leaves, using Blake3.
pub struct MerkleTree {
    /// All hashes stored in a flat array.
    /// Index 1 is the root. Children of node `i` are `2*i` and `2*i+1`.
    /// Leaves start at index `n` (where `n` is the number of leaves).
    nodes: Vec<[u8; 32]>,
    /// Number of leaves (always a power of two after padding).
    n_leaves: usize,
}

impl MerkleTree {
    /// Build a Merkle tree from leaf data.
    ///
    /// `leaves` is a slice of byte slices, each representing one leaf.
    /// The leaf count is padded to the next power of two with zero-hash leaves.
    pub fn build(leaves: &[&[u8]]) -> Self {
        assert!(!leaves.is_empty(), "cannot build empty Merkle tree");

        let n = leaves.len().next_power_of_two();
        // nodes array: index 0 unused, 1..n are internal, n..2n are leaves
        let mut nodes = vec![[0u8; 32]; 2 * n];

        // Hash leaves.
        for (i, leaf) in leaves.iter().enumerate() {
            nodes[n + i] = hash_leaf(leaf);
        }
        // Pad remaining leaves with hash of empty.
        let pad_hash = hash_leaf(b"");
        for i in leaves.len()..n {
            nodes[n + i] = pad_hash;
        }

        // Build internal nodes bottom-up.
        for i in (1..n).rev() {
            nodes[i] = hash_internal(&nodes[2 * i], &nodes[2 * i + 1]);
        }

        Self { nodes, n_leaves: n }
    }

    /// The Merkle root hash.
    pub fn root(&self) -> [u8; 32] {
        self.nodes[1]
    }

    /// Generate an authentication path (sibling hashes) for leaf at `index`.
    ///
    /// The path goes from leaf to root. Each entry is the sibling hash at
    /// that level.
    pub fn proof(&self, index: usize) -> Vec<[u8; 32]> {
        assert!(index < self.n_leaves, "leaf index out of bounds");
        let mut path = Vec::new();
        let mut pos = self.n_leaves + index;
        while pos > 1 {
            let sibling = pos ^ 1;
            path.push(self.nodes[sibling]);
            pos >>= 1;
        }
        path
    }
}

/// Verify a Merkle authentication path.
///
/// Given the leaf data, its index, the authentication path, and the expected
/// root, returns true if the path is valid.
pub fn verify_path(leaf_data: &[u8], index: usize, path: &[[u8; 32]], root: &[u8; 32]) -> bool {
    let mut hash = hash_leaf(leaf_data);
    let mut pos = index;
    for sibling in path {
        hash = if pos & 1 == 0 {
            hash_internal(&hash, sibling)
        } else {
            hash_internal(sibling, &hash)
        };
        pos >>= 1;
    }
    hash == *root
}

fn hash_leaf(data: &[u8]) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(LEAF_PREFIX);
    h.update(data);
    *h.finalize().as_bytes()
}

fn hash_internal(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(INTERNAL_PREFIX);
    h.update(left);
    h.update(right);
    *h.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_leaf_tree() {
        let tree = MerkleTree::build(&[b"hello"]);
        let proof = tree.proof(0);
        assert!(verify_path(b"hello", 0, &proof, &tree.root()));
    }

    #[test]
    fn four_leaves() {
        let leaves: Vec<&[u8]> = vec![b"a", b"b", b"c", b"d"];
        let tree = MerkleTree::build(&leaves);
        for (i, leaf) in leaves.iter().enumerate() {
            let proof = tree.proof(i);
            assert!(verify_path(leaf, i, &proof, &tree.root()));
        }
        // Tampered leaf should fail.
        let proof = tree.proof(0);
        assert!(!verify_path(b"x", 0, &proof, &tree.root()));
    }

    #[test]
    fn non_power_of_two_is_padded() {
        let leaves: Vec<&[u8]> = vec![b"one", b"two", b"three"];
        let tree = MerkleTree::build(&leaves);
        // All 3 leaves should verify.
        for (i, leaf) in leaves.iter().enumerate() {
            let proof = tree.proof(i);
            assert!(verify_path(leaf, i, &proof, &tree.root()));
        }
    }
}
