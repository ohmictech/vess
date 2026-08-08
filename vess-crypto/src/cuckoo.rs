// Cuckatoo27 — proof-of-work via cycle finding in a bipartite graph.
// Edge(nonce) = (siphash(key, 2*nonce) as u32, siphash(key, 2*nonce+1) as u32).
// Proof is 42 nonces whose edges form a single cycle.
// Solver: ~1.3GB (1.07GB edges + 256MB u8 degrees). Single-core, single-nonce.
// Verifier: O(42) edge checks, microseconds.

#[cfg(feature = "full")]
use std::collections::HashMap;

pub const CYCLE_LENGTH: usize = 42;
pub const EDGE_BITS: u32 = 27; // 2^27 nodes → ~800MB solver
pub const MAX_EDGES: usize = 1 << 27; // 134M edges, density 1.0 → 42-cycles abundant
pub const TEST_EDGE_BITS: u32 = 12; // 2^12=4096 nodes → instant tests
pub const TEST_CYCLE_LENGTH: usize = 6;
pub const MAX_EDGES_TEST: usize = 1 << 15; // 32K edges — covers test params
pub const MAX_SOLVE_ATTEMPTS: usize = 50;

pub type Proof = [u32; CYCLE_LENGTH];

// ---------- siphash-2-4 ----------

fn siphash_round(v: &mut [u64; 4]) {
    v[0] = v[0].wrapping_add(v[1]);
    v[1] = v[1].rotate_left(13) ^ v[0];
    v[0] = v[0].rotate_left(32);
    v[2] = v[2].wrapping_add(v[3]);
    v[3] = v[3].rotate_left(16) ^ v[2];
    v[0] = v[0].wrapping_add(v[3]);
    v[3] = v[3].rotate_left(21) ^ v[0];
    v[2] = v[2].wrapping_add(v[1]);
    v[1] = v[1].rotate_left(17) ^ v[2];
    v[2] = v[2].rotate_left(32);
}

fn siphash24(key: &[u8; 16], input: &[u8]) -> u64 {
    let k0 = u64::from_le_bytes(key[0..8].try_into().unwrap());
    let k1 = u64::from_le_bytes(key[8..16].try_into().unwrap());
    let mut v = [
        k0 ^ 0x736f6d6570736575,
        k1 ^ 0x646f72616e646f6d,
        k0 ^ 0x6c7967656e657261,
        k1 ^ 0x7465646279746573,
    ];
    let chunks = input.chunks_exact(8);
    let rem = chunks.remainder();
    for chunk in chunks {
        let m = u64::from_le_bytes(chunk.try_into().unwrap());
        v[3] ^= m;
        for _ in 0..2 {
            siphash_round(&mut v);
        }
        v[0] ^= m;
    }
    // Standard SipHash tail: b = (input_len << 56) | remaining bytes.
    let mut last = [0u8; 8];
    last[..rem.len()].copy_from_slice(rem);
    last[7] = (input.len() & 0xff) as u8;
    let m = u64::from_le_bytes(last);
    v[3] ^= m;
    for _ in 0..2 {
        siphash_round(&mut v);
    }
    v[0] ^= m;
    v[2] ^= 0xff;
    for _ in 0..4 {
        siphash_round(&mut v);
    }
    v[0] ^ v[1] ^ v[2] ^ v[3]
}

// ---------- edge generation ----------

fn siphash_key(header_hash: &[u8; 32]) -> [u8; 16] {
    let mut key = [0u8; 16];
    key.copy_from_slice(&header_hash[..16]);
    key
}

#[inline]
fn edge_pair(key: &[u8; 16], nonce: u64, edge_bits: u32) -> (u64, u64) {
    let mask = (1u64 << edge_bits) - 1;
    let a = siphash24(key, &(2 * nonce).to_le_bytes()) & mask;
    let b = siphash24(key, &(2 * nonce + 1).to_le_bytes()) & mask;
    (a, b)
}

// ---------- verifier ----------

/// Edge space searched by the solver for these parameters (nonces must stay inside it).
/// Production: 2^EDGE_BITS. Test params use the smaller test table.
fn max_edges_for(edge_bits: u32) -> u64 {
    if edge_bits <= 20 {
        MAX_EDGES_TEST as u64
    } else {
        MAX_EDGES as u64
    }
}

pub fn verify(header_hash: &[u8; 32], proof: &[u32], cycle_len: usize, edge_bits: u32) -> bool {
    if proof.len() != cycle_len || cycle_len > CYCLE_LENGTH {
        return false;
    }
    // Canonical form: strictly ascending nonces. Rejects permutation grinding
    // (same cycle, different order → different difficulty hash) and duplicates.
    if proof.windows(2).any(|w| w[0] >= w[1]) {
        return false;
    }
    // Every nonce must index an edge the solver could actually have used.
    let max_edges = max_edges_for(edge_bits);
    if proof.iter().any(|&n| n as u64 >= max_edges) {
        return false;
    }

    let key = siphash_key(header_hash);

    // ── zero-alloc: stack arrays instead of Vec + HashMap ─────────────

    // Edges: (u, v) for each nonce.
    let mut edges: [(u64, u64); CYCLE_LENGTH] = [(0, 0); CYCLE_LENGTH];
    // Node counter: (node_id, count). At most 2*cycle_len unique nodes.
    let mut nodes: [(u64, u32); CYCLE_LENGTH * 2] = [(0, 0); CYCLE_LENGTH * 2];
    let mut node_count: usize = 0;

    for i in 0..cycle_len {
        let (u, v) = edge_pair(&key, proof[i] as u64, edge_bits);
        edges[i] = (u, v);

        // insert-or-increment both endpoints
        for node in [u, v] {
            if let Some(entry) = nodes[..node_count].iter_mut().find(|(id, _)| *id == node) {
                entry.1 += 1;
            } else {
                if node_count >= CYCLE_LENGTH * 2 {
                    return false;
                }
                nodes[node_count] = (node, 1);
                node_count += 1;
            }
        }
    }

    // Every node must have degree exactly 2.
    if nodes[..node_count].iter().any(|&(_, deg)| deg != 2) {
        return false;
    }

    // ── cycle traversal ──────────────────────────────────────────────

    let mut visited = [false; CYCLE_LENGTH];
    let mut cur = edges[0].0;
    for _ in 0..cycle_len {
        let mut found = false;
        for i in 0..cycle_len {
            if visited[i] {
                continue;
            }
            let (u, v) = edges[i];
            if u == cur {
                visited[i] = true;
                cur = v;
                found = true;
                break;
            }
            if v == cur {
                visited[i] = true;
                cur = u;
                found = true;
                break;
            }
        }
        if !found {
            return false;
        }
    }
    cur == edges[0].0
}

// ---------- solver ----------

/// Scan-based leaf trimming: repeatedly remove edges with a degree-1 endpoint.
/// Uses only the edge array and u8 degree counters — no adjacency index.
///
/// Kept as the reference implementation for [`trim_live`]'s equivalence test
/// (`test_trim_equivalence`); production uses [`trim_live`] instead.
#[cfg(feature = "full")]
#[allow(dead_code)]
fn trim_scan(edges: &[(u32, u32)], alive: &mut [bool], udeg: &mut [u8], vdeg: &mut [u8]) -> bool {
    let mut changed = true;
    let mut any = false;
    while changed {
        changed = false;
        for i in 0..edges.len() {
            if !alive[i] {
                continue;
            }
            let (u, v) = (edges[i].0 as usize, edges[i].1 as usize);
            if udeg[u] <= 1 || vdeg[v] <= 1 {
                alive[i] = false;
                changed = true;
                any = true;
                udeg[u] = udeg[u].saturating_sub(1);
                vdeg[v] = vdeg[v].saturating_sub(1);
            }
        }
    }
    any
}

/// Leaf trimming using a shrinking list of live edge indices.
///
/// Each round filters `live` in place, dropping any edge whose endpoint has
/// degree <= 1 (cascading as degrees drop). Because the list collapses from
/// 134M edges to a few thousand within a couple of rounds, total work is a
/// small multiple of the edge count — vs. `trim_scan`, which rescans all edges
/// every round. The final result is the same 2-core either way.
#[cfg(feature = "full")]
fn trim_live(
    edges: &[(u32, u32)],
    live: &mut Vec<u32>,
    udeg: &mut [u8],
    vdeg: &mut [u8],
) -> bool {
    let mut any = false;
    loop {
        let mut changed = false;
        let mut w = 0;
        for r in 0..live.len() {
            let i = live[r];
            let (u, v) = (edges[i as usize].0 as usize, edges[i as usize].1 as usize);
            if udeg[u] > 1 && vdeg[v] > 1 {
                live[w] = i;
                w += 1;
            } else {
                changed = true;
                any = true;
                udeg[u] = udeg[u].saturating_sub(1);
                vdeg[v] = vdeg[v].saturating_sub(1);
            }
        }
        live.truncate(w);
        if !changed {
            break;
        }
    }
    any
}

/// Build compact adjacency for surviving edges only (few hundred nodes at most).
#[cfg(feature = "full")]
fn build_adj(edges: &[(u32, u32)], live: &[u32]) -> HashMap<u32, Vec<(usize, u32)>> {
    let mut adj: HashMap<u32, Vec<(usize, u32)>> = HashMap::new();
    for &i in live {
        let (u, v) = edges[i as usize];
        adj.entry(u).or_default().push((i as usize, v));
        adj.entry(v).or_default().push((i as usize, u));
    }
    adj
}

#[cfg(feature = "full")]
fn dfs_cycle(
    node: u32,
    target: u32,
    depth: usize,
    target_len: usize,
    adj: &HashMap<u32, Vec<(usize, u32)>>,
    visited_edge: &mut Vec<bool>,
    path: &mut Vec<usize>,
) -> bool {
    if depth == target_len {
        return node == target;
    }
    if let Some(neighbors) = adj.get(&node) {
        for &(edge_idx, next) in neighbors {
            if visited_edge[edge_idx] {
                continue;
            }
            if next == target && depth + 1 < target_len {
                continue;
            }
            visited_edge[edge_idx] = true;
            path.push(edge_idx);
            if dfs_cycle(next, target, depth + 1, target_len, adj, visited_edge, path) {
                return true;
            }
            path.pop();
            visited_edge[edge_idx] = false;
        }
    }
    false
}

#[cfg(feature = "full")]
fn find_cycle_compact(edges: &[(u32, u32)], live: &[u32], cycle_len: usize) -> Option<Vec<u32>> {
    let adj = build_adj(edges, live);
    let mut visited_edge = vec![false; edges.len()];
    let mut path = Vec::new();

    for &start in adj.keys() {
        path.clear();
        visited_edge.fill(false);
        if dfs_cycle(
            start,
            start,
            0,
            cycle_len,
            &adj,
            &mut visited_edge,
            &mut path,
        ) {
            let mut proof: Vec<u32> = path.iter().map(|&idx| idx as u32).collect();
            proof.sort();
            return Some(proof);
        }
    }
    None
}

#[cfg(feature = "full")]
pub fn solve(header_hash: &[u8; 32], cycle_len: usize, edge_bits: u32) -> Option<Vec<u32>> {
    let key = siphash_key(header_hash);
    let max_edges = if edge_bits <= 20 {
        MAX_EDGES_TEST
    } else {
        MAX_EDGES
    };
    let node_count = 1usize << edge_bits;

    // Phase 1: generate edges, count degrees (u8, saturating at 255)
    let mut udeg = vec![0u8; node_count];
    let mut vdeg = vec![0u8; node_count];
    let mut edges: Vec<(u32, u32)> = Vec::with_capacity(max_edges);

    for n in 0..max_edges as u64 {
        let (u, v) = edge_pair(&key, n, edge_bits);
        edges.push((u as u32, v as u32));
        udeg[u as usize] = udeg[u as usize].saturating_add(1);
        vdeg[v as usize] = vdeg[v as usize].saturating_add(1);
    }

    // Phase 2: leaf trimming via a shrinking live-edge list. Each round
    // re-examines only the surviving edges (which collapse from 134M to a
    // handful), so this is ~5-7x faster than rescanning all edges every round.
    let mut live: Vec<u32> = (0..edges.len() as u32).collect();
    for _ in 0..(edge_bits as usize + 2) {
        if live.len() <= cycle_len * 4 {
            break;
        }
        if !trim_live(&edges, &mut live, &mut udeg, &mut vdeg) {
            break;
        }
    }

    // Phase 3: compact DFS cycle search over the surviving edges.
    find_cycle_compact(&edges, &live, cycle_len)
}

/// Hash a proof into a VessId.
pub fn proof_to_id(proof: &[u32]) -> [u8; 32] {
    let mut data = [0u8; CYCLE_LENGTH * 4];
    for (i, n) in proof.iter().enumerate() {
        data[i * 4..(i + 1) * 4].copy_from_slice(&n.to_le_bytes());
    }
    crate::blake3_hash(&data)
}

/// Build the header hash that seeds siphash for a given mint.
/// Commits to: VESS_ID_V1 || chain_hash || diff_bits || address || timestamp || nonce.
pub fn mint_header(
    chain_hash: &[u8; 32],
    diff_bits: u32,
    address: &[u8; 32],
    timestamp: u64,
    nonce: u64,
) -> [u8; 32] {
    let mut pre = [0u8; 94]; // 10 + 32 + 4 + 32 + 8 + 8
    pre[0..10].copy_from_slice(crate::VESS_ID_V1);
    pre[10..42].copy_from_slice(chain_hash);
    pre[42..46].copy_from_slice(&diff_bits.to_le_bytes());
    pre[46..78].copy_from_slice(address);
    pre[78..86].copy_from_slice(&timestamp.to_le_bytes());
    pre[86..94].copy_from_slice(&nonce.to_le_bytes());
    crate::blake3_hash(&pre)
}

/// Try to solve with the given header; if no exact cycle found, bump header and retry.
#[cfg(feature = "full")]
pub fn solve_retry(
    header_hash: &[u8; 32],
    cycle_len: usize,
    edge_bits: u32,
    max_attempts: usize,
) -> Option<Vec<u32>> {
    let mut h = *header_hash;
    for _ in 0..max_attempts {
        if let Some(p) = solve(&h, cycle_len, edge_bits) {
            return Some(p);
        }
        h = crate::blake3_hash(&h);
    }
    None
}

#[cfg(all(test, feature = "full"))]
mod tests {
    use super::*;

    /// The live-list trim must leave exactly the same edges alive as the
    /// reference scan-based trim, on many random graphs.
    #[test]
    fn test_trim_equivalence() {
        let edge_bits = 12; // 2^12 nodes per partition
        let num_edges = 1 << 15; // same density as production (2^27 edges / 2^27 nodes)
        for seed in 0..20u64 {
            let header = crate::blake3_hash(&seed.to_le_bytes());
            let key = siphash_key(&header);
            let mut edges: Vec<(u32, u32)> = Vec::with_capacity(num_edges);
            let mut udeg = vec![0u8; 1 << edge_bits];
            let mut vdeg = vec![0u8; 1 << edge_bits];
            for n in 0..num_edges as u64 {
                let (u, v) = edge_pair(&key, n, edge_bits);
                edges.push((u as u32, v as u32));
                udeg[u as usize] = udeg[u as usize].saturating_add(1);
                vdeg[v as usize] = vdeg[v as usize].saturating_add(1);
            }

            // Reference: scan-based trim.
            let mut alive = vec![true; edges.len()];
            let mut ud1 = udeg.clone();
            let mut vd1 = vdeg.clone();
            while trim_scan(&edges, &mut alive, &mut ud1, &mut vd1) {}

            // New: live-list trim.
            let mut live: Vec<u32> = (0..edges.len() as u32).collect();
            let mut ud2 = udeg.clone();
            let mut vd2 = vdeg.clone();
            while trim_live(&edges, &mut live, &mut ud2, &mut vd2) {}

            // Both must agree on the surviving edge set.
            let mut ref_alive = vec![false; edges.len()];
            for (i, a) in alive.iter().enumerate() {
                ref_alive[i] = *a;
            }
            let mut new_alive = vec![false; edges.len()];
            for &i in &live {
                new_alive[i as usize] = true;
            }
            assert_eq!(ref_alive, new_alive, "trim mismatch for seed {seed}");
        }
    }

    #[test]
    fn test_solve_verify() {
        let h = [0xAA; 32];
        let p = solve_retry(&h, TEST_CYCLE_LENGTH, TEST_EDGE_BITS, MAX_SOLVE_ATTEMPTS)
            .expect("solver should find a cycle within retries");
        assert_eq!(p.len(), TEST_CYCLE_LENGTH);
        // Find which header hash produced this proof
        let mut hdr = h;
        let mut verified = false;
        for _ in 0..MAX_SOLVE_ATTEMPTS {
            if verify(&hdr, &p, TEST_CYCLE_LENGTH, TEST_EDGE_BITS) {
                verified = true;
                break;
            }
            hdr = crate::blake3_hash(&hdr);
        }
        assert!(verified, "proof must verify against its header");
    }

    #[test]
    fn test_tampered_rejected() {
        let h = [0xAA; 32];
        let p = solve_retry(&h, TEST_CYCLE_LENGTH, TEST_EDGE_BITS, MAX_SOLVE_ATTEMPTS).unwrap();
        let mut bad = p.clone();
        bad[0] ^= 1;
        // Find which header produced this proof by trying them
        let mut hdr = h;
        let mut ok = false;
        for _ in 0..MAX_SOLVE_ATTEMPTS {
            if verify(&hdr, &p, TEST_CYCLE_LENGTH, TEST_EDGE_BITS) {
                ok = true;
                break;
            }
            hdr = crate::blake3_hash(&hdr);
        }
        assert!(ok, "proof should verify against its header");
        assert!(
            !verify(&hdr, &bad, TEST_CYCLE_LENGTH, TEST_EDGE_BITS),
            "tampered proof must be rejected"
        );
    }

    #[test]
    fn test_proof_to_id_deterministic() {
        let h = [0xAA; 32];
        let p = solve_retry(&h, TEST_CYCLE_LENGTH, TEST_EDGE_BITS, MAX_SOLVE_ATTEMPTS).unwrap();
        let id = proof_to_id(&p);
        assert_ne!(id, [0u8; 32]);
        assert_eq!(proof_to_id(&p), id);
    }

    /// Solve and return (header, proof) for the header the proof actually verifies against.
    fn solved_header_and_proof() -> ([u8; 32], Vec<u32>) {
        let h = [0xAA; 32];
        let p = solve_retry(&h, TEST_CYCLE_LENGTH, TEST_EDGE_BITS, MAX_SOLVE_ATTEMPTS).unwrap();
        let mut hdr = h;
        for _ in 0..MAX_SOLVE_ATTEMPTS {
            if verify(&hdr, &p, TEST_CYCLE_LENGTH, TEST_EDGE_BITS) {
                return (hdr, p);
            }
            hdr = crate::blake3_hash(&hdr);
        }
        panic!("proof must verify against some header");
    }

    #[test]
    fn test_permuted_proof_rejected() {
        let (hdr, p) = solved_header_and_proof();
        assert!(
            p.windows(2).all(|w| w[0] < w[1]),
            "solver emits ascending proofs"
        );
        let mut permuted = p.clone();
        permuted.swap(0, 1); // breaks ascending order
        assert!(
            !verify(&hdr, &permuted, TEST_CYCLE_LENGTH, TEST_EDGE_BITS),
            "permuted proof must be rejected"
        );
    }

    #[test]
    fn test_duplicate_nonce_rejected() {
        let (hdr, p) = solved_header_and_proof();
        let mut dup = p.clone();
        dup[1] = dup[0]; // duplicate — also breaks strict ascending
        assert!(
            !verify(&hdr, &dup, TEST_CYCLE_LENGTH, TEST_EDGE_BITS),
            "duplicate nonce must be rejected"
        );
    }

    #[test]
    fn test_out_of_range_nonce_rejected() {
        let (hdr, p) = solved_header_and_proof();
        let mut oob = p.clone();
        *oob.last_mut().unwrap() = MAX_EDGES_TEST as u32; // beyond the solver's edge space
        assert!(
            !verify(&hdr, &oob, TEST_CYCLE_LENGTH, TEST_EDGE_BITS),
            "out-of-range nonce must be rejected"
        );
    }

    /// Run `cargo test cuckoo::tests::bench_difficulty -- --ignored --nocapture`
    /// to estimate mining time vs difficulty on your hardware.
    #[test]
    #[ignore]
    fn bench_difficulty() {
        // Quick: measure test-mode nonce throughput
        let h = [0x42; 32];
        let start = std::time::Instant::now();
        let mut found = 0u64;
        let mut hdr = h;
        while start.elapsed().as_secs_f64() < 3.0 {
            if solve(&hdr, TEST_CYCLE_LENGTH, TEST_EDGE_BITS).is_some() {
                found += 1;
            }
            hdr = crate::blake3_hash(&hdr);
        }
        let elapsed = start.elapsed().as_secs_f64();
        let test_nps = found as f64 / elapsed;
        eprintln!("=== CUCKATOO MINING BENCHMARK ===");
        eprintln!(
            "Test mode: {:.1} nonces/s ({} found in {:.1}s)",
            test_nps, found, elapsed
        );

        // Extrapolate to production: edge count ratio
        let test_edges = MAX_EDGES_TEST as f64;
        let prod_edges = MAX_EDGES as f64;
        let test_passes = (TEST_EDGE_BITS + 2) as f64;
        let prod_passes = (EDGE_BITS + 2) as f64;
        let work_ratio = (prod_edges / test_edges) * (prod_passes / test_passes);
        let est_nps = test_nps / work_ratio;
        eprintln!(
            "Work ratio (prod/test): {:.0}x (edges {:.0}x × passes {:.1}x)",
            work_ratio,
            prod_edges / test_edges,
            prod_passes / test_passes
        );
        eprintln!(
            "Estimated production: {:.4} nonces/s ≈ {:.1} nonces/hour",
            est_nps,
            est_nps * 3600.0
        );

        // Time to find each difficulty level (assuming cycle found per nonce)
        eprintln!("--- time to find difficulty D (leading zero bits) ---");
        eprintln!(
            "{:>3} bits | {:>12} nonces | {:>14} | {:>10}",
            "D", "2^D / 2", "expected time", "hashrate"
        );
        for d in [0, 4, 8, 12, 16, 20, 24, 28, 32u32] {
            let expected_nonces = if d == 0 {
                1.0
            } else {
                (1u64 << d) as f64 / 2.0
            };
            let seconds = expected_nonces / est_nps.max(0.0001);
            let hr = 1.0 / seconds.max(0.0001) * 3600.0;
            if seconds < 1.0 {
                eprintln!(
                    "{:>3} bits | {:>12.0} | {:>10.1} ms | {:>7.1}/h",
                    d,
                    expected_nonces,
                    seconds * 1000.0,
                    hr
                );
            } else if seconds < 3600.0 {
                eprintln!(
                    "{:>3} bits | {:>12.0} | {:>10.1} s  | {:>7.1}/h",
                    d, expected_nonces, seconds, hr
                );
            } else {
                let hours = seconds / 3600.0;
                eprintln!(
                    "{:>3} bits | {:>12.0} | {:>10.2} h  | {:>7.1}/h",
                    d, expected_nonces, hours, hr
                );
            }
        }
        eprintln!("==================================");
    }
}
