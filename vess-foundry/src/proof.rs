//! Interactive Oracle Proof (IOP) system for Vess minting proofs.
//!
//! Generates and verifies Merkle-committed execution trace proofs with
//! Fiat-Shamir random spot-check verification. The prover commits to the
//! full VM trace and scratchpad via Merkle trees, then opens random
//! positions chosen by a deterministic challenge derived from the
//! commitments. The verifier re-executes those VM steps and checks
//! consistency.
//!
//! Security: with K query positions, an attacker who fakes a fraction p
//! of the trace has only a (1-p)^K chance of avoiding detection.
//! With K=80: p=5% → 1.7% evasion, p=10% → 0.02% evasion.
//! Combined with local banishment on invalid proofs, each failed
//! attempt permanently costs the attacker a peer connection.

use blake3::Hasher;
use serde::{Deserialize, Serialize};

use crate::merkle::{self, MerkleTree};
use crate::vm::{self, CacheLine, VmStep, VmTrace, EXTRA_READS, DISK_READ_INTERVAL};
use crate::Denomination;

/// Number of random queries the verifier checks.
const NUM_QUERIES: usize = 80;

/// Number of u64 words per cache line.
const LINE_U64S: usize = 8;

/// Number of VM registers.
const NUM_REGS: usize = 8;

/// A single opened query in the proof.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryOpening {
    /// The step index being queried.
    pub step_index: u64,
    /// The trace row at this step (serialised as bytes).
    pub row_bytes: Vec<u8>,
    /// Merkle authentication path for this row in the trace tree.
    pub row_path: Vec<[u8; 32]>,
    /// The previous trace row (for transition verification).
    /// Empty for step 0 (boundary check uses initial registers instead).
    pub prev_row_bytes: Vec<u8>,
    /// Merkle authentication path for the previous row.
    pub prev_row_path: Vec<[u8; 32]>,
    /// The primary scratchpad cache line read during this step.
    pub scratchpad_line: [u64; LINE_U64S],
    /// Merkle authentication path for the primary scratchpad line.
    pub scratchpad_path: Vec<[u8; 32]>,
    /// Extra scratchpad lines for bandwidth amplification.
    pub extra_scratchpad_lines: Vec<[u64; LINE_U64S]>,
    /// Merkle authentication paths for the extra scratchpad lines.
    pub extra_scratchpad_paths: Vec<Vec<[u8; 32]>>,
    /// Disk dataset line (only meaningful when step_index % DISK_READ_INTERVAL == 0).
    pub disk_line: [u64; LINE_U64S],
    /// Merkle authentication path for the disk dataset line.
    pub disk_path: Vec<[u8; 32]>,
}

/// A complete Vess minting proof.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VessProof {
    /// Merkle root of the execution trace.
    pub trace_root: [u8; 32],
    /// Merkle root of the scratchpad.
    pub scratchpad_root: [u8; 32],
    /// Merkle root of the disk dataset.
    pub disk_root: [u8; 32],
    /// The minting nonce.
    pub nonce: [u8; 32],
    /// The denomination minted.
    pub denomination: Denomination,
    /// Random query openings.
    pub queries: Vec<QueryOpening>,
    /// Blake3 hash of the genesis owner's ML-DSA-65 verification key.
    /// Baked into the STARK seed — changing this invalidates the proof.
    pub owner_vk_hash: [u8; 32],
    /// The final VM register hash (= VessBill.digest).
    ///
    /// Included in the Fiat-Shamir challenge derivation so the bill's
    /// digest is bound to the proof: changing it shifts the query indices
    /// and invalidates all Merkle paths.
    pub trace_digest: [u8; 32],
}

/// Serialise a VmStep into a fixed byte layout for Merkle leaf hashing.
fn step_to_bytes(step: &VmStep) -> Vec<u8> {
    // Layout: mem_addr(4) + extra_addrs(4*EXTRA_READS) + disk_addr(4) + regs(8*8) + opcode(1)
    let mut buf = Vec::with_capacity(4 + 4 * EXTRA_READS + 4 + 8 * NUM_REGS + 1);
    buf.extend_from_slice(&step.mem_addr.to_le_bytes());
    for &ea in &step.extra_addrs {
        buf.extend_from_slice(&ea.to_le_bytes());
    }
    buf.extend_from_slice(&step.disk_addr.to_le_bytes());
    for reg in &step.regs {
        buf.extend_from_slice(&reg.to_le_bytes());
    }
    buf.push(step.opcode);
    buf
}

/// Expected byte size of a serialised VmStep.
const STEP_BYTES_LEN: usize = 4 + 4 * EXTRA_READS + 4 + 8 * NUM_REGS + 1;

/// Deserialise bytes back into a VmStep.
fn bytes_to_step(data: &[u8]) -> Option<VmStep> {
    if data.len() < STEP_BYTES_LEN {
        return None;
    }
    let mut off = 0;
    let mem_addr = u32::from_le_bytes(data[off..off + 4].try_into().ok()?);
    off += 4;
    let mut extra_addrs = [0u32; EXTRA_READS];
    for ea in extra_addrs.iter_mut() {
        *ea = u32::from_le_bytes(data[off..off + 4].try_into().ok()?);
        off += 4;
    }
    let disk_addr = u32::from_le_bytes(data[off..off + 4].try_into().ok()?);
    off += 4;
    let mut regs = [0u64; NUM_REGS];
    for reg in regs.iter_mut() {
        *reg = u64::from_le_bytes(data[off..off + 8].try_into().ok()?);
        off += 8;
    }
    let opcode = data[off];
    Some(VmStep {
        mem_addr,
        extra_addrs,
        disk_addr,
        regs,
        opcode,
    })
}

/// Serialise a cache line to bytes for Merkle leaf hashing.
fn line_to_bytes(line: &[u64; LINE_U64S]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(64);
    for &w in line {
        buf.extend_from_slice(&w.to_le_bytes());
    }
    buf
}

/// Derive K deterministic query indices from the proof commitments.
fn derive_query_indices(
    trace_root: &[u8; 32],
    scratchpad_root: &[u8; 32],
    disk_root: &[u8; 32],
    nonce: &[u8; 32],
    trace_digest: &[u8; 32],
    trace_len: u64,
) -> Vec<u64> {
    let mut h = Hasher::new();
    h.update(b"vess-iop-challenges");
    h.update(trace_root);
    h.update(scratchpad_root);
    h.update(disk_root);
    h.update(nonce);
    h.update(trace_digest);
    let mut seed = *h.finalize().as_bytes();

    let mut indices = Vec::with_capacity(NUM_QUERIES);
    while indices.len() < NUM_QUERIES {
        let mut h = Hasher::new();
        h.update(b"vess-iop-derive");
        h.update(&seed);
        h.update(&(indices.len() as u64).to_le_bytes());
        seed = *h.finalize().as_bytes();

        // Use the first 8 bytes as a u64 index.
        let raw = u64::from_le_bytes(seed[0..8].try_into().unwrap());
        // Queries must hit steps 1..trace_len (skip step 0 for transition checks,
        // except we always include step 0 as boundary).
        let idx = if indices.is_empty() {
            0 // First query is always the boundary (step 0).
        } else {
            1 + (raw % (trace_len - 1)) // Steps 1..trace_len-1
        };
        if !indices.contains(&idx) {
            indices.push(idx);
        }
    }
    indices
}

/// Derive the initial register state from the seed (matches vm::execute).
fn initial_registers(seed: &[u8; 32]) -> [u64; NUM_REGS] {
    let mut regs = [0u64; NUM_REGS];
    for (i, chunk) in seed.chunks(4).enumerate().take(NUM_REGS) {
        let mut buf = [0u8; 8];
        buf[..chunk.len()].copy_from_slice(chunk);
        regs[i] = u64::from_le_bytes(buf);
    }
    regs
}

/// Execute a single VM step given the previous register state, the
/// primary scratchpad line, extra scratchpad lines, an optional disk line,
/// and the step index.  Returns the expected (regs_after, opcode).
fn execute_one_step(
    prev_regs: &[u64; NUM_REGS],
    line: &[u64; LINE_U64S],
    extra_lines: &[[u64; LINE_U64S]],
    disk_line: Option<&[u64; LINE_U64S]>,
    step_idx: u64,
) -> ([u64; NUM_REGS], u8) {
    let mut regs = *prev_regs;

    // ── Bandwidth amplification: extra scratchpad reads ──────
    for (k, extra_line) in extra_lines.iter().enumerate() {
        let dst = ((step_idx as usize) + k + 3) % NUM_REGS;
        regs[dst] ^= extra_line[(step_idx as usize + k) % LINE_U64S];
        regs[dst] = regs[dst].rotate_right((11 + k as u32 * 3) & 63);
    }

    // ── Disk dataset read ────────────────────────────────────
    if let Some(dl) = disk_line {
        let d0 = (step_idx as usize) % NUM_REGS;
        let d1 = ((step_idx as usize) + 4) % NUM_REGS;
        regs[d0] = regs[d0].wrapping_add(dl[0] ^ dl[3]);
        regs[d1] ^= dl[5].rotate_left(19);
    }

    // ── Primary opcode execution ─────────────────────────────
    let opcode = ((step_idx ^ regs[0]) & 0x07) as u8;

    match opcode {
        0 => {
            let w = line[(step_idx as usize) % LINE_U64S];
            let dst = ((step_idx as usize) + 1) % NUM_REGS;
            regs[dst] ^= w;
            regs[dst] = regs[dst].rotate_right(17);
        }
        1 => {
            let w0 = line[(step_idx as usize) % LINE_U64S];
            let w1 = line[(step_idx as usize + 3) % LINE_U64S];
            let dst = ((step_idx as usize) + 2) % NUM_REGS;
            regs[dst] = regs[dst].wrapping_add(w0).wrapping_mul(w1 | 1);
        }
        2 => {
            let w = line[(step_idx as usize + 1) % LINE_U64S];
            let dst = ((step_idx as usize) + 3) % NUM_REGS;
            regs[dst] ^= regs[dst].wrapping_mul(w | 1);
        }
        3 => {
            let a = (step_idx as usize) % NUM_REGS;
            let b = ((step_idx as usize) + 4) % NUM_REGS;
            regs.swap(a, b);
            let w = line[(step_idx as usize + 2) % LINE_U64S];
            regs[a] = regs[a].wrapping_add(w);
        }
        4 => {
            let w = line[(step_idx as usize + 5) % LINE_U64S];
            let dst = ((step_idx as usize) + 5) % NUM_REGS;
            regs[dst] = (regs[dst] << 13) ^ w;
        }
        5 => {
            let w = line[(step_idx as usize + 4) % LINE_U64S];
            let dst = ((step_idx as usize) + 6) % NUM_REGS;
            regs[dst] = regs[dst].rotate_left(23).wrapping_add(w);
        }
        6 => {
            let dst = ((step_idx as usize) + 7) % NUM_REGS;
            for val in &line[..LINE_U64S] {
                regs[dst] ^= val;
            }
            regs[dst] = regs[dst].rotate_right(11);
        }
        _ => {
            let w = line[(step_idx as usize + 6) % LINE_U64S];
            let dst = (step_idx as usize) % NUM_REGS;
            regs[dst] = (!regs[dst]).wrapping_add(w);
        }
    }

    (regs, opcode)
}

// ── Prover ────────────────────────────────────────────────────────────

/// Generate an IOP proof for a minting execution.
///
/// The caller provides the full VM trace, the scratchpad, and the nonce
/// used during minting. The function builds Merkle trees, derives
/// Fiat-Shamir challenges, and opens the queried positions.
pub fn generate_proof(
    trace: &VmTrace,
    scratchpad: &[CacheLine],
    disk_dataset: &[CacheLine],
    nonce: &[u8; 32],
    denom: Denomination,
    owner_vk_hash: &[u8; 32],
) -> VessProof {
    let n_steps = trace.steps.len() as u64;
    assert!(n_steps >= NUM_QUERIES as u64, "trace too short for IOP");

    // Build trace Merkle tree (one leaf per step).
    let step_bytes: Vec<Vec<u8>> = trace.steps.iter().map(step_to_bytes).collect();
    let step_refs: Vec<&[u8]> = step_bytes.iter().map(|v| v.as_slice()).collect();
    let trace_tree = MerkleTree::build(&step_refs);

    // Build scratchpad Merkle tree (one leaf per cache line).
    let pad_bytes: Vec<Vec<u8>> = scratchpad
        .iter()
        .map(|cl| line_to_bytes(&cl.0))
        .collect();
    let pad_refs: Vec<&[u8]> = pad_bytes.iter().map(|v| v.as_slice()).collect();
    let pad_tree = MerkleTree::build(&pad_refs);

    // Build disk dataset Merkle tree.
    let disk_bytes: Vec<Vec<u8>> = disk_dataset
        .iter()
        .map(|cl| line_to_bytes(&cl.0))
        .collect();
    let disk_refs: Vec<&[u8]> = disk_bytes.iter().map(|v| v.as_slice()).collect();
    let disk_tree = MerkleTree::build(&disk_refs);

    let trace_root = trace_tree.root();
    let scratchpad_root = pad_tree.root();
    let disk_root = disk_tree.root();

    // Derive query indices (Fiat-Shamir).
    let query_indices = derive_query_indices(&trace_root, &scratchpad_root, &disk_root, nonce, &trace.digest, n_steps);

    // Open each query.
    let seed = crate::mint::derive_seed_pub(nonce, denom, owner_vk_hash);
    let _init_regs = initial_registers(&seed);

    let queries = query_indices
        .iter()
        .map(|&idx| {
            let i = idx as usize;
            let step = &trace.steps[i];

            let row_bytes = step_to_bytes(step);
            let row_path = trace_tree.proof(i);

            let (prev_row_bytes, prev_row_path) = if i == 0 {
                (Vec::new(), Vec::new())
            } else {
                let prev = &trace.steps[i - 1];
                (step_to_bytes(prev), trace_tree.proof(i - 1))
            };

            // Primary scratchpad line.
            let pad_idx = step.mem_addr as usize;
            let scratchpad_line = scratchpad[pad_idx].0;
            let scratchpad_path = pad_tree.proof(pad_idx);

            // Extra scratchpad lines (bandwidth amplification).
            // Use addresses recorded in the trace — the VM mutates registers
            // between extra reads, so static prev_regs can't derive later addrs.
            let mut extra_scratchpad_lines = Vec::with_capacity(EXTRA_READS);
            let mut extra_scratchpad_paths = Vec::with_capacity(EXTRA_READS);
            for k in 0..EXTRA_READS {
                let extra_addr = step.extra_addrs[k] as usize;
                extra_scratchpad_lines.push(scratchpad[extra_addr].0);
                extra_scratchpad_paths.push(pad_tree.proof(extra_addr));
            }

            // Disk dataset line (if applicable).
            let (disk_line, disk_path) = if idx as u64 % DISK_READ_INTERVAL == 0 {
                let da = step.disk_addr as usize;
                (disk_dataset[da].0, disk_tree.proof(da))
            } else {
                ([0u64; LINE_U64S], Vec::new())
            };

            QueryOpening {
                step_index: idx,
                row_bytes,
                row_path,
                prev_row_bytes,
                prev_row_path,
                scratchpad_line,
                scratchpad_path,
                extra_scratchpad_lines,
                extra_scratchpad_paths,
                disk_line,
                disk_path,
            }
        })
        .collect();

    VessProof {
        trace_root,
        scratchpad_root,
        disk_root,
        nonce: *nonce,
        denomination: denom,
        queries,
        owner_vk_hash: *owner_vk_hash,
        trace_digest: trace.digest,
    }
}

// ── Verifier ──────────────────────────────────────────────────────────

/// Verification errors.
#[derive(Debug)]
pub enum VerifyError {
    DeserializeFailed,
    WrongQueryCount,
    QueryIndexMismatch,
    TracePathInvalid(u64),
    PrevTracePathInvalid(u64),
    ScratchpadPathInvalid(u64),
    TransitionMismatch(u64),
    DigestMismatch,
    MalformedRow(u64),
}

/// Verify an IOP proof for a minted bill.
///
/// Checks:
/// 1. The Fiat-Shamir challenge indices match the proof's openings.
/// 2. All Merkle paths in the proof verify against the committed roots.
/// 3. At each queried step, re-executing the VM instruction on the opened
///    previous registers + scratchpad line produces the claimed next state.
/// 4. The final step's register hash matches the expected digest.
pub fn verify_proof(proof: &VessProof, expected_digest: &[u8; 32]) -> Result<(), VerifyError> {
    let n_steps = crate::mint::iterations_for(proof.denomination);
    let seed = crate::mint::derive_seed_pub(&proof.nonce, proof.denomination, &proof.owner_vk_hash);
    let init_regs = initial_registers(&seed);

    if proof.queries.len() != NUM_QUERIES {
        return Err(VerifyError::WrongQueryCount);
    }

    // Re-derive challenges deterministically.
    let expected_indices = derive_query_indices(
        &proof.trace_root,
        &proof.scratchpad_root,
        &proof.disk_root,
        &proof.nonce,
        expected_digest,
        n_steps,
    );

    let mask = (vm::SCRATCHPAD_LINES - 1) as u32;
    let disk_mask = (vm::DISK_DATASET_LINES - 1) as u32;

    // Verify each query opening.
    for (qi, query) in proof.queries.iter().enumerate() {
        let expected_idx = expected_indices[qi];
        if query.step_index != expected_idx {
            return Err(VerifyError::QueryIndexMismatch);
        }

        let step_idx = query.step_index;
        let i = step_idx as usize;

        // 1. Verify trace Merkle path for current row.
        if !merkle::verify_path(&query.row_bytes, i, &query.row_path, &proof.trace_root) {
            return Err(VerifyError::TracePathInvalid(step_idx));
        }

        // 2. Decode current row.
        let current_step =
            bytes_to_step(&query.row_bytes).ok_or(VerifyError::MalformedRow(step_idx))?;

        // 3. Get previous registers.
        let prev_regs = if i == 0 {
            init_regs
        } else {
            // Verify prev row Merkle path.
            if !merkle::verify_path(
                &query.prev_row_bytes,
                i - 1,
                &query.prev_row_path,
                &proof.trace_root,
            ) {
                return Err(VerifyError::PrevTracePathInvalid(step_idx));
            }
            let prev_step = bytes_to_step(&query.prev_row_bytes)
                .ok_or(VerifyError::MalformedRow(step_idx - 1))?;
            prev_step.regs
        };

        // 4. Verify primary address derivation.
        let expected_addr = (prev_regs[(step_idx as usize) % NUM_REGS] as u32) & mask;
        if current_step.mem_addr != expected_addr {
            return Err(VerifyError::TransitionMismatch(step_idx));
        }

        // 5. Verify primary scratchpad Merkle path.
        let pad_leaf = line_to_bytes(&query.scratchpad_line);
        if !merkle::verify_path(
            &pad_leaf,
            current_step.mem_addr as usize,
            &query.scratchpad_path,
            &proof.scratchpad_root,
        ) {
            return Err(VerifyError::ScratchpadPathInvalid(step_idx));
        }

        // 6. Verify extra scratchpad lines (bandwidth amplification).
        //    The VM mutates registers between extra reads, so we must
        //    iteratively track register state to derive later addresses.
        if query.extra_scratchpad_lines.len() != EXTRA_READS
            || query.extra_scratchpad_paths.len() != EXTRA_READS
        {
            return Err(VerifyError::TransitionMismatch(step_idx));
        }
        let mut working_regs = prev_regs;
        for k in 0..EXTRA_READS {
            let extra_reg = working_regs[((step_idx as usize) + k + 1) % NUM_REGS];
            let expected_extra_addr =
                (extra_reg.rotate_left((k as u32 + 1) * 7) as u32) & mask;
            if current_step.extra_addrs[k] != expected_extra_addr {
                return Err(VerifyError::TransitionMismatch(step_idx));
            }
            let extra_leaf = line_to_bytes(&query.extra_scratchpad_lines[k]);
            if !merkle::verify_path(
                &extra_leaf,
                expected_extra_addr as usize,
                &query.extra_scratchpad_paths[k],
                &proof.scratchpad_root,
            ) {
                return Err(VerifyError::ScratchpadPathInvalid(step_idx));
            }
            // Apply the same register mutation the VM does.
            let dst = ((step_idx as usize) + k + 3) % NUM_REGS;
            working_regs[dst] ^= query.extra_scratchpad_lines[k]
                [(step_idx as usize + k) % LINE_U64S];
            working_regs[dst] = working_regs[dst].rotate_right((11 + k as u32 * 3) & 63);
        }

        // 7. Verify disk dataset line (if this is a disk-read step).
        //    working_regs already has bandwidth amp applied.
        let disk_line_opt = if step_idx % DISK_READ_INTERVAL == 0 {
            let disk_reg = working_regs[((step_idx as usize) + 5) % NUM_REGS];
            let expected_disk_addr = (disk_reg as u32) & disk_mask;
            if current_step.disk_addr != expected_disk_addr {
                return Err(VerifyError::TransitionMismatch(step_idx));
            }
            let disk_leaf = line_to_bytes(&query.disk_line);
            if !merkle::verify_path(
                &disk_leaf,
                expected_disk_addr as usize,
                &query.disk_path,
                &proof.disk_root,
            ) {
                return Err(VerifyError::ScratchpadPathInvalid(step_idx));
            }
            Some(&query.disk_line)
        } else {
            None
        };

        // 8. Re-execute the step and check the result matches.
        let (expected_regs, expected_opcode) = execute_one_step(
            &prev_regs,
            &query.scratchpad_line,
            &query.extra_scratchpad_lines,
            disk_line_opt,
            step_idx,
        );

        if current_step.regs != expected_regs || current_step.opcode != expected_opcode {
            return Err(VerifyError::TransitionMismatch(step_idx));
        }
    }

    // 9. Verify the digest.
    if proof.trace_digest != *expected_digest {
        return Err(VerifyError::DigestMismatch);
    }

    Ok(())
}

/// Serialise a VessProof to bytes using postcard.
pub fn serialize_proof(proof: &VessProof) -> Vec<u8> {
    postcard::to_allocvec(proof).expect("proof serialization should not fail")
}

/// Deserialise a VessProof from bytes.
pub fn deserialize_proof(data: &[u8]) -> Result<VessProof, VerifyError> {
    postcard::from_bytes(data).map_err(|_| VerifyError::DeserializeFailed)
}

// ── Aggregate Proofs ─────────────────────────────────────────────────

/// An aggregate proof bundling multiple D1 STARK proofs into a single
/// higher-denomination bill.
///
/// Each D1 proof is independently verifiable. The aggregate denomination
/// equals the number of sub-proofs (1 solve = 1 vess).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregateProof {
    /// Individual D1 STARK proofs (postcard-serialised [`VessProof`]).
    pub d1_proofs: Vec<Vec<u8>>,
    /// Matching digests for each D1 proof.
    pub d1_digests: Vec<[u8; 32]>,
    /// Owner vk_hash baked into all sub-proofs.
    pub owner_vk_hash: [u8; 32],
}

impl AggregateProof {
    /// Serialize to bytes.
    pub fn serialize(&self) -> Vec<u8> {
        postcard::to_allocvec(self).expect("aggregate proof serialization should not fail")
    }

    /// Deserialize from bytes.
    pub fn deserialize(data: &[u8]) -> Result<Self, VerifyError> {
        postcard::from_bytes(data).map_err(|_| VerifyError::DeserializeFailed)
    }

    /// Compute the compound digest for DHT identity.
    ///
    /// `Blake3("vess-aggregate-digest-v0" || d1_digests... || d1_nonces...)`
    pub fn compound_digest(&self) -> Result<[u8; 32], VerifyError> {
        let mut h = Hasher::new();
        h.update(b"vess-aggregate-digest-v0");
        for d in &self.d1_digests {
            h.update(d);
        }
        // Include nonces from each sub-proof for uniqueness.
        // All sub-proofs MUST deserialize — a malformed entry would let
        // an attacker manipulate the compound digest.
        for proof_bytes in &self.d1_proofs {
            let p = deserialize_proof(proof_bytes)
                .map_err(|_| VerifyError::DigestMismatch)?;
            h.update(&p.nonce);
        }
        Ok(*h.finalize().as_bytes())
    }
}

/// Verify an aggregate proof for a claimed denomination.
///
/// Checks:
/// 1. Each sub-proof is a valid D1 STARK with correct difficulty.
/// 2. Sub-proof count matches the claimed denomination value.
/// 3. All sub-proofs share the same owner_vk_hash.
/// 4. The compound digest matches the expected bill digest.
pub fn verify_aggregate_proof(
    agg: &AggregateProof,
    expected_digest: &[u8; 32],
    claimed_denomination: u64,
) -> Result<(), VerifyError> {
    if agg.d1_proofs.len() != agg.d1_digests.len() {
        return Err(VerifyError::WrongQueryCount);
    }
    if agg.d1_proofs.len() as u64 != claimed_denomination {
        return Err(VerifyError::WrongQueryCount);
    }

    let d1_diff = crate::mint::difficulty_bits_for(crate::Denomination::D1);

    for (i, proof_bytes) in agg.d1_proofs.iter().enumerate() {
        let proof = deserialize_proof(proof_bytes)?;

        // Verify denomination is D1.
        if proof.denomination != crate::Denomination::D1 {
            return Err(VerifyError::TransitionMismatch(i as u64));
        }

        // Verify owner_vk_hash matches the aggregate claim.
        if proof.owner_vk_hash != agg.owner_vk_hash {
            return Err(VerifyError::TransitionMismatch(i as u64));
        }

        // Verify the STARK proof itself.
        verify_proof(&proof, &agg.d1_digests[i])?;

        // Verify the digest meets D1 difficulty.
        if !crate::mint::meets_difficulty_pub(&agg.d1_digests[i], d1_diff) {
            return Err(VerifyError::DigestMismatch);
        }
    }

    // Verify compound digest matches.
    let computed = agg.compound_digest()?;
    if computed != *expected_digest {
        return Err(VerifyError::DigestMismatch);
    }

    Ok(())
}

// ── Sampled Aggregate Proofs ─────────────────────────────────────────

/// Number of random D1 proofs spot-checked in a sampled aggregate.
///
/// With 80 samples, an attacker who fakes a fraction p of their solves
/// has a (1-p)^80 chance of passing.  p=5% → 1.7%, p=10% → 0.02%.
const AGGREGATE_SAMPLES: usize = 80;

/// A single opened position in a [`SampledAggregateProof`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SampledEntry {
    pub index: u64,
    pub d1_proof: Vec<u8>,
    pub digest: [u8; 32],
    pub nonce: [u8; 32],
    pub digest_path: Vec<[u8; 32]>,
    pub nonce_path: Vec<[u8; 32]>,
}

/// Sampled aggregate proof for high-denomination bills.
///
/// Commits to all N D1 digests and nonces via Merkle trees, then opens
/// only [`AGGREGATE_SAMPLES`] random positions chosen by Fiat-Shamir.
/// Proof size is O(K × log N) ≈ ~14 MiB constant regardless of N.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SampledAggregateProof {
    pub total_count: u64,
    pub digest_tree_root: [u8; 32],
    pub nonce_tree_root: [u8; 32],
    pub owner_vk_hash: [u8; 32],
    pub samples: Vec<SampledEntry>,
}

impl SampledAggregateProof {
    pub fn serialize(&self) -> Vec<u8> {
        postcard::to_allocvec(self).expect("sampled aggregate proof serialization should not fail")
    }

    pub fn deserialize(data: &[u8]) -> Result<Self, VerifyError> {
        postcard::from_bytes(data).map_err(|_| VerifyError::DeserializeFailed)
    }

    /// Compound digest for bill identity.
    ///
    /// `Blake3("vess-sampled-agg-v0" || total_count || digest_root || nonce_root || owner_vk_hash)`
    pub fn compound_digest(&self) -> [u8; 32] {
        let mut h = Hasher::new();
        h.update(b"vess-sampled-agg-v0");
        h.update(&self.total_count.to_le_bytes());
        h.update(&self.digest_tree_root);
        h.update(&self.nonce_tree_root);
        h.update(&self.owner_vk_hash);
        *h.finalize().as_bytes()
    }
}

/// Derive Fiat-Shamir challenge indices for sampled verification.
pub fn derive_aggregate_sample_indices(
    digest_root: &[u8; 32],
    nonce_root: &[u8; 32],
    total_count: u64,
    owner_vk_hash: &[u8; 32],
) -> Vec<u64> {
    let num_samples = std::cmp::min(AGGREGATE_SAMPLES, total_count as usize);
    let mut h = Hasher::new();
    h.update(b"vess-agg-challenge-v0");
    h.update(digest_root);
    h.update(nonce_root);
    h.update(&total_count.to_le_bytes());
    h.update(owner_vk_hash);
    let challenge = *h.finalize().as_bytes();

    let mut indices = Vec::with_capacity(num_samples);
    let mut counter = 0u64;
    while indices.len() < num_samples {
        let mut ih = Hasher::new();
        ih.update(&challenge);
        ih.update(&counter.to_le_bytes());
        let hash = *ih.finalize().as_bytes();
        let idx = u64::from_le_bytes(hash[..8].try_into().unwrap()) % total_count;
        if !indices.contains(&idx) {
            indices.push(idx);
        }
        counter += 1;
    }
    indices
}

/// Build a sampled aggregate proof.
///
/// `proof_for_index` is called lazily — only ~80 proofs are regenerated
/// regardless of total solve count.
pub fn build_sampled_aggregate(
    digests: &[[u8; 32]],
    nonces: &[[u8; 32]],
    owner_vk_hash: &[u8; 32],
    proof_for_index: &dyn Fn(usize) -> Vec<u8>,
) -> SampledAggregateProof {
    let total_count = digests.len() as u64;
    assert_eq!(digests.len(), nonces.len());
    assert!(total_count > 0);

    let digest_leaves: Vec<&[u8]> = digests.iter().map(|d| d.as_slice()).collect();
    let nonce_leaves: Vec<&[u8]> = nonces.iter().map(|n| n.as_slice()).collect();
    let digest_tree = MerkleTree::build(&digest_leaves);
    let nonce_tree = MerkleTree::build(&nonce_leaves);

    let sample_indices = derive_aggregate_sample_indices(
        &digest_tree.root(),
        &nonce_tree.root(),
        total_count,
        owner_vk_hash,
    );

    let samples: Vec<SampledEntry> = sample_indices
        .iter()
        .map(|&idx| {
            let i = idx as usize;
            SampledEntry {
                index: idx,
                d1_proof: proof_for_index(i),
                digest: digests[i],
                nonce: nonces[i],
                digest_path: digest_tree.proof(i),
                nonce_path: nonce_tree.proof(i),
            }
        })
        .collect();

    SampledAggregateProof {
        total_count,
        digest_tree_root: digest_tree.root(),
        nonce_tree_root: nonce_tree.root(),
        owner_vk_hash: *owner_vk_hash,
        samples,
    }
}

/// Verify a sampled aggregate proof.
pub fn verify_sampled_aggregate(
    sap: &SampledAggregateProof,
    expected_digest: &[u8; 32],
    claimed_denomination: u64,
) -> Result<(), VerifyError> {
    if sap.total_count != claimed_denomination {
        return Err(VerifyError::WrongQueryCount);
    }

    let expected_num_samples = std::cmp::min(AGGREGATE_SAMPLES, sap.total_count as usize);
    if sap.samples.len() != expected_num_samples {
        return Err(VerifyError::WrongQueryCount);
    }

    let expected_indices = derive_aggregate_sample_indices(
        &sap.digest_tree_root,
        &sap.nonce_tree_root,
        sap.total_count,
        &sap.owner_vk_hash,
    );

    let d1_diff = crate::mint::difficulty_bits_for(crate::Denomination::D1);

    for (j, sample) in sap.samples.iter().enumerate() {
        if sample.index != expected_indices[j] {
            return Err(VerifyError::QueryIndexMismatch);
        }

        if !merkle::verify_path(
            &sample.digest,
            sample.index as usize,
            &sample.digest_path,
            &sap.digest_tree_root,
        ) {
            return Err(VerifyError::TracePathInvalid(sample.index));
        }
        if !merkle::verify_path(
            &sample.nonce,
            sample.index as usize,
            &sample.nonce_path,
            &sap.nonce_tree_root,
        ) {
            return Err(VerifyError::TracePathInvalid(sample.index));
        }

        let proof = deserialize_proof(&sample.d1_proof)?;
        if proof.denomination != crate::Denomination::D1 {
            return Err(VerifyError::TransitionMismatch(sample.index));
        }
        if proof.owner_vk_hash != sap.owner_vk_hash {
            return Err(VerifyError::TransitionMismatch(sample.index));
        }
        if proof.nonce != sample.nonce {
            return Err(VerifyError::TransitionMismatch(sample.index));
        }
        verify_proof(&proof, &sample.digest)?;
        if !crate::mint::meets_difficulty_pub(&sample.digest, d1_diff) {
            return Err(VerifyError::DigestMismatch);
        }
    }

    let computed = sap.compound_digest();
    if computed != *expected_digest {
        return Err(VerifyError::DigestMismatch);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn step_serialization_round_trip() {
        let step = VmStep {
            mem_addr: 42,
            extra_addrs: [10, 20, 30],
            disk_addr: 99,
            regs: [1, 2, 3, 4, 5, 6, 7, 8],
            opcode: 3,
        };
        let bytes = step_to_bytes(&step);
        let recovered = bytes_to_step(&bytes).unwrap();
        assert_eq!(recovered.mem_addr, 42);
        assert_eq!(recovered.extra_addrs, [10, 20, 30]);
        assert_eq!(recovered.disk_addr, 99);
        assert_eq!(recovered.regs, [1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(recovered.opcode, 3);
    }

    #[test]
    fn execute_one_step_matches_vm() {
        // Build a small trace and verify our re-execution matches.
        let seed = [0x42u8; 32];
        let scratchpad = vm::build_scratchpad(&seed);
        let disk_dataset = vm::build_disk_dataset(&seed);
        let trace = vm::execute(&scratchpad, &disk_dataset, &seed, 10);
        let init_regs = initial_registers(&seed);

        // Build extra lines for step 0.
        let step0 = &trace.steps[0];
        let extra0: Vec<[u64; LINE_U64S]> = (0..EXTRA_READS)
            .map(|k| {
                let ea = step0.extra_addrs[k] as usize;
                scratchpad[ea].0
            })
            .collect();
        let disk0 = if 0 % DISK_READ_INTERVAL == 0 {
            Some(&disk_dataset[step0.disk_addr as usize].0)
        } else {
            None
        };
        let (regs, opcode) = execute_one_step(
            &init_regs,
            &scratchpad[step0.mem_addr as usize].0,
            &extra0,
            disk0,
            0,
        );
        assert_eq!(step0.regs, regs);
        assert_eq!(step0.opcode, opcode);

        // Verify step 5 (middle).
        let step5 = &trace.steps[5];
        let extra5: Vec<[u64; LINE_U64S]> = (0..EXTRA_READS)
            .map(|k| {
                let ea = step5.extra_addrs[k] as usize;
                scratchpad[ea].0
            })
            .collect();
        let disk5 = if 5 % DISK_READ_INTERVAL == 0 {
            Some(&disk_dataset[step5.disk_addr as usize].0)
        } else {
            None
        };
        let (regs, opcode) = execute_one_step(
            &trace.steps[4].regs,
            &scratchpad[step5.mem_addr as usize].0,
            &extra5,
            disk5,
            5,
        );
        assert_eq!(step5.regs, regs);
        assert_eq!(step5.opcode, opcode);
    }
}
