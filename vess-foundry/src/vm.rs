//! RandomX-inspired memory-hard virtual machine for Vess minting.
//!
//! The VM builds a large memory DAG (scratchpad) seeded from the minter's
//! challenge, then executes a pseudo-random program that performs non-linear
//! reads across the scratchpad, making the computation memory-hard and
//! resistant to ASIC shortcuts.
//!
//! Three layers of ASIC resistance:
//!
//! 1. **RAM scratchpad** (1 GiB) — data-dependent random reads.
//! 2. **Bandwidth amplification** — 4 scratchpad reads per VM step instead
//!    of 1, saturating the memory bus.
//! 3. **Disk dataset** (8 GiB) — a per-identity dataset that lives on
//!    NVMe/SSD. The VM reads one disk cache line every 8 steps, mixing
//!    it into the register state. This forces storage I/O that ASICs
//!    cannot shortcut.

use blake3::Hasher;

/// Scratchpad size: 1 GiB expressed in 64-byte cache lines.
///
/// Under the `test-mint` feature this is reduced to 1 MiB so that
/// minting completes in seconds rather than hours.
#[cfg(not(feature = "test-mint"))]
pub const SCRATCHPAD_LINES: usize = 1024 * 1024 * 1024 / 64; // 16_777_216 lines

#[cfg(feature = "test-mint")]
pub const SCRATCHPAD_LINES: usize = 1024 * 1024 / 64; // 16_384 lines (1 MiB)

/// Disk dataset size: 8 GiB expressed in 64-byte cache lines.
///
/// Under `test-mint` this is reduced to 1 MiB (same as scratchpad)
/// and kept in memory instead of on disk.
#[cfg(not(feature = "test-mint"))]
pub const DISK_DATASET_LINES: usize = 8 * 1024 * 1024 * 1024 / 64; // 134_217_728 lines

#[cfg(feature = "test-mint")]
pub const DISK_DATASET_LINES: usize = 1024 * 1024 / 64; // 16_384 lines (1 MiB)

/// How often the VM reads a disk cache line (every N steps).
pub const DISK_READ_INTERVAL: u64 = 8;

/// Number of extra scratchpad reads per step for bandwidth amplification.
/// Total reads per step = 1 (primary) + EXTRA_READS (secondary) = 4.
pub const EXTRA_READS: usize = 3;

/// Each cache line is 64 bytes (8 × u64).
const LINE_U64S: usize = 8;

/// Number of VM registers.
const NUM_REGS: usize = 8;

/// A single 64-byte cache line in the scratchpad.
#[derive(Clone, Copy)]
pub struct CacheLine(pub [u64; LINE_U64S]);

impl Default for CacheLine {
    fn default() -> Self {
        Self([0u64; LINE_U64S])
    }
}

/// One step of VM execution, recorded for the STARK trace.
#[derive(Clone, Debug)]
pub struct VmStep {
    /// Primary scratchpad line read address.
    pub mem_addr: u32,
    /// Secondary scratchpad read addresses (bandwidth amplification).
    pub extra_addrs: [u32; EXTRA_READS],
    /// Disk dataset read address (only valid when `step_idx % DISK_READ_INTERVAL == 0`).
    pub disk_addr: u32,
    /// Register file after this step.
    pub regs: [u64; NUM_REGS],
    /// The opcode executed (encoded as u8).
    pub opcode: u8,
}

/// The full execution trace produced by a minting run.
#[derive(Clone, Debug)]
pub struct VmTrace {
    pub steps: Vec<VmStep>,
    /// Final hash of the register file — the "nonce digest".
    pub digest: [u8; 32],
}

/// Build the 1 GiB scratchpad from a 32-byte seed.
///
/// Each line is derived from the previous line via Blake3, creating a
/// sequential-write / random-read memory pattern similar to RandomX's dataset
/// initialisation.
pub fn build_scratchpad(seed: &[u8; 32]) -> Vec<CacheLine> {
    let mut pad = vec![CacheLine::default(); SCRATCHPAD_LINES];

    // First line: direct hash of seed.
    let mut h = Hasher::new();
    h.update(seed);
    let first = h.finalize();
    fill_line_from_hash(&mut pad[0], first.as_bytes());

    // Subsequent lines: chain-hash from previous line.
    for i in 1..SCRATCHPAD_LINES {
        let mut h = Hasher::new();
        h.update(bytemuck_cast_line(&pad[i - 1]));
        let digest = h.finalize();
        fill_line_from_hash(&mut pad[i], digest.as_bytes());
    }

    pad
}

/// Build the 8 GiB disk dataset from a 32-byte identity seed.
///
/// The dataset is keyed to the minter's `owner_vk_hash`, so changing
/// identity requires regenerating all 8 GiB. In production this is
/// memory-mapped from an NVMe/SSD file; in tests it's just a Vec.
///
/// Generation uses a different domain separator from the scratchpad so
/// the two datasets are independent.
pub fn build_disk_dataset(identity_seed: &[u8; 32]) -> Vec<CacheLine> {
    let mut pad = vec![CacheLine::default(); DISK_DATASET_LINES];

    // First line: domain-separated hash of identity seed.
    let mut h = Hasher::new();
    h.update(b"vess-disk-dataset-v0");
    h.update(identity_seed);
    let first = h.finalize();
    fill_line_from_hash(&mut pad[0], first.as_bytes());

    // Subsequent lines: chain-hash.
    for i in 1..DISK_DATASET_LINES {
        let mut h = Hasher::new();
        h.update(bytemuck_cast_line(&pad[i - 1]));
        let digest = h.finalize();
        fill_line_from_hash(&mut pad[i], digest.as_bytes());
    }

    pad
}

/// Execute the pseudo-random program over the scratchpad and disk dataset.
///
/// `iterations` controls the number of VM steps (proportional to denomination).
/// Returns the full execution trace for STARK proving.
///
/// Each step performs:
/// 1. One primary scratchpad read (data-dependent address).
/// 2. Three secondary scratchpad reads (bandwidth amplification).
/// 3. Every 8th step: one disk dataset read.
/// 4. Opcode execution mixing all reads into registers.
pub fn execute(
    scratchpad: &[CacheLine],
    disk_dataset: &[CacheLine],
    seed: &[u8; 32],
    iterations: u64,
) -> VmTrace {
    let mut regs = [0u64; NUM_REGS];
    // Seed registers from the challenge.
    for (i, chunk) in seed.chunks(4).enumerate().take(NUM_REGS) {
        regs[i] = u64::from_le_bytes({
            let mut buf = [0u8; 8];
            buf[..chunk.len()].copy_from_slice(chunk);
            buf
        });
    }

    let mask = (scratchpad.len() - 1) as u32; // power-of-two mask for addressing
    let disk_mask = (disk_dataset.len() - 1) as u32;
    let mut steps = Vec::with_capacity(iterations as usize);

    for step_idx in 0..iterations {
        // ── Primary scratchpad read ──────────────────────────────
        let addr_reg = regs[(step_idx as usize) % NUM_REGS];
        let mem_addr = (addr_reg as u32) & mask;
        let line = &scratchpad[mem_addr as usize];

        // ── Bandwidth amplification: 3 extra scratchpad reads ────
        let mut extra_addrs = [0u32; EXTRA_READS];
        for k in 0..EXTRA_READS {
            let extra_reg = regs[((step_idx as usize) + k + 1) % NUM_REGS];
            let extra_addr = (extra_reg.rotate_left((k as u32 + 1) * 7) as u32) & mask;
            extra_addrs[k] = extra_addr;
            let extra_line = &scratchpad[extra_addr as usize];
            // Mix extra line into a secondary register via xor-rotate.
            let dst = ((step_idx as usize) + k + 3) % NUM_REGS;
            regs[dst] ^= extra_line.0[(step_idx as usize + k) % LINE_U64S];
            regs[dst] = regs[dst].rotate_right((11 + k as u32 * 3) & 63);
        }

        // ── Disk dataset read (every DISK_READ_INTERVAL steps) ───
        let disk_addr;
        if step_idx % DISK_READ_INTERVAL == 0 {
            let disk_reg = regs[((step_idx as usize) + 5) % NUM_REGS];
            disk_addr = (disk_reg as u32) & disk_mask;
            let disk_line = &disk_dataset[disk_addr as usize];
            // Mix disk data into two registers.
            let d0 = (step_idx as usize) % NUM_REGS;
            let d1 = ((step_idx as usize) + 4) % NUM_REGS;
            regs[d0] = regs[d0].wrapping_add(disk_line.0[0] ^ disk_line.0[3]);
            regs[d1] ^= disk_line.0[5].rotate_left(19);
        } else {
            disk_addr = 0;
        }

        // ── Primary opcode execution ─────────────────────────────
        let opcode = ((step_idx ^ regs[0]) & 0x07) as u8;

        match opcode {
            0 => {
                let w = line.0[(step_idx as usize) % LINE_U64S];
                let dst = ((step_idx as usize) + 1) % NUM_REGS;
                regs[dst] ^= w;
                regs[dst] = regs[dst].rotate_right(17);
            }
            1 => {
                let w0 = line.0[(step_idx as usize) % LINE_U64S];
                let w1 = line.0[(step_idx as usize + 3) % LINE_U64S];
                let dst = ((step_idx as usize) + 2) % NUM_REGS;
                regs[dst] = regs[dst].wrapping_add(w0).wrapping_mul(w1 | 1);
            }
            2 => {
                let w = line.0[(step_idx as usize + 1) % LINE_U64S];
                let dst = ((step_idx as usize) + 3) % NUM_REGS;
                regs[dst] ^= regs[dst].wrapping_mul(w | 1);
            }
            3 => {
                let a = (step_idx as usize) % NUM_REGS;
                let b = ((step_idx as usize) + 4) % NUM_REGS;
                regs.swap(a, b);
                let w = line.0[(step_idx as usize + 2) % LINE_U64S];
                regs[a] = regs[a].wrapping_add(w);
            }
            4 => {
                let w = line.0[(step_idx as usize + 5) % LINE_U64S];
                let dst = ((step_idx as usize) + 5) % NUM_REGS;
                regs[dst] = (regs[dst] << 13) ^ w;
            }
            5 => {
                let w = line.0[(step_idx as usize + 4) % LINE_U64S];
                let dst = ((step_idx as usize) + 6) % NUM_REGS;
                regs[dst] = regs[dst].rotate_left(23).wrapping_add(w);
            }
            6 => {
                let dst = ((step_idx as usize) + 7) % NUM_REGS;
                for j in 0..LINE_U64S {
                    regs[dst] ^= line.0[j];
                }
                regs[dst] = regs[dst].rotate_right(11);
            }
            _ => {
                let w = line.0[(step_idx as usize + 6) % LINE_U64S];
                let dst = (step_idx as usize) % NUM_REGS;
                regs[dst] = (!regs[dst]).wrapping_add(w);
            }
        }

        steps.push(VmStep {
            mem_addr,
            extra_addrs,
            disk_addr,
            regs,
            opcode,
        });
    }

    // Final digest: hash all registers together.
    let mut h = Hasher::new();
    for r in &regs {
        h.update(&r.to_le_bytes());
    }
    let digest = *h.finalize().as_bytes();

    VmTrace { steps, digest }
}

/// Execute the VM returning ONLY the final digest — no trace allocation.
///
/// This is the fast path for mining: skips the ~69 MB `Vec<VmStep>`
/// allocation that `execute()` performs. Call this first to check if a
/// nonce hits the difficulty target, then call `execute()` only on hits
/// to produce the full trace for STARK proof generation.
pub fn execute_digest_only(
    scratchpad: &[CacheLine],
    disk_dataset: &[CacheLine],
    seed: &[u8; 32],
    iterations: u64,
) -> [u8; 32] {
    let mut regs = [0u64; NUM_REGS];
    for (i, chunk) in seed.chunks(4).enumerate().take(NUM_REGS) {
        regs[i] = u64::from_le_bytes({
            let mut buf = [0u8; 8];
            buf[..chunk.len()].copy_from_slice(chunk);
            buf
        });
    }

    let mask = (scratchpad.len() - 1) as u32;
    let disk_mask = (disk_dataset.len() - 1) as u32;

    for step_idx in 0..iterations {
        // ── Primary scratchpad read ──────────────────────────────
        let addr_reg = regs[(step_idx as usize) % NUM_REGS];
        let mem_addr = (addr_reg as u32) & mask;
        let line = &scratchpad[mem_addr as usize];

        // ── Bandwidth amplification: 3 extra scratchpad reads ────
        for k in 0..EXTRA_READS {
            let extra_reg = regs[((step_idx as usize) + k + 1) % NUM_REGS];
            let extra_addr = (extra_reg.rotate_left((k as u32 + 1) * 7) as u32) & mask;
            let extra_line = &scratchpad[extra_addr as usize];
            let dst = ((step_idx as usize) + k + 3) % NUM_REGS;
            regs[dst] ^= extra_line.0[(step_idx as usize + k) % LINE_U64S];
            regs[dst] = regs[dst].rotate_right((11 + k as u32 * 3) & 63);
        }

        // ── Disk dataset read (every DISK_READ_INTERVAL steps) ───
        if step_idx % DISK_READ_INTERVAL == 0 {
            let disk_reg = regs[((step_idx as usize) + 5) % NUM_REGS];
            let disk_addr = (disk_reg as u32) & disk_mask;
            let disk_line = &disk_dataset[disk_addr as usize];
            let d0 = (step_idx as usize) % NUM_REGS;
            let d1 = ((step_idx as usize) + 4) % NUM_REGS;
            regs[d0] = regs[d0].wrapping_add(disk_line.0[0] ^ disk_line.0[3]);
            regs[d1] ^= disk_line.0[5].rotate_left(19);
        }

        // ── Primary opcode execution ─────────────────────────────
        let opcode = ((step_idx ^ regs[0]) & 0x07) as u8;

        match opcode {
            0 => {
                let w = line.0[(step_idx as usize) % LINE_U64S];
                let dst = ((step_idx as usize) + 1) % NUM_REGS;
                regs[dst] ^= w;
                regs[dst] = regs[dst].rotate_right(17);
            }
            1 => {
                let w0 = line.0[(step_idx as usize) % LINE_U64S];
                let w1 = line.0[(step_idx as usize + 3) % LINE_U64S];
                let dst = ((step_idx as usize) + 2) % NUM_REGS;
                regs[dst] = regs[dst].wrapping_add(w0).wrapping_mul(w1 | 1);
            }
            2 => {
                let w = line.0[(step_idx as usize + 1) % LINE_U64S];
                let dst = ((step_idx as usize) + 3) % NUM_REGS;
                regs[dst] ^= regs[dst].wrapping_mul(w | 1);
            }
            3 => {
                let a = (step_idx as usize) % NUM_REGS;
                let b = ((step_idx as usize) + 4) % NUM_REGS;
                regs.swap(a, b);
                let w = line.0[(step_idx as usize + 2) % LINE_U64S];
                regs[a] = regs[a].wrapping_add(w);
            }
            4 => {
                let w = line.0[(step_idx as usize + 5) % LINE_U64S];
                let dst = ((step_idx as usize) + 5) % NUM_REGS;
                regs[dst] = (regs[dst] << 13) ^ w;
            }
            5 => {
                let w = line.0[(step_idx as usize + 4) % LINE_U64S];
                let dst = ((step_idx as usize) + 6) % NUM_REGS;
                regs[dst] = regs[dst].rotate_left(23).wrapping_add(w);
            }
            6 => {
                let dst = ((step_idx as usize) + 7) % NUM_REGS;
                for j in 0..LINE_U64S {
                    regs[dst] ^= line.0[j];
                }
                regs[dst] = regs[dst].rotate_right(11);
            }
            _ => {
                let w = line.0[(step_idx as usize + 6) % LINE_U64S];
                let dst = (step_idx as usize) % NUM_REGS;
                regs[dst] = (!regs[dst]).wrapping_add(w);
            }
        }
    }

    let mut h = Hasher::new();
    for r in &regs {
        h.update(&r.to_le_bytes());
    }
    *h.finalize().as_bytes()
}

// ── helpers ───────────────────────────────────────────────────────────

fn fill_line_from_hash(line: &mut CacheLine, hash: &[u8; 32]) {
    // Expand 32-byte hash into 64-byte cache line by hashing again for the second half.
    let mut h = Hasher::new();
    h.update(hash);
    h.update(&[0x01]); // domain separation
    let second = h.finalize();

    for (i, chunk) in hash.chunks(8).enumerate() {
        line.0[i] = u64::from_le_bytes(chunk.try_into().unwrap());
    }
    for (i, chunk) in second.as_bytes().chunks(8).enumerate() {
        line.0[4 + i] = u64::from_le_bytes(chunk.try_into().unwrap());
    }
}

fn bytemuck_cast_line(line: &CacheLine) -> &[u8] {
    let ptr = line.0.as_ptr() as *const u8;
    // SAFETY: CacheLine is [u64; 8] = 64 bytes, all initialized.
    unsafe { std::slice::from_raw_parts(ptr, 64) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn smoke_test_small_execution() {
        let seed = [0xABu8; 32];
        // Use a tiny scratchpad for testing (not memory-hard, just functional).
        let mut small_pad = vec![CacheLine::default(); 1024];
        let mut h = Hasher::new();
        h.update(&seed);
        let first = h.finalize();
        fill_line_from_hash(&mut small_pad[0], first.as_bytes());
        for i in 1..1024 {
            let mut h = Hasher::new();
            h.update(bytemuck_cast_line(&small_pad[i - 1]));
            let d = h.finalize();
            fill_line_from_hash(&mut small_pad[i], d.as_bytes());
        }

        // Build a tiny disk dataset.
        let mut small_disk = vec![CacheLine::default(); 1024];
        let mut h = Hasher::new();
        h.update(b"vess-disk-dataset-v0");
        h.update(&seed);
        let first = h.finalize();
        fill_line_from_hash(&mut small_disk[0], first.as_bytes());
        for i in 1..1024 {
            let mut h = Hasher::new();
            h.update(bytemuck_cast_line(&small_disk[i - 1]));
            let d = h.finalize();
            fill_line_from_hash(&mut small_disk[i], d.as_bytes());
        }

        let trace = execute(&small_pad, &small_disk, &seed, 100);
        assert_eq!(trace.steps.len(), 100);
        assert_ne!(trace.digest, [0u8; 32]);
    }

    #[test]
    fn digest_only_matches_full_execute() {
        let seed = [0xABu8; 32];
        let mut small_pad = vec![CacheLine::default(); 1024];
        let mut h = Hasher::new();
        h.update(&seed);
        let first = h.finalize();
        fill_line_from_hash(&mut small_pad[0], first.as_bytes());
        for i in 1..1024 {
            let mut h = Hasher::new();
            h.update(bytemuck_cast_line(&small_pad[i - 1]));
            let d = h.finalize();
            fill_line_from_hash(&mut small_pad[i], d.as_bytes());
        }

        let mut small_disk = vec![CacheLine::default(); 1024];
        let mut h = Hasher::new();
        h.update(b"vess-disk-dataset-v0");
        h.update(&seed);
        let first = h.finalize();
        fill_line_from_hash(&mut small_disk[0], first.as_bytes());
        for i in 1..1024 {
            let mut h = Hasher::new();
            h.update(bytemuck_cast_line(&small_disk[i - 1]));
            let d = h.finalize();
            fill_line_from_hash(&mut small_disk[i], d.as_bytes());
        }

        let trace = execute(&small_pad, &small_disk, &seed, 200);
        let digest = execute_digest_only(&small_pad, &small_disk, &seed, 200);
        assert_eq!(trace.digest, digest);
    }
}
