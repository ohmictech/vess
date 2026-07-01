//! Peer handshake protocol for version integrity verification.
//!
//! Every artery node embeds a build-time `PROTOCOL_VERSION_HASH` — a Blake3
//! Merkle root over all workspace source files.  During the handshake a
//! challenger sends a random nonce and the peer must prove knowledge of an
//! *allowed* version hash via `blake3::keyed_hash(version_hash, nonce)`.
//!
//! # State machine
//!
//! ```text
//! Unknown ──▶ Challenged ──▶ Verified
//!                │
//!                ▼
//!            Banished
//! ```
//!
//! Peers start as [`PeerState::Unknown`].  When challenged they transition to
//! [`PeerState::Challenged`].  A valid response promotes them to
//! [`PeerState::Verified`]; failure leads to [`PeerState::Banished`] and
//! silent packet drop.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use argon2::{Algorithm, Argon2, Params, Version};
use rand::RngCore;

// ── Build-time version hash ──────────────────────────────────────────

include!(concat!(env!("OUT_DIR"), "/version_hash.rs"));

/// Sliding window of accepted protocol version hashes.
///
/// The current build's hash is always first.  Previous versions are loaded
/// from `vess-artery/versions.txt` at build time — add hex-encoded hashes
/// there during rolling upgrades so that peers running older builds are
/// still admitted.
///
/// Built at startup from the compile-time constants; cannot be tampered
/// with at runtime.
pub static ALLOWED_VERSIONS: std::sync::LazyLock<Vec<[u8; 32]>> = std::sync::LazyLock::new(|| {
    let mut v = vec![PROTOCOL_VERSION_HASH];
    v.extend_from_slice(PREVIOUS_VERSION_HASHES);
    v
});

// ── Handshake PoW parameters ────────────────────────────────────────

/// Argon2id memory cost for handshake PoW: 1 GiB (in KiB).
/// Fixed cost — does not scale with network size. High enough that
/// Sybil fleets pay a meaningful RAM cost per fake node, but tolerable
/// for honest users running a single node.
pub const HANDSHAKE_POW_M_COST: u32 = 1024 * 1024; // 1 GiB
/// Argon2id time cost (iterations) for handshake PoW.
pub const HANDSHAKE_POW_T_COST: u32 = 2;
/// Argon2id parallelism for handshake PoW.
pub const HANDSHAKE_POW_P_COST: u32 = 1;
/// Argon2id output length for handshake PoW.
pub const HANDSHAKE_POW_OUTPUT_LEN: usize = 32;

#[cfg(test)]
/// Reduced parameters for unit tests (fast: 1 KiB × 1 iteration).
pub const HANDSHAKE_POW_M_COST_TEST: u32 = 8; // 8 KiB
#[cfg(test)]
pub const HANDSHAKE_POW_T_COST_TEST: u32 = 1;

// ── Peer state machine ──────────────────────────────────────────────

/// Handshake lifecycle of a remote peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerState {
    /// Never challenged — no trust established.
    Unknown,
    /// Challenge nonce sent, awaiting HMAC response.
    Challenged,
    /// Peer proved it holds an allowed version hash.
    Verified,
    /// Peer failed verification — all traffic silently dropped.
    Banished,
}

/// Internal bookkeeping for a single peer.
#[derive(Debug, Clone)]
pub struct PeerEntry {
    pub state: PeerState,
    /// Nonce issued in the current (or most recent) challenge.
    pub challenge_nonce: Option<[u8; 32]>,
    /// When the challenge was issued (for timeout eviction).
    pub challenged_at: Option<Instant>,
    /// When the peer was verified.
    pub verified_at: Option<Instant>,
    /// Number of consecutive failed handshake attempts.
    /// Reset to 0 on successful verification.
    pub handshake_failures: u32,
    /// When the last handshake attempt was made (success or failure).
    /// Used for backoff calculation.
    pub last_handshake_at: Option<Instant>,
    /// True if this peer has submitted a valid Bitcoin burn proof,
    /// proving they are a real Vess user (not a Sybil). Required for
    /// TagLookup queries.
    pub has_proven_burn: bool,
    /// Relay encapsulation key (ML-KEM-768 scan_ek) shared during handshake.
    /// Present for nodes willing to relay onion payments.
    pub relay_ek: Option<Vec<u8>>,
}

// ── Peer registry ───────────────────────────────────────────────────

/// How long a peer's verification stays valid before re-handshake is required.
/// 20 minutes — frequent enough that Sybil fleets must continuously burn
/// resources, but long enough that honest nodes aren't overwhelmed.
pub const REVERIFICATION_INTERVAL: Duration = Duration::from_secs(20 * 60); // 20 minutes

/// Tracks handshake state for every known peer.
///
/// **Not internally synchronised** — the caller is expected to hold the
/// enclosing `Mutex` (e.g. inside `ArteryState`).
pub struct PeerRegistry {
    peers: HashMap<[u8; 32], PeerEntry>,
    /// Challenges older than this are evicted back to Unknown.
    challenge_timeout: Duration,
}

impl PeerRegistry {
    pub fn new(challenge_timeout: Duration) -> Self {
        Self {
            peers: HashMap::new(),
            challenge_timeout,
        }
    }

    /// Current state of `peer_id` (defaults to [`PeerState::Unknown`]).
    pub fn state(&self, peer_id: &[u8; 32]) -> PeerState {
        self.peers
            .get(peer_id)
            .map_or(PeerState::Unknown, |e| e.state)
    }

    /// Generate a random nonce, record it, and transition peer to Challenged.
    ///
    /// Returns `Some(nonce)` to embed in a [`HandshakeChallenge`] message,
    /// or `None` if the peer is Banished and should not be challenged.
    pub fn issue_challenge(&mut self, peer_id: [u8; 32]) -> Option<[u8; 32]> {
        // Never overwrite Banished entries — return None as sentinel.
        if let Some(existing) = self.peers.get(&peer_id) {
            if existing.state == PeerState::Banished {
                return None;
            }
            // If already Challenged and the challenge hasn't expired, return
            // the existing nonce.  This prevents concurrent tasks (handshake
            // drain + reverification) from overwriting each other's nonces
            // and causing spurious banishment.
            if existing.state == PeerState::Challenged {
                if let (Some(nonce), Some(at)) =
                    (existing.challenge_nonce, existing.challenged_at)
                {
                    if at.elapsed() < self.challenge_timeout {
                        return Some(nonce);
                    }
                }
            }
            // Verified peers fall through to get a fresh challenge
            // (needed for periodic reverification).
        }

        let mut nonce = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut nonce);

        // Preserve failure count across re-challenges so backoff works.
        let failures = self.peers.get(&peer_id).map(|e| e.handshake_failures).unwrap_or(0);
        self.peers.insert(
            peer_id,
            PeerEntry {
                state: PeerState::Challenged,
                challenge_nonce: Some(nonce),
                challenged_at: Some(Instant::now()),
                verified_at: None,
                handshake_failures: failures,
                last_handshake_at: Some(Instant::now()),
                has_proven_burn: false,
                relay_ek: None,
            },
        );
        Some(nonce)
    }

    /// Verify the HMAC in a [`HandshakeResponse`] against the stored nonce.
    ///
    /// Returns `true` if the peer is (or already was) Verified.
    /// Returns `false` only if the HMAC is invalid AND the peer was not
    /// already Verified — callers should only banish on `false`.
    pub fn verify_response(
        &mut self,
        peer_id: &[u8; 32],
        hmac: &[u8; 32],
        allowed_versions: &[[u8; 32]],
    ) -> bool {
        let entry = match self.peers.get(peer_id) {
            Some(e) if e.state == PeerState::Challenged => e,
            // Already Verified — treat as success (no state change needed).
            Some(e) if e.state == PeerState::Verified => return true,
            _ => return false,
        };
        let nonce = match &entry.challenge_nonce {
            Some(n) => *n,
            None => return false,
        };

        if verify_handshake_hmac(hmac, &nonce, allowed_versions) {
            self.peers.insert(
                *peer_id,
                PeerEntry {
                    state: PeerState::Verified,
                    challenge_nonce: None,
                    challenged_at: None,
                    verified_at: Some(Instant::now()),
                    handshake_failures: 0,
                    last_handshake_at: Some(Instant::now()),
                    has_proven_burn: false,
                    relay_ek: None,
                },
            );
            true
        } else {
            false
        }
    }

    /// Forcibly mark a peer as verified (e.g. self-verification or tests).
    pub fn mark_verified(&mut self, peer_id: [u8; 32]) {
        self.peers.insert(
            peer_id,
            PeerEntry {
                state: PeerState::Verified,
                challenge_nonce: None,
                challenged_at: None,
                verified_at: Some(Instant::now()),
                handshake_failures: 0,
                last_handshake_at: Some(Instant::now()),
                has_proven_burn: false,
                relay_ek: None,
            },
        );
    }

    /// Store a peer's relay encapsulation key (for onion routing).
    pub fn set_relay_ek(&mut self, peer_id: &[u8; 32], ek: Vec<u8>) {
        if let Some(entry) = self.peers.get_mut(peer_id) {
            entry.relay_ek = Some(ek);
        }
    }

    /// Get a peer's relay encapsulation key, if they shared one.
    pub fn relay_ek(&self, peer_id: &[u8; 32]) -> Option<&[u8]> {
        self.peers.get(peer_id).and_then(|e| e.relay_ek.as_deref())
    }

    /// Retrieve the challenge nonce for a peer (if one is stored).
    pub fn challenge_nonce(&self, peer_id: &[u8; 32]) -> Option<[u8; 32]> {
        self.peers.get(peer_id).and_then(|e| e.challenge_nonce)
    }

    /// Mark a peer as banished.  Preserves the failure count so that
    /// callers can decide whether to permanently banish or just track.
    pub fn mark_banished(&mut self, peer_id: [u8; 32]) {
        let failures = self.peers.get(&peer_id).map(|e| e.handshake_failures).unwrap_or(0);
        self.peers.insert(
            peer_id,
            PeerEntry {
                state: PeerState::Banished,
                challenge_nonce: None,
                challenged_at: None,
                verified_at: None,
                handshake_failures: failures,
                last_handshake_at: Some(Instant::now()),
                has_proven_burn: false,
                relay_ek: None,
            },
        );
    }

    /// Remove stale challenges that have exceeded the timeout,
    /// reverting them back to Unknown so they can be re-challenged.
    /// Returns the peer IDs that were evicted.
    pub fn evict_stale(&mut self) -> Vec<[u8; 32]> {
        let timeout = self.challenge_timeout;
        let mut evicted = Vec::new();
        self.peers.retain(|id, entry| {
            if entry.state == PeerState::Challenged {
                if let Some(at) = entry.challenged_at {
                    if at.elapsed() > timeout {
                        evicted.push(*id);
                        return false; // remove stale
                    }
                }
            }
            true
        });
        evicted
    }

    /// Increment the handshake failure count for a peer.
    /// Returns the new count.
    pub fn record_handshake_failure(&mut self, peer_id: &[u8; 32]) -> u32 {
        if let Some(entry) = self.peers.get_mut(peer_id) {
            entry.handshake_failures += 1;
            entry.last_handshake_at = Some(Instant::now());
            entry.handshake_failures
        } else {
            1
        }
    }

    /// Reset the handshake failure count on successful verification.
    pub fn record_handshake_success(&mut self, peer_id: &[u8; 32]) {
        if let Some(entry) = self.peers.get_mut(peer_id) {
            entry.handshake_failures = 0;
            entry.last_handshake_at = Some(Instant::now());
        }
    }

    /// Check whether a peer should be retried based on failure count and
    /// backoff. Returns `true` if enough time has passed since the last
    /// attempt.
    pub fn ready_for_retry(&self, peer_id: &[u8; 32]) -> bool {
        let Some(entry) = self.peers.get(peer_id) else {
            return true; // never attempted
        };
        if entry.state == PeerState::Verified {
            return false; // already verified, no retry needed
        }
        let failures = entry.handshake_failures.max(1);
        // Exponential backoff: 10s × 2^(failures-1), capped at ~5 min
        let backoff_secs = (10u64 << (failures - 1).min(5)).min(300);
        match entry.last_handshake_at {
            Some(at) => at.elapsed().as_secs() >= backoff_secs,
            None => true,
        }
    }

    /// Count of peers currently in a given state.
    pub fn count_in_state(&self, state: PeerState) -> usize {
        self.peers.values().filter(|e| e.state == state).count()
    }

    /// Return the node IDs of all currently verified peers.
    pub fn verified_peer_id_bytes(&self) -> Vec<[u8; 32]> {
        self.peers
            .iter()
            .filter(|(_, e)| e.state == PeerState::Verified)
            .map(|(id, _)| *id)
            .collect()
    }

    /// Return peer IDs whose verification is older than `max_age`.
    ///
    /// These peers should be re-challenged with the same handshake
    /// flow used at initial connection. Call this periodically (e.g.
    /// every hour) with `REVERIFICATION_INTERVAL` as `max_age`.
    pub fn peers_due_for_reverification(&self, max_age: Duration) -> Vec<[u8; 32]> {
        self.peers
            .iter()
            .filter_map(|(id, entry)| {
                if entry.state == PeerState::Verified {
                    if let Some(at) = entry.verified_at {
                        if at.elapsed() > max_age {
                            return Some(*id);
                        }
                    }
                }
                None
            })
            .collect()
    }

    /// Evict a verified peer back to Unknown state, forcing re-handshake.
    /// Does nothing if the peer is not currently Verified.
    pub fn evict_verified(&mut self, peer_id: &[u8; 32]) {
        if let Some(entry) = self.peers.get(peer_id) {
            if entry.state == PeerState::Verified {
                self.peers.insert(
                    *peer_id,
                    PeerEntry {
                        state: PeerState::Unknown,
                        challenge_nonce: None,
                        challenged_at: None,
                        verified_at: None,
                        handshake_failures: 0,
                        last_handshake_at: entry.last_handshake_at,
                        has_proven_burn: false,
                        relay_ek: None,
                    },
                );
            }
        }
    }
}

// ── Handshake PoW (Argon2id) ────────────────────────────────────────

/// Derive the Argon2id input for handshake PoW.
///
/// Binds the protocol version hash into the password so that PoW is
/// tied to a specific code version. Changing the code invalidates all
/// existing PoW — an attacker cannot precompute PoW for future versions.
///
/// `password = Blake3("vess-handshake-pow-v1" || PROTOCOL_VERSION_HASH || node_id || nonce)`
/// `salt     = Blake3("vess-handshake-salt-v1" || nonce)`
fn derive_pow_inputs(node_id: &[u8], nonce: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let password = {
        let mut h = blake3::Hasher::new();
        h.update(b"vess-handshake-pow-v1");
        h.update(&PROTOCOL_VERSION_HASH);
        h.update(node_id);
        h.update(nonce);
        *h.finalize().as_bytes()
    };
    let salt = {
        let mut h = blake3::Hasher::new();
        h.update(b"vess-handshake-salt-v1");
        h.update(nonce);
        *h.finalize().as_bytes()
    };
    (password, salt)
}

/// Compute the handshake Argon2id proof-of-work.
///
/// Returns the 32-byte Argon2id hash. This costs ~2-5 seconds + 256 MiB.
pub fn compute_handshake_pow(node_id: &[u8], nonce: &[u8; 32]) -> Vec<u8> {
    compute_handshake_pow_with_params(
        node_id,
        nonce,
        HANDSHAKE_POW_T_COST,
        HANDSHAKE_POW_M_COST,
        HANDSHAKE_POW_P_COST,
    )
}

/// Compute handshake PoW with custom parameters (for testing).
pub fn compute_handshake_pow_with_params(
    node_id: &[u8],
    nonce: &[u8; 32],
    t_cost: u32,
    m_cost: u32,
    p_cost: u32,
) -> Vec<u8> {
    let (password, salt) = derive_pow_inputs(node_id, nonce);
    let params = Params::new(m_cost, t_cost, p_cost, Some(HANDSHAKE_POW_OUTPUT_LEN))
        .expect("valid argon2 params");
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut output = vec![0u8; HANDSHAKE_POW_OUTPUT_LEN];
    argon2
        .hash_password_into(&password, &salt, &mut output)
        .expect("argon2 hash");
    output
}

/// Verify a handshake Argon2id proof-of-work.
///
/// Recomputes the hash from `(node_id, nonce)` and compares to the
/// provided `pow_hash`. Returns `true` if valid.
pub fn verify_handshake_pow(node_id: &[u8], nonce: &[u8; 32], pow_hash: &[u8]) -> bool {
    verify_handshake_pow_with_params(
        node_id,
        nonce,
        pow_hash,
        HANDSHAKE_POW_T_COST,
        HANDSHAKE_POW_M_COST,
        HANDSHAKE_POW_P_COST,
    )
}

/// Verify handshake PoW with custom parameters (for testing).
pub fn verify_handshake_pow_with_params(
    node_id: &[u8],
    nonce: &[u8; 32],
    pow_hash: &[u8],
    t_cost: u32,
    m_cost: u32,
    p_cost: u32,
) -> bool {
    if pow_hash.len() != HANDSHAKE_POW_OUTPUT_LEN {
        return false;
    }
    let expected = compute_handshake_pow_with_params(node_id, nonce, t_cost, m_cost, p_cost);
    constant_time_eq_slice(&expected, pow_hash)
}

// ── Claim / Genesis PoW (denomination-scaled) ───────────────────────

const CLAIM_POW_M_COST: u32 = 256 * 1024; // 256 MiB
const CLAIM_POW_P_COST: u32 = 1;
const CLAIM_POW_OUTPUT_LEN: usize = 32;

/// Compute PoW difficulty based on denomination value.
/// Returns the number of Argon2id passes required.
pub fn claim_pow_difficulty(denomination_value: u64) -> u32 {
    if denomination_value == 0 {
        return 1;
    }
    // log2 scale: 1→1, 2→2, 4→3, 8→4, 16→5, ..., capped at 16.
    let bits = 64 - denomination_value.leading_zeros();
    (bits.min(16)).max(1)
}

/// Compute a claim/genesis PoW nonce + hash.
/// Returns (nonce, hash, difficulty) where difficulty is the number of passes.
pub fn compute_claim_pow(
    mint_id: &[u8; 32],
    owner_vk_hash: &[u8; 32],
    denomination_value: u64,
) -> ([u8; 32], [u8; 32], u64) {
    let difficulty = claim_pow_difficulty(denomination_value) as u64;
    let mut nonce = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut nonce);
    let hash = compute_claim_pow_with_difficulty(mint_id, owner_vk_hash, &nonce, difficulty as u32);
    (nonce, hash, difficulty)
}

/// Compute claim PoW with explicit difficulty.
fn compute_claim_pow_with_difficulty(
    mint_id: &[u8; 32],
    owner_vk_hash: &[u8; 32],
    nonce: &[u8; 32],
    passes: u32,
) -> [u8; 32] {
    use argon2::{Algorithm, Argon2, Params, Version};
    let params = Params::new(
        CLAIM_POW_M_COST,
        passes, // time cost = difficulty passes
        CLAIM_POW_P_COST,
        Some(CLAIM_POW_OUTPUT_LEN),
    )
    .expect("valid claim PoW params");
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = [0u8; CLAIM_POW_OUTPUT_LEN];
    // Concatenate mint_id and owner_vk_hash as the password input.
    let mut password = Vec::with_capacity(64);
    password.extend_from_slice(mint_id);
    password.extend_from_slice(owner_vk_hash);
    argon
        .hash_password_into(&password, nonce, &mut out)
        .expect("Argon2id claim PoW");
    out
}

/// Verify a claim/genesis PoW.
/// Returns true if the PoW hash is valid for the given parameters.
pub fn verify_claim_pow(
    mint_id: &[u8; 32],
    owner_vk_hash: &[u8; 32],
    denomination_value: u64,
    nonce: &[u8; 32],
    pow_hash: &[u8],
) -> bool {
    if pow_hash.len() != CLAIM_POW_OUTPUT_LEN {
        return false;
    }
    let difficulty = claim_pow_difficulty(denomination_value);
    let expected = compute_claim_pow_with_difficulty(mint_id, owner_vk_hash, nonce, difficulty);
    constant_time_eq_slice(&expected, pow_hash)
}

/// Constant-time equality check for variable-length slices.
fn constant_time_eq_slice(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut acc = 0u8;
    for i in 0..a.len() {
        acc |= a[i] ^ b[i];
    }
    acc == 0
}

// ── HMAC helpers ────────────────────────────────────────────────────

/// Compute the handshake HMAC: `blake3::keyed_hash(version_hash, nonce)`.
pub fn compute_handshake_hmac(version_hash: &[u8; 32], nonce: &[u8; 32]) -> [u8; 32] {
    *blake3::keyed_hash(version_hash, nonce).as_bytes()
}

/// Verify an HMAC against *any* version in the sliding window.
///
/// Uses constant-time comparison to prevent timing side-channels.
pub fn verify_handshake_hmac(
    hmac: &[u8; 32],
    nonce: &[u8; 32],
    allowed_versions: &[[u8; 32]],
) -> bool {
    allowed_versions.iter().any(|vh| {
        let expected = compute_handshake_hmac(vh, nonce);
        constant_time_eq(&expected, hmac)
    })
}

/// Constant-time equality check for 32-byte arrays.
#[inline]
fn constant_time_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut acc = 0u8;
    for i in 0..32 {
        acc |= a[i] ^ b[i];
    }
    acc == 0
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hmac_round_trip() {
        let version = [0xAA; 32];
        let nonce = [0xBB; 32];
        let hmac = compute_handshake_hmac(&version, &nonce);
        assert!(verify_handshake_hmac(&hmac, &nonce, &[version]));
    }

    #[test]
    fn hmac_rejects_wrong_version() {
        let good = [0xAA; 32];
        let bad = [0xFF; 32];
        let nonce = [0xBB; 32];
        let hmac = compute_handshake_hmac(&bad, &nonce);
        assert!(!verify_handshake_hmac(&hmac, &nonce, &[good]));
    }

    #[test]
    fn hmac_accepts_any_allowed_version() {
        let v1 = [0x01; 32];
        let v2 = [0x02; 32];
        let nonce = [0xCC; 32];
        let hmac = compute_handshake_hmac(&v2, &nonce);
        assert!(verify_handshake_hmac(&hmac, &nonce, &[v1, v2]));
    }

    #[test]
    fn constant_time_eq_works() {
        let a = [0x42; 32];
        let b = [0x42; 32];
        let c = [0x43; 32];
        assert!(constant_time_eq(&a, &b));
        assert!(!constant_time_eq(&a, &c));
    }

    #[test]
    fn peer_registry_lifecycle() {
        let version = [0xAA; 32];
        let nonce_versions = &[version];

        let mut reg = PeerRegistry::new(Duration::from_secs(30));
        let peer = [0x01; 32];

        assert_eq!(reg.state(&peer), PeerState::Unknown);

        let nonce = reg.issue_challenge(peer).expect("non-banished peer should get a nonce");
        assert_eq!(reg.state(&peer), PeerState::Challenged);

        let hmac = compute_handshake_hmac(&version, &nonce);
        assert!(reg.verify_response(&peer, &hmac, nonce_versions));
        assert_eq!(reg.state(&peer), PeerState::Verified);
    }

    #[test]
    fn peer_registry_rejects_bad_hmac() {
        let version = [0xAA; 32];
        let mut reg = PeerRegistry::new(Duration::from_secs(30));
        let peer = [0x02; 32];

        let _nonce = reg.issue_challenge(peer).expect("non-banished peer should get a nonce");
        let bad_hmac = [0xFF; 32];
        assert!(!reg.verify_response(&peer, &bad_hmac, &[version]));
        // Still Challenged (caller is responsible for banishing).
        assert_eq!(reg.state(&peer), PeerState::Challenged);
    }

    #[test]
    fn peer_registry_banishment() {
        let mut reg = PeerRegistry::new(Duration::from_secs(30));
        let peer = [0x03; 32];

        reg.mark_banished(peer);
        assert_eq!(reg.state(&peer), PeerState::Banished);

        // Banished peers must NOT receive a valid nonce — issue_challenge
        // returns None, preventing a bypass where [0u8;32] was a valid nonce.
        assert!(reg.issue_challenge(peer).is_none());
    }

    #[test]
    fn banished_peer_never_gets_valid_challenge() {
        let mut reg = PeerRegistry::new(Duration::from_secs(30));
        let peer = [0x05; 32];

        // Fresh peer gets a nonce.
        let nonce = reg.issue_challenge(peer).expect("fresh peer should get nonce");
        assert_ne!(nonce, [0u8; 32]); // nonce should be random, not zero

        // Banish it.
        reg.mark_banished(peer);
        assert_eq!(reg.state(&peer), PeerState::Banished);

        // Should NEVER issue a challenge to a banished peer.
        assert!(reg.issue_challenge(peer).is_none());

        // Verify the state remains Banished (not overwritten to Challenged).
        assert_eq!(reg.state(&peer), PeerState::Banished);
    }

    #[test]
    fn stale_challenge_eviction() {
        let mut reg = PeerRegistry::new(Duration::from_millis(0));
        let peer = [0x04; 32];

        let _nonce = reg.issue_challenge(peer).expect("non-banished peer should get a nonce");
        assert_eq!(reg.state(&peer), PeerState::Challenged);

        // With a 0ms timeout, the challenge is immediately stale.
        std::thread::sleep(Duration::from_millis(1));
        reg.evict_stale();
        assert_eq!(reg.state(&peer), PeerState::Unknown);
    }

    #[test]
    fn protocol_version_hash_is_populated() {
        // The build script should produce a non-zero hash.
        assert_ne!(PROTOCOL_VERSION_HASH, [0u8; 32]);
    }

    #[test]
    fn allowed_versions_contains_current() {
        assert!(ALLOWED_VERSIONS.contains(&PROTOCOL_VERSION_HASH));
        // The current hash must always be the first entry.
        assert_eq!(ALLOWED_VERSIONS[0], PROTOCOL_VERSION_HASH);
    }

    #[test]
    fn previous_version_hashes_excludes_current() {
        // versions.txt entries that duplicate the current hash are filtered
        // out at build time, so PREVIOUS_VERSION_HASHES should never
        // contain the current build hash.
        assert!(
            !PREVIOUS_VERSION_HASHES.contains(&PROTOCOL_VERSION_HASH),
            "PREVIOUS_VERSION_HASHES should not duplicate PROTOCOL_VERSION_HASH"
        );
    }

    #[test]
    fn handshake_pow_round_trip() {
        let node_id = b"test-node-id-1234567890";
        let nonce = [0xCC; 32];
        let hash = compute_handshake_pow_with_params(
            node_id,
            &nonce,
            HANDSHAKE_POW_T_COST_TEST,
            HANDSHAKE_POW_M_COST_TEST,
            HANDSHAKE_POW_P_COST,
        );
        assert_eq!(hash.len(), HANDSHAKE_POW_OUTPUT_LEN);
        assert!(verify_handshake_pow_with_params(
            node_id,
            &nonce,
            &hash,
            HANDSHAKE_POW_T_COST_TEST,
            HANDSHAKE_POW_M_COST_TEST,
            HANDSHAKE_POW_P_COST,
        ));
    }

    #[test]
    fn handshake_pow_rejects_wrong_node_id() {
        let node_id = b"test-node-id-1234567890";
        let nonce = [0xDD; 32];
        let hash = compute_handshake_pow_with_params(
            node_id,
            &nonce,
            HANDSHAKE_POW_T_COST_TEST,
            HANDSHAKE_POW_M_COST_TEST,
            HANDSHAKE_POW_P_COST,
        );
        let wrong_node = b"wrong-node-id-xxx";
        assert!(!verify_handshake_pow_with_params(
            wrong_node,
            &nonce,
            &hash,
            HANDSHAKE_POW_T_COST_TEST,
            HANDSHAKE_POW_M_COST_TEST,
            HANDSHAKE_POW_P_COST,
        ));
    }

    #[test]
    fn handshake_pow_rejects_wrong_nonce() {
        let node_id = b"test-node-id-1234567890";
        let nonce = [0xEE; 32];
        let hash = compute_handshake_pow_with_params(
            node_id,
            &nonce,
            HANDSHAKE_POW_T_COST_TEST,
            HANDSHAKE_POW_M_COST_TEST,
            HANDSHAKE_POW_P_COST,
        );
        let wrong_nonce = [0xFF; 32];
        assert!(!verify_handshake_pow_with_params(
            node_id,
            &wrong_nonce,
            &hash,
            HANDSHAKE_POW_T_COST_TEST,
            HANDSHAKE_POW_M_COST_TEST,
            HANDSHAKE_POW_P_COST,
        ));
    }

    #[test]
    fn handshake_pow_rejects_empty() {
        let node_id = b"test-node-id";
        let nonce = [0xAA; 32];
        assert!(!verify_handshake_pow_with_params(
            node_id,
            &nonce,
            &[],
            HANDSHAKE_POW_T_COST_TEST,
            HANDSHAKE_POW_M_COST_TEST,
            HANDSHAKE_POW_P_COST,
        ));
    }

    #[test]
    fn peers_due_for_reverification_returns_stale() {
        let mut reg = PeerRegistry::new(Duration::from_secs(30));
        let peer = [0x10; 32];
        reg.mark_verified(peer);
        // With a zero-duration threshold, the peer is immediately stale.
        let stale = reg.peers_due_for_reverification(Duration::from_millis(0));
        assert!(stale.contains(&peer));
    }

    #[test]
    fn peers_due_for_reverification_excludes_fresh() {
        let mut reg = PeerRegistry::new(Duration::from_secs(30));
        let peer = [0x11; 32];
        reg.mark_verified(peer);
        // With a very long threshold, no peer should be stale.
        let stale = reg.peers_due_for_reverification(Duration::from_secs(999_999));
        assert!(stale.is_empty());
    }
}

