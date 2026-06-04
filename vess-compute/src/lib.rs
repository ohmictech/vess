//! **vess-compute** — Program definitions, compute receipts, and
//! DHT-addressed storage primitives for programmable Vess flows.
//!
//! This crate is intentionally foundational. It defines:
//!
//! - immutable program artifacts keyed by `prog_id`
//! - human-facing manifests that can point at immutable versions
//! - compute receipts that bind outputs to a program and proof
//! - DHT key derivations and a small in-memory DHT store
//! - program-address and program-owned bill routing primitives

pub mod vesslogic;

use anyhow::{anyhow, Result};
use argon2::Argon2;
use blake3::Hasher;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub use vesslogic::{
    compile_vesslogic_source, VessLogicBinding, VessLogicBinaryOp, VessLogicExpr,
    VessLogicInstruction, VessLogicLiteral, VessLogicProgram, VessLogicType,
    VESSLOGIC_VERSION_HEADER,
};

const PROGRAM_NAME_PREFIX: &str = "vl_";
const PROGRAM_NAME_PART_MIN_LEN: usize = 3;
const PROGRAM_NAME_PART_MAX_LEN: usize = 25;
pub const PROGRAM_POW_M_COST: u32 = 2_097_152;
pub const PROGRAM_POW_T_COST: u32 = 1;
pub const PROGRAM_POW_P_COST: u32 = 1;
pub const PROGRAM_POW_HASH_LEN: usize = 32;
pub const PROGRAM_PRUNE_SECS: u64 = 7 * 24 * 60 * 60;

fn hash_tagged(tag: &[u8], fields: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(tag);
    for field in fields {
        hasher.update(&(field.len() as u64).to_le_bytes());
        hasher.update(field);
    }
    *hasher.finalize().as_bytes()
}

fn program_pow_password(prog_id: &ProgramId, publisher_vk: Option<&[u8]>) -> Vec<u8> {
    let mut pwd = Vec::new();
    pwd.extend_from_slice(b"vess-program-pow-v1\0");
    pwd.extend_from_slice(prog_id.as_bytes());
    if let Some(publisher_vk) = publisher_vk {
        pwd.extend_from_slice(publisher_vk);
    }
    pwd
}

fn compute_program_pow_with_params(
    prog_id: &ProgramId,
    publisher_vk: Option<&[u8]>,
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<([u8; 32], Vec<u8>)> {
    let nonce: [u8; 32] = rand::random();
    let password = program_pow_password(prog_id, publisher_vk);
    let params = argon2::Params::new(m_cost, t_cost, p_cost, Some(PROGRAM_POW_HASH_LEN))
        .map_err(|e| anyhow!("argon2 params: {e}"))?;
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut hash = vec![0u8; PROGRAM_POW_HASH_LEN];
    argon2
        .hash_password_into(&password, &nonce, &mut hash)
        .map_err(|e| anyhow!("argon2 hash: {e}"))?;
    Ok((nonce, hash))
}

fn verify_program_pow_with_params(
    prog_id: &ProgramId,
    publisher_vk: Option<&[u8]>,
    pow_nonce: &[u8; 32],
    expected_hash: &[u8],
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<bool> {
    if expected_hash.len() != PROGRAM_POW_HASH_LEN {
        return Err(anyhow!("program pow hash must be 32 bytes"));
    }
    let password = program_pow_password(prog_id, publisher_vk);
    let params = argon2::Params::new(m_cost, t_cost, p_cost, Some(PROGRAM_POW_HASH_LEN))
        .map_err(|e| anyhow!("argon2 params: {e}"))?;
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut actual_hash = vec![0u8; PROGRAM_POW_HASH_LEN];
    argon2
        .hash_password_into(&password, pow_nonce, &mut actual_hash)
        .map_err(|e| anyhow!("argon2 hash: {e}"))?;
    Ok(actual_hash == expected_hash)
}

pub fn compute_program_pow(
    prog_id: &ProgramId,
    publisher_vk: Option<&[u8]>,
) -> Result<([u8; 32], Vec<u8>)> {
    compute_program_pow_with_params(
        prog_id,
        publisher_vk,
        PROGRAM_POW_M_COST,
        PROGRAM_POW_T_COST,
        PROGRAM_POW_P_COST,
    )
}

#[cfg(any(test, feature = "test-pow"))]
pub fn compute_program_pow_test(
    prog_id: &ProgramId,
    publisher_vk: Option<&[u8]>,
) -> Result<([u8; 32], Vec<u8>)> {
    compute_program_pow_with_params(prog_id, publisher_vk, 8, 1, 1)
}

pub fn verify_program_pow(
    prog_id: &ProgramId,
    publisher_vk: Option<&[u8]>,
    pow_nonce: &[u8; 32],
    expected_hash: &[u8],
) -> Result<bool> {
    verify_program_pow_with_params(
        prog_id,
        publisher_vk,
        pow_nonce,
        expected_hash,
        PROGRAM_POW_M_COST,
        PROGRAM_POW_T_COST,
        PROGRAM_POW_P_COST,
    )
}

#[cfg(any(test, feature = "test-pow"))]
pub fn verify_program_pow_test(
    prog_id: &ProgramId,
    publisher_vk: Option<&[u8]>,
    pow_nonce: &[u8; 32],
    expected_hash: &[u8],
) -> Result<bool> {
    verify_program_pow_with_params(prog_id, publisher_vk, pow_nonce, expected_hash, 8, 1, 1)
}

/// Canonical identifier for an immutable program artifact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ProgramId(pub [u8; 32]);

impl ProgramId {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Human-facing name for a family of program versions.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ProgramName(String);

impl ProgramName {
    pub fn new(raw: &str) -> Result<Self> {
        let raw = raw.trim();
        let canonical = raw.strip_prefix('+').unwrap_or(raw);
        let Some(name_part) = canonical.strip_prefix(PROGRAM_NAME_PREFIX) else {
            return Err(anyhow!("program name must start with +vl_ or vl_"));
        };
        if name_part.len() < PROGRAM_NAME_PART_MIN_LEN {
            return Err(anyhow!("program name too short"));
        }
        if name_part.len() > PROGRAM_NAME_PART_MAX_LEN {
            return Err(anyhow!("program name too long"));
        }
        if !name_part
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        {
            return Err(anyhow!(
                "program name suffix must be lowercase ASCII alphanumeric"
            ));
        }
        Ok(Self(format!("{PROGRAM_NAME_PREFIX}{name_part}")))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn display(&self) -> String {
        format!("+{}", self.0)
    }

    pub fn dht_key(&self) -> [u8; 32] {
        *blake3::hash(self.0.as_bytes()).as_bytes()
    }
}

impl std::fmt::Display for ProgramName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "+{}", self.0)
    }
}

/// Proof verifier family attached to a program or receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProofSystem {
    /// Native Vess STARK verifier for deterministic compute.
    VessStarkV1,
    /// Native Vess aggregate STARK verifier.
    VessStarkAggregateV1,
    /// External proof family routed by a verifier identifier.
    External {
        system: String,
        verifier: String,
        version: u32,
    },
}

impl ProofSystem {
    fn digest_bytes(&self) -> Vec<u8> {
        match self {
            Self::VessStarkV1 => b"vess-stark-v1".to_vec(),
            Self::VessStarkAggregateV1 => b"vess-stark-aggregate-v1".to_vec(),
            Self::External {
                system,
                verifier,
                version,
            } => {
                let mut out = Vec::new();
                out.extend_from_slice(system.as_bytes());
                out.push(0xff);
                out.extend_from_slice(verifier.as_bytes());
                out.push(0xfe);
                out.extend_from_slice(&version.to_le_bytes());
                out
            }
        }
    }
}

/// Immutable program artifact stored in the DHT under its content-derived `prog_id`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProgramDefinition {
    /// Canonical program or circuit bytes.
    pub code: Vec<u8>,
    /// Proof family used to verify receipts for this program.
    pub proof_system: ProofSystem,
    /// Hash of the public input schema.
    pub public_input_schema_hash: [u8; 32],
    /// Hash of the public output schema.
    pub public_output_schema_hash: [u8; 32],
    /// Hash of the opaque metadata document for UX and docs.
    pub metadata_hash: [u8; 32],
    /// Hash of the ABI or entrypoint schema.
    pub abi_hash: [u8; 32],
    /// Maximum cycle budget expected by this program.
    pub max_cycles: u64,
    /// Maximum memory footprint expected by this program.
    pub max_memory_bytes: u64,
    /// Whether this program may act as a bill-owning predicate.
    #[serde(default)]
    pub supports_program_owned_bills: bool,
    /// Named entrypoints available on the program.
    #[serde(default)]
    pub entrypoints: Vec<String>,
}

impl ProgramDefinition {
    pub fn validate(&self) -> Result<()> {
        if self.code.is_empty() {
            return Err(anyhow!("program code must not be empty"));
        }
        if self.max_cycles == 0 {
            return Err(anyhow!("program max_cycles must be non-zero"));
        }
        if self.max_memory_bytes == 0 {
            return Err(anyhow!("program max_memory_bytes must be non-zero"));
        }

        let mut seen = BTreeSet::new();
        for entrypoint in &self.entrypoints {
            if entrypoint.is_empty() {
                return Err(anyhow!("program entrypoint names must not be empty"));
            }
            if !seen.insert(entrypoint) {
                return Err(anyhow!("duplicate program entrypoint: {entrypoint}"));
            }
        }

        Ok(())
    }

    pub fn prog_id(&self) -> ProgramId {
        let proof_system = self.proof_system.digest_bytes();
        let mut entrypoints = Vec::new();
        for entrypoint in &self.entrypoints {
            entrypoints.extend_from_slice(&(entrypoint.len() as u64).to_le_bytes());
            entrypoints.extend_from_slice(entrypoint.as_bytes());
        }

        ProgramId(hash_tagged(
            b"vess-prog-id-v1",
            &[
                &self.code,
                &proof_system,
                &self.public_input_schema_hash,
                &self.public_output_schema_hash,
                &self.metadata_hash,
                &self.abi_hash,
                &self.max_cycles.to_le_bytes(),
                &self.max_memory_bytes.to_le_bytes(),
                &[self.supports_program_owned_bills as u8],
                &entrypoints,
            ],
        ))
    }
}

/// Published program record with optional provenance metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredProgram {
    pub definition: ProgramDefinition,
    pub published_at: u64,
    pub pow_nonce: [u8; 32],
    pub pow_hash: Vec<u8>,
    #[serde(default)]
    pub publisher_vk: Option<Vec<u8>>,
    #[serde(default)]
    pub signature: Vec<u8>,
    #[serde(default)]
    pub last_bill_sent_at: Option<u64>,
}

impl StoredProgram {
    pub fn prog_id(&self) -> ProgramId {
        self.definition.prog_id()
    }

    pub fn validate(&self) -> Result<()> {
        self.definition.validate()?;
        let publisher_vk = self.publisher_vk.as_deref();
        #[cfg(any(test, feature = "test-pow"))]
        let pow_ok = verify_program_pow_test(
            &self.prog_id(),
            publisher_vk,
            &self.pow_nonce,
            &self.pow_hash,
        )?;
        #[cfg(not(any(test, feature = "test-pow")))]
        let pow_ok = verify_program_pow(
            &self.prog_id(),
            publisher_vk,
            &self.pow_nonce,
            &self.pow_hash,
        )?;
        if !pow_ok {
            return Err(anyhow!("program proof-of-work verification failed"));
        }
        if let Some(last_bill_sent_at) = self.last_bill_sent_at {
            if last_bill_sent_at < self.published_at {
                return Err(anyhow!("program last_bill_sent_at cannot predate published_at"));
            }
        }
        Ok(())
    }

    pub fn last_activity_at(&self) -> u64 {
        self.last_bill_sent_at.unwrap_or(self.published_at)
    }

    pub fn note_bill_activity(&mut self, sent_at: u64) {
        self.last_bill_sent_at = Some(self.last_activity_at().max(sent_at));
    }
}

/// Version pointer inside a human-facing program manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProgramVersionPointer {
    pub version: u32,
    pub prog_id: ProgramId,
    #[serde(default)]
    pub changelog_hash: [u8; 32],
}

/// Mutable name record for a program family.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProgramManifest {
    pub name: ProgramName,
    pub latest_prog_id: ProgramId,
    #[serde(default)]
    pub versions: Vec<ProgramVersionPointer>,
    pub created_at: u64,
    pub updated_at: u64,
    #[serde(default)]
    pub publisher_vk: Option<Vec<u8>>,
    #[serde(default)]
    pub signature: Vec<u8>,
}

impl ProgramManifest {
    pub fn dht_key(&self) -> [u8; 32] {
        self.name.dht_key()
    }
}

/// Proof bundle attached to a compute receipt or program spend witness.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StarkProofEnvelope {
    pub proof_system: ProofSystem,
    pub proof_bytes: Vec<u8>,
    pub public_inputs_hash: [u8; 32],
    pub public_outputs_hash: [u8; 32],
    #[serde(default)]
    pub transcript_hash: [u8; 32],
}

impl StarkProofEnvelope {
    pub fn validate(&self) -> Result<()> {
        if self.proof_bytes.is_empty() {
            return Err(anyhow!("proof bytes must not be empty"));
        }
        Ok(())
    }

    pub fn proof_hash(&self) -> [u8; 32] {
        let proof_system = self.proof_system.digest_bytes();
        hash_tagged(
            b"vess-compute-proof-v1",
            &[
                &proof_system,
                &self.proof_bytes,
                &self.public_inputs_hash,
                &self.public_outputs_hash,
                &self.transcript_hash,
            ],
        )
    }
}

/// Immutable verification receipt for one program execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComputeReceipt {
    pub receipt_id: [u8; 32],
    pub prog_id: ProgramId,
    pub job_id: [u8; 32],
    pub public_inputs_hash: [u8; 32],
    pub public_outputs_hash: [u8; 32],
    pub proof_hash: [u8; 32],
    #[serde(default)]
    pub proof: Option<StarkProofEnvelope>,
    #[serde(default)]
    pub parent_receipt_ids: Vec<[u8; 32]>,
    pub created_at: u64,
}

impl ComputeReceipt {
    pub fn new(
        prog_id: ProgramId,
        job_id: [u8; 32],
        public_inputs_hash: [u8; 32],
        public_outputs_hash: [u8; 32],
        proof: Option<StarkProofEnvelope>,
        parent_receipt_ids: Vec<[u8; 32]>,
        created_at: u64,
    ) -> Self {
        let proof_hash = proof
            .as_ref()
            .map(StarkProofEnvelope::proof_hash)
            .unwrap_or_else(|| hash_tagged(b"vess-compute-empty-proof-v1", &[&prog_id.0, &job_id]));
        let receipt_id = hash_tagged(
            b"vess-compute-receipt-v1",
            &[
                &prog_id.0,
                &job_id,
                &public_inputs_hash,
                &public_outputs_hash,
                &proof_hash,
                &created_at.to_le_bytes(),
            ],
        );
        Self {
            receipt_id,
            prog_id,
            job_id,
            public_inputs_hash,
            public_outputs_hash,
            proof_hash,
            proof,
            parent_receipt_ids,
            created_at,
        }
    }

    pub fn validate_against_program(&self, definition: &ProgramDefinition) -> Result<()> {
        let expected_prog_id = definition.prog_id();
        if expected_prog_id != self.prog_id {
            return Err(anyhow!("receipt program id does not match definition"));
        }
        if let Some(proof) = &self.proof {
            proof.validate()?;
            if proof.proof_hash() != self.proof_hash {
                return Err(anyhow!("receipt proof hash does not match proof bytes"));
            }
            if proof.public_inputs_hash != self.public_inputs_hash {
                return Err(anyhow!("receipt public_inputs_hash does not match proof"));
            }
            if proof.public_outputs_hash != self.public_outputs_hash {
                return Err(anyhow!("receipt public_outputs_hash does not match proof"));
            }
            if proof.proof_system != definition.proof_system {
                return Err(anyhow!("receipt proof system does not match program"));
            }
        }
        Ok(())
    }
}

/// Addressable routing target for a program-owned bill or compute payment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProgramAddress {
    pub prog_id: ProgramId,
    pub entrypoint: String,
    #[serde(default)]
    pub state_key: Option<[u8; 32]>,
}

impl ProgramAddress {
    pub fn validate(&self) -> Result<()> {
        if self.entrypoint.is_empty() {
            return Err(anyhow!("program address entrypoint must not be empty"));
        }
        Ok(())
    }

    pub fn address_id(&self) -> [u8; 32] {
        let state_key = self.state_key.unwrap_or([0u8; 32]);
        hash_tagged(
            b"vess-program-address-v1",
            &[&self.prog_id.0, self.entrypoint.as_bytes(), &state_key],
        )
    }
}

/// Compact reference to a bill being routed into or out of a program.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BillReference {
    pub mint_id: [u8; 32],
    pub denomination_value: u64,
}

/// Intent to send bills to a program-controlled address.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProgramPaymentIntent {
    pub destination: ProgramAddress,
    pub input_bills: Vec<BillReference>,
    pub total_amount: u64,
    #[serde(default)]
    pub note_commitment: Option<[u8; 32]>,
    #[serde(default)]
    pub expected_receipt_id: Option<[u8; 32]>,
}

impl ProgramPaymentIntent {
    pub fn validate(&self) -> Result<()> {
        self.destination.validate()?;
        if self.input_bills.is_empty() {
            return Err(anyhow!("program payment must include at least one bill"));
        }
        let computed_total = self
            .input_bills
            .iter()
            .map(|bill| bill.denomination_value)
            .sum::<u64>();
        if computed_total != self.total_amount {
            return Err(anyhow!("program payment total_amount does not match bill set"));
        }
        Ok(())
    }
}

/// Ownership policy for a bill controlled by a program predicate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProgramOwnershipCondition {
    pub controller: ProgramAddress,
    pub required_proof_system: ProofSystem,
    pub state_commitment: [u8; 32],
}

impl ProgramOwnershipCondition {
    pub fn owner_commitment(&self) -> [u8; 32] {
        let proof_system = self.required_proof_system.digest_bytes();
        hash_tagged(
            b"vess-program-owner-v1",
            &[
                &self.controller.address_id(),
                &proof_system,
                &self.state_commitment,
            ],
        )
    }
}

/// Spend witness allowing a predicate-owned bill to rotate to a new owner.
/// This witness is carried on the normal `OwnershipClaim` path so peers can
/// validate the compute receipt and proof before accepting the ownership move.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProgramSpendWitness {
    pub receipt: ComputeReceipt,
    pub authorized_mint_ids: Vec<[u8; 32]>,
    pub next_owner_commitment: [u8; 32],
}

impl ProgramSpendWitness {
    pub fn witness_hash(&self) -> [u8; 32] {
        let mut mint_ids = Vec::new();
        for mint_id in &self.authorized_mint_ids {
            mint_ids.extend_from_slice(mint_id);
        }
        hash_tagged(
            b"vess-program-spend-witness-v1",
            &[
                &self.receipt.receipt_id,
                &mint_ids,
                &self.next_owner_commitment,
            ],
        )
    }

    pub fn validates_condition(
        &self,
        condition: &ProgramOwnershipCondition,
        definition: &ProgramDefinition,
    ) -> Result<()> {
        self.receipt.validate_against_program(definition)?;
        if self.receipt.prog_id != condition.controller.prog_id {
            return Err(anyhow!("spend witness receipt targets the wrong program"));
        }
        if let Some(proof) = &self.receipt.proof {
            if proof.proof_system != condition.required_proof_system {
                return Err(anyhow!("spend witness uses the wrong proof system"));
            }
        }
        Ok(())
    }
}

/// Request to store an immutable program in the DHT.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProgramStoreRequest {
    pub program: StoredProgram,
}

/// Request to fetch an immutable program by `prog_id`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProgramFetchRequest {
    pub prog_id: ProgramId,
}

/// Response to [`ProgramFetchRequest`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProgramFetchResponse {
    pub program: Option<StoredProgram>,
}

/// Request to store a mutable program manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProgramManifestStoreRequest {
    pub manifest: ProgramManifest,
}

/// Resolve a human-facing program name to its manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProgramManifestResolveRequest {
    pub name: ProgramName,
}

/// Response to [`ProgramManifestResolveRequest`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProgramManifestResolveResponse {
    pub manifest: Option<ProgramManifest>,
}

/// Reserved request shape for program execution jobs.
///
/// V1 nodes execute program interactions locally while constructing their own
/// ownership transitions rather than delegating work to mesh peers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComputeJobRequest {
    pub job_id: [u8; 32],
    pub prog_id: ProgramId,
    pub public_inputs: Vec<u8>,
    pub requested_at: u64,
    #[serde(default)]
    pub max_fee: u64,
    #[serde(default)]
    pub return_address: Option<ProgramAddress>,
    #[serde(default)]
    pub include_proof: bool,
}

/// Reserved response shape for [`ComputeJobRequest`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComputeJobResult {
    pub job_id: [u8; 32],
    pub accepted: bool,
    #[serde(default)]
    pub output_bytes: Vec<u8>,
    #[serde(default)]
    pub receipt: Option<ComputeReceipt>,
    #[serde(default)]
    pub error: Option<String>,
}

/// Request to persist a compute receipt in the DHT.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComputeReceiptStoreRequest {
    pub receipt: ComputeReceipt,
}

/// Request to fetch a compute receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComputeReceiptFetchRequest {
    pub receipt_id: [u8; 32],
}

/// Response to [`ComputeReceiptFetchRequest`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComputeReceiptFetchResponse {
    pub receipt: Option<ComputeReceipt>,
}

/// Request to enumerate receipts tied to one immutable program.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProgramReceiptListRequest {
    pub prog_id: ProgramId,
}

/// Response to [`ProgramReceiptListRequest`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProgramReceiptListResponse {
    pub receipt_ids: Vec<[u8; 32]>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProgramPruneReport {
    pub pruned_program_ids: Vec<ProgramId>,
    pub pruned_manifest_count: usize,
    pub pruned_receipt_count: usize,
}

/// Lightweight in-memory DHT helper for programs, manifests, and receipts.
#[derive(Debug, Clone, Default)]
pub struct ComputeDht {
    programs: BTreeMap<ProgramId, StoredProgram>,
    manifests: BTreeMap<[u8; 32], ProgramManifest>,
    receipts: BTreeMap<[u8; 32], ComputeReceipt>,
    receipts_by_program: BTreeMap<ProgramId, BTreeSet<[u8; 32]>>,
}

impl ComputeDht {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn store_program(&mut self, program: StoredProgram) -> Result<bool> {
        program.validate()?;
        let prog_id = program.prog_id();
        if let Some(existing) = self.programs.get_mut(&prog_id) {
            if program.last_activity_at() > existing.last_activity_at() {
                existing.last_bill_sent_at = Some(program.last_activity_at());
            }
            return Ok(false);
        }
        Ok(self.programs.insert(prog_id, program).is_none())
    }

    pub fn fetch_program(&self, prog_id: ProgramId) -> Option<&StoredProgram> {
        self.programs.get(&prog_id)
    }

    pub fn all_programs(&self) -> Vec<(ProgramId, StoredProgram)> {
        self.programs
            .iter()
            .map(|(prog_id, program)| (*prog_id, program.clone()))
            .collect()
    }

    pub fn mark_bill_sent_to_program(&mut self, prog_id: ProgramId, sent_at: u64) -> bool {
        let Some(program) = self.programs.get_mut(&prog_id) else {
            return false;
        };
        program.note_bill_activity(sent_at);
        true
    }

    pub fn store_manifest(&mut self, manifest: ProgramManifest) -> Result<bool> {
        if manifest.versions.is_empty() {
            return Err(anyhow!("program manifest must include at least one version pointer"));
        }
        let key = manifest.dht_key();
        Ok(self.manifests.insert(key, manifest).is_none())
    }

    pub fn resolve_manifest(&self, name: &ProgramName) -> Option<&ProgramManifest> {
        self.manifests.get(&name.dht_key())
    }

    pub fn all_manifests(&self) -> Vec<([u8; 32], ProgramManifest)> {
        self.manifests
            .iter()
            .map(|(key, manifest)| (*key, manifest.clone()))
            .collect()
    }

    pub fn store_receipt(&mut self, receipt: ComputeReceipt) -> Result<bool> {
        if let Some(program) = self.programs.get(&receipt.prog_id) {
            receipt.validate_against_program(&program.definition)?;
        }
        let receipt_id = receipt.receipt_id;
        let prog_id = receipt.prog_id;
        let inserted = self.receipts.insert(receipt_id, receipt).is_none();
        self.receipts_by_program
            .entry(prog_id)
            .or_default()
            .insert(receipt_id);
        Ok(inserted)
    }

    pub fn fetch_receipt(&self, receipt_id: &[u8; 32]) -> Option<&ComputeReceipt> {
        self.receipts.get(receipt_id)
    }

    pub fn all_receipts(&self) -> Vec<([u8; 32], ComputeReceipt)> {
        self.receipts
            .iter()
            .map(|(receipt_id, receipt)| (*receipt_id, receipt.clone()))
            .collect()
    }

    pub fn receipts_for_program(&self, prog_id: ProgramId) -> Vec<[u8; 32]> {
        self.receipts_by_program
            .get(&prog_id)
            .map(|ids| ids.iter().copied().collect())
            .unwrap_or_default()
    }

    pub fn prune_inactive_programs(
        &mut self,
        now: u64,
        active_program_ids: &BTreeSet<ProgramId>,
    ) -> ProgramPruneReport {
        let mut report = ProgramPruneReport::default();
        let expired: BTreeSet<ProgramId> = self
            .programs
            .iter()
            .filter_map(|(prog_id, program)| {
                if active_program_ids.contains(prog_id) {
                    return None;
                }
                let inactive_for = now.saturating_sub(program.last_activity_at());
                (inactive_for > PROGRAM_PRUNE_SECS).then_some(*prog_id)
            })
            .collect();

        if expired.is_empty() {
            return report;
        }

        for prog_id in &expired {
            self.programs.remove(prog_id);
            if let Some(receipt_ids) = self.receipts_by_program.remove(prog_id) {
                report.pruned_receipt_count += receipt_ids.len();
                for receipt_id in receipt_ids {
                    self.receipts.remove(&receipt_id);
                }
            }
        }

        let manifest_keys: Vec<[u8; 32]> = self.manifests.keys().copied().collect();
        for key in manifest_keys {
            let Some(mut manifest) = self.manifests.remove(&key) else {
                continue;
            };
            manifest
                .versions
                .retain(|version| !expired.contains(&version.prog_id));
            if let Some(latest) = manifest.versions.iter().max_by_key(|version| version.version) {
                manifest.latest_prog_id = latest.prog_id;
            }
            if manifest.versions.is_empty() {
                report.pruned_manifest_count += 1;
            } else {
                self.manifests.insert(key, manifest);
            }
        }

        report.pruned_program_ids = expired.into_iter().collect();
        report
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_program() -> ProgramDefinition {
        ProgramDefinition {
            code: vec![1, 2, 3, 4],
            proof_system: ProofSystem::VessStarkV1,
            public_input_schema_hash: [0x11; 32],
            public_output_schema_hash: [0x22; 32],
            metadata_hash: [0x33; 32],
            abi_hash: [0x44; 32],
            max_cycles: 10_000,
            max_memory_bytes: 1 << 20,
            supports_program_owned_bills: true,
            entrypoints: vec!["settle".to_owned(), "refund".to_owned()],
        }
    }

    #[test]
    fn program_name_validation_and_dht_key_are_deterministic() {
        let name = ProgramName::new("+vl_market1").unwrap();
        let name2 = ProgramName::new("vl_market1").unwrap();
        assert_eq!(name.as_str(), "vl_market1");
        assert_eq!(name.display(), "+vl_market1");
        assert_eq!(name.dht_key(), name2.dht_key());
        assert_eq!(name.dht_key(), *blake3::hash(b"vl_market1").as_bytes());
        assert!(ProgramName::new("+vl_BadName").is_err());
    }

    #[test]
    fn program_id_is_content_addressed() {
        let program = sample_program();
        let prog_id = program.prog_id();
        let same = sample_program();
        let mut changed = sample_program();
        changed.entrypoints.push("extra".to_owned());
        assert_eq!(prog_id, same.prog_id());
        assert_ne!(prog_id, changed.prog_id());
    }

    #[test]
    fn compute_dht_stores_programs_manifests_and_receipts() {
        let definition = sample_program();
        let prog_id = definition.prog_id();
        let (pow_nonce, pow_hash) = compute_program_pow_test(&prog_id, None).unwrap();
        let program = StoredProgram {
            definition: definition.clone(),
            published_at: 100,
            pow_nonce,
            pow_hash,
            publisher_vk: None,
            signature: Vec::new(),
            last_bill_sent_at: None,
        };

        let manifest = ProgramManifest {
            name: ProgramName::new("+vl_market1").unwrap(),
            latest_prog_id: prog_id,
            versions: vec![ProgramVersionPointer {
                version: 1,
                prog_id,
                changelog_hash: [0x55; 32],
            }],
            created_at: 100,
            updated_at: 100,
            publisher_vk: None,
            signature: Vec::new(),
        };

        let proof = StarkProofEnvelope {
            proof_system: ProofSystem::VessStarkV1,
            proof_bytes: vec![9, 9, 9],
            public_inputs_hash: [0x66; 32],
            public_outputs_hash: [0x77; 32],
            transcript_hash: [0x88; 32],
        };
        let receipt = ComputeReceipt::new(
            prog_id,
            [0x99; 32],
            proof.public_inputs_hash,
            proof.public_outputs_hash,
            Some(proof),
            vec![],
            101,
        );

        let mut dht = ComputeDht::new();
        assert!(dht.store_program(program).unwrap());
        assert!(dht.store_manifest(manifest.clone()).unwrap());
        assert!(dht.store_receipt(receipt.clone()).unwrap());

        assert!(dht.fetch_program(prog_id).is_some());
        assert_eq!(
            dht.resolve_manifest(&manifest.name).unwrap().latest_prog_id,
            prog_id
        );
        assert_eq!(dht.fetch_receipt(&receipt.receipt_id).unwrap().receipt_id, receipt.receipt_id);
        assert_eq!(dht.receipts_for_program(prog_id), vec![receipt.receipt_id]);
    }

    #[test]
    fn program_payment_and_spend_witness_validate() {
        let definition = sample_program();
        let prog_id = definition.prog_id();
        let address = ProgramAddress {
            prog_id,
            entrypoint: "settle".to_owned(),
            state_key: Some([0xaa; 32]),
        };
        let intent = ProgramPaymentIntent {
            destination: address.clone(),
            input_bills: vec![
                BillReference {
                    mint_id: [0x01; 32],
                    denomination_value: 2,
                },
                BillReference {
                    mint_id: [0x02; 32],
                    denomination_value: 5,
                },
            ],
            total_amount: 7,
            note_commitment: Some([0xbb; 32]),
            expected_receipt_id: None,
        };
        intent.validate().unwrap();

        let condition = ProgramOwnershipCondition {
            controller: address,
            required_proof_system: ProofSystem::VessStarkV1,
            state_commitment: [0xcc; 32],
        };
        let proof = StarkProofEnvelope {
            proof_system: ProofSystem::VessStarkV1,
            proof_bytes: vec![0x42],
            public_inputs_hash: [0xdd; 32],
            public_outputs_hash: [0xee; 32],
            transcript_hash: [0xff; 32],
        };
        let receipt = ComputeReceipt::new(
            prog_id,
            [0x12; 32],
            proof.public_inputs_hash,
            proof.public_outputs_hash,
            Some(proof),
            vec![],
            102,
        );
        let witness = ProgramSpendWitness {
            receipt,
            authorized_mint_ids: vec![[0x01; 32], [0x02; 32]],
            next_owner_commitment: [0x13; 32],
        };

        witness.validates_condition(&condition, &definition).unwrap();
    }

    #[test]
    fn program_pow_is_bound_to_program_id() {
        let definition = sample_program();
        let prog_id = definition.prog_id();
        let (pow_nonce, pow_hash) = compute_program_pow_test(&prog_id, None).unwrap();
        assert!(verify_program_pow_test(&prog_id, None, &pow_nonce, &pow_hash).unwrap());

        let mut changed = sample_program();
        changed.code.push(0x99);
        assert!(
            !verify_program_pow_test(&changed.prog_id(), None, &pow_nonce, &pow_hash).unwrap()
        );
    }

    #[test]
    fn prune_inactive_programs_keeps_active_program_owners() {
        let definition = sample_program();
        let prog_id = definition.prog_id();
        let (pow_nonce, pow_hash) = compute_program_pow_test(&prog_id, None).unwrap();
        let mut dht = ComputeDht::new();
        assert!(dht
            .store_program(StoredProgram {
                definition,
                published_at: 100,
                pow_nonce,
                pow_hash,
                publisher_vk: None,
                signature: Vec::new(),
                last_bill_sent_at: Some(100),
            })
            .unwrap());

        let active_program_ids = BTreeSet::from([prog_id]);
        let report = dht.prune_inactive_programs(100 + PROGRAM_PRUNE_SECS + 1, &active_program_ids);
        assert!(report.pruned_program_ids.is_empty());
        assert!(dht.fetch_program(prog_id).is_some());
    }
}