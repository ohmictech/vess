//! Reforge circuit — split/combine bills with value conservation.
//!
//! The STARK proof is the **immutable value anchor** — it proves real
//! computation was done for a denomination and never changes. Reforging
//! changes the **ownership layer**: mint_id + stealth binding.
//!
//! ```text
//! ┌──────────────┐              ┌──────────────┐
//! │  Input Bill   │  reforge    │  Output Bill  │
//! │  proof (STARK)│ ─────────▶  │  proof (SAME) │  ← preserved
//! │  digest       │             │  digest (SAME)│  ← preserved
//! │  mint_id_A    │             │  mint_id_B    │  ← new (split/combine)
//! │  stealth_old  │             │  stealth_new  │  ← new owner
//! └──────────────┘              └──────────────┘
//! ```
//!
//! For 1:1 same-denomination transfers (the common case), the original
//! STARK proof passes through unchanged — artery nodes verify it as-is.
//! The mint_id and chain_tip carry forward (ownership rotated via
//! OwnershipClaim messages).
//!
//! For split/combine (D20 → 2×D10), each output carries the proofs of
//! ALL input bills so verifiers can confirm value conservation. New
//! mint_ids are derived from the compound proof digest. Input mint_ids
//! are consumed (deleted from the ownership registry).

use crate::{Denomination, VessBill};
use anyhow::{anyhow, Result};
use blake3::Hasher;
use rand::RngCore;
use serde::{Deserialize, Serialize};

/// A compound proof for split/combine reforges.
///
/// Records the input bill digests and denominations so verifiers can
/// confirm value conservation. Individual STARK proofs are already
/// verified at bill genesis and stored in the ownership registry —
/// they don't need to be re-bundled here.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReforgeProof {
    /// Mint IDs of the consumed input bills (for registry lookup).
    pub input_mint_ids: Vec<[u8; 32]>,
    /// Original digest for each consumed input bill.
    pub input_digests: Vec<[u8; 32]>,
    /// Denomination for each consumed input bill.
    pub input_denominations: Vec<Denomination>,
}

/// Verify a compound reforge proof for a claimed output denomination.
///
/// Checks:
/// 1. The proof digest matches the expected digest.
/// 2. The sum of input denominations is returned for the caller to
///    verify value conservation across all outputs.
///
/// Individual STARK proofs were already verified at genesis — the
/// relay can confirm inputs are active via `registry.is_active()`.
pub fn verify_reforge_proof(
    reforge_proof: &ReforgeProof,
    expected_digest: &[u8; 32],
) -> Result<u64> {
    if reforge_proof.input_mint_ids.len() != reforge_proof.input_digests.len()
        || reforge_proof.input_mint_ids.len() != reforge_proof.input_denominations.len()
    {
        anyhow::bail!("reforge proof: array length mismatch");
    }

    // Verify that the compound digest matches the serialized proof.
    let re_serialized = postcard::to_allocvec(reforge_proof)
        .map_err(|e| anyhow!("re-serialize reforge proof: {e}"))?;
    let mut h = Hasher::new();
    h.update(b"vess-reforge-digest-v0");
    h.update(&re_serialized);
    let computed_digest = *h.finalize().as_bytes();
    if computed_digest != *expected_digest {
        anyhow::bail!("reforge proof digest mismatch");
    }

    // Sum the input denominations — caller checks conservation.
    let input_sum: u64 = reforge_proof
        .input_denominations
        .iter()
        .map(|d| d.value())
        .sum();

    Ok(input_sum)
}

/// Serialize a ReforgeProof to bytes using postcard.
pub fn serialize_reforge_proof(proof: &ReforgeProof) -> Vec<u8> {
    postcard::to_allocvec(proof).expect("reforge proof serialization should not fail")
}

/// Deserialize a ReforgeProof from bytes.
pub fn deserialize_reforge_proof(data: &[u8]) -> Result<ReforgeProof> {
    postcard::from_bytes(data).map_err(|e| anyhow!("reforge proof deserialization failed: {e}"))
}

/// A request to reforge one or more input bills into new output denominations.
#[derive(Debug, Clone)]
pub struct ReforgeRequest {
    /// The bills being consumed (melted down).
    pub inputs: Vec<VessBill>,
    /// The desired output denominations.
    pub output_denominations: Vec<Denomination>,
    /// Stealth IDs for each output bill (one per output denomination).
    /// These bind each output to its intended owner.
    pub output_stealth_ids: Vec<[u8; 32]>,
}

/// The result of a successful reforge operation.
#[derive(Debug, Clone)]
pub struct ReforgeResult {
    /// Newly created bills with fresh timestamps.
    /// Paired with proof bytes (needed for OwnershipGenesis of split/combine outputs).
    pub outputs: Vec<(VessBill, Vec<u8>)>,
    /// Mint IDs of the consumed input bills. These MUST be deleted from
    /// the ownership registry to prevent double-spending the inputs.
    pub consumed_mint_ids: Vec<[u8; 32]>,
}

/// Execute a reforge operation.
///
/// Validates that `∑ input denominations == ∑ output denominations`,
/// then produces fresh bills for each requested output.
///
/// # Errors
///
/// Returns an error if:
/// - Zero inputs or outputs are provided.
/// - The value sum doesn't balance.
/// - The number of stealth IDs doesn't match the output denominations.
pub fn reforge(request: ReforgeRequest) -> Result<ReforgeResult> {
    if request.inputs.is_empty() {
        return Err(anyhow!("reforge requires at least one input bill"));
    }
    if request.output_denominations.is_empty() {
        return Err(anyhow!("reforge requires at least one output denomination"));
    }
    if request.output_denominations.len() != request.output_stealth_ids.len() {
        return Err(anyhow!(
            "stealth ID count ({}) must match output denomination count ({})",
            request.output_stealth_ids.len(),
            request.output_denominations.len()
        ));
    }

    // Verify value conservation.
    let input_sum: u64 = request.inputs.iter().map(|b| b.denomination.value()).sum();
    let output_sum: u64 = request
        .output_denominations
        .iter()
        .map(|d| d.value())
        .sum();

    if input_sum != output_sum {
        return Err(anyhow!(
            "value not conserved: inputs sum to {input_sum}, outputs sum to {output_sum}"
        ));
    }

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let mut rng = rand::thread_rng();

    // Collect consumed mint_ids from inputs.
    let consumed_mint_ids: Vec<[u8; 32]> = request.inputs.iter().map(|b| b.mint_id).collect();

    // Determine if this is a 1:1 same-denomination reforge (the common
    // case: ownership transfer / privacy reforge). In that case each
    // output inherits the STARK proof of the matching input directly.
    let is_one_to_one = request.inputs.len() == request.output_denominations.len()
        && request
            .inputs
            .iter()
            .zip(request.output_denominations.iter())
            .all(|(inp, &out_d)| inp.denomination == out_d);

    // For split/combine, bundle ALL input proofs + digests + denominations
    // into a compound proof so verifiers can confirm value conservation.
    let compound_proof: Option<Vec<u8>> = if !is_one_to_one {
        let rp = ReforgeProof {
            input_mint_ids: request.inputs.iter().map(|b| b.mint_id).collect(),
            input_digests: request.inputs.iter().map(|b| b.digest).collect(),
            input_denominations: request.inputs.iter().map(|b| b.denomination).collect(),
        };
        Some(postcard::to_allocvec(&rp).expect("reforge proof serialization should not fail"))
    } else {
        None
    };

    let compound_digest: Option<[u8; 32]> = compound_proof.as_ref().map(|cp| {
        let mut h = Hasher::new();
        h.update(b"vess-reforge-digest-v0");
        h.update(cp);
        *h.finalize().as_bytes()
    });

    // Generate output bills.
    let outputs: Vec<(VessBill, Vec<u8>)> = request
        .output_denominations
        .iter()
        .zip(request.output_stealth_ids.iter())
        .enumerate()
        .map(|(i, (&denom, stealth_id))| {
            // Fresh nonce for each output.
            let mut nonce = [0u8; 32];
            rng.fill_bytes(&mut nonce);

            // Proof bytes: carry forward from input or use compound.
            let proof_bytes = if is_one_to_one {
                // 1:1 — inherit the ORIGINAL STARK proof unchanged.
                // The proof lives on the OwnershipRecord, not the bill.
                // Return it for potential re-genesis by the caller.
                Vec::new() // 1:1 reforge reuses the same mint_id/chain_tip, no new genesis needed.
            } else {
                // Split/combine — compound proof with all input STARKs.
                compound_proof.clone().unwrap()
            };

            let digest = if is_one_to_one {
                request.inputs[i].digest
            } else {
                compound_digest.unwrap()
            };

            // mint_id and chain_tip handling:
            // For 1:1, each output inherits its input's mint_id/chain_tip
            // (ownership is rotated via OwnershipClaim, not here).
            // For split/combine, derive NEW mint_ids from compound digest
            // so each output is a fresh identity in the ownership registry.
            let (mint_id, chain_tip) = if is_one_to_one {
                (request.inputs[i].mint_id, request.inputs[i].chain_tip)
            } else {
                // New mint_id for split/combine outputs.
                let mint_id = {
                    let mut h = Hasher::new();
                    h.update(b"vess-reforge-mint-id-v0");
                    h.update(&compound_digest.unwrap());
                    h.update(&(i as u32).to_le_bytes());
                    h.update(&nonce);
                    *h.finalize().as_bytes()
                };
                // chain_tip will be set when registered via OwnershipGenesis.
                // Use zeroed placeholder — the wallet must call genesis_chain_tip()
                // before registering.
                (mint_id, [0u8; 32])
            };

            (VessBill {
                denomination: denom,
                digest,
                created_at: now,
                stealth_id: *stealth_id,
                dht_index: 0, // Assigned by wallet when stored in DHT.
                mint_id,
                chain_tip,
                chain_depth: 0,
            }, proof_bytes)
        })
        .collect();

    Ok(ReforgeResult {
        outputs,
        consumed_mint_ids,
    })
}

/// Convenience: self-reforge a single bill.
///
/// The bill keeps the same denomination, mint_id, and chain_tip.
/// Useful for privacy (unlinking bill history via stealth rotation).
pub fn self_reforge(bill: VessBill) -> Result<ReforgeResult> {
    let stealth_id = bill.stealth_id;
    let denom = bill.denomination;
    reforge(ReforgeRequest {
        inputs: vec![bill],
        output_denominations: vec![denom],
        output_stealth_ids: vec![stealth_id],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_bill(denom: Denomination) -> VessBill {
        VessBill {
            denomination: denom,
            digest: [0xBB; 32],
            created_at: 1000,
            stealth_id: [0xCC; 32],
            dht_index: 0,
            mint_id: [0xAA; 32],
            chain_tip: [0xDD; 32],
            chain_depth: 0,
        }
    }

    #[test]
    fn split_d20_into_two_d10() {
        let bill = make_test_bill(Denomination::D20);
        let result = reforge(ReforgeRequest {
            inputs: vec![bill],
            output_denominations: vec![Denomination::D10, Denomination::D10],
            output_stealth_ids: vec![[0x01; 32], [0x02; 32]],
        })
        .unwrap();

        assert_eq!(result.outputs.len(), 2);
        assert_eq!(result.outputs[0].0.denomination, Denomination::D10);
        assert_eq!(result.outputs[1].0.denomination, Denomination::D10);
        assert_eq!(result.consumed_mint_ids.len(), 1);
        // Each output has a unique mint_id.
        assert_ne!(result.outputs[0].0.mint_id, result.outputs[1].0.mint_id);
        // Split outputs get NEW mint_ids (not inherited from input).
        assert_ne!(result.outputs[0].0.mint_id, [0xAA; 32]);
    }

    #[test]
    fn combine_five_d1_into_d5() {
        let bills: Vec<VessBill> = (0..5).map(|_| make_test_bill(Denomination::D1)).collect();
        let result = reforge(ReforgeRequest {
            inputs: bills,
            output_denominations: vec![Denomination::D5],
            output_stealth_ids: vec![[0x01; 32]],
        })
        .unwrap();

        assert_eq!(result.outputs.len(), 1);
        assert_eq!(result.outputs[0].0.denomination, Denomination::D5);
        assert_eq!(result.consumed_mint_ids.len(), 5);
    }

    #[test]
    fn value_mismatch_fails() {
        let bill = make_test_bill(Denomination::D10);
        let result = reforge(ReforgeRequest {
            inputs: vec![bill],
            output_denominations: vec![Denomination::D20],
            output_stealth_ids: vec![[0x01; 32]],
        });
        assert!(result.is_err());
    }

    #[test]
    fn self_reforge_preserves_mint_id() {
        let bill = make_test_bill(Denomination::D5);
        let original_mint_id = bill.mint_id;

        let result = self_reforge(bill).unwrap();
        assert_eq!(result.outputs.len(), 1);
        assert_eq!(result.outputs[0].0.denomination, Denomination::D5);
        // 1:1 reforge preserves mint_id and chain_tip.
        assert_eq!(result.outputs[0].0.mint_id, original_mint_id);
        assert_eq!(result.consumed_mint_ids, vec![original_mint_id]);
    }

    #[test]
    fn change_making_d20_to_d10_plus_d5_plus_d5() {
        let bill = make_test_bill(Denomination::D20);
        let result = reforge(ReforgeRequest {
            inputs: vec![bill],
            output_denominations: vec![Denomination::D10, Denomination::D5, Denomination::D5],
            output_stealth_ids: vec![[0x01; 32], [0x02; 32], [0x03; 32]],
        })
        .unwrap();

        assert_eq!(result.outputs.len(), 3);
        let total: u64 = result.outputs.iter().map(|(b, _)| b.denomination.value()).sum();
        assert_eq!(total, 20);
    }
}
