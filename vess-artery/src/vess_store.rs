//! Vess Store — DHT-distributed Vess store with validation and conflict resolution.
//!
//! Each Vess is its own mini chain. Consumed inputs stay active for verification,
//! pruned only when buried 10+ depths behind the current owner.
use std::collections::{HashMap, HashSet};
use vess_foundry::Vess;
use vess_foundry::clock;

#[derive(Debug, Clone, Default)]
pub struct VessStore {
    active: HashMap<[u8; 32], Vess>,
    /// Set of consumed Vess IDs (tombstoned — can never be spent again).
    consumed: HashSet<[u8; 32]>,
    /// Epochs for which a dev faucet has already been claimed.
    pub faucet_epochs: HashSet<u64>,
}

impl VessStore {
    // ── Dev faucet ────────────────────────────────────────────────

    /// Validate and store a dev faucet bill.
    /// One per epoch, 20,000 Vess, signed by the dev key.
    /// Owner can be any address the dev chooses to receive to.
    pub fn validate_faucet(&mut self, v: &Vess) -> Result<(), String> {
        if v.amount != vess_protocol::DEV_FAUCET_AMOUNT {
            return Err(format!("faucet must be {} Vess", vess_protocol::DEV_FAUCET_AMOUNT));
        }
        if self.faucet_epochs.contains(&v.epoch) {
            return Err(format!("faucet already claimed for epoch {}", v.epoch));
        }

        // Dev signs: "vess-faucet-v1" || epoch || amount || owner_vk
        let mut msg = blake3::Hasher::new();
        msg.update(b"vess-faucet-v1");
        msg.update(&v.epoch.to_be_bytes());
        msg.update(&v.amount.to_be_bytes());
        msg.update(&v.owner_vk);
        let sig_msg = *msg.finalize().as_bytes();

        if !vess_foundry::spend_auth::verify_spend(
            &vess_protocol::DEV_VK, &sig_msg, &v.change_sig,
        ).unwrap_or(false) {
            return Err("faucet: invalid dev signature".into());
        }

        self.faucet_epochs.insert(v.epoch);
        self.upsert_one(v);
        Ok(())
    }

    // ── Batch upsert (payment + change) ────────────────────────────

    /// Validate and store a batch of Vess outputs sharing the same consumed inputs.
    /// Used for payment + change: both consume the same inputs, one owner authorizes.
    ///
    /// Rules:
    /// - Sum of output amounts MUST equal sum of input amounts (no inflation/burn)
    /// - Previous owner (of inputs) must sign the batch commitment
    /// - Chain tips must advance for each output
    /// - Inputs are consumed atomically only if all outputs validate
    pub fn validate_and_upsert_batch(&mut self, outputs: &[Vess]) -> Result<(), String> {
        if outputs.is_empty() {
            return Ok(());
        }

        let consumed_ids = &outputs[0].consumed;

        // ── Mined Vess (no inputs) ──
        if consumed_ids.is_empty() {
            // Faucet bills: special validation (dev key, epoch uniqueness)
            if outputs.len() == 1 && outputs[0].is_faucet() {
                return self.validate_faucet(&outputs[0]).map(|_| ());
            }
            // Regular mined Vess: Argon2d verification
            for v in outputs {
                if v.is_mined() {
                    vess_foundry::mine::verify_mined_vess(v, clock::current_epoch())?;
                }
                self.upsert_one(v);
            }
            return Ok(());
        }

        // All outputs must share the same consumed set
        for v in outputs {
            if v.consumed != *consumed_ids {
                return Err("batch outputs must share the same consumed inputs".into());
            }
        }

        // ── Double-spend guard ──
        for id in consumed_ids {
            if self.consumed.contains(id) {
                return Err(format!(
                    "input {} already consumed",
                    hex::encode(&id[..8])
                ));
            }
        }

        // ── Value conservation ──
        let mut input_sum: u64 = 0;
        for id in consumed_ids {
            let input = self.active.get(id)
                .ok_or_else(|| format!("input {} not found", hex::encode(&id[..8])))?;
            input_sum += input.amount;
        }
        let output_sum: u64 = outputs.iter().map(|v| v.amount).sum();
        if output_sum != input_sum {
            return Err(format!(
                "value mismatch: inputs sum {} ≠ outputs sum {}",
                input_sum, output_sum
            ));
        }

        // ── Previous owner must authorize ──
        let prev_vk = &self.active.get(&consumed_ids[0])
            .ok_or("consumed input not found")?
            .owner_vk;
        let commitment = Vess::change_commitment(consumed_ids, outputs);
        if !vess_foundry::spend_auth::verify_spend(
            prev_vk, &commitment, &outputs[0].change_sig,
        )
        .unwrap_or(false)
        {
            return Err("change_sig invalid — previous owner must authorize".into());
        }

        // ── Chain tips must advance ──
        let prev_tip = self.active.get(&consumed_ids[0])
            .map(|input| input.chain_tip)
            .unwrap_or([0u8; 32]);
        for v in outputs {
            let expected_tip = vess_foundry::advance_chain_tip_with_hash(
                &prev_tip, &v.owner_vk_hash(), &v.digest,
            );
            if v.chain_tip != expected_tip {
                return Err("chain_tip does not advance correctly".into());
            }
        }

        // ── Atomic commit: consume inputs, insert outputs ──
        for id in consumed_ids {
            self.consumed.insert(*id);
        }
        for v in outputs {
            self.upsert_one(v);
        }
        Ok(())
    }

    // ── Single upsert ──────────────────────────────────────────────

    /// Store a single Vess (for single-output spends).
    pub fn validate_and_upsert(&mut self, v: &Vess) -> Result<(), String> {
        self.validate_and_upsert_batch(&[v.clone()])
    }

    /// Store without validation (for locally-created bills).
    pub fn upsert_one(&mut self, v: &Vess) -> bool {
        let id = v.compute_vess_id();
        if self.consumed.contains(&id) {
            return false;
        }
        if let Some(existing) = self.active.get(&id) {
            if v.chain_depth < existing.chain_depth {
                return false;
            }
            if v.chain_depth > existing.chain_depth {
                self.active.insert(id, v.clone());
                return true;
            }
            // Equal depth: deterministic tiebreaker
            if id >= existing.compute_vess_id() {
                return false;
            }
        }
        self.active.insert(id, v.clone());
        true
    }

    /// Legacy alias.
    pub fn upsert(&mut self, v: &Vess) -> bool {
        self.upsert_one(v)
    }

    // ── Pruning ────────────────────────────────────────────────────

    const PRUNE_DEPTH_THRESHOLD: u64 = 10;

    /// Prune consumed records only when BOTH:
    /// - Gap ≥ 10 depths behind current owner
    /// - Original mined epoch is > 3 epochs old (72 hours)
    /// This prevents rapid re-submission of mined Vess within the 48h window.
    pub fn prune_deep_buried(&mut self, current_epoch: u64) {
        let to_remove: Vec<[u8; 32]> = self
            .consumed
            .iter()
            .filter(|&&consumed_id| {
                match self.active.get(&consumed_id) {
                    Some(v) => {
                        let max_successor_depth = self
                            .active
                            .values()
                            .filter(|other| other.consumed.contains(&consumed_id))
                            .map(|other| other.chain_depth)
                            .max()
                            .unwrap_or(0);
                        let gap = max_successor_depth.saturating_sub(v.chain_depth);
                        let epoch_old_enough = if v.is_mined() {
                            current_epoch.saturating_sub(v.epoch) > 3
                        } else {
                            true
                        };
                        gap >= Self::PRUNE_DEPTH_THRESHOLD && epoch_old_enough
                    }
                    None => true,
                }
            })
            .cloned()
            .collect();

        for id in to_remove {
            self.consumed.remove(&id);
            self.active.remove(&id);
        }
    }

    // ── Accessors ──────────────────────────────────────────────────

    pub fn is_consumed(&self, id: &[u8; 32]) -> bool {
        self.consumed.contains(id)
    }
    pub fn get(&self, id: &[u8; 32]) -> Option<&Vess> {
        self.active.get(id)
    }
    pub fn len(&self) -> usize {
        self.active.len()
    }
    pub fn iter(&self) -> impl Iterator<Item = &Vess> {
        self.active.values()
    }
}
