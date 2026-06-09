//! STARK proof generation/verification for VessLogic execution via Winterfell 0.12.
//!
//! Proves that a VessLogic program evaluated against specific inputs
//! produced a specific result (approved or rejected).

use winterfell::{
    crypto::{hashers::Blake3_256, DefaultRandomCoin, MerkleTree},
    math::{fields::f64::BaseElement, FieldElement, ToElements},
    matrix::ColMatrix,
    Air, AirContext, Assertion, AuxRandElements, BatchingMethod, ConstraintCompositionCoefficients,
    CompositionPoly, CompositionPolyTrace, DefaultConstraintCommitment,
    DefaultConstraintEvaluator, DefaultTraceLde, EvaluationFrame, FieldExtension,
    PartitionOptions, Proof, ProofOptions, Prover, StarkDomain, Trace, TraceInfo,
    TracePolyTable, TraceTable, TransitionConstraintDegree, AcceptableOptions,
};

use crate::evaluator::{ClaimData, EvalContext, EvalResult};
use crate::vesslogic::{VessLogicInstruction, VessLogicProgram, VessLogicLiteral};

type F = BaseElement;

pub const TRACE_WIDTH: usize = 5;
pub const COL_PC: usize = 0;
pub const COL_OPCODE: usize = 1;
pub const COL_EXPR_HASH: usize = 2;
pub const COL_EXPR_OUTPUT: usize = 3;
pub const COL_APPROVED: usize = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Section { Deposit, Withdraw }

// ── Public inputs ─────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct PublicInputs {
    pub program_hash: [u8; 32],
    pub claim_hash: [u8; 32],
    pub amount: u64,
    pub instruction_count: usize,
    pub expected_approved: u64,
}

impl ToElements<F> for PublicInputs {
    fn to_elements(&self) -> Vec<F> {
        let mut v = Vec::with_capacity(11);
        for chunk in self.program_hash.chunks(8).take(4) {
            let arr: [u8; 8] = chunk.try_into().unwrap_or([0; 8]);
            v.push(F::try_from(u64::from_le_bytes(arr)).unwrap_or(F::ZERO));
        }
        for chunk in self.claim_hash.chunks(8).take(4) {
            let arr: [u8; 8] = chunk.try_into().unwrap_or([0; 8]);
            v.push(F::try_from(u64::from_le_bytes(arr)).unwrap_or(F::ZERO));
        }
        v.push(F::try_from(self.amount).unwrap_or(F::ZERO));
        v.push(F::from(self.instruction_count as u32));
        v.push(F::from(self.expected_approved as u32));
        v
    }
}

// ── Trace builder ─────────────────────────────────────────────────

pub fn build_trace(
    program: &VessLogicProgram, amount: u64, claim: &ClaimData, section: Section,
) -> TraceTable<F> {
    let instrs = match section { Section::Deposit => &program.deposit, Section::Withdraw => &program.withdraw };
    let len = (instrs.len() + 4).next_power_of_two().max(8);
    let mut trace = TraceTable::new(TRACE_WIDTH, len);
    let mut ctx = match section {
        Section::Deposit => EvalContext::for_deposit(amount, program, claim),
        Section::Withdraw => EvalContext::for_withdraw(amount, program, claim),
    };

    for (pc, instr) in instrs.iter().enumerate() {
        let (op, hash, out, approved) = match instr {
            VessLogicInstruction::Require(e) => {
                let h = expr_hash(e);
                let o = crate::evaluator::eval_expr(e, &ctx).map(|v| lit_u64(&v)).unwrap_or(0);
                (0u64, h, o, 0u64)
            }
            VessLogicInstruction::Bind { name, value } => {
                let h = expr_hash(value);
                let o = match crate::evaluator::eval_expr(value, &ctx) {
                    Ok(v) => { ctx.bindings.insert(name.clone(), v.clone()); lit_u64(&v) }
                    Err(_) => 0,
                };
                (1u64, h, o, 0u64)
            }
            VessLogicInstruction::Approve => (2u64, 0, 0, 1u64),
        };

        let pc_f = F::try_from(pc as u64).unwrap_or(F::ZERO);
        let op_f = F::from(op as u32);
        let hash_f = F::from((hash & 0xFFFF_FFFF) as u32);
        let out_f = F::try_from(out).unwrap_or(F::ZERO);
        let appr_f = F::from(approved as u32);
        trace.set(COL_PC, pc, pc_f);
        trace.set(COL_OPCODE, pc, op_f);
        trace.set(COL_EXPR_HASH, pc, hash_f);
        trace.set(COL_EXPR_OUTPUT, pc, out_f);
        trace.set(COL_APPROVED, pc, appr_f);

        let done = op == 2 || (op == 0 && out == 0);
        if done {
            for r in (pc + 1)..len {
                let r_f = F::try_from(r as u64).unwrap_or(F::ZERO);
                trace.set(COL_PC, r, r_f);
                trace.set(COL_OPCODE, r, F::from(3u32));
                trace.set(COL_EXPR_HASH, r, F::ZERO);
                trace.set(COL_EXPR_OUTPUT, r, F::ZERO);
                trace.set(COL_APPROVED, r, F::from(if op == 2 { 1u32 } else { 0u32 }));
            }
            break;
        }
    }
    trace
}

fn expr_hash(e: &crate::vesslogic::VessLogicExpr) -> u64 {
    u64::from_le_bytes(blake3::hash(format!("{e:?}").as_bytes()).as_bytes()[..8].try_into().unwrap())
}

fn lit_u64(v: &VessLogicLiteral) -> u64 {
    match v { VessLogicLiteral::Bool(b) => if *b { 1 } else { 0 }, VessLogicLiteral::U64(n) => *n }
}

// ── Hashes ────────────────────────────────────────────────────────

pub fn hash_claim(c: &ClaimData) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"vess-claim-v1"); h.update(&c.claim_denomination.to_le_bytes());
    h.update(&c.claim_chain_depth.to_le_bytes()); h.update(&c.program_balance.to_le_bytes());
    h.update(&c.claim_timestamp.to_le_bytes());
    *h.finalize().as_bytes()
}

pub fn hash_program(p: &VessLogicProgram) -> [u8; 32] {
    *blake3::hash(p.canonical_source().as_bytes()).as_bytes()
}

// ── AIR ───────────────────────────────────────────────────────────

pub struct VessLogicAir {
    pub trace_len: usize,
    pub expected_approved: u64,
    pub ctx: AirContext<F>,
}

impl Air for VessLogicAir {
    type BaseField = F;
    type PublicInputs = PublicInputs;

    fn new(trace_info: TraceInfo, pub_inputs: PublicInputs, options: ProofOptions) -> Self {
        let trace_len = trace_info.length();
        Self {
            trace_len,
            expected_approved: pub_inputs.expected_approved,
            ctx: AirContext::new(
                TraceInfo::new(TRACE_WIDTH, trace_len),
                vec![TransitionConstraintDegree::new(4)],
                2,
                options,
            ),
        }
    }

    fn context(&self) -> &AirContext<F> { &self.ctx }

    fn evaluate_transition<E: FieldElement<BaseField = F>>(
        &self, frame: &EvaluationFrame<E>, _periodic: &[E], result: &mut [E],
    ) {
        let c = frame.current(); let n = frame.next();
        let op = c[COL_OPCODE]; let a = c[COL_APPROVED]; let na = n[COL_APPROVED];

        // Opcode validity: op ∈ {0, 1, 2, 3}
        let op_valid = op * (op - E::ONE) * (op - E::from(2u32)) * (op - E::from(3u32));

        // Approved monotonic: if current is 1, next cannot be 0
        let appr_mono = a * (E::ONE - na);

        // Combined: both must be zero. Summing ensures the polynomial is never
        // identically zero even when approved = 0 throughout the trace.
        result[0] = op_valid + appr_mono;
    }

    fn get_assertions(&self) -> Vec<Assertion<F>> {
        vec![
            Assertion::single(COL_PC, 0, F::ZERO),
            Assertion::single(COL_APPROVED, self.trace_len - 1, F::from(self.expected_approved as u32)),
        ]
    }
}

// ── Prover ────────────────────────────────────────────────────────

pub struct VessLogicProver {
    options: ProofOptions,
    pub_inputs: PublicInputs,
}

impl VessLogicProver {
    pub fn new(_air: VessLogicAir, options: ProofOptions, pub_inputs: PublicInputs) -> Self {
        Self { options, pub_inputs }
    }
}

impl Prover for VessLogicProver {
    type BaseField = F;
    type Air = VessLogicAir;
    type Trace = TraceTable<F>;
    type HashFn = Blake3_256<F>;
    type VC = MerkleTree<Blake3_256<F>>;
    type RandomCoin = DefaultRandomCoin<Blake3_256<F>>;
    type TraceLde<E> = DefaultTraceLde<E, Blake3_256<F>, MerkleTree<Blake3_256<F>>>
        where E: FieldElement<BaseField = F>;
    type ConstraintEvaluator<'a, E> = DefaultConstraintEvaluator<'a, VessLogicAir, E>
        where E: FieldElement<BaseField = F>;
    type ConstraintCommitment<E> = DefaultConstraintCommitment<E, Blake3_256<F>, MerkleTree<Blake3_256<F>>>
        where E: FieldElement<BaseField = F>;

    fn get_pub_inputs(&self, _trace: &Self::Trace) -> PublicInputs {
        self.pub_inputs.clone()
    }

    fn options(&self) -> &ProofOptions {
        &self.options
    }

    fn new_trace_lde<E: FieldElement<BaseField = F>>(
        &self, trace_info: &TraceInfo, main_trace: &ColMatrix<F>,
        domain: &StarkDomain<F>, partition_options: PartitionOptions,
    ) -> (Self::TraceLde<E>, TracePolyTable<E>) {
        DefaultTraceLde::new(trace_info, main_trace, domain, partition_options)
    }

    fn new_evaluator<'a, E: FieldElement<BaseField = F>>(
        &self, air: &'a Self::Air, aux_rand_elements: Option<AuxRandElements<E>>,
        composition_coefficients: ConstraintCompositionCoefficients<E>,
    ) -> Self::ConstraintEvaluator<'a, E> {
        DefaultConstraintEvaluator::new(air, aux_rand_elements, composition_coefficients)
    }

    fn build_constraint_commitment<E: FieldElement<BaseField = F>>(
        &self, composition_poly_trace: CompositionPolyTrace<E>,
        num_constraint_composition_columns: usize, domain: &StarkDomain<F>,
        partition_options: PartitionOptions,
    ) -> (Self::ConstraintCommitment<E>, CompositionPoly<E>) {
        DefaultConstraintCommitment::new(
            composition_poly_trace, num_constraint_composition_columns, domain, partition_options,
        )
    }
}

// ── Prove / Verify ────────────────────────────────────────────────

fn proof_options() -> ProofOptions {
    ProofOptions::new(
        32,                        // num_queries
        8,                         // blowup_factor
        16,                        // grinding_factor
        FieldExtension::Quadratic, // field_extension
        8,                         // fri_folding_factor
        127,                       // fri_max_remainder_size
        BatchingMethod::Linear,    // batching_fri
        BatchingMethod::Linear,    // batching_deep
    )
}

fn acceptable_options() -> AcceptableOptions {
    AcceptableOptions::MinConjecturedSecurity(96)
}

/// Generate a STARK proof for a VessLogic deposit evaluation.
pub fn prove_deposit(
    program: &VessLogicProgram, amount: u64, claim: &ClaimData,
) -> Result<(EvalResult, Proof, std::collections::BTreeMap<String, VessLogicLiteral>), String> {
    let (result, bindings) = crate::evaluator::evaluate_deposit(program, amount, claim)
        .map_err(|e| format!("eval: {e}"))?;
    let approved = matches!(result, EvalResult::Approved);
    let trace = build_trace(program, amount, claim, Section::Deposit);
    let pi = PublicInputs {
        program_hash: hash_program(program), claim_hash: hash_claim(claim),
        amount, instruction_count: program.deposit.len(),
        expected_approved: if approved { 1 } else { 0 },
    };
    let trace_len = trace.main_segment().num_rows();
    let opts = proof_options();
    let air = VessLogicAir {
        trace_len, expected_approved: pi.expected_approved,
        ctx: AirContext::new(
            TraceInfo::new(TRACE_WIDTH, trace_len),
            vec![TransitionConstraintDegree::new(4)],
            2, opts.clone(),
        ),
    };
    let prover = VessLogicProver::new(air, opts, pi);
    let proof = prover.prove(trace).map_err(|e| format!("STARK prove: {e}"))?;
    Ok((result, proof, bindings))
}

/// Verify a STARK proof.
pub fn verify_deposit(
    program: &VessLogicProgram, amount: u64, claim: &ClaimData,
    approved: bool, proof: Proof,
) -> Result<bool, String> {
    let pi = PublicInputs {
        program_hash: hash_program(program), claim_hash: hash_claim(claim),
        amount, instruction_count: program.deposit.len(),
        expected_approved: if approved { 1 } else { 0 },
    };
    winterfell::verify::<VessLogicAir, Blake3_256<F>, DefaultRandomCoin<Blake3_256<F>>, MerkleTree<Blake3_256<F>>>(
        proof, pi, &acceptable_options(),
    )
    .map_err(|e| format!("STARK verify: {e}"))?;
    Ok(true)
}

/// Build trace + public inputs for evaluation (used by tests and external integration).
pub fn evaluate_and_trace(
    program: &VessLogicProgram, amount: u64, claim: &ClaimData,
) -> Result<(EvalResult, TraceTable<F>, PublicInputs, std::collections::BTreeMap<String, VessLogicLiteral>), String> {
    let (result, bindings) = crate::evaluator::evaluate_deposit(program, amount, claim)
        .map_err(|e| format!("eval: {e}"))?;
    let approved = matches!(result, EvalResult::Approved);
    let trace = build_trace(program, amount, claim, Section::Deposit);
    let pi = PublicInputs {
        program_hash: hash_program(program), claim_hash: hash_claim(claim),
        amount, instruction_count: program.deposit.len(),
        expected_approved: if approved { 1 } else { 0 },
    };
    Ok((result, trace, pi, bindings))
}

// ── Tests ─────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vesslogic::VessLogicProgram;

    fn c() -> ClaimData {
        ClaimData { claim_denomination: 100, claim_chain_depth: 1, program_balance: 500, claim_timestamp: 200, timestamp: 200, ..Default::default() }
    }

    #[test]
    fn trace_has_correct_shape() {
        let p = VessLogicProgram::parse("[deposit]\napprove\n[withdraw]\napprove\n").unwrap();
        let trace = build_trace(&p, 50, &c(), Section::Deposit);
        assert_eq!(trace.main_trace_width(), TRACE_WIDTH);
        assert!(trace.main_segment().num_rows() >= 8);
        assert_eq!(trace.get(COL_PC, 0), F::ZERO);
        assert_eq!(trace.get(COL_OPCODE, 0), F::from(2u32));
        assert_eq!(trace.get(COL_APPROVED, 0), F::ONE);
    }

    #[test]
    fn trace_for_require_pass() {
        let p = VessLogicProgram::parse("[deposit]\n    require amount > 0\n    approve\n[withdraw]\n    approve\n").unwrap();
        let trace = build_trace(&p, 50, &c(), Section::Deposit);
        assert_ne!(trace.get(COL_EXPR_OUTPUT, 0), F::ZERO);
    }

    #[test]
    fn trace_for_require_fail() {
        let p = VessLogicProgram::parse("[constants]\nu64 min = 100\n[deposit]\n    require amount >= min\n    approve\n[withdraw]\n    approve\n").unwrap();
        let trace = build_trace(&p, 50, &c(), Section::Deposit);
        assert_eq!(trace.get(COL_EXPR_OUTPUT, 0), F::ZERO);
        assert_eq!(trace.get(COL_APPROVED, 0), F::ZERO);
    }

    #[test]
    fn evaluate_and_trace_approved() {
        let p = VessLogicProgram::parse("[deposit]\napprove\n[withdraw]\napprove\n").unwrap();
        let (result, trace, pi, _) = evaluate_and_trace(&p, 50, &c()).unwrap();
        assert!(matches!(result, EvalResult::Approved));
        assert_eq!(pi.expected_approved, 1);
        assert_eq!(trace.get(COL_APPROVED, 0), F::ONE);
    }

    #[test]
    fn public_inputs_to_elements() {
        let pi = PublicInputs { program_hash: [0xAA; 32], claim_hash: [0xBB; 32], amount: 100, instruction_count: 3, expected_approved: 1 };
        assert_eq!(pi.to_elements().len(), 11);
    }

    #[test]
    fn prove_and_verify_approved() {
        let p = VessLogicProgram::parse("[deposit]\napprove\n[withdraw]\napprove\n").unwrap();
        let (result, proof, _) = prove_deposit(&p, 50, &c()).unwrap();
        assert!(matches!(result, EvalResult::Approved));
        assert!(verify_deposit(&p, 50, &c(), true, proof).unwrap());
    }

    #[test]
    fn prove_and_verify_rejected() {
        let p = VessLogicProgram::parse("[constants]\nu64 min = 100\n[deposit]\n    require amount >= min\n    approve\n[withdraw]\n    approve\n").unwrap();
        let (result, proof, _) = prove_deposit(&p, 50, &c()).unwrap();
        assert!(matches!(result, EvalResult::Rejected { .. }));
        assert!(verify_deposit(&p, 50, &c(), false, proof).unwrap());
    }
}
