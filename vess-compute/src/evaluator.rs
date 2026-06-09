//! VessLogic runtime evaluator — tree-walking interpreter.
//!
//! Evaluates a parsed [`VessLogicProgram`] against an [`EvalContext`]
//! containing the claim data (amount, denomination, timestamps, etc.).
//!
//! # Execution model
//!
//! Each `[deposit]` / `[withdraw]` block is a sequence of instructions:
//!   - `require(expr)` — if expr is false, execution halts (rejected)
//!   - `bind name = expr` — bind a variable for use in later instructions
//!   - `approve` — terminal: execution succeeds
//!
//! Built-in functions available in expressions:
//!   - `after(ts)`, `before(ts)`, `between(start, end, ts)` — timelocks
//!   - `all_of(a, b, ...)`, `any_of(a, b, ...)` — logical combinators
//!   - `satisfies(link)` — cross-program link (evaluated via DHT)

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use anyhow::{anyhow, Result};

use crate::vesslogic::{
    VessLogicBinaryOp, VessLogicExpr, VessLogicInstruction, VessLogicLiteral,
    VessLogicProgram, VessLogicUnaryOp,
};

// ── Link resolver trait ───────────────────────────────────────────

/// Resolves cross-program `satisfies(link)` calls during evaluation.
///
/// When a program references another via `[links]`, the evaluator delegates
/// to this resolver to fetch and evaluate the linked program's predicate.
/// The `Arc` allows sharing across contexts and threads.
pub trait LinkResolver: Send + Sync {
    /// Evaluate the linked program's deposit predicate. Return `true` if accepted.
    fn resolve_deposit(&self, link_name: &str, ctx: &EvalContext) -> Result<bool>;
    /// Evaluate the linked program's withdraw predicate. Return `true` if accepted.
    fn resolve_withdraw(&self, link_name: &str, ctx: &EvalContext) -> Result<bool>;
}

/// No-op resolver for when DHT access isn't available (tests, local eval).
pub struct PermissiveLinkResolver;

impl LinkResolver for PermissiveLinkResolver {
    fn resolve_deposit(&self, _: &str, _: &EvalContext) -> Result<bool> { Ok(true) }
    fn resolve_withdraw(&self, _: &str, _: &EvalContext) -> Result<bool> { Ok(true) }
}

// ── Evaluation context ────────────────────────────────────────────

/// Runtime values supplied to the evaluator for a specific claim.
///
/// Deposit context populates `amount` (the incoming amount).
/// Withdraw context populates `requested` (the amount being withdrawn).
/// Both contexts share the claim metadata.
#[derive(Clone)]
pub struct EvalContext {
    /// Amount being deposited (set for `[deposit]`, zero for `[withdraw]`).
    pub amount: u64,
    /// Amount being withdrawn (set for `[withdraw]`, zero for `[deposit]`).
    pub requested: u64,
    /// Sender's identity commitment.
    pub sender: [u8; 32],
    /// Current Unix timestamp.
    pub timestamp: u64,
    /// Timestamp from the claim itself.
    pub claim_timestamp: u64,
    /// Current balance of the program (sum of bills it owns).
    pub program_balance: u64,
    /// Pre-transition state commitment.
    pub current_state: [u8; 32],
    /// Post-transition state commitment.
    pub next_state: [u8; 32],
    /// Mint ID of the bill being claimed.
    pub claim_mint_id: [u8; 32],
    /// Previous owner commitment.
    pub claim_prev_owner: [u8; 32],
    /// New owner commitment.
    pub claim_new_owner: [u8; 32],
    /// Chain depth of the claim.
    pub claim_chain_depth: u64,
    /// Denomination value of the claimed bill.
    pub claim_denomination: u64,
    /// Whether the claim has a previous program owner.
    pub claim_has_prev_program: bool,
    /// Whether the claim has a new program owner.
    pub claim_has_new_program: bool,

    /// Program constants (from `[constants]` section).
    pub constants: HashMap<String, VessLogicLiteral>,
    /// Runtime bindings (from `bind` instructions, scoped to current block).
    pub bindings: HashMap<String, VessLogicLiteral>,

    /// Optional resolver for cross-program `satisfies(link)` calls.
    /// Defaults to [`PermissiveLinkResolver`] (always passes).
    #[allow(clippy::type_complexity)]
    pub link_resolver: Arc<dyn LinkResolver>,
}

impl std::fmt::Debug for EvalContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EvalContext")
            .field("amount", &self.amount)
            .field("requested", &self.requested)
            .field("claim_denomination", &self.claim_denomination)
            .field("program_balance", &self.program_balance)
            .field("claim_timestamp", &self.claim_timestamp)
            .field("bindings", &self.bindings)
            .finish()
    }
}

impl EvalContext {
    /// Create a context for evaluating a deposit block.
    pub fn for_deposit(
        amount: u64,
        program: &VessLogicProgram,
        claim: &ClaimData,
    ) -> Self {
        let mut constants = HashMap::new();
        for binding in &program.constants {
            constants.insert(binding.name.clone(), eval_literal_binding(binding));
        }
        Self {
            amount,
            requested: 0,
            sender: claim.sender,
            timestamp: claim.timestamp,
            claim_timestamp: claim.claim_timestamp,
            program_balance: claim.program_balance,
            current_state: claim.current_state,
            next_state: claim.next_state,
            claim_mint_id: claim.claim_mint_id,
            claim_prev_owner: claim.claim_prev_owner,
            claim_new_owner: claim.claim_new_owner,
            claim_chain_depth: claim.claim_chain_depth,
            claim_denomination: claim.claim_denomination,
            claim_has_prev_program: claim.claim_has_prev_program,
            claim_has_new_program: claim.claim_has_new_program,
            constants,
            bindings: HashMap::new(),
            link_resolver: Arc::new(PermissiveLinkResolver),
        }
    }

    /// Create a context for evaluating a withdraw block.
    pub fn for_withdraw(
        requested: u64,
        program: &VessLogicProgram,
        claim: &ClaimData,
    ) -> Self {
        let mut constants = HashMap::new();
        for binding in &program.constants {
            constants.insert(binding.name.clone(), eval_literal_binding(binding));
        }
        Self {
            amount: 0,
            requested,
            sender: claim.sender,
            timestamp: claim.timestamp,
            claim_timestamp: claim.claim_timestamp,
            program_balance: claim.program_balance,
            current_state: claim.current_state,
            next_state: claim.next_state,
            claim_mint_id: claim.claim_mint_id,
            claim_prev_owner: claim.claim_prev_owner,
            claim_new_owner: claim.claim_new_owner,
            claim_chain_depth: claim.claim_chain_depth,
            claim_denomination: claim.claim_denomination,
            claim_has_prev_program: claim.claim_has_prev_program,
            claim_has_new_program: claim.claim_has_new_program,
            constants,
            bindings: HashMap::new(),
            link_resolver: Arc::new(PermissiveLinkResolver),
        }
    }

    /// Look up a variable: built-ins → constants → bindings.
    fn lookup(&self, name: &str) -> Result<VessLogicLiteral> {
        // Built-in deposit variables
        match name {
            "amount" => return Ok(VessLogicLiteral::U64(self.amount)),
            "sender" => return Ok(VessLogicLiteral::U64(u64::from_le_bytes(self.sender[..8].try_into().unwrap()))),
            "timestamp" => return Ok(VessLogicLiteral::U64(self.timestamp)),
            "claim_timestamp" => return Ok(VessLogicLiteral::U64(self.claim_timestamp)),
            "program_balance" => return Ok(VessLogicLiteral::U64(self.program_balance)),
            "current_state" => return Ok(VessLogicLiteral::U64(u64::from_le_bytes(self.current_state[..8].try_into().unwrap()))),
            "next_state" => return Ok(VessLogicLiteral::U64(u64::from_le_bytes(self.next_state[..8].try_into().unwrap()))),
            "claim_mint_id" => return Ok(VessLogicLiteral::U64(u64::from_le_bytes(self.claim_mint_id[..8].try_into().unwrap()))),
            "claim_prev_owner" => return Ok(VessLogicLiteral::U64(u64::from_le_bytes(self.claim_prev_owner[..8].try_into().unwrap()))),
            "claim_new_owner" => return Ok(VessLogicLiteral::U64(u64::from_le_bytes(self.claim_new_owner[..8].try_into().unwrap()))),
            "claim_chain_depth" => return Ok(VessLogicLiteral::U64(self.claim_chain_depth)),
            "claim_denomination" => return Ok(VessLogicLiteral::U64(self.claim_denomination)),
            "claim_has_prev_program" => return Ok(VessLogicLiteral::Bool(self.claim_has_prev_program)),
            "claim_has_new_program" => return Ok(VessLogicLiteral::Bool(self.claim_has_new_program)),
            // Withdraw built-in
            "requested" => return Ok(VessLogicLiteral::U64(self.requested)),
            _ => {}
        }

        // Constants
        if let Some(value) = self.constants.get(name) {
            return Ok(value.clone());
        }

        // Runtime bindings
        if let Some(value) = self.bindings.get(name) {
            return Ok(value.clone());
        }

        Err(anyhow!("undefined variable: {name}"))
    }
}

/// Minimal claim data needed by the evaluator.
#[derive(Debug, Clone)]
pub struct ClaimData {
    pub sender: [u8; 32],
    pub timestamp: u64,
    pub claim_timestamp: u64,
    pub program_balance: u64,
    pub current_state: [u8; 32],
    pub next_state: [u8; 32],
    pub claim_mint_id: [u8; 32],
    pub claim_prev_owner: [u8; 32],
    pub claim_new_owner: [u8; 32],
    pub claim_chain_depth: u64,
    pub claim_denomination: u64,
    pub claim_has_prev_program: bool,
    pub claim_has_new_program: bool,
}

impl Default for ClaimData {
    fn default() -> Self {
        Self {
            sender: [0u8; 32],
            timestamp: 0,
            claim_timestamp: 0,
            program_balance: 0,
            current_state: [0u8; 32],
            next_state: [0u8; 32],
            claim_mint_id: [0u8; 32],
            claim_prev_owner: [0u8; 32],
            claim_new_owner: [0u8; 32],
            claim_chain_depth: 0,
            claim_denomination: 0,
            claim_has_prev_program: false,
            claim_has_new_program: false,
        }
    }
}

// ── Evaluation result ─────────────────────────────────────────────

/// Outcome of evaluating a VessLogic program block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EvalResult {
    /// Execution reached `approve` — the transaction is authorized.
    Approved,
    /// A `require` check failed — the transaction is rejected.
    Rejected { reason: String },
}

// ── Expression evaluator ──────────────────────────────────────────

/// Evaluate a VessLogic expression to a literal value.
pub fn eval_expr(expr: &VessLogicExpr, ctx: &EvalContext) -> Result<VessLogicLiteral> {
    match expr {
        VessLogicExpr::Literal(lit) => Ok(lit.clone()),

        VessLogicExpr::Variable(name) => ctx.lookup(name),

        VessLogicExpr::Unary { op, expr } => {
            let val = eval_expr(expr, ctx)?;
            eval_unary(*op, val)
        }

        VessLogicExpr::Binary { left, op, right } => {
            let lhs = eval_expr(left, ctx)?;
            let rhs = eval_expr(right, ctx)?;
            eval_binary(*op, lhs, rhs)
        }

        VessLogicExpr::Call { name, args } => {
            eval_builtin(name, args, ctx)
        }
    }
}

fn eval_unary(op: VessLogicUnaryOp, val: VessLogicLiteral) -> Result<VessLogicLiteral> {
    match op {
        VessLogicUnaryOp::Neg => match val {
            VessLogicLiteral::U64(n) => Ok(VessLogicLiteral::U64(n.checked_neg().ok_or_else(|| anyhow!("negation overflow"))?)),
            VessLogicLiteral::Bool(_) => Err(anyhow!("cannot negate a boolean")),
        },
        VessLogicUnaryOp::Not => match val {
            VessLogicLiteral::Bool(b) => Ok(VessLogicLiteral::Bool(!b)),
            VessLogicLiteral::U64(n) => Ok(VessLogicLiteral::Bool(n == 0)),
        },
    }
}

fn eval_binary(op: VessLogicBinaryOp, lhs: VessLogicLiteral, rhs: VessLogicLiteral) -> Result<VessLogicLiteral> {
    use VessLogicBinaryOp::*;
    match (lhs, rhs) {
        (VessLogicLiteral::U64(a), VessLogicLiteral::U64(b)) => match op {
            Add => Ok(VessLogicLiteral::U64(a.checked_add(b).ok_or_else(|| anyhow!("addition overflow"))?)),
            Sub => Ok(VessLogicLiteral::U64(a.checked_sub(b).ok_or_else(|| anyhow!("subtraction underflow"))?)),
            Mul => Ok(VessLogicLiteral::U64(a.checked_mul(b).ok_or_else(|| anyhow!("multiplication overflow"))?)),
            Div => {
                if b == 0 { return Err(anyhow!("division by zero")); }
                Ok(VessLogicLiteral::U64(a / b))
            }
            Mod => {
                if b == 0 { return Err(anyhow!("modulo by zero")); }
                Ok(VessLogicLiteral::U64(a % b))
            }
            Eq => Ok(VessLogicLiteral::Bool(a == b)),
            NotEq => Ok(VessLogicLiteral::Bool(a != b)),
            Lt => Ok(VessLogicLiteral::Bool(a < b)),
            Lte => Ok(VessLogicLiteral::Bool(a <= b)),
            Gt => Ok(VessLogicLiteral::Bool(a > b)),
            Gte => Ok(VessLogicLiteral::Bool(a >= b)),
            Or => Ok(VessLogicLiteral::Bool(a != 0 || b != 0)),
            And => Ok(VessLogicLiteral::Bool(a != 0 && b != 0)),
        },
        (VessLogicLiteral::Bool(a), VessLogicLiteral::Bool(b)) => match op {
            Or => Ok(VessLogicLiteral::Bool(a || b)),
            And => Ok(VessLogicLiteral::Bool(a && b)),
            Eq => Ok(VessLogicLiteral::Bool(a == b)),
            NotEq => Ok(VessLogicLiteral::Bool(a != b)),
            _ => Err(anyhow!("comparison/arithmetic not supported on booleans")),
        },
        (VessLogicLiteral::U64(a), VessLogicLiteral::Bool(b)) => {
            match op {
                Or => Ok(VessLogicLiteral::Bool(a != 0 || b)),
                And => Ok(VessLogicLiteral::Bool(a != 0 && b)),
                _ => Err(anyhow!("cannot mix u64 and bool in this operation")),
            }
        }
        (VessLogicLiteral::Bool(a), VessLogicLiteral::U64(b)) => {
            match op {
                Or => Ok(VessLogicLiteral::Bool(a || b != 0)),
                And => Ok(VessLogicLiteral::Bool(a && b != 0)),
                _ => Err(anyhow!("cannot mix u64 and bool in this operation")),
            }
        }
    }
}

fn to_bool(val: &VessLogicLiteral) -> bool {
    match val {
        VessLogicLiteral::Bool(b) => *b,
        VessLogicLiteral::U64(n) => *n != 0,
    }
}

fn to_u64(val: &VessLogicLiteral) -> Result<u64> {
    match val {
        VessLogicLiteral::U64(n) => Ok(*n),
        VessLogicLiteral::Bool(b) => Ok(if *b { 1 } else { 0 }),
    }
}

// ── Built-in function evaluator ───────────────────────────────────

fn eval_builtin(name: &str, args: &[VessLogicExpr], ctx: &EvalContext) -> Result<VessLogicLiteral> {
    match name {
        "abs" => {
            if args.len() != 1 {
                return Err(anyhow!("abs requires 1 argument"));
            }
            let val = eval_expr(&args[0], ctx)?;
            match val {
                VessLogicLiteral::U64(n) => Ok(VessLogicLiteral::U64(n)),
                VessLogicLiteral::Bool(b) => Ok(VessLogicLiteral::U64(if b { 1 } else { 0 })),
            }
        }

        "after" => {
            if args.len() != 1 {
                return Err(anyhow!("after requires 1 argument (timestamp)"));
            }
            let ts = to_u64(&eval_expr(&args[0], ctx)?)?;
            Ok(VessLogicLiteral::Bool(ctx.claim_timestamp > ts))
        }

        "before" => {
            if args.len() != 1 {
                return Err(anyhow!("before requires 1 argument (timestamp)"));
            }
            let ts = to_u64(&eval_expr(&args[0], ctx)?)?;
            Ok(VessLogicLiteral::Bool(ctx.claim_timestamp < ts))
        }

        "between" => {
            if args.len() < 2 || args.len() > 3 {
                return Err(anyhow!("between requires 2 or 3 arguments (start, end, [timestamp])"));
            }
            let start = to_u64(&eval_expr(&args[0], ctx)?)?;
            let end = to_u64(&eval_expr(&args[1], ctx)?)?;
            let ts = if args.len() == 3 {
                to_u64(&eval_expr(&args[2], ctx)?)?
            } else {
                ctx.claim_timestamp
            };
            Ok(VessLogicLiteral::Bool(ts >= start && ts <= end))
        }

        "clamp" => {
            if args.len() != 3 {
                return Err(anyhow!("clamp requires 3 arguments (value, min, max)"));
            }
            let val = to_u64(&eval_expr(&args[0], ctx)?)?;
            let min = to_u64(&eval_expr(&args[1], ctx)?)?;
            let max = to_u64(&eval_expr(&args[2], ctx)?)?;
            Ok(VessLogicLiteral::U64(val.clamp(min, max)))
        }

        "all_of" => {
            if args.is_empty() {
                return Err(anyhow!("all_of requires at least 1 argument"));
            }
            for arg in args {
                if !to_bool(&eval_expr(arg, ctx)?) {
                    return Ok(VessLogicLiteral::Bool(false));
                }
            }
            Ok(VessLogicLiteral::Bool(true))
        }

        "any_of" => {
            if args.is_empty() {
                return Err(anyhow!("any_of requires at least 1 argument"));
            }
            for arg in args {
                if to_bool(&eval_expr(arg, ctx)?) {
                    return Ok(VessLogicLiteral::Bool(true));
                }
            }
            Ok(VessLogicLiteral::Bool(false))
        }

        "satisfies" => {
            if args.len() != 1 {
                return Err(anyhow!("satisfies requires 1 argument (link name)"));
            }
            // Extract link name — the argument must be a variable referencing
            // a declared link from the [links] section.
            let link_name = match &args[0] {
                VessLogicExpr::Variable(name) => name.clone(),
                _ => return Err(anyhow!("satisfies argument must be a link name (variable)")),
            };
            // Delegate to the resolver (DHT-aware in production, permissive in tests)
            let approved = ctx.link_resolver.resolve_deposit(&link_name, ctx)?;
            Ok(VessLogicLiteral::Bool(approved))
        }

        _ => Err(anyhow!("unknown built-in function: {name}")),
    }
}

// ── Instruction evaluator ─────────────────────────────────────────

/// Evaluate a single VessLogic instruction within a context.
/// Returns `None` to continue, `Some(EvalResult)` to halt.
pub fn eval_instruction(
    instr: &VessLogicInstruction,
    ctx: &mut EvalContext,
) -> Result<Option<EvalResult>> {
    match instr {
        VessLogicInstruction::Require(expr) => {
            let result = eval_expr(expr, ctx)?;
            if !to_bool(&result) {
                return Ok(Some(EvalResult::Rejected {
                    reason: format!("require() failed: expression evaluated to false"),
                }));
            }
            Ok(None) // continue
        }

        VessLogicInstruction::Bind { name, value } => {
            let val = eval_expr(value, ctx)?;
            ctx.bindings.insert(name.clone(), val);
            Ok(None) // continue
        }

        VessLogicInstruction::Approve => {
            Ok(Some(EvalResult::Approved))
        }
    }
}

// ── Block evaluator ───────────────────────────────────────────────

/// Evaluate an entire instruction block (deposit or withdraw).
/// Returns the final result and the accumulated bindings.
pub fn eval_block(
    instructions: &[VessLogicInstruction],
    ctx: &mut EvalContext,
) -> Result<(EvalResult, BTreeMap<String, VessLogicLiteral>)> {
    for instr in instructions {
        if let Some(result) = eval_instruction(instr, ctx)? {
            let bindings: BTreeMap<String, VessLogicLiteral> = ctx
                .bindings
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();
            return Ok((result, bindings));
        }
    }
    Err(anyhow!("instruction block did not terminate with approve"))
}

// ── Top-level entry points ────────────────────────────────────────

/// Evaluate the deposit block of a program.
pub fn evaluate_deposit(
    program: &VessLogicProgram,
    amount: u64,
    claim: &ClaimData,
) -> Result<(EvalResult, BTreeMap<String, VessLogicLiteral>)> {
    let mut ctx = EvalContext::for_deposit(amount, program, claim);
    eval_block(&program.deposit, &mut ctx)
}

/// Evaluate the withdraw block of a program.
pub fn evaluate_withdraw(
    program: &VessLogicProgram,
    requested: u64,
    claim: &ClaimData,
) -> Result<(EvalResult, BTreeMap<String, VessLogicLiteral>)> {
    let mut ctx = EvalContext::for_withdraw(requested, program, claim);
    eval_block(&program.withdraw, &mut ctx)
}

// ── Helpers ───────────────────────────────────────────────────────

fn eval_literal_binding(binding: &crate::vesslogic::VessLogicBinding) -> VessLogicLiteral {
    match &binding.value {
        VessLogicExpr::Literal(lit) => lit.clone(),
        _ => {
            // Constant expressions are evaluated at compile time with no context.
            // If they reference variables, they'll fail validation.
            VessLogicLiteral::U64(0)
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vesslogic::VessLogicProgram;

    fn parse_program(source: &str) -> VessLogicProgram {
        VessLogicProgram::parse(source).expect("parse test program")
    }

    fn default_claim() -> ClaimData {
        ClaimData {
            claim_denomination: 100,
            claim_chain_depth: 1,
            program_balance: 500,
            claim_timestamp: 200,
            timestamp: 200,
            claim_has_new_program: true,
            ..Default::default()
        }
    }

    #[test]
    fn simple_deposit_approve() {
        let prog = parse_program("[deposit]\napprove\n[withdraw]\napprove\n");
        let (result, _) = evaluate_deposit(&prog, 50, &default_claim()).unwrap();
        assert_eq!(result, EvalResult::Approved);
    }

    #[test]
    fn deposit_require_amount_min() {
        let prog = parse_program("
            [constants]\n    u64 min_deposit = 10\n
            [deposit]\n    require amount >= min_deposit\n    approve\n
            [withdraw]\n    approve\n
        ");
        // amount 50 >= min_deposit 10 → pass
        let (result, _) = evaluate_deposit(&prog, 50, &default_claim()).unwrap();
        assert_eq!(result, EvalResult::Approved);

        // amount 5 < min_deposit 10 → fail
        let (result, _) = evaluate_deposit(&prog, 5, &default_claim()).unwrap();
        assert!(matches!(result, EvalResult::Rejected { .. }));
    }

    #[test]
    fn deposit_denomination_gating() {
        let prog = parse_program("
            [constants]\n    u64 max_denom = 100\n
            [deposit]\n    require claim_denomination <= max_denom\n    approve\n
            [withdraw]\n    approve\n
        ");
        // denom 100 <= max 100 → pass
        let claim = ClaimData { claim_denomination: 100, ..default_claim() };
        let (result, _) = evaluate_deposit(&prog, 50, &claim).unwrap();
        assert_eq!(result, EvalResult::Approved);

        // denom 200 > max 100 → fail
        let claim = ClaimData { claim_denomination: 200, ..default_claim() };
        let (result, _) = evaluate_deposit(&prog, 50, &claim).unwrap();
        assert!(matches!(result, EvalResult::Rejected { .. }));
    }

    #[test]
    fn deposit_balance_cap() {
        let prog = parse_program("
            [constants]\n    u64 cap = 1000\n
            [deposit]\n    require program_balance + amount <= cap\n    approve\n
            [withdraw]\n    approve\n
        ");
        // 500 + 400 = 900 <= 1000 → pass
        let claim = ClaimData { program_balance: 500, ..default_claim() };
        let (result, _) = evaluate_deposit(&prog, 400, &claim).unwrap();
        assert_eq!(result, EvalResult::Approved);

        // 500 + 600 = 1100 > 1000 → fail
        let (result, _) = evaluate_deposit(&prog, 600, &claim).unwrap();
        assert!(matches!(result, EvalResult::Rejected { .. }));
    }

    #[test]
    fn withdraw_require_amount() {
        let prog = parse_program("
            [constants]\n    u64 max_withdraw = 200\n
            [deposit]\n    approve\n
            [withdraw]\n    require requested <= max_withdraw\n    require requested <= program_balance\n    approve\n
        ");
        let claim = ClaimData { program_balance: 500, ..default_claim() };
        // 150 <= 200 AND 150 <= 500 → pass
        let (result, _) = evaluate_withdraw(&prog, 150, &claim).unwrap();
        assert_eq!(result, EvalResult::Approved);

        // 300 > 200 → fail
        let (result, _) = evaluate_withdraw(&prog, 300, &claim).unwrap();
        assert!(matches!(result, EvalResult::Rejected { .. }));
    }

    #[test]
    fn timelock_after() {
        let prog = parse_program("
            [constants]\n    u64 unlock_at = 100\n
            [deposit]\n    approve\n
            [withdraw]\n    require after(unlock_at)\n    approve\n
        ");
        // claim_timestamp 200 > unlock_at 100 → pass
        let claim = ClaimData { claim_timestamp: 200, ..default_claim() };
        let (result, _) = evaluate_withdraw(&prog, 50, &claim).unwrap();
        assert_eq!(result, EvalResult::Approved);

        // claim_timestamp 50 < unlock_at 100 → fail
        let claim = ClaimData { claim_timestamp: 50, ..default_claim() };
        let (result, _) = evaluate_withdraw(&prog, 50, &claim).unwrap();
        assert!(matches!(result, EvalResult::Rejected { .. }));
    }

    #[test]
    fn bind_and_reference() {
        let prog = parse_program("
            [constants]\n    u64 cap = 1000\n
            [deposit]\n    require amount > 0\n    bind new_total = program_balance + amount\n    require new_total <= cap\n    approve\n
            [withdraw]\n    approve\n
        ");
        let claim = ClaimData { program_balance: 500, ..default_claim() };
        // bind new_total = 500 + 400 = 900; 900 <= 1000 → pass
        let (result, bindings) = evaluate_deposit(&prog, 400, &claim).unwrap();
        assert_eq!(result, EvalResult::Approved);
        assert_eq!(bindings.get("new_total"), Some(&VessLogicLiteral::U64(900)));
    }

    #[test]
    fn compound_conditions() {
        let prog = parse_program("
            [constants]\n    u64 min_deposit = 10\n    u64 max_denom = 200\n
            [deposit]\n    require amount >= min_deposit\n    require claim_denomination <= max_denom\n    require program_balance + amount <= 1000\n    approve\n
            [withdraw]\n    approve\n
        ");
        let claim = ClaimData {
            claim_denomination: 100,
            program_balance: 300,
            ..default_claim()
        };
        // All pass: 50 >= 10, 100 <= 200, 300+50=350 <= 1000
        let (result, _) = evaluate_deposit(&prog, 50, &claim).unwrap();
        assert_eq!(result, EvalResult::Approved);
    }

    #[test]
    fn boolean_constant() {
        let prog = parse_program("
            [constants]\n    bool paused = false\n
            [deposit]\n    require !paused\n    approve\n
            [withdraw]\n    approve\n
        ");
        let (result, _) = evaluate_deposit(&prog, 50, &default_claim()).unwrap();
        assert_eq!(result, EvalResult::Approved);
    }

    #[test]
    fn all_of_any_of() {
        let prog = parse_program("
            [constants]\n    u64 a = 10\n    u64 b = 20\n    u64 c = 30\n
            [deposit]\n    require all_of(a < b, b < c)\n    require any_of(a > c, b < c)\n    approve\n
            [withdraw]\n    approve\n
        ");
        let (result, _) = evaluate_deposit(&prog, 50, &default_claim()).unwrap();
        assert_eq!(result, EvalResult::Approved);
    }
}
