//! Canonical VessLogic covenant templates.
pub struct CovenantTemplate {
    pub name: &'static str,
    pub description: &'static str,
    pub source: &'static str,
}
pub fn all_templates() -> Vec<CovenantTemplate> {
    vec![timelock_vault(), capped_treasury(), recurring_disbursement(), two_of_three_escrow()]
}
pub fn find_template(name: &str) -> Option<CovenantTemplate> {
    let lower = name.to_ascii_lowercase();
    all_templates().into_iter().find(|t| t.name.to_ascii_lowercase() == lower || t.name.to_ascii_lowercase().contains(&lower))
}
fn timelock_vault() -> CovenantTemplate {
    CovenantTemplate {
        name: "timelock-vault",
        description: "Timelocked vault",
        source: r#"[constants]
u64 release_at = 1800000000
u64 min_claim_depth = 3

[deposit]
require(amount > 0)
approve

[withdraw]
require(timestamp >= release_at)
require(claim_chain_depth >= min_claim_depth)
require(claim_has_prev_program == true)
approve
"#,
    }
}
fn capped_treasury() -> CovenantTemplate {
    CovenantTemplate {
        name: "capped-treasury",
        description: "Capped treasury",
        source: r#"[constants]
u64 max_balance = 100000
u64 max_withdraw = 10000

[deposit]
require(amount + program_balance <= max_balance)
approve

[withdraw]
require(requested <= max_withdraw)
require(requested <= program_balance)
approve
"#,
    }
}
fn recurring_disbursement() -> CovenantTemplate {
    CovenantTemplate {
        name: "recurring-disbursement",
        description: "Recurring disbursement",
        source: r#"[constants]
u64 interval_secs = 2592000
u64 per_interval = 1000
u64 max_intervals = 12

[deposit]
require(amount > 0)
approve

[withdraw]
require(claim_chain_depth * interval_secs <= timestamp)
require(claim_chain_depth < max_intervals)
require(requested == per_interval)
require(requested <= program_balance)
approve
"#,
    }
}
fn two_of_three_escrow() -> CovenantTemplate {
    CovenantTemplate {
        name: "two-of-three-escrow",
        description: "Two-of-three escrow",
        source: r#"[links]
signer1_covenant
signer2_covenant
signer3_covenant

[constants]
u64 min_approvals = 2

[deposit]
require(amount > 0)
approve

[withdraw]
require(requested <= program_balance)
approve
"#,
    }
}
