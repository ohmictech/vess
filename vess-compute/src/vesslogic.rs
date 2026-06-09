use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const VESSLOGIC_VERSION_HEADER: &str = "vesslogic:v1";

const DEPOSIT_BUILTINS: &[&str] = &[
    "amount",
    "sender",
    "timestamp",
    "claim_timestamp",
    "program_balance",
    "current_state",
    "next_state",
    "claim_mint_id",
    "claim_prev_owner",
    "claim_new_owner",
    "claim_chain_depth",
    "claim_denomination",
    "claim_has_prev_program",
    "claim_has_new_program",
];
const WITHDRAW_BUILTINS: &[&str] = &[
    "requested",
    "sender",
    "timestamp",
    "claim_timestamp",
    "program_balance",
    "current_state",
    "next_state",
    "claim_mint_id",
    "claim_prev_owner",
    "claim_new_owner",
    "claim_chain_depth",
    "claim_denomination",
    "claim_has_prev_program",
    "claim_has_new_program",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VessLogicType {
    U64,
    Bool,
    Address,
    Bytes32,
}

impl VessLogicType {
    fn parse(raw: &str) -> Result<Self> {
        match raw {
            "u64" => Ok(Self::U64),
            "bool" => Ok(Self::Bool),
            "address" => Ok(Self::Address),
            "bytes32" => Ok(Self::Bytes32),
            _ => Err(anyhow!("unsupported VessLogic type {raw}")),
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            Self::U64 => "u64",
            Self::Bool => "bool",
            Self::Address => "address",
            Self::Bytes32 => "bytes32",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VessLogicSection {
    Constants,
    Links,
    Deposit,
    Withdraw,
}

impl VessLogicSection {
    fn parse(raw: &str) -> Result<Self> {
        match raw {
            "constants" => Ok(Self::Constants),
            "links" => Ok(Self::Links),
            "deposit" => Ok(Self::Deposit),
            "withdraw" => Ok(Self::Withdraw),
            _ => Err(anyhow!("unsupported VessLogic section [{raw}]")),
        }
    }

    fn header(&self) -> &'static str {
        match self {
            Self::Constants => "constants",
            Self::Links => "links",
            Self::Deposit => "deposit",
            Self::Withdraw => "withdraw",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VessLogicBinding {
    pub ty: VessLogicType,
    pub name: String,
    pub value: VessLogicExpr,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VessLogicInstruction {
    Require(VessLogicExpr),
    Bind { name: String, value: VessLogicExpr },
    Approve,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VessLogicExpr {
    Literal(VessLogicLiteral),
    Variable(String),
    Unary {
        op: VessLogicUnaryOp,
        expr: Box<VessLogicExpr>,
    },
    Binary {
        left: Box<VessLogicExpr>,
        op: VessLogicBinaryOp,
        right: Box<VessLogicExpr>,
    },
    Call {
        name: String,
        args: Vec<VessLogicExpr>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VessLogicLiteral {
    U64(u64),
    Bool(bool),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VessLogicUnaryOp {
    Neg,
    Not,
}

impl VessLogicUnaryOp {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Neg => "-",
            Self::Not => "!",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VessLogicBinaryOp {
    Or,
    And,
    Eq,
    NotEq,
    Lt,
    Lte,
    Gt,
    Gte,
    Add,
    Sub,
    Mul,
    Div,
    Mod,
}

impl VessLogicBinaryOp {
    fn precedence(&self) -> u8 {
        match self {
            Self::Or => 1,
            Self::And => 2,
            Self::Eq | Self::NotEq => 3,
            Self::Lt | Self::Lte | Self::Gt | Self::Gte => 4,
            Self::Add | Self::Sub => 5,
            Self::Mul | Self::Div | Self::Mod => 6,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            Self::Or => "||",
            Self::And => "&&",
            Self::Eq => "==",
            Self::NotEq => "!=",
            Self::Lt => "<",
            Self::Lte => "<=",
            Self::Gt => ">",
            Self::Gte => ">=",
            Self::Add => "+",
            Self::Sub => "-",
            Self::Mul => "*",
            Self::Div => "/",
            Self::Mod => "%",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VessLogicProgram {
    pub constants: Vec<VessLogicBinding>,
    pub links: Vec<String>,
    pub deposit: Vec<VessLogicInstruction>,
    pub withdraw: Vec<VessLogicInstruction>,
}

impl VessLogicProgram {
    pub fn parse(source: &str) -> Result<Self> {
        let mut constants = Vec::new();
        let mut links = Vec::new();
        let mut deposit = Vec::new();
        let mut withdraw = Vec::new();
        let mut current_section = None;

        for (line_index, raw_line) in source.lines().enumerate() {
            let logical_line = raw_line.split('#').next().unwrap_or("").trim();
            if logical_line.is_empty() {
                continue;
            }
            if logical_line.starts_with('[') && logical_line.ends_with(']') {
                let header = &logical_line[1..logical_line.len() - 1];
                current_section = Some(VessLogicSection::parse(header.trim()).map_err(|error| {
                    anyhow!("line {}: {error}", line_index + 1)
                })?);
                continue;
            }

            let section = current_section.ok_or_else(|| {
                anyhow!(
                    "line {}: VessLogic statements must appear under a section header",
                    line_index + 1
                )
            })?;
            match section {
                VessLogicSection::Constants => constants.push(
                    parse_binding_line(logical_line)
                        .map_err(|error| anyhow!("line {}: {error}", line_index + 1))?,
                ),
                VessLogicSection::Links => links.push(
                    parse_link_line(logical_line)
                        .map_err(|error| anyhow!("line {}: {error}", line_index + 1))?,
                ),
                VessLogicSection::Deposit => deposit.push(
                    parse_instruction_line(logical_line)
                        .map_err(|error| anyhow!("line {}: {error}", line_index + 1))?,
                ),
                VessLogicSection::Withdraw => withdraw.push(
                    parse_instruction_line(logical_line)
                        .map_err(|error| anyhow!("line {}: {error}", line_index + 1))?,
                ),
            }
        }

        let program = Self {
            constants,
            links,
            deposit,
            withdraw,
        };
        program.validate()?;
        Ok(program)
    }

    pub fn validate(&self) -> Result<()> {
        if self.deposit.is_empty() {
            return Err(anyhow!("VessLogic requires a non-empty [deposit] section"));
        }
        if self.withdraw.is_empty() {
            return Err(anyhow!("VessLogic requires a non-empty [withdraw] section"));
        }
        validate_terminal_approve("deposit", &self.deposit)?;
        validate_terminal_approve("withdraw", &self.withdraw)?;

        let mut declared_constants = BTreeSet::new();
        for binding in &self.constants {
            ensure_fresh_identifier(&binding.name, &declared_constants, "constant")?;
            validate_expr(&binding.value, &declared_constants)?;
            declared_constants.insert(binding.name.clone());
        }

        let mut declared_links = BTreeSet::new();
        for link in &self.links {
            ensure_fresh_identifier(link, &declared_links, "link")?;
            declared_links.insert(link.clone());
        }

        let mut deposit_scope = declared_constants.clone();
        deposit_scope.extend(declared_links.iter().cloned());
        deposit_scope.extend(DEPOSIT_BUILTINS.iter().map(|value| value.to_string()));
        validate_instruction_block(&self.deposit, &deposit_scope)?;

        let mut withdraw_scope = declared_constants;
        withdraw_scope.extend(declared_links);
        withdraw_scope.extend(WITHDRAW_BUILTINS.iter().map(|value| value.to_string()));
        validate_instruction_block(&self.withdraw, &withdraw_scope)?;
        Ok(())
    }

    pub fn canonical_source(&self) -> String {
        let mut sections = Vec::new();
        if !self.constants.is_empty() {
            sections.push(render_binding_section("constants", &self.constants));
        }
        if !self.links.is_empty() {
            sections.push(render_link_section("links", &self.links));
        }
        sections.push(render_instruction_section("deposit", &self.deposit));
        sections.push(render_instruction_section("withdraw", &self.withdraw));
        sections.join("\n\n")
    }

    pub fn compile(&self) -> Vec<u8> {
        let mut out = String::new();
        out.push_str(VESSLOGIC_VERSION_HEADER);
        out.push('\n');
        out.push_str(&self.canonical_source());
        out.into_bytes()
    }

    pub fn entrypoints(&self) -> Vec<String> {
        vec![
            VessLogicSection::Deposit.header().to_string(),
            VessLogicSection::Withdraw.header().to_string(),
        ]
    }
}

pub fn compile_vesslogic_source(source: &str) -> Result<Vec<u8>> {
    Ok(VessLogicProgram::parse(source)?.compile())
}

fn render_binding_section(header: &str, bindings: &[VessLogicBinding]) -> String {
    let mut lines = vec![format!("[{header}]")];
    for binding in bindings {
        lines.push(format!(
            "{} {} = {}",
            binding.ty.as_str(),
            binding.name,
            render_expr(&binding.value, 0)
        ));
    }
    lines.join("\n")
}

fn render_instruction_section(header: &str, instructions: &[VessLogicInstruction]) -> String {
    let mut lines = vec![format!("[{header}]")];
    for instruction in instructions {
        let line = match instruction {
            VessLogicInstruction::Require(expr) => {
                format!("require {}", render_expr(expr, 0))
            }
            VessLogicInstruction::Bind { name, value } => {
                format!("bind {name} = {}", render_expr(value, 0))
            }
            VessLogicInstruction::Approve => "approve".to_string(),
        };
        lines.push(line);
    }
    lines.join("\n")
}

fn render_link_section(header: &str, links: &[String]) -> String {
    let mut lines = vec![format!("[{header}]")];
    lines.extend(links.iter().cloned());
    lines.join("\n")
}

fn render_expr(expr: &VessLogicExpr, parent_precedence: u8) -> String {
    match expr {
        VessLogicExpr::Literal(VessLogicLiteral::U64(value)) => value.to_string(),
        VessLogicExpr::Literal(VessLogicLiteral::Bool(value)) => value.to_string(),
        VessLogicExpr::Variable(name) => name.clone(),
        VessLogicExpr::Call { name, args } => {
            let rendered_args = args
                .iter()
                .map(|arg| render_expr(arg, 0))
                .collect::<Vec<_>>()
                .join(", ");
            format!("{name}({rendered_args})")
        }
        VessLogicExpr::Unary { op, expr } => {
            let rendered = format!("{}{}", op.as_str(), render_expr(expr, 7));
            if 7 < parent_precedence {
                format!("({rendered})")
            } else {
                rendered
            }
        }
        VessLogicExpr::Binary { left, op, right } => {
            let precedence = op.precedence();
            let rendered = format!(
                "{} {} {}",
                render_expr(left, precedence),
                op.as_str(),
                render_expr(right, precedence + 1)
            );
            if precedence < parent_precedence {
                format!("({rendered})")
            } else {
                rendered
            }
        }
    }
}

fn validate_terminal_approve(section: &str, instructions: &[VessLogicInstruction]) -> Result<()> {
    if !matches!(instructions.last(), Some(VessLogicInstruction::Approve)) {
        return Err(anyhow!(
            "VessLogic [{section}] must end with an explicit approve"
        ));
    }
    if instructions[..instructions.len().saturating_sub(1)]
        .iter()
        .any(|instruction| matches!(instruction, VessLogicInstruction::Approve))
    {
        return Err(anyhow!(
            "VessLogic [{section}] may only use approve as the final line"
        ));
    }
    Ok(())
}

fn ensure_fresh_identifier(name: &str, existing: &BTreeSet<String>, kind: &str) -> Result<()> {
    validate_identifier(name)?;
    if existing.contains(name) {
        return Err(anyhow!("duplicate {kind} identifier {name}"));
    }
    Ok(())
}

fn validate_instruction_block(
    instructions: &[VessLogicInstruction],
    scope: &BTreeSet<String>,
) -> Result<()> {
    let mut scope = scope.clone();
    for instruction in instructions {
        match instruction {
            VessLogicInstruction::Require(expr) => validate_expr(expr, &scope)?,
            VessLogicInstruction::Bind { name, value } => {
                validate_identifier(name)?;
                validate_expr(value, &scope)?;
                // Bind variables are visible to subsequent instructions
                scope.insert(name.clone());
            }
            VessLogicInstruction::Approve => {}
        }
    }
    Ok(())
}

fn validate_expr(expr: &VessLogicExpr, allowed_identifiers: &BTreeSet<String>) -> Result<()> {
    match expr {
        VessLogicExpr::Literal(_) => Ok(()),
        VessLogicExpr::Variable(name) => {
            if !allowed_identifiers.contains(name) {
                return Err(anyhow!("unknown VessLogic identifier {name}"));
            }
            Ok(())
        }
        VessLogicExpr::Unary { expr, .. } => validate_expr(expr, allowed_identifiers),
        VessLogicExpr::Binary { left, right, .. } => {
            validate_expr(left, allowed_identifiers)?;
            validate_expr(right, allowed_identifiers)
        }
        VessLogicExpr::Call { name, args } => {
            validate_function_call(name, args)?;
            for arg in args {
                validate_expr(arg, allowed_identifiers)?;
            }
            Ok(())
        }
    }
}

fn validate_function_call(name: &str, args: &[VessLogicExpr]) -> Result<()> {
    match name {
        "min" | "max" => {
            if args.len() != 2 {
                return Err(anyhow!("VessLogic function {name} expects 2 argument(s)"));
            }
        }
        "abs" | "satisfies" | "after" | "before" => {
            if args.len() != 1 {
                return Err(anyhow!("VessLogic function {name} expects 1 argument(s)"));
            }
        }
        "clamp" | "between" => {
            if args.len() != 3 {
                return Err(anyhow!("VessLogic function {name} expects 3 argument(s)"));
            }
        }
        "all_of" | "any_of" => {
            if args.is_empty() {
                return Err(anyhow!("VessLogic function {name} expects at least 1 argument"));
            }
        }
        _ => return Err(anyhow!("unsupported VessLogic function {name}")),
    }
    Ok(())
}

fn parse_link_line(line: &str) -> Result<String> {
    let link = line.trim().to_string();
    validate_identifier(&link)?;
    Ok(link)
}

fn parse_binding_line(line: &str) -> Result<VessLogicBinding> {
    let (left, value) = line
        .split_once('=')
        .ok_or_else(|| anyhow!("bindings must use `<type> <name> = <expr>`"))?;
    let mut parts = left.split_whitespace();
    let ty = parts
        .next()
        .ok_or_else(|| anyhow!("missing binding type"))
        .and_then(VessLogicType::parse)?;
    let name = parts
        .next()
        .ok_or_else(|| anyhow!("missing binding name"))?
        .trim()
        .to_string();
    if parts.next().is_some() {
        return Err(anyhow!("bindings may only declare one identifier per line"));
    }
    validate_identifier(&name)?;
    let value = parse_expr(value.trim())?;
    Ok(VessLogicBinding { ty, name, value })
}

fn parse_instruction_line(line: &str) -> Result<VessLogicInstruction> {
    if line == "approve" {
        return Ok(VessLogicInstruction::Approve);
    }
    if let Some(expr) = line.strip_prefix("require ") {
        return Ok(VessLogicInstruction::Require(parse_expr(expr.trim())?));
    }
    if let Some(rest) = line
        .strip_prefix("bind ")
        .or_else(|| line.strip_prefix("emit "))
    {
        let (name, value) = rest
            .split_once('=')
            .ok_or_else(|| anyhow!("bind must use `bind <name> = <expr>`"))?;
        let name = name.trim().to_string();
        validate_identifier(&name)?;
        return Ok(VessLogicInstruction::Bind {
            name,
            value: parse_expr(value.trim())?,
        });
    }
    Err(anyhow!(
        "unsupported VessLogic instruction; use require, bind, or approve"
    ))
}

fn validate_identifier(name: &str) -> Result<()> {
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return Err(anyhow!("identifier must not be empty"));
    };
    if !first.is_ascii_lowercase() && first != '_' {
        return Err(anyhow!(
            "identifier {name} must start with a lowercase ASCII letter or _"
        ));
    }
    if !chars.all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '_') {
        return Err(anyhow!(
            "identifier {name} may only contain lowercase ASCII letters, digits, and _"
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Token {
    Number(u64),
    Bool(bool),
    Identifier(String),
    LParen,
    RParen,
    Comma,
    Operator(VessLogicBinaryOp),
    UnaryBang,
}

fn parse_expr(source: &str) -> Result<VessLogicExpr> {
    let tokens = tokenize(source)?;
    if tokens.is_empty() {
        return Err(anyhow!("expression must not be empty"));
    }
    let mut parser = ExprParser::new(tokens);
    let expr = parser.parse_expression()?;
    if parser.peek().is_some() {
        return Err(anyhow!("unexpected trailing tokens in expression"));
    }
    Ok(expr)
}

fn tokenize(source: &str) -> Result<Vec<Token>> {
    let bytes = source.as_bytes();
    let mut index = 0;
    let mut tokens = Vec::new();
    while index < bytes.len() {
        let ch = bytes[index] as char;
        match ch {
            ' ' | '\t' => index += 1,
            '(' => {
                tokens.push(Token::LParen);
                index += 1;
            }
            ')' => {
                tokens.push(Token::RParen);
                index += 1;
            }
            ',' => {
                tokens.push(Token::Comma);
                index += 1;
            }
            '+' => {
                tokens.push(Token::Operator(VessLogicBinaryOp::Add));
                index += 1;
            }
            '-' => {
                tokens.push(Token::Operator(VessLogicBinaryOp::Sub));
                index += 1;
            }
            '*' => {
                tokens.push(Token::Operator(VessLogicBinaryOp::Mul));
                index += 1;
            }
            '/' => {
                tokens.push(Token::Operator(VessLogicBinaryOp::Div));
                index += 1;
            }
            '%' => {
                tokens.push(Token::Operator(VessLogicBinaryOp::Mod));
                index += 1;
            }
            '!' => {
                if bytes.get(index + 1) == Some(&(b'=')) {
                    tokens.push(Token::Operator(VessLogicBinaryOp::NotEq));
                    index += 2;
                } else {
                    tokens.push(Token::UnaryBang);
                    index += 1;
                }
            }
            '=' => {
                if bytes.get(index + 1) == Some(&(b'=')) {
                    tokens.push(Token::Operator(VessLogicBinaryOp::Eq));
                    index += 2;
                } else {
                    return Err(anyhow!("unexpected `=` inside expression"));
                }
            }
            '<' => {
                if bytes.get(index + 1) == Some(&(b'=')) {
                    tokens.push(Token::Operator(VessLogicBinaryOp::Lte));
                    index += 2;
                } else {
                    tokens.push(Token::Operator(VessLogicBinaryOp::Lt));
                    index += 1;
                }
            }
            '>' => {
                if bytes.get(index + 1) == Some(&(b'=')) {
                    tokens.push(Token::Operator(VessLogicBinaryOp::Gte));
                    index += 2;
                } else {
                    tokens.push(Token::Operator(VessLogicBinaryOp::Gt));
                    index += 1;
                }
            }
            '&' => {
                if bytes.get(index + 1) == Some(&(b'&')) {
                    tokens.push(Token::Operator(VessLogicBinaryOp::And));
                    index += 2;
                } else {
                    return Err(anyhow!("single `&` is not allowed; use &&"));
                }
            }
            '|' => {
                if bytes.get(index + 1) == Some(&(b'|')) {
                    tokens.push(Token::Operator(VessLogicBinaryOp::Or));
                    index += 2;
                } else {
                    return Err(anyhow!("single `|` is not allowed; use ||"));
                }
            }
            '0'..='9' => {
                let start = index;
                while index < bytes.len() && (bytes[index] as char).is_ascii_digit() {
                    index += 1;
                }
                let value = source[start..index]
                    .parse::<u64>()
                    .map_err(|error| anyhow!("invalid integer literal: {error}"))?;
                tokens.push(Token::Number(value));
            }
            'a'..='z' | '_' => {
                let start = index;
                while index < bytes.len() {
                    let next = bytes[index] as char;
                    if next.is_ascii_lowercase() || next.is_ascii_digit() || next == '_' {
                        index += 1;
                    } else {
                        break;
                    }
                }
                let ident = &source[start..index];
                match ident {
                    "true" => tokens.push(Token::Bool(true)),
                    "false" => tokens.push(Token::Bool(false)),
                    _ => tokens.push(Token::Identifier(ident.to_string())),
                }
            }
            _ => return Err(anyhow!("unsupported character `{ch}` in expression")),
        }
    }
    Ok(tokens)
}

struct ExprParser {
    tokens: Vec<Token>,
    index: usize,
}

impl ExprParser {
    fn new(tokens: Vec<Token>) -> Self {
        Self { tokens, index: 0 }
    }

    fn parse_expression(&mut self) -> Result<VessLogicExpr> {
        self.parse_or()
    }

    fn parse_or(&mut self) -> Result<VessLogicExpr> {
        self.parse_binary_chain(Self::parse_and, &[VessLogicBinaryOp::Or])
    }

    fn parse_and(&mut self) -> Result<VessLogicExpr> {
        self.parse_binary_chain(Self::parse_equality, &[VessLogicBinaryOp::And])
    }

    fn parse_equality(&mut self) -> Result<VessLogicExpr> {
        self.parse_binary_chain(
            Self::parse_comparison,
            &[VessLogicBinaryOp::Eq, VessLogicBinaryOp::NotEq],
        )
    }

    fn parse_comparison(&mut self) -> Result<VessLogicExpr> {
        self.parse_binary_chain(
            Self::parse_term,
            &[
                VessLogicBinaryOp::Lt,
                VessLogicBinaryOp::Lte,
                VessLogicBinaryOp::Gt,
                VessLogicBinaryOp::Gte,
            ],
        )
    }

    fn parse_term(&mut self) -> Result<VessLogicExpr> {
        self.parse_binary_chain(
            Self::parse_factor,
            &[VessLogicBinaryOp::Add, VessLogicBinaryOp::Sub],
        )
    }

    fn parse_factor(&mut self) -> Result<VessLogicExpr> {
        self.parse_binary_chain(
            Self::parse_unary,
            &[
                VessLogicBinaryOp::Mul,
                VessLogicBinaryOp::Div,
                VessLogicBinaryOp::Mod,
            ],
        )
    }

    fn parse_unary(&mut self) -> Result<VessLogicExpr> {
        match self.peek() {
            Some(Token::UnaryBang) => {
                self.index += 1;
                Ok(VessLogicExpr::Unary {
                    op: VessLogicUnaryOp::Not,
                    expr: Box::new(self.parse_unary()?),
                })
            }
            Some(Token::Operator(VessLogicBinaryOp::Sub)) => {
                self.index += 1;
                Ok(VessLogicExpr::Unary {
                    op: VessLogicUnaryOp::Neg,
                    expr: Box::new(self.parse_unary()?),
                })
            }
            _ => self.parse_primary(),
        }
    }

    fn parse_primary(&mut self) -> Result<VessLogicExpr> {
        match self.next() {
            Some(Token::Number(value)) => Ok(VessLogicExpr::Literal(VessLogicLiteral::U64(value))),
            Some(Token::Bool(value)) => Ok(VessLogicExpr::Literal(VessLogicLiteral::Bool(value))),
            Some(Token::Identifier(name)) => {
                if matches!(self.peek(), Some(Token::LParen)) {
                    self.index += 1;
                    let mut args = Vec::new();
                    if !matches!(self.peek(), Some(Token::RParen)) {
                        loop {
                            args.push(self.parse_expression()?);
                            if matches!(self.peek(), Some(Token::Comma)) {
                                self.index += 1;
                                continue;
                            }
                            break;
                        }
                    }
                    self.expect(Token::RParen)?;
                    Ok(VessLogicExpr::Call { name, args })
                } else {
                    Ok(VessLogicExpr::Variable(name))
                }
            }
            Some(Token::LParen) => {
                let expr = self.parse_expression()?;
                self.expect(Token::RParen)?;
                Ok(expr)
            }
            Some(other) => Err(anyhow!("unexpected token {other:?} in expression")),
            None => Err(anyhow!("unexpected end of expression")),
        }
    }

    fn parse_binary_chain(
        &mut self,
        next_level: fn(&mut Self) -> Result<VessLogicExpr>,
        ops: &[VessLogicBinaryOp],
    ) -> Result<VessLogicExpr> {
        let mut expr = next_level(self)?;
        loop {
            let Some(Token::Operator(op)) = self.peek().cloned() else {
                break;
            };
            if !ops.contains(&op) {
                break;
            }
            self.index += 1;
            let right = next_level(self)?;
            expr = VessLogicExpr::Binary {
                left: Box::new(expr),
                op,
                right: Box::new(right),
            };
        }
        Ok(expr)
    }

    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.index)
    }

    fn next(&mut self) -> Option<Token> {
        let token = self.tokens.get(self.index).cloned();
        if token.is_some() {
            self.index += 1;
        }
        token
    }

    fn expect(&mut self, expected: Token) -> Result<()> {
        let token = self.next().ok_or_else(|| anyhow!("unexpected end of expression"))?;
        if token == expected {
            Ok(())
        } else {
            Err(anyhow!("expected {expected:?}, got {token:?}"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
        [constants]
        u64 min_deposit = 5
        u64 max_withdraw = 250
        u64 cap = 1000
        u64 withdraw_unlock_at = 86400
        bool paused = false

        [links]
        compliance_guard
        risk_guard

        [deposit]
        require !paused
        require amount >= min_deposit
        require program_balance + amount <= cap
        require all_of(compliance_guard, risk_guard)
        require claim_has_new_program || claim_chain_depth >= 1
        bind credited = amount
        bind locked_state = next_state
        approve

        [withdraw]
        require !paused
        require requested > 0
        require requested <= max_withdraw
        require requested <= program_balance
        require satisfies(compliance_guard)
        require claim_has_prev_program
        require after(withdraw_unlock_at)
        bind debited = requested
        bind prior_state = current_state
        bind next_locked_state = next_state
        approve
    "#;

    #[test]
    fn parses_and_compiles_vesslogic_program() {
        let program = VessLogicProgram::parse(SAMPLE).unwrap();
        assert_eq!(program.entrypoints(), vec!["deposit", "withdraw"]);
        let compiled = program.compile();
        let compiled_text = String::from_utf8(compiled).unwrap();
        assert!(compiled_text.starts_with(VESSLOGIC_VERSION_HEADER));
        assert!(compiled_text.contains("[links]"));
        assert!(compiled_text.contains("[deposit]"));
        assert!(compiled_text.contains("bind locked_state = next_state"));
    }

    #[test]
    fn canonicalizes_comments_and_spacing() {
        let left = VessLogicProgram::parse(SAMPLE).unwrap().compile();
        let right = compile_vesslogic_source(
            "[constants]\n\
             u64 min_deposit = 5 # comment\n\
               u64 max_withdraw = 250\n\
             u64 cap = 1000\n\
                         u64 withdraw_unlock_at = 86400\n\
             bool paused = false\n\
                         [links]\n\
                         compliance_guard\n\
                         risk_guard\n\
             [deposit]\n\
             require !paused\n\
             require amount >= min_deposit\n\
                             require program_balance + amount <= cap\n\
                         require all_of(compliance_guard, risk_guard)\n\
                             require claim_has_new_program || claim_chain_depth >= 1\n\
                         bind credited = amount\n\
                             bind locked_state = next_state\n\
             approve\n\
             [withdraw]\n\
             require !paused\n\
             require requested > 0\n\
                             require requested <= max_withdraw\n\
                             require requested <= program_balance\n\
                         require satisfies(compliance_guard)\n\
                             require claim_has_prev_program\n\
                         require after(withdraw_unlock_at)\n\
                         bind debited = requested\n\
                             bind prior_state = current_state\n\
                             bind next_locked_state = next_state\n\
             approve\n",
        )
        .unwrap();
        assert_eq!(left, right);
    }

        #[test]
        fn canonicalizes_legacy_emit_to_bind() {
                let program = VessLogicProgram::parse(
                        "[deposit]\nemit credited = amount\napprove\n[withdraw]\nemit debited = requested\napprove\n",
                )
                .unwrap();
                let canonical = program.canonical_source();
                assert!(canonical.contains("bind credited = amount"));
                assert!(!canonical.contains("emit credited = amount"));
        }

        #[test]
        fn accepts_links_and_claim_context_builtins() {
                let program = VessLogicProgram::parse(
                "[constants]\nu64 withdraw_unlock_at = 1\n[links]\nmain_guard\nfallback_guard\n[deposit]\nrequire any_of(main_guard, fallback_guard)\nrequire claim_has_new_program\nrequire claim_timestamp >= withdraw_unlock_at\nbind linked_state = next_state\napprove\n[withdraw]\nrequire satisfies(main_guard)\nrequire claim_mint_id == claim_mint_id\nrequire between(withdraw_unlock_at, claim_timestamp, claim_timestamp + 10)\napprove\n",
                )
                .unwrap();
                assert_eq!(program.links, vec!["main_guard".to_string(), "fallback_guard".to_string()]);
        }

        #[test]
        fn accepts_timelock_helpers() {
            let program = VessLogicProgram::parse(
                "[constants]\nu64 unlock_at = 100\nu64 window_end = 200\n[deposit]\nrequire before(window_end)\napprove\n[withdraw]\nrequire after(unlock_at)\nrequire between(unlock_at, claim_timestamp, window_end)\napprove\n",
            )
            .unwrap();
            let canonical = program.canonical_source();
            assert!(canonical.contains("require after(unlock_at)"));
            assert!(canonical.contains("require between(unlock_at, claim_timestamp, window_end)"));
        }

    #[test]
    fn rejects_missing_terminal_approve() {
        let error = VessLogicProgram::parse(
            "[deposit]\nrequire amount > 0\n[withdraw]\nrequire requested > 0\napprove\n",
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("[deposit] must end with an explicit approve"));
    }

    #[test]
    fn rejects_unknown_identifiers() {
        let error = VessLogicProgram::parse(
            "[deposit]\nrequire unknown > 0\napprove\n[withdraw]\nrequire requested <= program_balance\napprove\n",
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("unknown VessLogic identifier unknown"));
    }

    #[test]
    fn rejects_program_level_state_sections() {
        let error = VessLogicProgram::parse(
            "[state]\nu64 total_locked = 0\n[deposit]\nrequire amount > 0\napprove\n[withdraw]\nrequire requested > 0\napprove\n",
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("unsupported VessLogic section [state]"));
    }
}