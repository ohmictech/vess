//! Vess wallet CLI — light client for key management and transaction building.
//!
//! Interactive mode (no flags):
//!   cargo run -p vess-wallet
//!
//! Non-interactive flags:
//!   --import <db-path>       Import coinbase from node's treasure chest
//!   --balance                Print balance and exit
//!   --consolidate            Merge UTXOs down to 1 and exit
//!   --invoice <amount>       Print a vess:// invoice URL
//!   --pay <vess://...>       Build payment for an invoice (requires --out)
//!   --out <file>             Export signed payment blob to file
//!   --submit <file>          Claim a payment blob received OOB
//!   --connect <addr>         Connect to node (default 127.0.0.1:9876)
//!   --wallet <path>          Use a specific wallet file (default: wallet.vess)
//!   --password <pw>          Wallet password (default: empty)

use std::io::{self, Write, BufRead};
use std::net::SocketAddr;
use vess_crypto::{OwnerHash, VessPayment};
use vess_wallet::Wallet;

const WALLET_FILE: &str = "wallet.vess";

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() > 1 {
        run_flags(&args);
        return;
    }
    run_interactive();
}

fn load_or_create(wallet_path: &str, password: &[u8]) -> Wallet {
    if let Ok(data) = std::fs::read(wallet_path) {
        if let Some(w) = Wallet::load(&data, password) {
            return w;
        }
    }
    Wallet::new(password)
}

fn run_flags(args: &[String]) {
    let mut wallet_path = WALLET_FILE.to_string();
    let mut password: Vec<u8> = Vec::new();
    let mut node_addr: SocketAddr = "127.0.0.1:9876".parse().unwrap();
    let mut action: Option<String> = None;
    let mut action_arg: Option<String> = None;
    let mut out_file: Option<String> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--wallet" => { i += 1; if i < args.len() { wallet_path = args[i].clone(); } }
            "--password" => { i += 1; if i < args.len() { password = args[i].as_bytes().to_vec(); } }
            "--connect" => { i += 1; if i < args.len() { node_addr = args[i].parse().unwrap_or(node_addr); } }
            "--import" => { action = Some("import".into()); i += 1; if i < args.len() { action_arg = Some(args[i].clone()); } }
            "--balance" => { action = Some("balance".into()); }
            "--consolidate" => { action = Some("consolidate".into()); }
            "--invoice" => { action = Some("invoice".into()); i += 1; if i < args.len() { action_arg = Some(args[i].clone()); } }
            "--pay" => { action = Some("pay".into()); i += 1; if i < args.len() { action_arg = Some(args[i].clone()); } }
            "--out" => { i += 1; if i < args.len() { out_file = Some(args[i].clone()); } }
            "--submit" => { action = Some("submit".into()); i += 1; if i < args.len() { action_arg = Some(args[i].clone()); } }
            _ => { eprintln!("unknown flag: {}", args[i]); return; }
        }
        i += 1;
    }

    let mut w = load_or_create(&wallet_path, &password);
    if !w.connect_full(node_addr) {
        eprintln!("warning: handshake with {} failed, RPC may not work", node_addr);
    }

    match action.as_deref() {
        Some("import") => {
            let path = action_arg.as_deref().unwrap_or("../vess-db");
            let count = w.import_treasure(path);
            println!("imported {} coinbase outputs from {}", count, path);
            println!("balance: {} VESS ({} claimed, {} unclaimed)",
                w.balance(), w.vbank_claimed.len(), w.vbank_unclaimed.len());
        }
        Some("balance") => {
            println!("{}", w.balance());
        }
        Some("consolidate") => {
            let before = w.vbank_claimed.len();
            let n = w.consolidate();
            println!("consolidated: {} payments, {} → {} UTXOs, balance={}",
                n, before, w.vbank_claimed.len(), w.balance());
        }
        Some("invoice") => {
            let amount: u64 = action_arg.as_deref().and_then(|s| s.parse().ok()).unwrap_or(1);
            println!("{}", w.build_invoice(Some(amount), None));
        }
        Some("pay") => {
            let path = match &out_file {
                Some(p) => p,
                None => { eprintln!("--pay requires --out <file> (payments are OOB)"); return; },
            };
            let url = action_arg.as_deref().unwrap_or("");
            match parse_invoice(url) {
                Some((oh, amount)) => {
                    match w.export_payment(&[(oh, amount)]) {
                        Some(blob) => {
                            if std::fs::write(path, &blob).is_ok() {
                                println!("payment exported to {} ({} VESS → {:?}…, {} bytes)",
                                    path, amount, &oh[..4], blob.len());
                            } else {
                                println!("failed to write {}", path);
                            }
                        }
                        None => println!("insufficient funds"),
                    }
                }
                None => println!("invalid invoice URL"),
            }
        }
        Some("submit") => {
            let path = action_arg.as_deref().unwrap_or("");
            match std::fs::read(path) {
                Ok(data) => {
                    let mut pos = 0;
                    match VessPayment::decode(&data, &mut pos) {
                        Some(payment) => {
                            if w.claim_payment(&payment) {
                                println!("payment claimed: {} VESS, id={:?}…",
                                    payment.output_sum(), &payment.payment_id[..8]);
                            } else {
                                println!("submit failed — node rejected the payment");
                            }
                        }
                        None => println!("failed to decode payment from {}", path),
                    }
                }
                Err(_) => println!("cannot read file: {}", path),
            }
        }
        _ => {
            println!("usage: vess-wallet-cli --import <db> | --balance | --consolidate | --invoice <n> | --pay <url> [--out <file>] | --submit <file>");
        }
    }

    let _ = std::fs::write(&wallet_path, &w.save());
}

fn run_interactive() {
    let mut wallet: Option<Wallet> = None;

    if std::path::Path::new(WALLET_FILE).exists() {
        print!("wallet password: ");
        io::stdout().flush().unwrap();
        let pw = read_line();
        if let Ok(data) = std::fs::read(WALLET_FILE) {
            wallet = Wallet::load(&data, pw.as_bytes());
            if wallet.is_some() {
                println!("wallet loaded ({} VESS balance)", wallet.as_ref().unwrap().balance());
            } else {
                println!("bad password — starting with empty wallet");
            }
        }
    }

    if wallet.is_none() {
        wallet = Some(Wallet::new(b"default"));
        println!("empty wallet created — use 'connect <addr>' and 'import <db>' to get started");
    }

    let w = wallet.as_mut().unwrap();

    loop {
        print!("> ");
        io::stdout().flush().unwrap();
        let line = read_line();
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.is_empty() { continue; }

        match parts[0] {
            "help" | "h" => {
                println!("commands: connect, balance, invoice, pay, consolidate, import, peers, save, exit");
            }
            "connect" | "c" => {
                let addr = parts.get(1).map_or("127.0.0.1:9876", |s| *s);
                match addr.parse::<SocketAddr>() {
                    Ok(sa) => {
                        if let Err(e) = w.bind() {
                            println!("bind failed: {}", e);
                            continue;
                        }
                        let init = w.connect(sa);
                        // Send handshake init via UDP — the node responds, we complete
                        // For now, just store the addr; actual UDP exchange needs the socket
                        println!("connecting to {}... (handshake bytes: {} bytes)", sa, init.len());
                    }
                    Err(e) => println!("bad address: {}", e),
                }
            }
            "balance" | "b" | "bal" => {
                println!("balance: {} VESS ({} claimed, {} unclaimed)",
                    w.balance(), w.vbank_claimed.len(), w.vbank_unclaimed.len());
            }
            "invoice" | "inv" => {
                let amount: u64 = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(1);
                let memo = parts.get(2).map_or("", |s| *s);
                let url = w.build_invoice(Some(amount), Some(memo));
                println!("{}", url);
            }
            "pay" | "p" => {
                let url = parts.get(1).unwrap_or(&"");
                if url.is_empty() {
                    println!("usage: pay <vess://...>");
                    continue;
                }
                // Parse vess:// URL: vess://<owner_hash_hex>?amount=N&memo=M
                match parse_invoice(url) {
                    Some((oh, amount)) => {
                        match w.build_payment(&[(oh, amount)]) {
                            Some(payment) => {
                                let data = payment.encode();
                                // Submit via RPC would need the UDP socket; for now just display
                                println!("payment built: {} bytes, id={:?}",
                                    data.len(), &payment.payment_id[..8]);
                                match w.send(&payment) {
                                    true => println!("sent!"),
                                    false => println!("send failed — connect to node first"),
                                }
                            }
                            None => println!("insufficient funds"),
                        }
                    }
                    None => println!("invalid invoice URL"),
                }
            }
            "consolidate" | "cons" => {
                let n = w.consolidate();
                if n > 0 {
                    println!("consolidated with {} payment{} ({} UTXOs remain)",
                        n, if n > 1 { "s" } else { "" }, w.vbank_claimed.len());
                } else {
                    println!("nothing to consolidate (need ≥2 UTXOs)");
                }
            }
            "import" | "imp" => {
                let path = parts.get(1).unwrap_or(&"../vess-db");
                let count = w.import_treasure(path);
                println!("imported {} coinbase outputs from {}", count, path);
            }
            "peers" => {
                // Would need RPC GetPeers call through the UDP socket
                println!("peers: use 'connect' to connect to a node");
            }
            "save" | "s" => {
                match std::fs::write(WALLET_FILE, &w.save()) {
                    Ok(_) => println!("saved to {}", WALLET_FILE),
                    Err(e) => println!("save failed: {}", e),
                }
            }
            "exit" | "quit" | "q" => {
                let _ = std::fs::write(WALLET_FILE, &w.save());
                println!("wallet saved. goodbye.");
                break;
            }
            _ => println!("unknown command. try: connect, balance, invoice, pay, import, save"),
        }
    }
}

fn read_line() -> String {
    let stdin = io::stdin();
    let mut line = String::new();
    stdin.lock().read_line(&mut line).unwrap();
    line.trim().to_string()
}

/// Parse a vess:// URL into (owner_hash, amount).
/// Format: vess://<64-hex-chars>?amount=N&memo=...
fn parse_invoice(url: &str) -> Option<(OwnerHash, u64)> {
    let body = url.strip_prefix("vess://")?;
    let (hex, query) = body.split_once('?').unwrap_or((body, ""));
    if hex.len() != 64 { return None; }
    let mut oh = [0u8; 32];
    hex::decode_to_slice(hex, &mut oh).ok()?;
    let amount: u64 = query.split('&')
        .find(|p| p.starts_with("amount="))
        .and_then(|p| p.strip_prefix("amount="))
        .and_then(|s| s.parse().ok())
        .unwrap_or(1);
    Some((oh, amount))
}
