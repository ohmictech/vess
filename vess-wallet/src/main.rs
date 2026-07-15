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
use vess_crypto::{OwnerHash, VessPayment, SpendCondition};
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
    let mut action_arg2: Option<String> = None;
    let mut out_file: Option<String> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--wallet" => { i += 1; if i < args.len() { wallet_path = args[i].clone(); } }
            "--password" => { i += 1; if i < args.len() { password = args[i].as_bytes().to_vec(); } }
            "--connect" => { i += 1; if i < args.len() { node_addr = args[i].parse().unwrap_or(node_addr); } }
            "--import" => { action = Some("import".into()); i += 1; if i < args.len() { action_arg = Some(args[i].clone()); } }
            "--import-key" => { action = Some("import-key".into()); i += 1; if i < args.len() { action_arg = Some(args[i].clone()); i += 1; if i < args.len() { action_arg2 = Some(args[i].clone()); } } }
            "--balance" => { action = Some("balance".into()); }
            "--consolidate" => { action = Some("consolidate".into()); }
            "--invoice" => { action = Some("invoice".into()); i += 1; if i < args.len() { action_arg = Some(args[i].clone()); } }
            "--pay" => { action = Some("pay".into()); i += 1; if i < args.len() { action_arg = Some(args[i].clone()); } }
            "--out" => { i += 1; if i < args.len() { out_file = Some(args[i].clone()); } }
            "--submit" => { action = Some("submit".into()); i += 1; if i < args.len() { action_arg = Some(args[i].clone()); } }
            "--receive" => { action = Some("receive".into()); i += 1; if i < args.len() { action_arg = Some(args[i].clone()); } }
            "--export" => { action = Some("export".into()); i += 1; if i < args.len() { action_arg = Some(args[i].clone()); } }
            "--sync" => { action = Some("sync".into()); }
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
        Some("import-key") => {
            let pub_path = action_arg.as_deref().unwrap_or("dev-pub.key");
            let sec_path = action_arg2.as_deref().unwrap_or("dev-sec.key");
            match w.import_keypair_files(pub_path, sec_path) {
                Some(oh) => println!("imported keypair: owner_hash={}", hex::encode(oh)),
                None => println!("failed to read keypair from {} / {}", pub_path, sec_path),
            }
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
            println!("{}", w.build_invoice(Some(amount), None, None, None));
        }
        Some("pay") => {
            let path = match &out_file {
                Some(p) => p,
                None => { eprintln!("--pay requires --out <file> (payments are OOB)"); return; },
            };
            let url = action_arg.as_deref().unwrap_or("");
            match parse_invoice(url) {
                Some((oh, amount, sc)) => {
                    match w.export_payment(&[(oh, amount, sc)]) {
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
        Some("receive") => {
            let path = action_arg.as_deref().unwrap_or("received.vess");
            match std::fs::read(path) {
                Ok(data) => {
                    match w.receive_blob(&data) {
                        Some(count) => println!("received {} outputs, balance now: {} VESS", count, w.balance()),
                        None => println!("failed to decode payment blob"),
                    }
                }
                Err(_) => println!("cannot read file: {}", path),
            }
        }
        Some("export") => {
            let url = action_arg.as_deref().unwrap_or("");
            let path = out_file.as_deref().unwrap_or("payment.vess");
            match parse_invoice(url) {
                Some((oh, amount, sc)) => {
                    match w.export_payment(&[(oh, amount, sc)]) {
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
        Some("sync") => {
            let (moved, remaining) = w.sync();
            println!("sync: {} confirmed, {} still unclaimed ({} total balance)", moved, remaining, w.balance());
        }
        _ => {
            println!("usage: vess-wallet-cli --import <db> | --balance | --consolidate | --invoice <n> | --pay <url> [--out <file>] | --export <url> [--out <file>] | --submit <file> | --receive <file> | --sync");
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
                println!("commands: connect, balance, invoice, pay, export, receive, submit, sync, status, consolidate, import, import-key, save, exit");
            }
            "connect" | "c" => {
                let addr = parts.get(1).map_or("127.0.0.1:9876", |s| *s);
                match addr.parse::<SocketAddr>() {
                    Ok(sa) => {
                        print!("connecting to {}... ", sa);
                        io::stdout().flush().unwrap();
                        match w.connect_full(sa) {
                            true => println!("connected ✓"),
                            false => println!("failed — is the node running?"),
                        }
                        let _ = std::fs::write(WALLET_FILE, &w.save());
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
                let memo = parts.get(2).filter(|s| !s.starts_with("--")).map_or("", |s| s);
                let hashlock = parts.iter().position(|&s| s == "--hashlock")
                    .and_then(|i| parts.get(i + 1))
                    .and_then(|s| {
                        let mut hl = [0u8; 32];
                        hex::decode_to_slice(s, &mut hl).ok()?;
                        Some(hl)
                    });
                let timelock = parts.iter().position(|&s| s == "--timelock")
                    .and_then(|i| parts.get(i + 1))
                    .and_then(|s| s.parse::<u64>().ok());
                let sc = if hashlock.is_some() || timelock.is_some() {
                    Some(SpendCondition {
                        hashlock: hashlock.unwrap_or([0u8; 32]),
                        timelock_after: timelock.unwrap_or(0),
                    })
                } else {
                    None
                };
                let url = w.build_invoice(Some(amount), Some(memo), hashlock.as_ref(), timelock);
                println!("{}", url);
            }
            "pay" | "p" => {
                let url = parts.get(1).unwrap_or(&"");
                if url.is_empty() {
                    println!("usage: pay <vess://...> [--out <file>] [--send]");
                    continue;
                }
                let out_file = parts.iter().position(|&s| s == "--out")
                    .and_then(|i| parts.get(i + 1).copied())
                    .unwrap_or("payment.vess");
                let do_send = parts.contains(&"--send");

                match parse_invoice(url) {
                    Some((oh, amount, sc)) => {
                        match w.build_payment(&[(oh, amount, sc)]) {
                            Some(payment) => {
                                let data = payment.encode();
                                let hex4: String = payment.payment_id[..4].iter().map(|b| format!("{:02x}", b)).collect();
                                println!("payment built: {} bytes, id={}", data.len(), hex4);

                                let _ = std::fs::write(out_file, &data);
                                println!("exported to {} (hand this to the receiver)", out_file);

                                if do_send {
                                    match w.send(&payment) {
                                        true => println!("submitted to network ✓"),
                                        false => println!("submit failed — connect to node first"),
                                    }
                                } else {
                                    println!("not submitted — receiver runs 'submit {}' to claim", out_file);
                                }
                                let _ = std::fs::write(WALLET_FILE, &w.save());
                            }
                            None => println!("insufficient funds"),
                        }
                    }
                    None => println!("invalid invoice URL"),
                }
            }
            "export" | "exp" | "e" => {
                let url = parts.get(1).unwrap_or(&"");
                if url.is_empty() {
                    println!("usage: export <vess://...> [--out <file>]");
                    continue;
                }
                let out_file = parts.iter().position(|&s| s == "--out")
                    .and_then(|i| parts.get(i + 1).copied())
                    .unwrap_or("payment.vess");
                let url_only = if parts.len() > 2 && parts[2] == "--out" { parts[1] } else { url };

                match parse_invoice(url_only) {
                    Some((oh, amount, sc)) => {
                        match w.export_payment(&[(oh, amount, sc)]) {
                            Some(blob) => {
                                if std::fs::write(out_file, &blob).is_ok() {
                                    println!("payment exported to {} ({} VESS → {:?}…, {} bytes)",
                                        out_file, amount, &oh[..4], blob.len());
                                    println!("give this file to the receiver — they run 'receive {}' or 'submit {}'", out_file, out_file);
                                } else {
                                    println!("failed to write {}", out_file);
                                }
                            }
                            None => println!("insufficient funds"),
                        }
                    }
                    None => println!("invalid invoice URL"),
                }
            }
            "sync" | "syn" => {
                match w.sync() {
                    (moved, remaining) => {
                        println!("sync: {} confirmed, {} still unclaimed ({} total balance)",
                            moved, remaining, w.balance());
                        if moved > 0 {
                            let _ = std::fs::write(WALLET_FILE, &w.save());
                        }
                    }
                }
            }            "status" | "stat" => {
                println!("connected:  {}", if w.connected() { "yes" } else { "no" });
                if let Some(addr) = w.node() {
                    println!("node:       {}", addr);
                    if w.connected() {
                        if let Some(n) = w.peer_count() {
                            println!("peer count: {}", n);
                        }
                    }
                }
                println!("balance:    {} VESS", w.balance());
                println!("claimed:    {} UTXOs", w.vbank_claimed.len());
                println!("unclaimed:  {} UTXOs", w.vbank_unclaimed.len());
                println!("keypairs:   {}", w.keypair_count());
                let (built, received) = w.history_counts();
                println!("history:    {} built, {} received", built, received);
            }            "receive" | "recv" | "r" => {
                let path = parts.get(1).unwrap_or(&"received.vess");
                match std::fs::read(path) {
                    Ok(data) => {
                        match w.receive_blob(&data) {
                            Some(count) => {
                                println!("received {} outputs ({} VESS total balance now)",
                                    count, w.balance());
                                let _ = std::fs::write(WALLET_FILE, &w.save());
                            }
                            None => println!("failed to decode payment blob — invalid file"),
                        }
                    }
                    Err(_) => println!("cannot read file: {}", path),
                }
            }
            "submit" | "sub" => {
                let path = parts.get(1).unwrap_or(&"received.vess");
                match std::fs::read(path) {
                    Ok(data) => {
                        let mut pos = 0;
                        match VessPayment::decode(&data, &mut pos) {
                            Some(payment) => {
                                if w.claim_payment(&payment) {
                                    println!("payment submitted to network: {} VESS, id={:?}…",
                                        payment.output_sum(), &payment.payment_id[..8]);
                                    println!("balance: {} VESS ({} claimed, {} unclaimed)",
                                        w.balance(), w.vbank_claimed.len(), w.vbank_unclaimed.len());
                                    let _ = std::fs::write(WALLET_FILE, &w.save());
                                } else {
                                    println!("submit failed — connect to node first or node rejected");
                                }
                            }
                            None => println!("failed to decode payment from {}", path),
                        }
                    }
                    Err(_) => println!("cannot read file: {}", path),
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
            "import-key" | "impk" => {
                let pub_path = parts.get(1).unwrap_or(&"dev-pub.key");
                let sec_path = parts.get(2).unwrap_or(&"dev-sec.key");
                match w.import_keypair_files(pub_path, sec_path) {
                    Some(oh) => {
                        println!("imported keypair: owner_hash={}", hex::encode(oh));
                        println!("run 'import <db>' or sync to find matching UTXOs");
                        let _ = std::fs::write(WALLET_FILE, &w.save());
                    }
                    None => println!("failed to read keypair from {} / {}", pub_path, sec_path),
                }
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

/// Parse a vess:// URL into (owner_hash, amount, spend_condition).
/// Format: vess://<64-hex-chars>?amount=N&hashlock=<hex>&timelock=<unix>
fn parse_invoice(url: &str) -> Option<(OwnerHash, u64, Option<SpendCondition>)> {
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
    let hashlock: Option<[u8; 32]> = query.split('&')
        .find(|p| p.starts_with("hashlock="))
        .and_then(|p| p.strip_prefix("hashlock="))
        .and_then(|s| {
            let mut hl = [0u8; 32];
            hex::decode_to_slice(s, &mut hl).ok()?;
            Some(hl)
        });
    let timelock: Option<u64> = query.split('&')
        .find(|p| p.starts_with("timelock="))
        .and_then(|p| p.strip_prefix("timelock="))
        .and_then(|s| s.parse().ok());
    let sc = if hashlock.is_some() || timelock.is_some() {
        Some(SpendCondition {
            hashlock: hashlock.unwrap_or([0u8; 32]),
            timelock_after: timelock.unwrap_or(0),
        })
    } else {
        None
    };
    Some((oh, amount, sc))
}
