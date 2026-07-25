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
use vess_crypto::{OwnerHash, SpendCondition, VessPayment};
use vess_wallet::Wallet;

const WALLET_FILE: &str = "wallet.vess";

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() == 3 && args[1] == "--wallet" {
        run_interactive(&args[2]);
        return;
    }
    if args.len() == 2 && args[1] == "--list-wallets" {
        list_wallets();
        return;
    }
    if args.len() > 1 {
        run_flags(&args);
        return;
    }
    // No flags: discover wallets or create new.
    let existing = discover_wallets();
    if existing.is_empty() {
        run_interactive_new();
    } else if existing.len() == 1 {
        run_interactive(&existing[0]);
    } else {
        println!("found {} wallet files:", existing.len());
        for (i, path) in existing.iter().enumerate() {
            println!("  [{}] {}", i + 1, path);
        }
        print!("select wallet number (or enter for new): ");
        io::stdout().flush().unwrap();
        let line = read_line();
        if let Ok(n) = line.trim().parse::<usize>() {
            if n >= 1 && n <= existing.len() {
                run_interactive(&existing[n - 1]);
                return;
            }
        }
        run_interactive_new();
    }
}

fn list_wallets() {
    let wallets = discover_wallets();
    if wallets.is_empty() { println!("no wallet files found"); }
    for path in wallets { println!("{}", path); }
}

fn discover_wallets() -> Vec<String> {
    let mut wallets: Vec<String> = std::fs::read_dir(".").ok().into_iter().flatten()
        .filter_map(|entry| entry.ok())
        .filter_map(|entry| {
            let path = entry.path();
            (path.extension().and_then(|ext| ext.to_str()) == Some("vess"))
                .then(|| path.display().to_string())
        })
        .collect();
    wallets.sort();
    wallets
}

fn load_or_create(wallet_path: &str, password: &[u8]) -> Option<Wallet> {
    if std::path::Path::new(wallet_path).exists() {
        let Ok(data) = std::fs::read(wallet_path) else { return None; };
        Wallet::load(&data, password)
    } else {
        Some(Wallet::new(password))
    }
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
            "--password" => { i += 1; if i < args.len() { eprintln!("warning: --password leaks via shell history and process lists; use interactive mode instead"); password = args[i].as_bytes().to_vec(); } }
            "--connect" => { i += 1; if i < args.len() { node_addr = args[i].parse().unwrap_or(node_addr); } }
            "--import" => { action = Some("import".into()); i += 1; if i < args.len() { action_arg = Some(args[i].clone()); } }
            "--import-key" => { action = Some("import-key".into()); i += 1; if i < args.len() { action_arg = Some(args[i].clone()); i += 1; if i < args.len() { action_arg2 = Some(args[i].clone()); } } }
            "--balance" => { action = Some("balance".into()); }
            "--consolidate" => { action = Some("consolidate".into()); }
            "--invoice" => { action = Some("invoice".into()); i += 1; if i < args.len() { action_arg = Some(args[i].clone()); } }
            "--pay" => { action = Some("pay".into()); i += 1; if i < args.len() { action_arg = Some(args[i].clone()); } }
            "--out" => { i += 1; if i < args.len() { out_file = Some(args[i].clone()); } }
            "--receive" => { action = Some("receive".into()); i += 1; if i < args.len() { action_arg = Some(args[i].clone()); } }
            "--sync" => { action = Some("sync".into()); }
            _ => { eprintln!("unknown flag: {}", args[i]); return; }
        }
        i += 1;
    }

    let mut w = match load_or_create(&wallet_path, &password) {
        Some(w) => w,
        None => { eprintln!("error: wrong password or corrupt wallet file"); return; }
    };
    if !w.connect_full(node_addr) {
        eprintln!("warning: handshake with {} failed, RPC may not work", node_addr);
    }

    match action.as_deref() {
        Some("import") => {
            let path = action_arg.as_deref().unwrap_or("../vess-db");
            let count = w.import_treasure(path);
            println!("imported {} coinbase outputs from {}", count, path);
            println!("balance: {} VESS ({} claimed, {} unclaimed{})",
                w.balance(), w.vbank_claimed.len(), w.vbank_unclaimed.len(),
                if w.pending_balance() > 0 { format!(", {} pending", w.pending_balance()) } else { String::new() });
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
            let pending = w.pending_balance();
            if pending > 0 {
                println!("{} ({} pending)", w.balance(), pending);
            } else {
                println!("{}", w.balance());
            }
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
        Some("receive") => {
            let path = action_arg.as_deref().unwrap_or("received.vess");
            match std::fs::read(path) {
                Ok(data) => {
                    let mut pos = 0;
                    match VessPayment::decode(&data, &mut pos) {
                        Some(payment) => {
                            if w.claim_payment(&payment) {
                                println!("payment claimed: {} VESS, id={:?}…",
                                    payment.output_sum(), &payment.payment_id[..8]);
                            } else {
                                println!("claim failed — connect to node first or node rejected");
                            }
                        }
                        None => println!("failed to decode payment from {}", path),
                    }
                }
                Err(_) => println!("cannot read file: {}", path),
            }
        }
        Some("sync") => {
            let (moved, remaining) = w.sync();
            println!("sync: {} confirmed, {} still unclaimed ({} total balance)", moved, remaining, w.balance());
        }
        _ => {
            println!("usage: vess-wallet --import <db> | --import-key <pub> <sec> | --balance | --consolidate | --invoice <n> | --pay <url> --out <file> | --receive <file> | --sync");
        }
    }

    if let Err(error) = w.save_to_path(&wallet_path) {
        eprintln!("failed to save wallet: {}", error);
    }
}

fn run_interactive(wallet_path: &str) {
    let wallet = if std::path::Path::new(wallet_path).exists() {
        let pw = rpassword::prompt_password(format!("password for {}: ", wallet_path)).unwrap_or_default();
        match std::fs::read(wallet_path) {
            Ok(data) => match Wallet::load(&data, pw.as_bytes()) {
                Some(w) => { println!("loaded ({} VESS)", w.balance()); Some(w) }
                None => { println!("bad password"); return; }
            },
            Err(_) => { println!("failed to read {}", wallet_path); return; }
        }
    } else {
        // File doesn't exist — create new.
        Some(create_new_wallet(wallet_path))
    };

    let Some(mut w) = wallet else { return };
    interactive_loop(&mut w, wallet_path);
}

/// No wallets exist at all — prompt for a filename and create.
fn run_interactive_new() {
    println!("no wallet files found");
    print!("new wallet filename [wallet.vess]: ");
    io::stdout().flush().unwrap();
    let raw = read_line();
    let mut name = if raw.trim().is_empty() { "wallet.vess".to_string() } else { raw.trim().to_string() };
    if !name.ends_with(".vess") { name.push_str(".vess"); }
    let mut w = create_new_wallet(&name);
    interactive_loop(&mut w, &name);
}

fn create_new_wallet(path: &str) -> Wallet {
    let pw = rpassword::prompt_password("set password (or enter for none): ").unwrap_or_default();
    let w = Wallet::new(pw.as_bytes());
    if pw.is_empty() {
        println!("created {} (no password)", path);
    } else {
        println!("created {} (password protected)", path);
    }
    println!("  use 'connect <addr>' and 'import <db>' to get started");
    w
}

fn interactive_loop(w: &mut Wallet, wallet_path: &str) {
    loop {
        print!("> ");
        io::stdout().flush().unwrap();
        let line = read_line();
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.is_empty() { continue; }

        match parts[0] {
            "help" | "h" => {
                println!("commands: connect, balance, invoice, pay, receive, sync, status, consolidate, import, import-key, save, exit");
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
                        let _ = w.save_to_path(wallet_path);
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
                let expires = parts.iter().position(|&s| s == "--expires")
                    .and_then(|i| parts.get(i + 1))
                    .and_then(|s| s.parse::<u64>().ok());
                let url = w.build_invoice(Some(amount), Some(memo), hashlock.as_ref(), expires);
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
                                let _ = w.save_to_path(wallet_path);
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
                            let _ = w.save_to_path(wallet_path);
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
                let pending = w.pending_balance();
                println!("claimed:    {} UTXOs{}", w.vbank_claimed.len(),
                    if pending > 0 { format!(" ({} VESS pending)", pending) } else { String::new() });
                println!("unclaimed:  {} UTXOs", w.vbank_unclaimed.len());
                println!("keypairs:   {}", w.keypair_count());
                let (built, received) = w.history_counts();
                println!("history:    {} built, {} received", built, received);
            }            "receive" | "recv" | "r" => {
                let path = parts.get(1).unwrap_or(&"received.vess");
                match std::fs::read(path) {
                    Ok(data) => {
                        let mut pos = 0;
                        match VessPayment::decode(&data, &mut pos) {
                            Some(payment) => {
                                if w.claim_payment(&payment) {
                                    println!("payment claimed: {} VESS, id={:?}…",
                                        payment.output_sum(), &payment.payment_id[..8]);
                                    println!("balance: {} VESS ({} claimed, {} unclaimed)",
                                        w.balance(), w.vbank_claimed.len(), w.vbank_unclaimed.len());
                                    let _ = w.save_to_path(wallet_path);
                                } else {
                                    println!("claim failed — connect to node first or node rejected");
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
                        let _ = w.save_to_path(wallet_path);
                    }
                    None => println!("failed to read keypair from {} / {}", pub_path, sec_path),
                }
            }
            "peers" => {
                // Would need RPC GetPeers call through the UDP socket
                println!("peers: use 'connect' to connect to a node");
            }
            "save" | "s" => {
                match w.save_to_path(wallet_path) {
                    Ok(_) => println!("saved to {}", wallet_path),
                    Err(e) => println!("save failed: {}", e),
                }
            }
            "exit" | "quit" | "q" => {
                let _ = w.save_to_path(wallet_path);
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
/// Format: vess://<64-hex-chars>?amount=N&hashlock=<hex>&expires=<unix>
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
    let expires: Option<u64> = query.split('&')
        .find(|p| p.starts_with("expires="))
        .and_then(|p| p.strip_prefix("expires="))
        .and_then(|s| s.parse().ok());
    let sc = if hashlock.is_some() || expires.is_some() {
        Some(SpendCondition {
            hashlock: hashlock.unwrap_or([0u8; 32]),
            expires_at: expires.unwrap_or(0),
        })
    } else {
        None
    };
    Some((oh, amount, sc))
}
