//! `vess` — node, wallet, and miner, all driving the same core.
//!
//! Commands operate either on a local data directory (opening the database for the duration of the
//! command) or against a running node over the binary RPC.

mod config;

use std::collections::{HashMap, HashSet};
use std::io::{IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use vess_core::constants::{
    MAX_BLOCK_BYTES, ML_DSA_PK_BYTES, ML_DSA_SIG_BYTES, NetworkProfile, P2P_DEFAULT_PORT,
    PREIMAGE_BYTES, RPC_DEFAULT_PORT, TX_PAYLOAD_BYTES,
};
use vess_core::hash::chain_id;
use vess_core::{AccountId, BlockHeader, Hash, JointTransfer, PublicKey, Transaction};
use vess_net::rpc::{ReplyBody, Request, StatusInfo};
use vess_node::{Node, bind_rpc, serve};
use vess_wallet::{Keyring, NodeClient, RecoveryPhrase, Wallet};
use zeroize::Zeroizing;

const USAGE: &str = concat!(
    "vess ",
    env!("CARGO_PKG_VERSION"),
    " — Vess reference node

  vess [--config FILE]                 # run the configured node
  vess node init    [--datadir DIR] [--network devnet|testnet|mainnet]
  vess node run     [--datadir DIR] [--network ...] [--rpc PORT] [--port P2P] [--peer A,B] [--mine --payout HEX]
                    [--mine-threads N]   # 1-256 CPU workers
                    [--prune-blocks N] [--prune-headers N] [--prune-undo N] [--trust-snapshot]   # 0 = keep everything
                    [--finality-depth N]   # blocks below the tip that no branch may replace; 0 = off
                    [--seed A,B]   # extra bootstrap peers; VESS_SEEDS also works
                    [--no-mine] [--no-trust-snapshot]   # snapshot trust defaults on
  vess node params  [--network devnet|testnet|mainnet]
  vess node status  --datadir DIR | --rpc HOST:PORT
  vess node history --datadir DIR | --rpc HOST:PORT
  vess node block   --rpc HOST:PORT (--height N | --id HEX)
  vess node tx      --rpc HOST:PORT --id HEX               # position and content
  vess node watch   --rpc HOST:PORT [--count N] [--timeout MS]   # N replies, 0 = forever
  vess node account --rpc HOST:PORT --account HEX      # balance, nonce, state hash
  vess node proof   --rpc HOST:PORT --account HEX      # Merkle proof against the state root
  vess node witness --rpc HOST:PORT --id HEX           # stateless witness: parent-state proofs
  vess node verify-stateless --rpc HOST:PORT --id HEX  # validate a block with headers + witness only

  vess wallet new         [--datadir DIR] --name NAME [--legacy] [--password-file FILE | --password-env VAR]
                          [--unsafe-phrase-stdout]
  vess wallet restore     [--datadir DIR] --name NAME [--password-file FILE | --password-env VAR] [--mnemonic-stdin]
  vess wallet addresses   [--datadir DIR] --name NAME [--count N] [--password-*]   # HD accounts
  vess wallet address     [--datadir DIR] --name NAME [--index N] [--password-file FILE | --password-env VAR]
  vess wallet address     --public-key HEX            # derive an address from a public key
  vess wallet sign        [--datadir DIR] --name NAME --message TEXT [--index N] [--password-*]
  vess wallet sign verify --message TEXT (--proof FILE | --public-key HEX --signature HEX) [--account HEX]
                          # --proof - reads wallet sign output from stdin
  vess wallet balance     [--datadir DIR] --name NAME [--index N] [--rpc ADDR] [--password-*]
  vess wallet send        [--datadir DIR] --name NAME (--to HEX | --rules FILE) --amount N [--fee N] [--index N] [--rpc ADDR] [--password-*]
                          [--payload HEX32]   # optional 32-byte payload, signed with the transfer
  vess wallet spend       [--datadir DIR] --name NAME --rules FILE [--preimage HEX32] [--fee N] [--rpc ADDR] [--password-*]
                          # claim an escrow with the preimage, or refund it once refund_height passes
  vess wallet set-state   [--datadir DIR] --name NAME --state-hash HEX [--fee N] [--rpc ADDR] [--password-*]
  vess wallet watch       [--datadir DIR] --name NAME --rpc ADDR [--count N] [--timeout MS] [--password-*]

  vess wallet futures-fund   [--datadir DIR] --name NAME --rules FILE --amount N [--fee N] [--tx FILE]
                             [--counterparty HEX] [--counterparty-amount N] [--rpc ADDR] [--password-*]
                          # build the dual-signed deposit into a futures pot; --tx names the file
  vess wallet futures-sign   [--datadir DIR] --name NAME [--tx FILE] [--password-*]
                          # add this wallet's signature to a prebuilt funding transaction
  vess wallet futures-submit [--datadir DIR] [--tx FILE] [--rpc ADDR] [--password-*]
                          # submit a fully signed funding transaction
  vess wallet futures-settle [--datadir DIR] --name NAME --rules FILE [--fee N] [--rpc ADDR] [--password-*]
                          # split a matured pot by the measured supply delta; unsigned, so anyone may run it

  --password-file FILE reads the first line of FILE; --password-env VAR reads an environment
  variable. HD wallet creation and recovery require a password. Only `wallet new --legacy` can
  write an unencrypted keyfile. New HD wallets display a 24-word recovery phrase exactly once.
  Recovery reads the phrase without terminal echo; --mnemonic-stdin accepts piped input instead.
  --unsafe-phrase-stdout allows creation with redirected output, which may expose the phrase.

  --rules FILE is an escrow's spend condition, one key=value per line: hash_lock (32-byte hex of
  BLAKE3(preimage)), refund_height, recipient, owner, max_fee. The escrow's account id is derived
  from exactly these bytes, so funding it is `wallet send --rules FILE` and the file is required to
  ever spend it. Before refund_height a spend needs --preimage and pays recipient; afterwards it
  needs no preimage and pays owner. Either way the balance moves whole, and the spender is fixed.

  A futures rules file is also key=value: start_supply, target_delta, earliest_settle_height,
  recipient, owner, max_fee. The pot's account id is derived from exactly those bytes. Both parties
  fund it in one transaction they both sign, so the pot is never half funded; from
  earliest_settle_height anyone may settle it, and consensus splits the pot linearly in the measured
  supply delta: recipient gets pot * min(delta, 2*target_delta) / (2*target_delta), owner the rest.
  At exactly target_delta the split is even.

  vess miner [--datadir DIR] --payout HEX [--blocks N] [--rpc ADDR]

  vess export --datadir DIR --out DIR [--from H] [--to H]   # bodies as verifiable chunk files
  vess archive verify --dir DIR                             # re-hash every chunk, no node needed
  vess archive encode --dir DIR [--data 10] [--parity 4]    # Reed-Solomon shards under DIR/shards
  vess archive decode --dir DIR/shards --out DIR            # rebuild from any `data` of the shards

All output is plain `key=value` text. Nothing is JSON.
Commands load vess.toml beside the executable (or --config FILE), creating it if absent,
except for offline signature verification.
Config data paths are relative to the config; --datadir paths are relative to the working directory.
Explicit options override the file for that invocation.
"
);

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("error: {message}");
            ExitCode::FAILURE
        }
    }
}

struct Args {
    flags: HashMap<String, String>,
    valueless: HashSet<String>,
}

impl Args {
    fn parse(raw: &[String]) -> Args {
        let mut flags = HashMap::new();
        let mut valueless = HashSet::new();
        let mut index = 0;
        while index < raw.len() {
            let token = &raw[index];
            if let Some(name) = token.strip_prefix("--") {
                if let Some((key, value)) = name.split_once('=') {
                    flags.insert(key.to_string(), value.to_string());
                    valueless.remove(key);
                } else if index + 1 < raw.len() && !raw[index + 1].starts_with("--") {
                    flags.insert(name.to_string(), raw[index + 1].clone());
                    valueless.remove(name);
                    index += 1;
                } else {
                    flags.insert(name.to_string(), String::from("true"));
                    valueless.insert(name.to_string());
                }
            }
            index += 1;
        }
        Args { flags, valueless }
    }

    fn get(&self, key: &str) -> Option<&str> {
        self.flags.get(key).map(|s| s.as_str())
    }

    fn set_default(&mut self, key: &str, value: &str) {
        self.flags
            .entry(key.to_string())
            .or_insert_with(|| value.to_string());
    }

    fn require(&self, key: &str) -> Result<&str, String> {
        self.get(key).ok_or_else(|| format!("missing --{key}"))
    }

    fn require_value(&self, key: &str) -> Result<&str, String> {
        if self.valueless.contains(key) {
            return Err(format!("--{key} requires a value"));
        }
        self.require(key)
    }

    fn number(&self, key: &str, default: u64) -> Result<u64, String> {
        match self.get(key) {
            None => Ok(default),
            Some(value) => value
                .parse::<u64>()
                .map_err(|_| format!("--{key} must be a decimal integer")),
        }
    }
}

fn network(args: &Args) -> Result<NetworkProfile, String> {
    match args.get("network").unwrap_or("devnet") {
        "devnet" => Ok(NetworkProfile::DEVNET),
        "testnet" => Ok(NetworkProfile::TESTNET),
        "mainnet" => Ok(NetworkProfile::MAINNET),
        other => Err(format!("unknown network {other}")),
    }
}

fn datadir(args: &Args) -> Result<PathBuf, String> {
    Ok(PathBuf::from(args.require("datadir")?))
}

fn wallet_path(dir: &Path, name: &str) -> PathBuf {
    dir.join("wallets").join(format!("{name}.key"))
}

fn parse_hash(value: &str) -> Result<Hash, String> {
    let value = value.strip_prefix("0x").unwrap_or(value);
    if value.len() != 64 {
        return Err("expected 32 bytes of hex".into());
    }
    if !value.is_ascii() {
        return Err("invalid hex".into());
    }
    let mut out = [0u8; 32];
    for (index, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| "invalid hex".to_string())?;
    }
    Ok(out)
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// Decode any-length hex, for inputs that are not a 32-byte hash (public keys, for example).
fn decode_hex(value: &str) -> Result<Vec<u8>, String> {
    let value = value.strip_prefix("0x").unwrap_or(value);
    if !value.len().is_multiple_of(2) {
        return Err("hex string must have an even number of digits".into());
    }
    if !value.is_ascii() {
        return Err("invalid hex".into());
    }
    let mut out = Vec::with_capacity(value.len() / 2);
    for index in 0..value.len() / 2 {
        out.push(
            u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
                .map_err(|_| "invalid hex".to_string())?,
        );
    }
    Ok(out)
}

/// Where a command applies: an in-process node or a remote one.
enum Target {
    Local(Box<Node>),
    Remote(String),
}

impl Target {
    fn open(args: &Args, network: NetworkProfile) -> Result<Target, String> {
        match args.get("rpc") {
            Some(addr) => Ok(Target::Remote(addr.to_string())),
            None => {
                let dir = datadir(args)?;
                let trust_snapshots = args.get("trust-snapshot").is_some();
                let node = Node::open_with_snapshot_trust(&dir, network, trust_snapshots).map_err(|e| {
                    let text = e.to_string();
                    if text.contains("already open") {
                        format!("{text} — a node is running on this datadir; pass --rpc HOST:PORT instead")
                    } else {
                        text
                    }
                })?;
                Ok(Target::Local(Box::new(node)))
            }
        }
    }

    fn request_raw(&mut self, request: Request) -> Result<vess_net::rpc::Reply, String> {
        match self {
            Target::Local(node) => Ok(node.handle_rpc(request)),
            Target::Remote(addr) => {
                let mut client = NodeClient::connect(addr).map_err(|e| e.to_string())?;
                client.call_raw(request).map_err(|e| e.to_string())
            }
        }
    }

    fn request(&mut self, request: Request) -> Result<ReplyBody, String> {
        let reply = self.request_raw(request)?;
        if reply.is_ok() {
            Ok(reply.body)
        } else {
            Err(format!(
                "node rejected the object (reason {})",
                reply.reason
            ))
        }
    }

    fn status(&mut self) -> Result<StatusInfo, String> {
        match self.request(Request::Status)? {
            ReplyBody::Status(status) => Ok(status),
            _ => Err("unexpected status reply".into()),
        }
    }

    fn balance(&mut self, account: &AccountId) -> Result<vess_net::rpc::AccountInfo, String> {
        match self.request(Request::Balance(*account))? {
            ReplyBody::Account(info) => Ok(info),
            _ => Err("unexpected balance reply".into()),
        }
    }
}

fn run(raw: &[String]) -> Result<(), String> {
    vess_node::log::init();
    if raw
        .first()
        .is_some_and(|arg| arg == "help" || arg == "--help")
    {
        println!("{USAGE}");
        return Ok(());
    }
    if raw.len() >= 3 && raw[0] == "wallet" && raw[1] == "sign" && raw[2] == "verify" {
        return wallet_verify_signature(&raw[3..]);
    }
    let bare = raw.first().is_none_or(|arg| arg.starts_with("--"));
    let (group, command, mut args) = if bare {
        ("node", "run", Args::parse(raw))
    } else {
        (
            raw[0].as_str(),
            raw.get(1).map(|s| s.as_str()).unwrap_or(""),
            Args::parse(&raw[1..]),
        )
    };
    if !matches!(
        (group, command),
        (
            "node",
            "init"
                | "run"
                | "status"
                | "history"
                | "params"
                | "block"
                | "tx"
                | "watch"
                | "account"
                | "proof"
                | "witness"
                | "verify-stateless"
        ) | (
            "wallet",
            "new"
                | "restore"
                | "address"
                | "addresses"
                | "sign"
                | "balance"
                | "send"
                | "spend"
                | "set-state"
                | "watch"
                | "futures-fund"
                | "futures-sign"
                | "futures-submit"
                | "futures-settle"
        ) | ("miner", _)
            | ("export", _)
            | ("archive", "verify" | "encode" | "decode")
    ) {
        return Err(format!("unknown command {:?}\n\n{USAGE}", (group, command)));
    }
    config::configure(&mut args, (group, command) == ("node", "run"))?;

    match (group, command) {
        ("node", "init") => node_init(&args),
        ("node", "run") => node_run(&args),
        ("node", "status") => node_status(&args),
        ("node", "history") => node_history(&args),
        ("node", "params") => node_params(&args),
        ("node", "block") => node_block(&args),
        ("node", "tx") => node_transaction(&args),
        ("node", "watch") => node_watch(&args),
        ("node", "account") => node_account(&args),
        ("node", "proof") => node_proof(&args),
        ("node", "witness") => node_witness(&args),
        ("node", "verify-stateless") => node_verify_stateless(&args),
        ("wallet", "new") => wallet_new(&args),
        ("wallet", "restore") => wallet_restore(&args),
        ("wallet", "address") => wallet_address(&args),
        ("wallet", "addresses") => wallet_addresses(&args),
        ("wallet", "sign") => wallet_sign(&args),
        ("wallet", "balance") => wallet_balance(&args),
        ("wallet", "send") => wallet_send(&args),
        ("wallet", "spend") => wallet_spend(&args),
        ("wallet", "futures-fund") => wallet_futures_fund(&args),
        ("wallet", "futures-sign") => wallet_futures_sign(&args),
        ("wallet", "futures-submit") => wallet_futures_submit(&args),
        ("wallet", "futures-settle") => wallet_futures_settle(&args),
        ("wallet", "set-state") => wallet_set_state(&args),
        ("wallet", "watch") => wallet_watch(&args),
        ("miner", _) => miner(&args),
        ("export", _) => export_archive(&args),
        ("archive", "verify") => archive_verify(&args),
        ("archive", "encode") => archive_encode(&args),
        ("archive", "decode") => archive_decode(&args),
        other => Err(format!("unknown command {other:?}\n\n{USAGE}")),
    }
}

fn node_init(args: &Args) -> Result<(), String> {
    let network = network(args)?;
    let dir = datadir(args)?;
    let node = Node::open_with_snapshot_trust(&dir, network, args.get("trust-snapshot").is_some())
        .map_err(|e| e.to_string())?;
    println!("network={}", network.network);
    println!("chain_id={}", hex(&chain_id(network.network)));
    println!(
        "genesis_id={}",
        hex(&node.chain().main_header_at(0).unwrap().id())
    );
    println!("state_root={}", hex(&node.root()));
    println!("datadir={}", dir.display());
    Ok(())
}

fn node_run(args: &Args) -> Result<(), String> {
    let network = network(args)?;
    let dir = datadir(args)?;
    let rpc_port = args.number("rpc", RPC_DEFAULT_PORT as u64)?;
    let p2p_port = args.number("port", P2P_DEFAULT_PORT as u64)?;

    // `--peer` keeps a session forever; `--seed`, `VESS_SEEDS` and the compiled-in defaults are
    // bootstrap hints. All four are merged into one list, because a seed becomes an ordinary peer
    // the moment it answers and the address book takes over from there.
    let env_seeds = std::env::var("VESS_SEEDS").unwrap_or_default();
    let default_seeds = vess_core::constants::default_seeds(network.network).join(",");
    let peers = vess_node::peers::bootstrap(&[
        args.get("peer").unwrap_or(""),
        args.get("seed").unwrap_or(""),
        env_seeds.as_str(),
        default_seeds.as_str(),
    ]);

    let trust_snapshots = args.get("trust-snapshot").is_some();
    let mut node = Node::open_with_snapshot_trust(&dir, network, trust_snapshots)
        .map_err(|e| e.to_string())?;
    let known_peers = node.peer_book_size().0;
    // Pruning is destructive and stored with the data, so the flags only override when present.
    if args.get("prune-blocks").is_some()
        || args.get("prune-headers").is_some()
        || args.get("prune-undo").is_some()
    {
        let current = node.prune_policy();
        let policy = vess_storage::PrunePolicy::new(
            match args.get("prune-blocks") {
                Some(_) => args.number("prune-blocks", 0)?,
                None => current.blocks,
            },
            match args.get("prune-headers") {
                Some(_) => args.number("prune-headers", 0)?,
                None => current.headers,
            },
        )
        .with_undo(match args.get("prune-undo") {
            Some(_) => args.number("prune-undo", 0)?,
            None => current.undo,
        });
        node.set_prune_policy(policy).map_err(|e| e.to_string())?;
    }
    if args.get("finality-depth").is_some() {
        node.set_finality_depth(args.number("finality-depth", 0)?);
    }
    let policy = node.prune_policy();
    if node.trust_snapshots() {
        eprintln!(
            "warning: snapshot trust is enabled; a majority of connected peer identities may authorize \
             a state this node cannot yet validate (one peer is enough when connected alone); \
             identities can be controlled by one party"
        );
    }
    if let vess_net::rpc::ReplyBody::HistoryStatus {
        status: 1,
        height,
        target,
    } = node.handle_rpc(Request::HistoryStatus).body
    {
        eprintln!(
            "warning: snapshot history remains trusted while background verification is pending \
             ({height}/{target} blocks replayed)"
        );
    }
    if !policy.is_archival() {
        eprintln!(
            "pruning: keeping {} blocks of bodies and {} blocks of headers below the tip \
             (0 = keep everything)",
            policy.blocks, policy.headers
        );
        if policy.blocks != 0 {
            eprintln!(
                "note: this node cannot serve blocks older than {} below its tip. A peer further \
                 behind can only join by state snapshot, which trusts a peer \
                 majority for the state at that height because no finality anchor exists yet.",
                policy.blocks
            );
        }
    }
    let status = node.status();
    let rpc_listener = bind_rpc(&format!("127.0.0.1:{rpc_port}")).map_err(|e| e.to_string())?;
    let p2p_listener =
        std::net::TcpListener::bind(format!("0.0.0.0:{p2p_port}")).map_err(|e| e.to_string())?;

    println!("rpc=127.0.0.1:{rpc_port}");
    println!("p2p=0.0.0.0:{p2p_port}");
    println!("network={}", status.network);
    println!("height={}", status.height);
    println!("tip={}", hex(&status.tip));
    if !peers.is_empty() {
        println!("peers={}", peers.join(","));
    }
    if known_peers > 0 {
        println!("known_peers={known_peers}");
    }

    let shared = Arc::new(Mutex::new(node));

    {
        let server = shared.clone();
        let listen_port = p2p_port as u16;
        std::thread::spawn(move || vess_node::p2p::serve(server, p2p_listener, listen_port));
    }

    // Start dialling if there is anyone to dial: configured/seeded addresses, or peers remembered
    // from `peers.txt`. A node whose `--peer` was dropped from the command line still rejoins the
    // network it found last time.
    if !peers.is_empty() || known_peers > 0 {
        let poller = shared.clone();
        let listen_port = p2p_port as u16;
        std::thread::spawn(move || {
            vess_node::p2p::poll(poller, peers, Duration::from_millis(300), listen_port)
        });
    }

    if args.get("mine").is_some() {
        let payout = parse_hash(args.require("payout")?)?;
        let workers = args.number("mine-threads", 1)?;
        for worker in 0..workers {
            let miner = shared.clone();
            std::thread::Builder::new()
                .name(format!("vess-miner-{worker}"))
                .spawn(move || vess_node::p2p::mine(miner, payout, worker))
                .map_err(|e| format!("cannot start mining worker {worker}: {e}"))?;
        }
        vess_node::log_info!("miner", "started {workers} mining worker(s)");
    }

    serve(shared, rpc_listener).map_err(|e| e.to_string())
}

fn node_status(args: &Args) -> Result<(), String> {
    let network = network(args)?;
    let mut target = Target::open(args, network)?;
    let status = target.status()?;
    println!("network={}", status.network);
    println!("height={}", status.height);
    println!("tip={}", hex(&status.tip));
    println!("chain_work={}", status.chain_work);
    println!("mempool_transactions={}", status.mempool_transactions);
    println!("total_supply={}", status.total_supply);
    println!("next_reward={}", status.next_reward);
    println!("next_dev_fee={}", status.next_dev_fee);
    println!("next_timestamp_ms={}", status.next_timestamp_ms);
    println!("peers_inbound={}", status.peers_inbound);
    println!("peers_outbound={}", status.peers_outbound);
    println!("bans={}", status.bans);
    println!("prune_blocks={}", status.prune_blocks);
    println!("prune_headers={}", status.prune_headers);
    println!("oldest_body_height={}", status.oldest_body_height);
    println!("oldest_header_height={}", status.oldest_header_height);
    Ok(())
}

fn node_history(args: &Args) -> Result<(), String> {
    let mut target = Target::open(args, network(args)?)?;
    let ReplyBody::HistoryStatus {
        status,
        height,
        target,
    } = target.request(Request::HistoryStatus)?
    else {
        return Err("unexpected history status reply".into());
    };
    let label = match status {
        0 => "not_tracked",
        1 => "pending",
        2 => "verified",
        3 => "invalid",
        _ => return Err(format!("unknown history verification status {status}")),
    };
    println!("history_status={label}");
    println!("history_height={height}");
    println!("history_target={target}");
    Ok(())
}

fn node_params(args: &Args) -> Result<(), String> {
    let network = network(args)?;
    print!("{}", vess_core::params::describe(network));
    Ok(())
}

fn node_block(args: &Args) -> Result<(), String> {
    let network = network(args)?;
    let query = match (args.get("height"), args.get("id")) {
        (Some(height), None) => vess_net::rpc::BlockQuery::Height(
            height
                .parse()
                .map_err(|_| String::from("--height must be a decimal integer"))?,
        ),
        (None, Some(id)) => vess_net::rpc::BlockQuery::Id(parse_hash(id)?),
        _ => return Err("give exactly one of --height or --id".into()),
    };
    let mut target = Target::open(args, network)?;
    match target.request(Request::Block(query))? {
        ReplyBody::Block(block) => {
            println!("id={}", hex(&block.id));
            println!("height={}", block.height);
            println!("timestamp_unix_ms={}", block.timestamp_unix_ms);
            println!("chain_work={}", block.chain_work);
            println!("state_root={}", hex(&block.state_root));
            println!("transactions={}", block.transaction_ids.len());
            for id in &block.transaction_ids {
                println!("tx={}", hex(id));
            }
            Ok(())
        }
        _ => Err("unexpected block reply".into()),
    }
}

fn node_transaction(args: &Args) -> Result<(), String> {
    let network = network(args)?;
    let id = parse_hash(args.require("id")?)?;
    let mut target = Target::open(args, network)?;
    match target.request(Request::Transaction(id))? {
        ReplyBody::Transaction(info) => {
            println!("txid={}", hex(&info.transaction_id));
            println!("status={}", vess_net::tx_status::name(info.status));
            println!("in_mempool={}", u8::from(info.in_mempool));
            match (info.block_id, info.height) {
                (Some(block_id), Some(height)) => {
                    println!("block={}", hex(&block_id));
                    println!("height={height}");
                    println!("confirmations={}", info.confirmations);
                }
                // `status` already says more than this; `unmined` stays for pending only.
                _ if info.status == vess_net::tx_status::PENDING => println!("unmined=1"),
                _ => {}
            }
            if info.kind != 0 {
                // Content, not just position: this is what lets a scanner recognise a payment to
                // an address it owns without having to diff balances.
                let kind = match info.kind {
                    1 => "transfer".to_string(),
                    2 => "state-update".to_string(),
                    other => format!("kind{other}"),
                };
                println!("kind={kind}");
                println!("sender={}", hex(&info.sender_id));
                if info.kind == 1 {
                    println!("recipient={}", hex(&info.recipient_id));
                    println!("amount={}", info.amount);
                    if let Some(payload) = &info.payload {
                        println!("payload={}", hex(payload));
                    }
                } else {
                    println!("new_state_hash={}", hex(&info.new_state_hash));
                }
                println!("fee={}", info.fee);
                if let Some(escrow) = &info.escrow {
                    println!("escrow_hash_lock={}", hex(&escrow.rules.hash_lock));
                    println!("escrow_refund_height={}", escrow.rules.refund_height);
                    println!("escrow_owner={}", hex(&escrow.rules.owner_account_id));
                    println!("escrow_max_fee={}", escrow.rules.max_fee);
                    println!("escrow_claimed={}", u8::from(escrow.claimed));
                }
            }
            Ok(())
        }
        _ => Err("unexpected transaction reply".into()),
    }
}

/// Follow the chain by long-polling `WAIT_FOR_TIP`, so nothing is polled on a timer and no block is
/// missed between two requests.
fn node_watch(args: &Args) -> Result<(), String> {
    let count = args.number("count", 0)?;
    let timeout_ms = args.number("timeout", 10_000)?;
    if timeout_ms == 0 || timeout_ms > u64::from(vess_node::MAX_WAIT_MS) {
        return Err(format!(
            "--timeout must be between 1 and {} ms",
            vess_node::MAX_WAIT_MS
        ));
    }
    let addr = args.require("rpc")?;
    let mut client = NodeClient::connect(addr).map_err(|e| e.to_string())?;
    // `--count` bounds the number of *replies* (a block or an idle timeout), so a watch against a
    // node that is not producing blocks still terminates. `0` watches forever.
    let mut seen = 0u64;
    let mut after = match client
        .call_raw(Request::Status)
        .map_err(|e| e.to_string())?
    {
        reply if reply.is_ok() => match reply.body {
            ReplyBody::Status(status) => {
                println!("start height={} tip={}", status.height, hex(&status.tip));
                status.tip
            }
            _ => return Err("unexpected status reply".into()),
        },
        reply => return Err(format!("node rejected status (reason {})", reply.reason)),
    };
    while count == 0 || seen < count {
        let reply = client
            .call_raw(Request::WaitForTip {
                after,
                timeout_ms: timeout_ms as u32,
            })
            .map_err(|e| e.to_string())?;
        if !reply.is_ok() {
            return Err(format!("node rejected wait (reason {})", reply.reason));
        }
        match reply.body {
            ReplyBody::Tip { tip, height } => {
                if tip == after {
                    println!("idle height={height} (timeout)");
                } else {
                    println!("height={height} tip={}", hex(&tip));
                }
                seen += 1;
                after = tip;
            }
            _ => return Err("unexpected tip reply".into()),
        }
    }
    Ok(())
}

fn wallet_new(args: &Args) -> Result<(), String> {
    let network = network(args)?;
    let dir = datadir(args)?;
    let name = args.require("name")?;
    let path = wallet_path(&dir, name);
    if path.exists() {
        return Err(format!("{} already exists", path.display()));
    }
    let pass = passphrase(args)?;
    let keyring = if args.get("legacy").is_some() {
        Keyring::Single(Box::new(Wallet::create(network.network)))
    } else {
        if pass.is_none() {
            return Err(
                "an HD keyfile must be encrypted: supply --password-file or --password-env".into(),
            );
        }
        if !std::io::stdout().is_terminal() && args.get("unsafe-phrase-stdout").is_none() {
            return Err("refusing to print the recovery phrase to redirected stdout; use a terminal or explicitly pass --unsafe-phrase-stdout".into());
        }
        let phrase = RecoveryPhrase::generate().map_err(|e| e.to_string())?;
        eprintln!(
            "Write down the following recovery phrase privately. Anyone who knows it can spend your funds."
        );
        eprintln!("It is shown only once and cannot be recovered from the keyfile.");
        let stdout = std::io::stdout();
        let mut out = stdout.lock();
        write!(out, "recovery_phrase=")
            .map_err(|e| format!("cannot display recovery phrase: {e}"))?;
        for (index, word) in phrase.words().enumerate() {
            if index != 0 {
                write!(out, " ").map_err(|e| format!("cannot display recovery phrase: {e}"))?;
            }
            write!(out, "{word}").map_err(|e| format!("cannot display recovery phrase: {e}"))?;
        }
        writeln!(out)
            .and_then(|_| out.flush())
            .map_err(|e| format!("cannot display recovery phrase; wallet was not created: {e}"))?;
        phrase.keyring(network.network)
    };
    keyring
        .save_new(&path, pass.as_ref())
        .map_err(|e| e.to_string())?;
    if pass.is_none() {
        eprintln!(
            "warning: no passphrase given, so {} is UNENCRYPTED.\n\
             Pass --password-file FILE (or --password-env VAR) to encrypt it with Argon2id.",
            path.display()
        );
    }
    println!("name={name}");
    println!("hd={}", u8::from(keyring.is_hd()));
    println!("encrypted={}", u8::from(pass.is_some()));
    if keyring.is_hd() {
        // The index is part of the address, so print the first one as the default account.
        println!(
            "account={}",
            hex(&keyring.account_id(0).map_err(|e| e.to_string())?)
        );
        println!("index=0");
    } else {
        println!(
            "account={}",
            hex(&keyring.account(0).map_err(|e| e.to_string())?.account_id())
        );
    }
    println!("keyfile={}", path.display());
    Ok(())
}

fn wallet_restore(args: &Args) -> Result<(), String> {
    let network = network(args)?;
    let dir = datadir(args)?;
    let name = args.require("name")?;
    let path = wallet_path(&dir, name);
    if path.exists() {
        return Err(format!("{} already exists", path.display()));
    }
    let pass = passphrase(args)?
        .ok_or("an HD keyfile must be encrypted: supply --password-file or --password-env")?;
    let words = if args.get("mnemonic-stdin").is_some() {
        if std::io::stdin().is_terminal() {
            return Err(
                "--mnemonic-stdin requires piped input; omit it for hidden terminal entry".into(),
            );
        }
        let mut words = Zeroizing::new(String::new());
        std::io::stdin()
            .lock()
            .take(4097)
            .read_to_string(&mut words)
            .map_err(|e| format!("cannot read recovery phrase: {e}"))?;
        if words.len() > 4096 {
            return Err("recovery phrase input is too long".into());
        }
        words
    } else {
        if !std::io::stdin().is_terminal() {
            return Err("recovery requires a terminal for hidden input, or --mnemonic-stdin for piped input".into());
        }
        Zeroizing::new(
            rpassword::prompt_password("Enter your 24-word recovery phrase (input hidden): ")
                .map_err(|e| format!("cannot read recovery phrase: {e}"))?,
        )
    };
    let phrase = RecoveryPhrase::parse(&words).map_err(|e| e.to_string())?;
    let keyring = phrase.keyring(network.network);
    let account = keyring.account_id(0).map_err(|e| e.to_string())?;
    keyring
        .save_new(&path, Some(&pass))
        .map_err(|e| e.to_string())?;
    println!("name={name}");
    println!("hd=1");
    println!("encrypted=1");
    println!("account={}", hex(&account));
    println!("index=0");
    println!("keyfile={}", path.display());
    Ok(())
}

/// List the accounts a keyfile can derive, so a receiving wallet can display them.
fn wallet_addresses(args: &Args) -> Result<(), String> {
    let network = network(args)?;
    let dir = datadir(args)?;
    let name = args.require("name")?;
    let count = args.number("count", 5)?;
    if count == 0 {
        return Err("--count must be positive".into());
    }
    let pass = passphrase(args)?;
    let keyring = Keyring::open(&wallet_path(&dir, name), network.network, pass.as_ref())
        .map_err(|e| e.to_string())?;
    println!("name={name}");
    println!("hd={}", u8::from(keyring.is_hd()));
    if keyring.is_hd() {
        let accounts = keyring
            .account_ids(count as u32)
            .map_err(|e| e.to_string())?;
        for (index, account) in accounts.iter().enumerate() {
            println!("account[{index}]={}", hex(account));
        }
    } else {
        // A single-key keyfile has exactly one account; listing a range would fail on index 1.
        let account = keyring.account(0).map_err(|e| e.to_string())?;
        println!("account[0]={}", hex(&account.account_id()));
        eprintln!("note: this keyfile holds one account, so only index 0 exists");
    }
    Ok(())
}

/// The passphrase for a keyfile, if the operator supplied one. Files are preferred over environment
/// variables because a file is not visible in `ps` and does not leak into shell history.
fn passphrase(args: &Args) -> Result<Option<vess_wallet::keyfile::Passphrase>, String> {
    match (args.get("password-file"), args.get("password-env")) {
        (Some(_), Some(_)) => Err("give only one of --password-file and --password-env".into()),
        (Some(path), None) => vess_wallet::keyfile::Passphrase::from_file(Path::new(path))
            .map(Some)
            .map_err(|e| e.to_string()),
        (None, Some(var)) => vess_wallet::keyfile::Passphrase::from_env(var)
            .map(Some)
            .map_err(|e| e.to_string()),
        (None, None) => Ok(None),
    }
}

fn load_wallet(args: &Args, network: NetworkProfile) -> Result<Wallet, String> {
    let dir = datadir(args)?;
    let name = args.require("name")?;
    let pass = passphrase(args)?;
    let keyring = Keyring::open(&wallet_path(&dir, name), network.network, pass.as_ref())
        .map_err(|e| e.to_string())?;
    let index = u32::try_from(args.number("index", 0)?)
        .map_err(|_| "--index must be between 0 and 4294967295")?;
    keyring.account(index).map_err(|e| e.to_string())
}

fn wallet_sign(args: &Args) -> Result<(), String> {
    let message = args.require_value("message")?;
    let network = network(args)?;
    let wallet = load_wallet(args, network)?;
    let signature = wallet
        .sign_message(message.as_bytes())
        .map_err(|error| format!("message signing failed: {error:?}"))?;
    println!("algorithm=ML-DSA-65");
    println!("context={}", vess_wallet::MESSAGE_SIGNING_CONTEXT);
    println!("account={}", hex(&wallet.account_id()));
    println!("public_key={}", hex(wallet.public_key()));
    println!("signature={}", hex(&signature));
    Ok(())
}

fn verify_options(raw: &[String]) -> Result<HashMap<String, String>, String> {
    let allowed = ["message", "proof", "public-key", "signature", "account"];
    let mut options = HashMap::new();
    let mut index = 0;
    while index < raw.len() {
        let token = &raw[index];
        let option = token
            .strip_prefix("--")
            .ok_or_else(|| format!("unexpected argument {token:?}"))?;
        let (name, value) = if let Some((name, value)) = option.split_once('=') {
            (name, value)
        } else {
            let value = raw
                .get(index + 1)
                .filter(|value| !value.starts_with("--"))
                .ok_or_else(|| format!("--{option} requires a value"))?;
            index += 1;
            (option, value.as_str())
        };
        if !allowed.contains(&name) {
            return Err(format!("unknown verification option --{name}"));
        }
        if options
            .insert(name.to_string(), value.to_string())
            .is_some()
        {
            return Err(format!("duplicate verification option --{name}"));
        }
        index += 1;
    }
    Ok(options)
}

fn fixed_hex<const N: usize>(value: &str, name: &str) -> Result<[u8; N], String> {
    let digits = value.strip_prefix("0x").unwrap_or(value);
    if digits.len() != N * 2 {
        return Err(format!("{name} must be {N} bytes of hex"));
    }
    decode_hex(value)?
        .try_into()
        .map_err(|_| format!("{name} must be {N} bytes of hex"))
}

fn read_signature_proof(path: &str) -> Result<HashMap<String, String>, String> {
    const LIMIT: u64 = 32_768;
    let input: Box<dyn Read> = if path == "-" {
        Box::new(std::io::stdin())
    } else {
        Box::new(
            std::fs::File::open(path)
                .map_err(|error| format!("cannot open signature proof {path}: {error}"))?,
        )
    };
    let mut bytes = Vec::new();
    input
        .take(LIMIT + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("cannot read signature proof: {error}"))?;
    if bytes.len() as u64 > LIMIT {
        return Err("signature proof is too long".into());
    }
    let text = if bytes.starts_with(&[0xff, 0xfe]) || bytes.starts_with(&[0xfe, 0xff]) {
        let little_endian = bytes[0] == 0xff;
        let encoded = &bytes[2..];
        if !encoded.len().is_multiple_of(2) {
            return Err("invalid UTF-16 signature proof".into());
        }
        let words: Vec<u16> = encoded
            .chunks_exact(2)
            .map(|pair| {
                if little_endian {
                    u16::from_le_bytes([pair[0], pair[1]])
                } else {
                    u16::from_be_bytes([pair[0], pair[1]])
                }
            })
            .collect();
        String::from_utf16(&words).map_err(|_| "invalid UTF-16 signature proof")?
    } else {
        String::from_utf8(bytes).map_err(|_| "signature proof must be UTF-8 or UTF-16")?
    };
    let text = text.strip_prefix('\u{feff}').unwrap_or(&text);
    let mut fields = HashMap::new();
    for line in text.lines().filter(|line| !line.is_empty()) {
        let (name, value) = line
            .split_once('=')
            .ok_or("malformed signature proof line")?;
        if !["algorithm", "context", "account", "public_key", "signature"].contains(&name) {
            return Err(format!("unknown signature proof field {name:?}"));
        }
        if fields.insert(name.to_string(), value.to_string()).is_some() {
            return Err(format!("duplicate signature proof field {name:?}"));
        }
    }
    for name in ["algorithm", "context", "account", "public_key", "signature"] {
        if !fields.contains_key(name) {
            return Err(format!("missing signature proof field {name}"));
        }
    }
    if fields["algorithm"] != "ML-DSA-65"
        || fields["context"] != vess_wallet::MESSAGE_SIGNING_CONTEXT
    {
        return Err("unsupported signature proof algorithm or context".into());
    }
    Ok(fields)
}

fn wallet_verify_signature(raw: &[String]) -> Result<(), String> {
    let options = verify_options(raw)?;
    let message = options.get("message").ok_or("missing --message")?;
    let proof = match options.get("proof") {
        Some(path) => {
            if options.contains_key("public-key") || options.contains_key("signature") {
                return Err("give either --proof or --public-key and --signature".into());
            }
            Some(read_signature_proof(path)?)
        }
        None => None,
    };
    let (public_key, signature, claimed_account) = match &proof {
        Some(fields) => (
            fields["public_key"].as_str(),
            fields["signature"].as_str(),
            Some(fields["account"].as_str()),
        ),
        None => (
            options
                .get("public-key")
                .ok_or("missing --public-key")?
                .as_str(),
            options
                .get("signature")
                .ok_or("missing --signature")?
                .as_str(),
            None,
        ),
    };
    let public_key = fixed_hex::<ML_DSA_PK_BYTES>(public_key, "public key")?;
    let signature = fixed_hex::<ML_DSA_SIG_BYTES>(signature, "signature")?;
    let account = vess_crypto::account_id(&public_key);
    let claimed_account = claimed_account
        .map(|value| fixed_hex::<32>(value, "proof account"))
        .transpose()?;
    let expected_account = options
        .get("account")
        .map(|value| fixed_hex::<32>(value, "expected account"))
        .transpose()?;
    if claimed_account.is_some_and(|claimed| claimed != account)
        || expected_account.is_some_and(|expected| expected != account)
    {
        println!("valid=0");
        return Err("public key does not match the account".into());
    }
    if !vess_crypto::verify(
        &public_key,
        vess_wallet::MESSAGE_SIGNING_CONTEXT.as_bytes(),
        message.as_bytes(),
        &signature,
    ) {
        println!("valid=0");
        return Err("message signature is invalid".into());
    }
    println!("valid=1");
    println!("account={}", hex(&account));
    Ok(())
}

fn wallet_address(args: &Args) -> Result<(), String> {
    // A recipient address *is* BLAKE3("VESS-ACCOUNT-V1" || public_key), so anyone holding a public
    // key can derive the address it pays. That makes an out-of-band key exchange sufficient.
    if let Some(public_key) = args.get("public-key") {
        let bytes = decode_hex(public_key)?;
        if bytes.len() != ML_DSA_PK_BYTES {
            return Err(format!(
                "expected a {ML_DSA_PK_BYTES}-byte public key, got {} bytes",
                bytes.len()
            ));
        }
        let mut key = [0u8; ML_DSA_PK_BYTES];
        key.copy_from_slice(&bytes);
        println!("account={}", hex(&vess_core::hash::account_id(&key)));
        return Ok(());
    }
    let network = network(args)?;
    let wallet = load_wallet(args, network)?;
    println!("account={}", hex(&wallet.account_id()));
    // A public key is what a counterparty needs to contribute to a futures pot; the address alone
    // is a hash and cannot be used to build their input.
    println!("public_key={}", hex(wallet.public_key().as_slice()));
    println!("network={}", network.network);
    Ok(())
}

fn wallet_balance(args: &Args) -> Result<(), String> {
    let network = network(args)?;
    let wallet = load_wallet(args, network)?;
    let mut target = Target::open(args, network)?;
    let info = target.balance(&wallet.account_id())?;
    println!("account={}", hex(&wallet.account_id()));
    println!("exists={}", u8::from(info.exists));
    println!("balance={}", info.balance);
    println!("next_nonce={}", info.next_nonce);
    println!("state_hash={}", hex(&info.state_hash));
    Ok(())
}

/// Read any account's state, without needing a keyfile for it.
fn node_account(args: &Args) -> Result<(), String> {
    let network = network(args)?;
    let account = parse_hash(args.require("account")?)?;
    let mut target = Target::open(args, network)?;
    let info = target.balance(&account)?;
    println!("account={}", hex(&account));
    println!("exists={}", u8::from(info.exists));
    println!("balance={}", info.balance);
    println!("next_nonce={}", info.next_nonce);
    println!("state_hash={}", hex(&info.state_hash));
    Ok(())
}

/// Ask for a Merkle proof of an account against the root the node currently holds. Inclusion and
/// non-inclusion are both provable, which is how a caller distinguishes "empty" from "absent".
fn node_proof(args: &Args) -> Result<(), String> {
    let network = network(args)?;
    let account = parse_hash(args.require("account")?)?;
    let mut target = Target::open(args, network)?;
    match target.request(Request::Proof(account))? {
        ReplyBody::Proof(info) => {
            println!("account={}", hex(&account));
            println!("root={}", hex(&info.root));
            println!("included={}", u8::from(info.value.is_some()));
            if let Some(value) = &info.value {
                println!("value={}", hex(value));
            }
            println!("siblings={}", info.siblings.len());
            for sibling in &info.siblings {
                println!("sibling={}", hex(sibling));
            }
            Ok(())
        }
        _ => Err("unexpected proof reply".into()),
    }
}

/// Read a rules file: `key=value` lines naming the escrow's spend condition. The account id is
/// derived from these bytes, so the file is the escrow's only handle.
fn load_rules(path: &str) -> Result<vess_core::Rules, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("reading {path}: {e}"))?;
    let mut fields: HashMap<&str, &str> = HashMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| format!("{path}: expected key=value"))?;
        fields.insert(key.trim(), value.trim());
    }
    let field = |key: &str| {
        fields
            .get(key)
            .copied()
            .ok_or_else(|| format!("{path}: missing {key}"))
    };
    let height = |key: &str| -> Result<u64, String> {
        field(key)?
            .parse()
            .map_err(|_| format!("{path}: {key} must be a decimal height"))
    };
    let number = |key: &str| -> Result<u64, String> {
        field(key)?
            .parse()
            .map_err(|_| format!("{path}: {key} must be a decimal integer"))
    };
    Ok(vess_core::Rules {
        version: vess_core::constants::RULES_VERSION,
        hash_lock: fixed_hex::<32>(field("hash_lock")?, "hash_lock")?,
        refund_height: height("refund_height")?,
        recipient_account_id: fixed_hex::<32>(field("recipient")?, "recipient")?,
        owner_account_id: fixed_hex::<32>(field("owner")?, "owner")?,
        max_fee: number("max_fee")?,
    })
}

/// Verify a block from its witness alone: the parent state root comes from our own header chain, so
/// nothing here reads an account tree.
fn node_verify_stateless(args: &Args) -> Result<(), String> {
    let network = network(args)?;
    let id = parse_hash(args.require("id")?)?;
    let mut target = Target::open(args, network)?;

    let height = match target.request(Request::Block(vess_net::rpc::BlockQuery::Id(id)))? {
        ReplyBody::Block(block) => block.height,
        _ => return Err("unexpected block reply".into()),
    };
    if height == 0 {
        return Err("genesis has no body and no witness".into());
    }
    // The trusted input: the parent's state root, taken from the header chain we hold ourselves.
    let parent_root = match target.request(Request::Block(vess_net::rpc::BlockQuery::Height(
        height - 1,
    )))? {
        ReplyBody::Block(block) => block.state_root,
        _ => return Err("unexpected parent block reply".into()),
    };
    let (body, witness) = match target.request(Request::Witness(id))? {
        ReplyBody::Witness { body, witness } => (body, witness),
        _ => return Err("unexpected witness reply".into()),
    };

    let (header, transactions) = vess_consensus::split_block(&body).map_err(|e| e.to_string())?;
    let root = vess_consensus::verify_witness(
        &network,
        &parent_root,
        &header,
        &transactions,
        height,
        &witness,
    )
    .map_err(|e| e.to_string())?;
    if root != header.state_root {
        return Err(format!(
            "witness produced state root {} but the header commits to {}",
            hex(&root),
            hex(&header.state_root)
        ));
    }

    println!("verified=stateless");
    println!("block={}", hex(&id));
    println!("height={height}");
    println!("transactions={}", transactions.len());
    println!("witness_accounts={}", witness.accounts.len());
    println!("witness_bytes={}", witness_bytes(&witness));
    println!("state_root={}", hex(&root));
    Ok(())
}

fn witness_bytes(witness: &vess_core::BlockWitness) -> usize {
    32 + 4
        + witness
            .accounts
            .iter()
            .map(vess_core::AccountWitness::encoded_len)
            .sum::<usize>()
}

fn node_witness(args: &Args) -> Result<(), String> {
    let network = network(args)?;
    let id = parse_hash(args.require("id")?)?;
    let mut target = Target::open(args, network)?;
    match target.request(Request::Witness(id))? {
        ReplyBody::Witness { witness, .. } => {
            println!("block={}", hex(&id));
            println!("account_root={}", hex(&witness.account_root));
            println!("accounts={}", witness.accounts.len());
            println!("bytes={}", witness_bytes(&witness));
            for account in &witness.accounts {
                let state = match account.account {
                    Some(account) => {
                        format!("balance={} nonce={}", account.balance, account.next_nonce)
                    }
                    None => "absent".to_string(),
                };
                println!(
                    "account={} {state} siblings={}",
                    hex(&account.id),
                    account.siblings.len()
                );
            }
            Ok(())
        }
        _ => Err("unexpected witness reply".into()),
    }
}

/// Read a futures rules file: `key=value` lines naming a contract's terms.
///
/// The pot's account id is derived from exactly these bytes, so this file is the contract's only
/// handle: funding pays the derived id, and only these bytes can ever spend it.
fn load_futures_rules(path: &str) -> Result<vess_core::FuturesRules, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("reading {path}: {e}"))?;
    let mut fields: HashMap<&str, &str> = HashMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| format!("{path}: expected key=value"))?;
        fields.insert(key.trim(), value.trim());
    }
    let field = |key: &str| {
        fields
            .get(key)
            .copied()
            .ok_or_else(|| format!("{path}: missing {key}"))
    };
    let number = |key: &str| -> Result<u64, String> {
        field(key)?
            .parse()
            .map_err(|_| format!("{path}: {key} must be a decimal integer"))
    };
    Ok(vess_core::FuturesRules {
        version: vess_core::constants::RULES_VERSION_FUTURES,
        start_supply: number("start_supply")?,
        target_delta: number("target_delta")?,
        earliest_settle_height: number("earliest_settle_height")?,
        recipient_account_id: fixed_hex::<32>(field("recipient")?, "recipient")?,
        owner_account_id: fixed_hex::<32>(field("owner")?, "owner")?,
        max_fee: number("max_fee")?,
    })
}

/// Where a joint transaction is carried between the parties: one hex line.
fn futures_tx_path(args: &Args) -> PathBuf {
    PathBuf::from(args.get("tx").unwrap_or("futures.tx"))
}

fn read_joint_transfer(path: &Path) -> Result<JointTransfer, String> {
    let text =
        std::fs::read_to_string(path).map_err(|e| format!("reading {}: {e}", path.display()))?;
    let bytes = decode_hex(text.trim())?;
    vess_core::codec::from_bytes(&bytes).map_err(|e| format!("{}: {e}", path.display()))
}

fn write_joint_transfer(path: &Path, tx: &JointTransfer) -> Result<(), String> {
    let bytes = vess_core::codec::to_bytes(tx);
    std::fs::write(path, format!("{}\n", hex(&bytes)))
        .map_err(|e| format!("writing {}: {e}", path.display()))
}

/// Build the joint funding transaction both parties sign.
///
/// The pot is either funded exactly as declared or not at all, because the two debits live in one
/// transaction. That is why there is no deposit-first risk and no refund path: nothing is ever half
/// funded.
fn wallet_futures_fund(args: &Args) -> Result<(), String> {
    let network = network(args)?;
    let wallet = load_wallet(args, network)?;
    let rules = load_futures_rules(args.require("rules")?)?;
    let pot = rules.account_id();
    let amount = args.number("amount", 0)?;
    if amount == 0 {
        return Err("--amount must be positive".into());
    }
    let fee = args.number("fee", 0)?;

    let mut target = Target::open(args, network)?;
    let mine = target.balance(&wallet.account_id())?;
    let mut inputs = vec![wallet.joint_input(amount, mine.next_nonce)];

    if let Some(value) = args.get("counterparty") {
        let key: PublicKey = decode_hex(value)?
            .try_into()
            .map_err(|_| "--counterparty must be an ML-DSA public key".to_string())?;
        let account = vess_core::hash::account_id(&key);
        let theirs = target.balance(&account)?;
        let their_amount = match args.get("counterparty-amount") {
            Some(value) => value
                .parse()
                .map_err(|_| "--counterparty-amount must be a decimal integer".to_string())?,
            None => amount,
        };
        inputs.push(vess_core::TransferInput {
            authority: vess_core::InputAuthority::Signature {
                public_key: key,
                signature: [0u8; ML_DSA_SIG_BYTES],
            },
            amount: their_amount,
            nonce: theirs.next_nonce,
        });
    }

    let mut tx = wallet
        .build_joint_funding(inputs, pot, fee)
        .ok_or_else(|| "--fee exceeds the contributed amount".to_string())?;
    wallet.sign_joint_transfer(&mut tx);
    let path = futures_tx_path(args);
    write_joint_transfer(&path, &tx)?;

    println!("pot={}", hex(&pot));
    println!("txid={}", hex(&tx.tx_id()));
    println!("accounts={}", tx.inputs.len());
    println!("file={}", path.display());
    Ok(())
}

/// Add this wallet's signature to a prebuilt funding transaction.
fn wallet_futures_sign(args: &Args) -> Result<(), String> {
    let network = network(args)?;
    let wallet = load_wallet(args, network)?;
    let path = futures_tx_path(args);
    let mut tx = read_joint_transfer(&path)?;
    wallet.sign_joint_transfer(&mut tx);
    write_joint_transfer(&path, &tx)?;
    println!("signed={}", hex(&tx.tx_id()));
    println!("file={}", path.display());
    Ok(())
}

/// Submit a fully signed funding transaction.
fn wallet_futures_submit(args: &Args) -> Result<(), String> {
    let network = network(args)?;
    let path = futures_tx_path(args);
    let tx = read_joint_transfer(&path)?;
    let id = tx.tx_id();
    let mut target = Target::open(args, network)?;
    match target.request(Request::SubmitJointTransfer(tx))? {
        ReplyBody::Accepted(_) => {
            println!("accepted=funding");
            println!("txid={}", hex(&id));
            Ok(())
        }
        _ => Err("unexpected reply".into()),
    }
}

/// Settle a matured futures pot. Nothing here is signed: the terms name both destinations and
/// consensus derives both amounts, so any holder of the terms can submit it.
fn wallet_futures_settle(args: &Args) -> Result<(), String> {
    let network = network(args)?;
    let wallet = load_wallet(args, network)?;
    let rules = load_futures_rules(args.require("rules")?)?;
    let pot = rules.account_id();
    let fee = args.number("fee", 0)?;

    let mut target = Target::open(args, network)?;
    let info = target.balance(&pot)?;
    if !info.exists {
        return Err(format!("pot {} has no balance", hex(&pot)));
    }
    let supply = target.status()?.total_supply as u128;
    let (owner, recipient) = rules
        .split(
            info.balance
                .checked_sub(fee)
                .ok_or("--fee exceeds the pot")?,
            supply,
        )
        .ok_or("the futures terms are unusable")?;
    let tx = wallet
        .build_futures_settle(&rules, fee, info.next_nonce, info.balance, supply)
        .ok_or_else(|| "--fee exceeds the pot".to_string())?;
    let id = tx.tx_id();
    let body = target.request(Request::SubmitJointTransfer(tx))?;
    let ReplyBody::Accepted(_) = body else {
        return Err(format!("unexpected reply {body:?}"));
    };

    println!("accepted=settlement");
    println!("pot={}", hex(&pot));
    println!("txid={}", hex(&id));
    println!("supply={supply}");
    println!("owner_amount={owner}");
    println!("recipient_amount={recipient}");
    println!("fee={fee}");
    Ok(())
}

fn wallet_send(args: &Args) -> Result<(), String> {
    let network = network(args)?;
    let wallet = load_wallet(args, network)?;
    let (recipient, escrow) = match (args.get("to"), args.get("rules")) {
        (Some(to), None) => (parse_hash(to)?, None),
        (None, Some(path)) => {
            let rules = load_rules(path)?;
            (rules.account_id(), Some(rules))
        }
        _ => return Err("give exactly one of --to or --rules".into()),
    };
    let amount = args.number("amount", 0)?;
    if amount == 0 {
        return Err("--amount must be positive".into());
    }
    let fee = args.number("fee", 0)?;
    let payload = match args.get("payload") {
        None => None,
        Some(value) => Some(fixed_hex::<TX_PAYLOAD_BYTES>(value, "--payload")?),
    };
    let mut target = Target::open(args, network)?;
    let info = target.balance(&wallet.account_id())?;
    let tx =
        wallet.build_transfer_with_payload(recipient, amount, fee, info.next_nonce, 0, payload);
    match target.request(Request::SubmitTransfer(tx))? {
        ReplyBody::Accepted(id) => {
            println!("accepted=transfer");
            println!("txid={}", hex(&id));
            println!("nonce={}", info.next_nonce);
            if let Some(rules) = escrow {
                println!("escrow={}", hex(&rules.account_id()));
                println!("refund_height={}", rules.refund_height);
            }
            Ok(())
        }
        _ => Err("unexpected reply".into()),
    }
}

/// Write every body this node still holds as verifiable chunk files.
///
/// Runs on the store directly, so it works on an offline data directory (a running node holds the
/// database lock). The export covers whatever the prune policy kept: a pruned node exports the part
/// of history it has, an archival node exports everything.
fn export_archive(args: &Args) -> Result<(), String> {
    let network = network(args)?;
    let dir = datadir(args)?;
    let out = PathBuf::from(args.require("out")?);
    let store =
        vess_storage::Store::open(&dir.join("ledger.redb"), network).map_err(|e| e.to_string())?;
    let chain = store.load_chain().map_err(|e| e.to_string())?;
    let oldest = store.oldest_body_height().map_err(|e| e.to_string())?;
    let from = args.number("from", oldest.max(1))?;
    let to = args.number("to", chain.best_height())?;
    if from > to {
        return Err(format!("--from {from} is above --to {to}"));
    }
    let summary = vess_node::archive::export(&out, network.network, from, to, |height| {
        let header = chain
            .main_header_at(height)
            .ok_or_else(|| format!("no header at height {height}"))?;
        store.body(&header.id()).map_err(|e| e.to_string())
    })?;
    println!("chunks={}", summary.chunks);
    println!("blocks={}", summary.blocks);
    println!("bytes={}", summary.bytes);
    println!("first={}", summary.first);
    println!("last={}", summary.last);
    println!("dir={}", out.display());
    Ok(())
}

fn archive_verify(args: &Args) -> Result<(), String> {
    let dir = PathBuf::from(args.require("dir")?);
    let summary = vess_node::archive::verify(&dir)?;
    println!("chunks={}", summary.chunks);
    println!("blocks={}", summary.blocks);
    println!("status=ok");
    Ok(())
}

fn archive_encode(args: &Args) -> Result<(), String> {
    let dir = PathBuf::from(args.require("dir")?);
    let data = args.number("data", 10)? as usize;
    let parity = args.number("parity", 4)? as usize;
    let sets = vess_node::archive::encode(&dir, data, parity)?;
    let shards: usize = sets.iter().map(|set| set.shards.len()).sum();
    println!("files={}", sets.len());
    println!("shards={shards}");
    println!("data={data}");
    println!("parity={parity}");
    println!("dir={}", dir.join("shards").display());
    Ok(())
}

fn archive_decode(args: &Args) -> Result<(), String> {
    let dir = PathBuf::from(args.require("dir")?);
    let out = PathBuf::from(args.require("out")?);
    let written = vess_node::archive::decode(&dir, &out)?;
    println!("files={}", written.len());
    println!("dir={}", out.display());
    Ok(())
}

/// Claim an escrow with its preimage, or refund it to the owner once `refund_height` has passed.
/// Nothing here is signed: the rules name the destination, so this can be run by anyone.
fn wallet_spend(args: &Args) -> Result<(), String> {
    let network = network(args)?;
    let wallet = load_wallet(args, network)?;
    let rules = load_rules(args.require("rules")?)?;
    let escrow = rules.account_id();
    let preimage = match args.get("preimage") {
        None => None,
        Some(value) => Some(fixed_hex::<PREIMAGE_BYTES>(value, "--preimage")?),
    };
    let fee = args.number("fee", 0)?;
    let mut target = Target::open(args, network)?;
    let info = target.balance(&escrow)?;
    if !info.exists {
        return Err(format!("escrow {} has no balance", hex(&escrow)));
    }
    let tx = wallet
        .build_rules_spend(&rules, preimage, fee, info.next_nonce, info.balance)
        .ok_or_else(|| format!("--fee {fee} exceeds the escrow balance {}", info.balance))?;
    match target.request(Request::SubmitTransfer(tx))? {
        ReplyBody::Accepted(id) => {
            println!(
                "accepted={}",
                if preimage.is_some() {
                    "claim"
                } else {
                    "refund"
                }
            );
            println!("escrow={}", hex(&escrow));
            println!("txid={}", hex(&id));
            println!("amount={}", info.balance - fee);
            println!("fee={fee}");
            println!("nonce={}", info.next_nonce);
            Ok(())
        }
        _ => Err("unexpected reply".into()),
    }
}

/// Follow one account's state with `WAIT_FOR_ACCOUNT`: no poll interval to choose, and blocks that
/// do not touch the account produce no output.
fn wallet_watch(args: &Args) -> Result<(), String> {
    let network = network(args)?;
    let wallet = load_wallet(args, network)?;
    let account = wallet.account_id();
    let count = args.number("count", 0)?;
    let timeout_ms = args.number("timeout", 10_000)?;
    if timeout_ms == 0 || timeout_ms > u64::from(vess_node::MAX_WAIT_MS) {
        return Err(format!(
            "--timeout must be between 1 and {} ms",
            vess_node::MAX_WAIT_MS
        ));
    }
    let addr = args.require("rpc")?;
    let mut client = NodeClient::connect(addr).map_err(|e| e.to_string())?;
    let mut seen = 0u64;
    let mut since = match client
        .call_raw(Request::Balance(account))
        .map_err(|e| e.to_string())?
    {
        reply if reply.is_ok() => match reply.body {
            ReplyBody::Account(info) => {
                println!(
                    "start balance={} next_nonce={} state_hash={}",
                    info.balance,
                    info.next_nonce,
                    hex(&info.state_hash)
                );
                info
            }
            _ => return Err("unexpected balance reply".into()),
        },
        reply => return Err(format!("node rejected balance (reason {})", reply.reason)),
    };
    while count == 0 || seen < count {
        let reply = client
            .call_raw(Request::WaitForAccount {
                account,
                since: since.clone(),
                timeout_ms: timeout_ms as u32,
            })
            .map_err(|e| e.to_string())?;
        if !reply.is_ok() {
            return Err(format!("node rejected wait (reason {})", reply.reason));
        }
        match reply.body {
            ReplyBody::Account(info) => {
                if info == since {
                    println!("idle balance={} (timeout)", info.balance);
                } else {
                    println!(
                        "balance={} next_nonce={} state_hash={}",
                        info.balance,
                        info.next_nonce,
                        hex(&info.state_hash)
                    );
                }
                seen += 1;
                since = info;
            }
            _ => return Err("unexpected account reply".into()),
        }
    }
    Ok(())
}

fn wallet_set_state(args: &Args) -> Result<(), String> {
    let network = network(args)?;
    let wallet = load_wallet(args, network)?;
    let new_state = parse_hash(args.require("state-hash")?)?;
    let fee = args.number("fee", 0)?;
    let mut target = Target::open(args, network)?;
    let info = target.balance(&wallet.account_id())?;
    let tx = wallet.build_state_update(new_state, fee, info.next_nonce, 0);
    match target.request(Request::SubmitStateUpdate(tx))? {
        ReplyBody::Accepted(id) => {
            println!("accepted=state-update");
            println!("txid={}", hex(&id));
        }
        _ => return Err("unexpected reply".into()),
    }
    Ok(())
}

fn miner(args: &Args) -> Result<(), String> {
    if args.get("mine-threads").is_some() {
        return Err("--mine-threads applies to node run, not the separate miner command".into());
    }
    let network = network(args)?;
    let payout = parse_hash(args.require("payout")?)?;
    let blocks = args.number("blocks", 1)?;
    let mut target = Target::open(args, network)?;

    for index in 0..blocks {
        let started = std::time::Instant::now();
        loop {
            let template_started = std::time::Instant::now();
            let (mut header, transactions, height) =
                match target.request(Request::Template(payout))? {
                    ReplyBody::Template(template) => {
                        (template.header, template.transactions, template.height)
                    }
                    _ => return Err("unexpected template reply".into()),
                };
            let mut last_check = None;
            match vess_node::mine_fresh(&mut header, 200_000_000, template_started, |parent| {
                if last_check.is_some_and(|last: std::time::Instant| {
                    last.elapsed() < Duration::from_millis(50)
                }) {
                    return Ok(false);
                }
                let tip = target.status()?.tip;
                last_check = Some(std::time::Instant::now());
                Ok::<bool, String>(tip != *parent)
            })? {
                vess_node::MiningResult::Found => {}
                vess_node::MiningResult::Refresh => continue,
                vess_node::MiningResult::Exhausted => {
                    return Err("no solution after 200 million nonces".into());
                }
            }
            let bytes = assemble_block(&header, &transactions)?;
            let bytes_len = bytes.len();
            let reply = target.request_raw(Request::SubmitMinedBlock(bytes))?;
            if reply.reason == vess_node::reason::NOT_TIP {
                continue;
            }
            if !reply.is_ok() {
                return Err(format!(
                    "node rejected mined block (reason {})",
                    reply.reason
                ));
            }
            let id = match reply.body {
                ReplyBody::Accepted(id) => id,
                _ => return Err("unexpected reply".into()),
            };
            println!(
                "mined={} height={} nonce_ms={} bytes={}",
                hex(&id),
                height,
                started.elapsed().as_millis(),
                bytes_len
            );
            break;
        }
        let _ = index;
    }
    Ok(())
}

fn assemble_block(header: &BlockHeader, transactions: &[Transaction]) -> Result<Vec<u8>, String> {
    let body = vess_consensus::encode_body(transactions).map_err(|e| e.to_string())?;
    let mut bytes = Vec::with_capacity(234 + body.len());
    bytes.extend_from_slice(&header.canonical());
    bytes.extend_from_slice(&body);
    if bytes.len() > MAX_BLOCK_BYTES {
        return Err("assembled block exceeds the size limit".into());
    }
    Ok(bytes)
}
