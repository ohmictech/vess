//! `vess` — node, wallet, and miner, all driving the same core.
//!
//! Commands operate either on a local data directory (opening the database for the duration of the
//! command) or against a running node over the binary RPC.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use vess_core::constants::{
    MAX_BLOCK_BYTES, ML_DSA_PK_BYTES, NetworkProfile, P2P_DEFAULT_PORT, RPC_DEFAULT_PORT,
};
use vess_core::hash::chain_id;
use vess_core::{AccountId, BlockHeader, Hash, Transaction};
use vess_net::rpc::{ReplyBody, Request, StatusInfo};
use vess_node::{Node, bind_rpc, serve};
use vess_wallet::{Keyring, NodeClient, Wallet};

const USAGE: &str = "\
vess 0.1.0 — Vess reference node

  vess node init    --datadir DIR [--network devnet|testnet|mainnet]
  vess node run     --datadir DIR [--network ...] [--rpc PORT] [--port P2P] [--peer A,B] [--mine --payout HEX]
                    [--prune-blocks N] [--prune-headers N] [--trust-snapshot]   # 0 = keep everything
                    [--seed A,B]   # extra bootstrap peers; VESS_SEEDS also works
  vess node params  --network devnet|testnet|mainnet
  vess node status  --datadir DIR | --rpc HOST:PORT
  vess node block   --rpc HOST:PORT (--height N | --id HEX)
  vess node tx      --rpc HOST:PORT --id HEX               # position and content
  vess node watch   --rpc HOST:PORT [--count N] [--timeout MS]   # N replies, 0 = forever
  vess node account --rpc HOST:PORT --account HEX      # balance, nonce, state hash
  vess node proof   --rpc HOST:PORT --account HEX      # Merkle proof against the state root

  vess wallet new         --datadir DIR --name NAME [--legacy] [--password-file FILE | --password-env VAR]
  vess wallet addresses   --datadir DIR --name NAME [--count N] [--password-*]   # HD accounts
  vess wallet address     --datadir DIR --name NAME [--index N] [--password-file FILE | --password-env VAR]
  vess wallet address     --public-key HEX            # derive an address from a public key
  vess wallet balance     --datadir DIR --name NAME [--index N] [--rpc ADDR] [--password-*]
  vess wallet send        --datadir DIR --name NAME --to HEX --amount N [--fee N] [--index N] [--rpc ADDR] [--password-*]
  vess wallet set-state   --datadir DIR --name NAME --state-hash HEX [--fee N] [--rpc ADDR] [--password-*]
  vess wallet watch       --datadir DIR --name NAME --rpc ADDR [--count N] [--timeout MS] [--password-*]

  --password-file FILE reads the first line of FILE; --password-env VAR reads an environment
  variable. Without either, `wallet new` writes an UNENCRYPTED keyfile (legacy format) and says so,
  and any other wallet command needs one to open an encrypted keyfile.

  vess miner --datadir DIR --payout HEX [--blocks N] [--rpc ADDR]

All output is plain `key=value` text. Nothing is JSON.
";

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
}

impl Args {
    fn parse(raw: &[String]) -> Args {
        let mut flags = HashMap::new();
        let mut index = 0;
        while index < raw.len() {
            let token = &raw[index];
            if let Some(name) = token.strip_prefix("--") {
                if let Some((key, value)) = name.split_once('=') {
                    flags.insert(key.to_string(), value.to_string());
                } else if index + 1 < raw.len() && !raw[index + 1].starts_with("--") {
                    flags.insert(name.to_string(), raw[index + 1].clone());
                    index += 1;
                } else {
                    flags.insert(name.to_string(), String::from("true"));
                }
            }
            index += 1;
        }
        Args { flags }
    }

    fn get(&self, key: &str) -> Option<&str> {
        self.flags.get(key).map(|s| s.as_str())
    }

    fn require(&self, key: &str) -> Result<&str, String> {
        self.get(key).ok_or_else(|| format!("missing --{key}"))
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
                let node = Node::open(&dir, network).map_err(|e| {
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
    if raw.is_empty() || raw[0] == "help" || raw[0] == "--help" {
        println!("{USAGE}");
        return Ok(());
    }
    let args = Args::parse(&raw[1..]);
    let group = raw[0].as_str();
    let command = raw.get(1).map(|s| s.as_str()).unwrap_or("");

    match (group, command) {
        ("node", "init") => node_init(&args),
        ("node", "run") => node_run(&args),
        ("node", "status") => node_status(&args),
        ("node", "params") => node_params(&args),
        ("node", "block") => node_block(&args),
        ("node", "tx") => node_transaction(&args),
        ("node", "watch") => node_watch(&args),
        ("node", "account") => node_account(&args),
        ("node", "proof") => node_proof(&args),
        ("wallet", "new") => wallet_new(&args),
        ("wallet", "address") => wallet_address(&args),
        ("wallet", "addresses") => wallet_addresses(&args),
        ("wallet", "balance") => wallet_balance(&args),
        ("wallet", "send") => wallet_send(&args),
        ("wallet", "set-state") => wallet_set_state(&args),
        ("wallet", "watch") => wallet_watch(&args),
        ("miner", _) => miner(&args),
        other => Err(format!("unknown command {other:?}\n\n{USAGE}")),
    }
}

fn node_init(args: &Args) -> Result<(), String> {
    let network = network(args)?;
    let dir = datadir(args)?;
    let node = Node::open(&dir, network).map_err(|e| e.to_string())?;
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

    let mut node = Node::open(&dir, network).map_err(|e| e.to_string())?;
    let known_peers = node.peer_book_size().0;
    // Pruning is destructive and stored with the data, so the flags only override when present.
    if args.get("prune-blocks").is_some() || args.get("prune-headers").is_some() {
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
        );
        node.set_prune_policy(policy).map_err(|e| e.to_string())?;
    }
    let policy = node.prune_policy();
    // A snapshot this node cannot verify against a block it validated itself makes the peer's word
    // the whole account set, so it is opt-in.
    node.set_trust_snapshots(args.get("trust-snapshot").is_some());
    if node.trust_snapshots() {
        eprintln!(
            "warning: --trust-snapshot is on; a peer may supply the account set at a height this \
             node cannot validate"
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
                 behind can only join by state snapshot (--trust-snapshot), which trusts the peer \
                 for the state at that height because no trusted checkpoint exists yet.",
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
        let miner = shared.clone();
        let interval = args.number("mine-interval", 250)?;
        std::thread::spawn(move || {
            vess_node::p2p::mine(miner, payout, Duration::from_millis(interval))
        });
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
                } else {
                    println!("new_state_hash={}", hex(&info.new_state_hash));
                }
                println!("fee={}", info.fee);
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
    // New wallets are hierarchical: one master seed, accounts by index, one backup. `--legacy` writes
    // the older single-key shape, which still opens and still has exactly one address.
    let keyring = if args.get("legacy").is_some() {
        Keyring::Single(Box::new(Wallet::create(network.network)))
    } else {
        Keyring::create(network.network)
    };
    let pass = passphrase(args)?;
    keyring
        .save(&path, pass.as_ref())
        .map_err(|e| e.to_string())?;
    if pass.is_none() && keyring.is_hd() {
        // An HD keyring has no unencrypted representation: the plaintext format cannot say what the
        // seed means. `save` refuses rather than downgrading, so this cannot be reached, but say why.
        return Err("an HD keyfile must be encrypted".into());
    }
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
    keyring
        .account(args.number("index", 0)? as u32)
        .map_err(|e| e.to_string())
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

fn wallet_send(args: &Args) -> Result<(), String> {
    let network = network(args)?;
    let wallet = load_wallet(args, network)?;
    let recipient = parse_hash(args.require("to")?)?;
    let amount = args.number("amount", 0)?;
    if amount == 0 {
        return Err("--amount must be positive".into());
    }
    let fee = args.number("fee", 0)?;
    let mut target = Target::open(args, network)?;
    let info = target.balance(&wallet.account_id())?;
    let tx = wallet.build_transfer(recipient, amount, fee, info.next_nonce, 0);
    match target.request(Request::SubmitTransfer(tx))? {
        ReplyBody::Accepted(id) => {
            println!("accepted=transfer");
            println!("txid={}", hex(&id));
            println!("nonce={}", info.next_nonce);
        }
        _ => return Err("unexpected reply".into()),
    }
    Ok(())
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
