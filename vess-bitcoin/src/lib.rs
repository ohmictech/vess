use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context, Result};
use bitcoin::block::{Block, Header};
use bitcoin::blockdata::constants::genesis_block;
use bitcoin::consensus::{serialize, Decodable, Params};
use bitcoin::hashes::{sha256d, Hash};
use bitcoin::io::ErrorKind as BitcoinIoErrorKind;
use bitcoin::p2p::address::Address;
use bitcoin::p2p::message::{NetworkMessage, RawNetworkMessage};
use bitcoin::p2p::message_blockdata::{GetHeadersMessage, Inventory};
use bitcoin::p2p::message_network::VersionMessage;
use bitcoin::p2p::{Magic, ServiceFlags};
use bitcoin::pow::{CompactTarget, Work};
use bitcoin::{BlockHash, Transaction, TxMerkleNode, Txid};
use rand::Rng;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream as TokioTcpStream};
use tokio::sync::{broadcast, mpsc, oneshot};
use tracing::{info, warn};
use vess_mesh::{decode_mesh_contact_string, validate_public_mesh_contact};

mod wallet;

pub use wallet::{
    BitcoinWallet, BurnTransactionPlan, DerivedAddress, Keychain, OwnedUtxo, PendingBurn,
    WalletTransactionUpdate,
};

const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const READ_TIMEOUT: Duration = Duration::from_millis(500);
const MAX_CACHED_TXS: usize = 1024;
const MAX_CACHED_BLOCKS: usize = 64;
const DEFAULT_VESS_SEED_PORT: u16 = 18349;
const DEFAULT_VESS_SEED_SCAN_INTERVAL: Duration = Duration::from_secs(20);
const DEFAULT_VESS_SEED_SUCCESS_REPROBE_INTERVAL: Duration = Duration::from_secs(10 * 60);
const DEFAULT_VESS_SEED_FAILURE_REPROBE_INTERVAL: Duration = Duration::from_secs(5 * 60);
const MAX_VESS_SEED_FAILURE_REPROBE_INTERVAL: Duration = Duration::from_secs(60 * 60);
const VESS_SEED_PROTOCOL_VERSION: u8 = 1;
const MAX_VESS_SEED_MESSAGE_BYTES: usize = 64 * 1024;
const MAX_VESS_SEED_NODES: usize = 128;
const MAX_VESS_SEED_NODE_AGE_SECS: u64 = 24 * 60 * 60;
const MAX_VESS_SEED_NODE_FUTURE_SKEW_SECS: u64 = 10 * 60;
const MAX_VESS_SEED_REQUESTS_PER_MINUTE: u32 = 12;
const VESS_SEED_PROBE_TIMEOUT: Duration = Duration::from_secs(2);
const DEFAULT_TARGET_PEERS: usize = 24;
const DEFAULT_STABLE_TARGET_PEERS: usize = 4;
const DEFAULT_PEER_MAINTENANCE_INTERVAL: Duration = Duration::from_secs(15);
const DEFAULT_BITCOIN_PEER_RETRY_INTERVAL: Duration = Duration::from_secs(60);
const MAX_BITCOIN_PEER_RETRY_INTERVAL: Duration = Duration::from_secs(15 * 60);

fn exponential_backoff_secs(base: Duration, exponent: u32, max: Duration) -> u64 {
    let base_secs = base.as_secs().max(1);
    let max_secs = max.as_secs().max(base_secs);
    let factor = 1u64.checked_shl(exponent.min(20)).unwrap_or(u64::MAX);
    base_secs.saturating_mul(factor).min(max_secs)
}

fn current_unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn seed_node_timestamp_is_reasonable(last_seen_unix: u64, now_unix: u64) -> bool {
    last_seen_unix <= now_unix.saturating_add(MAX_VESS_SEED_NODE_FUTURE_SKEW_SECS)
        && now_unix.saturating_sub(last_seen_unix) <= MAX_VESS_SEED_NODE_AGE_SECS
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct VessSeedNode {
    pub node_id: String,
    pub contact: String,
    #[serde(default = "current_unix_timestamp")]
    pub last_seen_unix: u64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct VessSeedRequest {
    version: u8,
    requester_node: Option<VessSeedNode>,
    known_nodes: Vec<VessSeedNode>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct VessSeedResponse {
    version: u8,
    accepted: bool,
    local_node: Option<VessSeedNode>,
    known_nodes: Vec<VessSeedNode>,
}

#[derive(Debug, Clone, Copy, Default)]
struct VessSeedClientWindow {
    window_started_unix: u64,
    requests_in_window: u32,
}

#[derive(Debug, Clone)]
pub struct BurnConfirmationProof {
    pub txid: Txid,
    pub block_hash: BlockHash,
    pub block_height: u64,
    pub confirmations: u32,
    pub required_confirmations: u32,
    pub chain_work: [u8; 32],
    pub merkle_root: TxMerkleNode,
    pub merkle_proof: Vec<[u8; 32]>,
    pub merkle_index: u32,
    pub header_time: u32,
}

#[derive(Debug, Clone)]
struct HeaderRecord {
    hash: BlockHash,
    header: Header,
    height: usize,
    chain_work: Work,
}

#[derive(Debug)]
struct HeaderChain {
    network: BitcoinNetwork,
    records: Vec<HeaderRecord>,
    index: HashMap<BlockHash, usize>,
}

impl HeaderChain {
    fn new(network: BitcoinNetwork) -> Self {
        let genesis = genesis_block(network.bitcoin_network());
        let hash = genesis.block_hash();
        let record = HeaderRecord {
            hash,
            header: genesis.header,
            height: 0,
            chain_work: genesis.header.work(),
        };
        let mut index = HashMap::new();
        index.insert(hash, 0);
        Self {
            network,
            records: vec![record],
            index,
        }
    }

    fn best_height(&self) -> usize {
        self.records.len().saturating_sub(1)
    }

    fn best_hash(&self) -> BlockHash {
        self.records
            .last()
            .map(|record| record.hash)
            .unwrap_or_else(BlockHash::all_zeros)
    }

    fn candidate_blocks_since(&self, earliest_time: u64) -> Vec<(BlockHash, usize, Header, Work)> {
        self.records
            .iter()
            .enumerate()
            .rev()
            .filter(|(_, record)| record.header.time as u64 >= earliest_time)
            .map(|(_, record)| (record.hash, record.height, record.header, record.chain_work))
            .collect()
    }

    fn expected_next_bits(&self, parent_height: usize, candidate: &Header) -> CompactTarget {
        let params = self.network.consensus_params();
        let parent = self.records[parent_height].header;
        let next_height = parent_height + 1;
        let interval = params.difficulty_adjustment_interval() as usize;

        if params.no_pow_retargeting {
            return parent.bits;
        }

        if interval > 0 && next_height % interval == 0 {
            let epoch_start_height = next_height.saturating_sub(interval);
            let epoch_start = self.records[epoch_start_height].header;
            return CompactTarget::from_header_difficulty_adjustment(epoch_start, parent, params);
        }

        if params.allow_min_difficulty_blocks {
            let max_bits = params.max_attainable_target.to_compact_lossy();
            if candidate.time as u64 > parent.time as u64 + params.pow_target_spacing * 2 {
                return max_bits;
            }
            return self.last_non_min_bits(parent_height, max_bits, interval);
        }

        parent.bits
    }

    fn last_non_min_bits(
        &self,
        mut height: usize,
        max_bits: CompactTarget,
        interval: usize,
    ) -> CompactTarget {
        loop {
            let record = &self.records[height];
            if record.header.bits != max_bits || (interval > 0 && height % interval == 0) {
                return record.header.bits;
            }
            if height == 0 {
                return record.header.bits;
            }
            height -= 1;
        }
    }

    fn append_headers(&mut self, headers: &[Header]) -> Result<Option<BlockHash>> {
        let mut last_inserted = None;
        for header in headers {
            let block_hash = header.block_hash();
            if self.index.contains_key(&block_hash) {
                continue;
            }

            let Some(parent_height) = self.index.get(&header.prev_blockhash).copied() else {
                return Err(anyhow!(
                    "bitcoin header parent {} unknown for {}",
                    header.prev_blockhash,
                    block_hash
                ));
            };
            if parent_height + 1 != self.records.len() {
                return Err(anyhow!(
                    "bitcoin header {} does not extend current best chain",
                    block_hash
                ));
            }
            let expected_bits = self.expected_next_bits(parent_height, header);
            header
                .validate_pow(expected_bits.into())
                .map_err(|e| anyhow!(e))
                .context("bitcoin header PoW validation failed")?;

            let next_height = self.records.len();
            let parent_work = self.records[parent_height].chain_work;
            let chain_work = parent_work + header.work();
            anyhow::ensure!(
                chain_work > parent_work,
                "bitcoin header {} did not increase cumulative chainwork",
                block_hash
            );
            self.records.push(HeaderRecord {
                hash: block_hash,
                header: *header,
                height: next_height,
                chain_work,
            });
            self.index.insert(block_hash, next_height);
            last_inserted = Some(block_hash);
        }
        Ok(last_inserted)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum BitcoinNetwork {
    Mainnet,
    Testnet,
    Signet,
    Regtest,
}

impl BitcoinNetwork {
    fn consensus_params(self) -> Params {
        Params::new(self.bitcoin_network())
    }

    fn required_burn_confirmations(self) -> u32 {
        match self {
            Self::Mainnet | Self::Testnet | Self::Signet => 6,
            Self::Regtest => 1,
        }
    }

    fn magic(self) -> Magic {
        match self {
            Self::Mainnet => Magic::BITCOIN,
            Self::Testnet => Magic::TESTNET3,
            Self::Signet => Magic::SIGNET,
            Self::Regtest => Magic::REGTEST,
        }
    }

    fn port(self) -> u16 {
        match self {
            Self::Mainnet => 8333,
            Self::Testnet => 18333,
            Self::Signet => 38333,
            Self::Regtest => 18444,
        }
    }

    fn default_seeds(self) -> &'static [&'static str] {
        match self {
            Self::Mainnet => &[
                "seed.bitcoin.sipa.be",
                "dnsseed.bluematt.me",
                "dnsseed.bitcoin.dashjr.org",
                "seed.bitcoinstats.com",
                "seed.bitcoin.jonasschnelli.ch",
            ],
            Self::Testnet => &[
                "testnet-seed.bitcoin.jonasschnelli.ch",
                "seed.tbtc.petertodd.org",
                "seed.testnet.bitcoin.sprovoost.nl",
                "testnet-seed.bluematt.me",
            ],
            Self::Signet => &[
                "seed.signet.bitcoin.sprovoost.nl",
                "seed.signet.achownodes.xyz",
            ],
            Self::Regtest => &[],
        }
    }
}

#[derive(Debug, Clone)]
pub struct BitcoinConfig {
    pub network: BitcoinNetwork,
    pub peers: Vec<SocketAddr>,
    pub seeds: Vec<String>,
    pub target_peers: usize,
    pub connect_timeout: Duration,
    pub user_agent: String,
    pub vess_seed_port: u16,
    pub vess_seed_scan_interval: Duration,
    pub allow_private_vess_seed_contacts: bool,
}

impl Default for BitcoinConfig {
    fn default() -> Self {
        let network = BitcoinNetwork::Mainnet;
        Self {
            network,
            peers: Vec::new(),
            seeds: network
                .default_seeds()
                .iter()
                .map(|s| s.to_string())
                .collect(),
            target_peers: DEFAULT_TARGET_PEERS,
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            user_agent: "/vess-bitcoin:0.1.0/".to_string(),
            vess_seed_port: DEFAULT_VESS_SEED_PORT,
            vess_seed_scan_interval: DEFAULT_VESS_SEED_SCAN_INTERVAL,
            allow_private_vess_seed_contacts: false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ObservedTransaction {
    pub txid: Txid,
    pub transaction: Transaction,
    pub peer: SocketAddr,
}

#[derive(Clone)]
pub struct BitcoinLightClient {
    command_tx: mpsc::UnboundedSender<ClientCommand>,
    incoming_txs: broadcast::Sender<ObservedTransaction>,
    connected_peers: Arc<AtomicUsize>,
    active_peers: Arc<Mutex<HashSet<SocketAddr>>>,
    cache: Arc<Mutex<HashMap<Txid, Transaction>>>,
    block_cache: Arc<Mutex<HashMap<BlockHash, Block>>>,
    header_chain: Arc<Mutex<HeaderChain>>,
    known_vess_nodes: Arc<Mutex<HashMap<String, VessSeedNode>>>,
    known_bitcoin_peers: Arc<Mutex<HashSet<SocketAddr>>>,
    local_vess_node: Arc<Mutex<Option<VessSeedNode>>>,
    vess_probe_state: Arc<Mutex<HashMap<SocketAddr, VessSeedProbeState>>>,
    vess_seed_port: u16,
    allow_private_vess_seed_contacts: bool,
}

enum ClientCommand {
    RequestTx {
        txid: Txid,
        reply: oneshot::Sender<Result<Option<Transaction>>>,
    },
    RequestBlock {
        block_hash: BlockHash,
        reply: oneshot::Sender<Result<Option<Block>>>,
    },
    BroadcastTx {
        transaction: Transaction,
        reply: oneshot::Sender<Result<Txid>>,
    },
}

enum PeerCommand {
    RequestTx(Txid),
    RequestBlock(BlockHash),
    BroadcastTx(Transaction),
}

enum ManagerEvent {
    PeerConnected(SocketAddr),
    PeerExited(SocketAddr),
}

#[derive(Debug, Clone, Copy, Default)]
struct VessSeedProbeState {
    last_attempt_unix: u64,
    next_allowed_unix: u64,
    last_success_unix: u64,
    consecutive_failures: u32,
}

impl VessSeedProbeState {
    fn eligible(&self, now: u64) -> bool {
        now >= self.next_allowed_unix
    }

    fn mark_attempt(&mut self, now: u64) {
        self.last_attempt_unix = now;
        self.next_allowed_unix = now.saturating_add(VESS_SEED_PROBE_TIMEOUT.as_secs().max(1));
    }

    fn record_success(&mut self, now: u64) {
        self.last_attempt_unix = now;
        self.last_success_unix = now;
        self.consecutive_failures = 0;
        self.next_allowed_unix =
            now.saturating_add(DEFAULT_VESS_SEED_SUCCESS_REPROBE_INTERVAL.as_secs());
    }

    fn record_failure(&mut self, now: u64) {
        self.last_attempt_unix = now;
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        self.next_allowed_unix = now.saturating_add(exponential_backoff_secs(
            DEFAULT_VESS_SEED_FAILURE_REPROBE_INTERVAL,
            self.consecutive_failures.saturating_sub(1),
            MAX_VESS_SEED_FAILURE_REPROBE_INTERVAL,
        ));
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct BitcoinPeerRetryState {
    next_allowed_unix: u64,
    consecutive_failures: u32,
}

impl BitcoinPeerRetryState {
    fn eligible(&self, now: u64) -> bool {
        now >= self.next_allowed_unix
    }

    fn record_success(&mut self) {
        self.next_allowed_unix = 0;
        self.consecutive_failures = 0;
    }

    fn record_failure(&mut self, now: u64) {
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        self.next_allowed_unix = now.saturating_add(exponential_backoff_secs(
            DEFAULT_BITCOIN_PEER_RETRY_INTERVAL,
            self.consecutive_failures.saturating_sub(1),
            MAX_BITCOIN_PEER_RETRY_INTERVAL,
        ));
    }
}

struct SharedState {
    pending: Mutex<HashMap<Txid, Vec<oneshot::Sender<Result<Option<Transaction>>>>>>,
    cache: Arc<Mutex<HashMap<Txid, Transaction>>>,
    pending_blocks: Mutex<HashMap<BlockHash, Vec<oneshot::Sender<Result<Option<Block>>>>>>,
    block_cache: Arc<Mutex<HashMap<BlockHash, Block>>>,
    header_chain: Arc<Mutex<HeaderChain>>,
    incoming_txs: broadcast::Sender<ObservedTransaction>,
    connected_peers: Arc<AtomicUsize>,
    active_peers: Arc<Mutex<HashSet<SocketAddr>>>,
    known_bitcoin_peers: Arc<Mutex<HashSet<SocketAddr>>>,
    local_vess_node: Arc<Mutex<Option<VessSeedNode>>>,
}

impl BitcoinLightClient {
    pub async fn spawn(config: BitcoinConfig) -> Result<Self> {
        let (command_tx, command_rx) = mpsc::unbounded_channel();
        let (incoming_txs, _) = broadcast::channel(256);
        let connected_peers = Arc::new(AtomicUsize::new(0));
        let active_peers = Arc::new(Mutex::new(HashSet::new()));
        let cache = Arc::new(Mutex::new(HashMap::new()));
        let block_cache = Arc::new(Mutex::new(HashMap::new()));
        let header_chain = Arc::new(Mutex::new(HeaderChain::new(config.network)));
        let known_vess_nodes = Arc::new(Mutex::new(HashMap::new()));
        let vess_probe_state = Arc::new(Mutex::new(HashMap::new()));
        let shared = Arc::new(SharedState {
            pending: Mutex::new(HashMap::new()),
            cache: cache.clone(),
            pending_blocks: Mutex::new(HashMap::new()),
            block_cache: block_cache.clone(),
            header_chain: header_chain.clone(),
            incoming_txs: incoming_txs.clone(),
            connected_peers: connected_peers.clone(),
            active_peers: active_peers.clone(),
            known_bitcoin_peers: Arc::new(Mutex::new(HashSet::new())),
            local_vess_node: Arc::new(Mutex::new(None)),
        });

        let resolved_peers = resolve_peers(&config).await?;
        let vess_seed_port = config.vess_seed_port;
        let allow_private_vess_seed_contacts = config.allow_private_vess_seed_contacts;
        {
            let mut known_peers = shared.known_bitcoin_peers.lock().unwrap();
            known_peers.extend(resolved_peers.iter().copied());
        }
        let known_bitcoin_peers = shared.known_bitcoin_peers.clone();
        let local_vess_node = shared.local_vess_node.clone();
        tokio::spawn(run_vess_seed_listener(
            config.vess_seed_port,
            known_bitcoin_peers.clone(),
            known_vess_nodes.clone(),
            local_vess_node.clone(),
            allow_private_vess_seed_contacts,
        ));
        tokio::spawn(run_vess_seed_scanner(
            config.vess_seed_port,
            config.vess_seed_scan_interval,
            known_bitcoin_peers.clone(),
            known_vess_nodes.clone(),
            local_vess_node.clone(),
            vess_probe_state.clone(),
            allow_private_vess_seed_contacts,
        ));
        tokio::spawn(run_manager(config, resolved_peers, command_rx, shared));

        Ok(Self {
            command_tx,
            incoming_txs,
            connected_peers,
            active_peers,
            cache,
            block_cache,
            header_chain,
            known_vess_nodes,
            known_bitcoin_peers,
            local_vess_node,
            vess_probe_state,
            vess_seed_port,
            allow_private_vess_seed_contacts,
        })
    }

    pub fn set_local_vess_seed_node(&self, node_id: impl Into<String>, contact: impl Into<String>) {
        let seed = VessSeedNode {
            node_id: node_id.into(),
            contact: contact.into(),
            last_seen_unix: current_unix_timestamp(),
        };
        {
            let mut local = self.local_vess_node.lock().unwrap();
            *local = Some(seed.clone());
        }
        upsert_known_vess_node(&self.known_vess_nodes, seed, true);
    }

    pub fn known_vess_nodes(&self) -> Vec<VessSeedNode> {
        snapshot_known_vess_nodes(&self.known_vess_nodes, &self.local_vess_node)
    }

    pub async fn discover_vess_nodes(&self) -> Vec<VessSeedNode> {
        probe_vess_seed_candidates(
            self.vess_seed_port,
            self.known_bitcoin_peers.clone(),
            self.known_vess_nodes.clone(),
            self.local_vess_node.clone(),
            self.vess_probe_state.clone(),
            self.allow_private_vess_seed_contacts,
        )
        .await;
        self.known_vess_nodes()
    }

    pub async fn request_transaction(&self, txid: Txid) -> Result<Option<Transaction>> {
        if let Some(tx) = self.cache.lock().unwrap().get(&txid).cloned() {
            return Ok(Some(tx));
        }
        let (reply_tx, reply_rx) = oneshot::channel();
        self.command_tx
            .send(ClientCommand::RequestTx {
                txid,
                reply: reply_tx,
            })
            .map_err(|_| anyhow!("bitcoin light client is not running"))?;
        tokio::time::timeout(Duration::from_secs(15), reply_rx)
            .await
            .context("timed out waiting for tx response")?
            .map_err(|_| anyhow!("bitcoin light client request channel closed"))?
    }

    pub async fn broadcast_transaction(&self, transaction: Transaction) -> Result<Txid> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.command_tx
            .send(ClientCommand::BroadcastTx {
                transaction,
                reply: reply_tx,
            })
            .map_err(|_| anyhow!("bitcoin light client is not running"))?;
        reply_rx
            .await
            .map_err(|_| anyhow!("bitcoin light client broadcast channel closed"))?
    }

    pub async fn request_burn_confirmation(
        &self,
        txid: Txid,
        earliest_time: u64,
    ) -> Result<Option<BurnConfirmationProof>> {
        let (candidate_headers, best_height, required_confirmations) = {
            let chain = self.header_chain.lock().unwrap();
            (
                chain.candidate_blocks_since(earliest_time),
                chain.best_height(),
                chain.network.required_burn_confirmations(),
            )
        };

        for (block_hash, height, header, chain_work) in candidate_headers {
            let confirmations = best_height.saturating_sub(height).saturating_add(1) as u32;
            if confirmations < required_confirmations {
                continue;
            }
            let Some(block) = self.request_block(block_hash).await? else {
                continue;
            };
            if !block.check_merkle_root() {
                warn!(block_hash = %block_hash, "bitcoin block merkle root mismatch");
                continue;
            }
            if let Some((merkle_index, merkle_proof)) = compute_merkle_proof(&block, txid) {
                return Ok(Some(BurnConfirmationProof {
                    txid,
                    block_hash,
                    block_height: height as u64,
                    confirmations,
                    required_confirmations,
                    chain_work: chain_work.to_be_bytes(),
                    merkle_root: header.merkle_root,
                    merkle_proof,
                    merkle_index,
                    header_time: header.time,
                }));
            }
        }

        Ok(None)
    }

    pub fn subscribe_transactions(&self) -> broadcast::Receiver<ObservedTransaction> {
        self.incoming_txs.subscribe()
    }

    pub fn connected_peers(&self) -> usize {
        self.connected_peers.load(Ordering::Relaxed)
    }

    pub fn active_peers(&self) -> Vec<SocketAddr> {
        let mut peers: Vec<_> = self.active_peers.lock().unwrap().iter().copied().collect();
        peers.sort_unstable();
        peers
    }

    pub async fn wait_for_peers(&self, min_peers: usize, timeout: Duration) -> usize {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let connected = self.connected_peers();
            if connected >= min_peers || tokio::time::Instant::now() >= deadline {
                return connected;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }

    async fn request_block(&self, block_hash: BlockHash) -> Result<Option<Block>> {
        if let Some(block) = self.block_cache.lock().unwrap().get(&block_hash).cloned() {
            return Ok(Some(block));
        }
        let (reply_tx, reply_rx) = oneshot::channel();
        self.command_tx
            .send(ClientCommand::RequestBlock {
                block_hash,
                reply: reply_tx,
            })
            .map_err(|_| anyhow!("bitcoin light client is not running"))?;
        tokio::time::timeout(Duration::from_secs(20), reply_rx)
            .await
            .context("timed out waiting for block response")?
            .map_err(|_| anyhow!("bitcoin light client block request channel closed"))?
    }
}

async fn run_vess_seed_listener(
    vess_seed_port: u16,
    known_bitcoin_peers: Arc<Mutex<HashSet<SocketAddr>>>,
    known_vess_nodes: Arc<Mutex<HashMap<String, VessSeedNode>>>,
    local_vess_node: Arc<Mutex<Option<VessSeedNode>>>,
    allow_private_vess_seed_contacts: bool,
) {
    let request_windows = Arc::new(Mutex::new(HashMap::<IpAddr, VessSeedClientWindow>::new()));
    let listener = match TcpListener::bind((Ipv4Addr::UNSPECIFIED, vess_seed_port)).await {
        Ok(listener) => listener,
        Err(e) => {
            warn!(
                port = vess_seed_port,
                "failed to bind Vess seed listener: {e}"
            );
            return;
        }
    };

    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                let known_bitcoin_peers = known_bitcoin_peers.clone();
                let known_vess_nodes = known_vess_nodes.clone();
                let local_vess_node = local_vess_node.clone();
                let request_windows = request_windows.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_vess_seed_connection(
                        stream,
                        peer,
                        known_bitcoin_peers,
                        known_vess_nodes,
                        local_vess_node,
                        request_windows,
                        allow_private_vess_seed_contacts,
                    )
                    .await
                    {
                        warn!(peer = %peer, "Vess seed connection failed: {e}");
                    }
                });
            }
            Err(e) => warn!(
                port = vess_seed_port,
                "accept on Vess seed listener failed: {e}"
            ),
        }
    }
}

async fn run_vess_seed_scanner(
    vess_seed_port: u16,
    scan_interval: Duration,
    known_bitcoin_peers: Arc<Mutex<HashSet<SocketAddr>>>,
    known_vess_nodes: Arc<Mutex<HashMap<String, VessSeedNode>>>,
    local_vess_node: Arc<Mutex<Option<VessSeedNode>>>,
    vess_probe_state: Arc<Mutex<HashMap<SocketAddr, VessSeedProbeState>>>,
    allow_private_vess_seed_contacts: bool,
) {
    let mut interval = tokio::time::interval(scan_interval);
    loop {
        interval.tick().await;
        probe_vess_seed_candidates(
            vess_seed_port,
            known_bitcoin_peers.clone(),
            known_vess_nodes.clone(),
            local_vess_node.clone(),
            vess_probe_state.clone(),
            allow_private_vess_seed_contacts,
        )
        .await;
    }
}

fn due_vess_seed_probe_peers(
    known_bitcoin_peers: &HashSet<SocketAddr>,
    probe_state: &HashMap<SocketAddr, VessSeedProbeState>,
    now: u64,
) -> Vec<SocketAddr> {
    let mut peers: Vec<_> = known_bitcoin_peers
        .iter()
        .copied()
        .filter(|peer| probe_state.get(peer).copied().unwrap_or_default().eligible(now))
        .collect();
    peers.sort_by_key(|peer| {
        let state = probe_state.get(peer).copied().unwrap_or_default();
        (state.last_attempt_unix, state.last_success_unix, *peer)
    });
    peers
}

fn mark_vess_seed_probe_attempts(
    probe_state: &mut HashMap<SocketAddr, VessSeedProbeState>,
    peers: &[SocketAddr],
    now: u64,
) {
    for peer in peers {
        probe_state.entry(*peer).or_default().mark_attempt(now);
    }
}

fn record_vess_seed_probe_success(
    vess_probe_state: &Arc<Mutex<HashMap<SocketAddr, VessSeedProbeState>>>,
    peer: SocketAddr,
) {
    let now = current_unix_timestamp();
    vess_probe_state
        .lock()
        .unwrap()
        .entry(peer)
        .or_default()
        .record_success(now);
}

fn record_vess_seed_probe_failure(
    vess_probe_state: &Arc<Mutex<HashMap<SocketAddr, VessSeedProbeState>>>,
    peer: SocketAddr,
) {
    let now = current_unix_timestamp();
    vess_probe_state
        .lock()
        .unwrap()
        .entry(peer)
        .or_default()
        .record_failure(now);
}

async fn probe_vess_seed_candidates(
    vess_seed_port: u16,
    known_bitcoin_peers: Arc<Mutex<HashSet<SocketAddr>>>,
    known_vess_nodes: Arc<Mutex<HashMap<String, VessSeedNode>>>,
    local_vess_node: Arc<Mutex<Option<VessSeedNode>>>,
    vess_probe_state: Arc<Mutex<HashMap<SocketAddr, VessSeedProbeState>>>,
    allow_private_vess_seed_contacts: bool,
) {
    let known_peers = known_bitcoin_peers.lock().unwrap().clone();
    let now = current_unix_timestamp();
    let peers = {
        let probe_state = vess_probe_state.lock().unwrap();
        due_vess_seed_probe_peers(&known_peers, &probe_state, now)
    };
    if peers.is_empty() {
        return;
    }
    {
        let mut probe_state = vess_probe_state.lock().unwrap();
        mark_vess_seed_probe_attempts(&mut probe_state, &peers, now);
    }
    let request = VessSeedRequest {
        version: VESS_SEED_PROTOCOL_VERSION,
        requester_node: refreshed_local_vess_node(&local_vess_node),
        known_nodes: snapshot_known_vess_nodes(&known_vess_nodes, &local_vess_node),
    };

    let mut tasks = tokio::task::JoinSet::new();
    for peer in peers {
        let addr = SocketAddr::new(peer.ip(), vess_seed_port);
        let request = request.clone();
        tasks.spawn(async move {
            let result = match tokio::time::timeout(
                VESS_SEED_PROBE_TIMEOUT,
                probe_vess_seed_peer(addr, &request),
            )
            .await
            {
                Ok(result) => result,
                Err(_) => Err(anyhow!("Vess seed probe timed out")),
            };
            (addr, result)
        });
    }

    while let Some(joined) = tasks.join_next().await {
        let Ok((addr, result)) = joined else {
            continue;
        };
        match result {
            Ok(response) if response.accepted => {
                record_vess_seed_probe_success(&vess_probe_state, addr);
                if let Some(node) = response.local_node {
                    upsert_known_vess_node(
                        &known_vess_nodes,
                        node,
                        allow_private_vess_seed_contacts,
                    );
                }
                merge_known_vess_nodes(
                    &known_vess_nodes,
                    response.known_nodes,
                    allow_private_vess_seed_contacts,
                );
            }
            Ok(_) => {
                record_vess_seed_probe_failure(&vess_probe_state, addr);
            }
            Err(e) => {
                record_vess_seed_probe_failure(&vess_probe_state, addr);
                warn!(peer = %addr, "Vess seed probe failed: {e}");
            }
        }
    }
}

async fn probe_vess_seed_peer(
    addr: SocketAddr,
    request: &VessSeedRequest,
) -> Result<VessSeedResponse> {
    let mut stream = tokio::time::timeout(DEFAULT_CONNECT_TIMEOUT, TokioTcpStream::connect(addr))
        .await
        .with_context(|| format!("timed out connecting to Vess seed peer {addr}"))??;
    write_seed_message(&mut stream, request).await?;
    read_seed_message(&mut stream).await
}

async fn handle_vess_seed_connection(
    mut stream: TokioTcpStream,
    peer: SocketAddr,
    known_bitcoin_peers: Arc<Mutex<HashSet<SocketAddr>>>,
    known_vess_nodes: Arc<Mutex<HashMap<String, VessSeedNode>>>,
    local_vess_node: Arc<Mutex<Option<VessSeedNode>>>,
    request_windows: Arc<Mutex<HashMap<IpAddr, VessSeedClientWindow>>>,
    allow_private_vess_seed_contacts: bool,
) -> Result<()> {
    let now_unix = current_unix_timestamp();
    let accepted = should_accept_vess_seed_request(
        peer,
        &known_bitcoin_peers.lock().unwrap(),
        &mut request_windows.lock().unwrap(),
        now_unix,
    );
    if !accepted {
        let response = VessSeedResponse {
            version: VESS_SEED_PROTOCOL_VERSION,
            accepted: false,
            local_node: None,
            known_nodes: Vec::new(),
        };
        write_seed_message(&mut stream, &response).await?;
        return Ok(());
    }

    let request: VessSeedRequest = read_seed_message(&mut stream).await?;
    if request.version != VESS_SEED_PROTOCOL_VERSION {
        let response = VessSeedResponse {
            version: VESS_SEED_PROTOCOL_VERSION,
            accepted: false,
            local_node: refreshed_local_vess_node(&local_vess_node),
            known_nodes: Vec::new(),
        };
        write_seed_message(&mut stream, &response).await?;
        return Ok(());
    }

    if let Some(node) = request.requester_node {
        upsert_known_vess_node(
            &known_vess_nodes,
            node,
            allow_private_vess_seed_contacts,
        );
    }
    merge_known_vess_nodes(
        &known_vess_nodes,
        request.known_nodes,
        allow_private_vess_seed_contacts,
    );

    let response = VessSeedResponse {
        version: VESS_SEED_PROTOCOL_VERSION,
        accepted: true,
        local_node: refreshed_local_vess_node(&local_vess_node),
        known_nodes: snapshot_known_vess_nodes(&known_vess_nodes, &local_vess_node),
    };
    write_seed_message(&mut stream, &response).await?;
    Ok(())
}

fn known_bitcoin_peer_matches_ip(peer: SocketAddr, known_bitcoin_peers: &HashSet<SocketAddr>) -> bool {
    known_bitcoin_peers.iter().any(|known| known.ip() == peer.ip())
}

fn rate_limit_vess_seed_client(
    peer: SocketAddr,
    request_windows: &mut HashMap<IpAddr, VessSeedClientWindow>,
    now_unix: u64,
) -> bool {
    let entry = request_windows.entry(peer.ip()).or_default();
    if now_unix.saturating_sub(entry.window_started_unix) >= 60 {
        entry.window_started_unix = now_unix;
        entry.requests_in_window = 0;
    }
    if entry.requests_in_window >= MAX_VESS_SEED_REQUESTS_PER_MINUTE {
        return false;
    }
    entry.requests_in_window += 1;
    true
}

fn should_accept_vess_seed_request(
    peer: SocketAddr,
    known_bitcoin_peers: &HashSet<SocketAddr>,
    request_windows: &mut HashMap<IpAddr, VessSeedClientWindow>,
    now_unix: u64,
) -> bool {
    known_bitcoin_peer_matches_ip(peer, known_bitcoin_peers)
        && rate_limit_vess_seed_client(peer, request_windows, now_unix)
}

fn refreshed_local_vess_node(
    local_vess_node: &Arc<Mutex<Option<VessSeedNode>>>,
) -> Option<VessSeedNode> {
    local_vess_node.lock().unwrap().clone().map(|mut node| {
        node.last_seen_unix = current_unix_timestamp();
        node
    })
}

async fn read_seed_message<T: serde::de::DeserializeOwned>(
    stream: &mut TokioTcpStream,
) -> Result<T> {
    let message_len = stream
        .read_u32()
        .await
        .context("read Vess seed message length")? as usize;
    if message_len > MAX_VESS_SEED_MESSAGE_BYTES {
        return Err(anyhow!("Vess seed message too large: {message_len} bytes"));
    }
    let mut buffer = vec![0u8; message_len];
    stream
        .read_exact(&mut buffer)
        .await
        .context("read Vess seed message body")?;
    serde_json::from_slice(&buffer).context("decode Vess seed message")
}

async fn write_seed_message<T: serde::Serialize>(
    stream: &mut TokioTcpStream,
    message: &T,
) -> Result<()> {
    let payload = serde_json::to_vec(message).context("encode Vess seed message")?;
    if payload.len() > MAX_VESS_SEED_MESSAGE_BYTES {
        return Err(anyhow!(
            "Vess seed message too large: {} bytes",
            payload.len()
        ));
    }
    stream
        .write_u32(payload.len() as u32)
        .await
        .context("write Vess seed message length")?;
    stream
        .write_all(&payload)
        .await
        .context("write Vess seed message body")?;
    stream.flush().await.context("flush Vess seed message")?;
    Ok(())
}

fn snapshot_known_vess_nodes(
    known_vess_nodes: &Arc<Mutex<HashMap<String, VessSeedNode>>>,
    local_vess_node: &Arc<Mutex<Option<VessSeedNode>>>,
) -> Vec<VessSeedNode> {
    let mut nodes = known_vess_nodes.lock().unwrap().clone();
    if let Some(node) = refreshed_local_vess_node(local_vess_node) {
        nodes.insert(node.node_id.clone(), node);
    }
    let mut nodes: Vec<_> = nodes.into_values().collect();
    nodes.sort_unstable_by(|left, right| {
        right
            .last_seen_unix
            .cmp(&left.last_seen_unix)
            .then_with(|| left.node_id.cmp(&right.node_id))
    });
    if nodes.len() > MAX_VESS_SEED_NODES {
        nodes.truncate(MAX_VESS_SEED_NODES);
    }
    nodes
}

fn merge_known_vess_nodes(
    known_vess_nodes: &Arc<Mutex<HashMap<String, VessSeedNode>>>,
    nodes: Vec<VessSeedNode>,
    allow_private_vess_seed_contacts: bool,
) {
    for node in nodes {
        upsert_known_vess_node(known_vess_nodes, node, allow_private_vess_seed_contacts);
    }
}

fn upsert_known_vess_node(
    known_vess_nodes: &Arc<Mutex<HashMap<String, VessSeedNode>>>,
    mut node: VessSeedNode,
    allow_private_vess_seed_contacts: bool,
) {
    let node_id = node.node_id.trim().to_string();
    let contact = node.contact.trim().to_string();
    if node_id.is_empty() || contact.is_empty() {
        return;
    }
    if !seed_contact_matches_node_id(&node_id, &contact, allow_private_vess_seed_contacts) {
        warn!(
            node_id,
            "skipping Vess seed node with invalid or mismatched mesh contact"
        );
        return;
    }
    let now_unix = current_unix_timestamp();
    if node.last_seen_unix == 0 {
        node.last_seen_unix = now_unix;
    }
    if !seed_node_timestamp_is_reasonable(node.last_seen_unix, now_unix) {
        warn!(node_id, last_seen_unix = node.last_seen_unix, "skipping stale or future-dated Vess seed node");
        return;
    }
    node.node_id = node_id.clone();
    node.contact = contact;

    let mut known = known_vess_nodes.lock().unwrap();
    match known.get(&node.node_id) {
        Some(existing) if existing.last_seen_unix > node.last_seen_unix => {
            return;
        }
        Some(existing)
            if existing.last_seen_unix == node.last_seen_unix
                && existing.contact != node.contact =>
        {
            warn!(node_id, "ignoring equal-timestamp Vess seed contact replacement");
            return;
        }
        _ => {
            known.insert(node.node_id.clone(), node);
        }
    }
}

fn seed_contact_matches_node_id(
    node_id: &str,
    contact: &str,
    allow_private_vess_seed_contacts: bool,
) -> bool {
    let Ok(contact) = decode_mesh_contact_string(contact) else {
        return false;
    };
    if !allow_private_vess_seed_contacts && validate_public_mesh_contact(&contact).is_err() {
        return false;
    }
    contact
        .node_id()
        .map(|contact_node_id| contact_node_id.to_string() == node_id)
        .unwrap_or(false)
}

async fn resolve_peers(config: &BitcoinConfig) -> Result<Vec<SocketAddr>> {
    let mut peers = config.peers.clone();
    for seed in &config.seeds {
        let host = format!("{}:{}", seed, config.network.port());
        let resolved = tokio::net::lookup_host(host.as_str()).await;
        match resolved {
            Ok(addrs) => peers.extend(addrs),
            Err(e) => warn!(seed = %seed, "bitcoin DNS seed resolution failed: {e}"),
        }
    }
    peers.sort_unstable();
    peers.dedup();
    if peers.is_empty() {
        return Err(anyhow!("no bitcoin peers resolved"));
    }
    Ok(peers)
}

async fn run_manager(
    config: BitcoinConfig,
    resolved_peers: Vec<SocketAddr>,
    mut command_rx: mpsc::UnboundedReceiver<ClientCommand>,
    shared: Arc<SharedState>,
) {
    let (manager_event_tx, mut manager_event_rx) = mpsc::unbounded_channel();
    let preferred_peers = resolved_peers;
    let mut peer_senders: HashMap<SocketAddr, mpsc::UnboundedSender<PeerCommand>> =
        HashMap::new();
    let mut peer_order = Vec::new();
    let mut peer_retry_state: HashMap<SocketAddr, BitcoinPeerRetryState> = HashMap::new();
    let mut next_peer = 0usize;
    let mut maintenance = tokio::time::interval(DEFAULT_PEER_MAINTENANCE_INTERVAL);

    maintain_peer_pool(
        &config,
        &preferred_peers,
        &shared,
        &manager_event_tx,
        &mut peer_senders,
        &mut peer_order,
        &mut peer_retry_state,
    );

    loop {
        tokio::select! {
            _ = maintenance.tick() => {
                maintain_peer_pool(
                    &config,
                    &preferred_peers,
                    &shared,
                    &manager_event_tx,
                    &mut peer_senders,
                    &mut peer_order,
                    &mut peer_retry_state,
                );
            }
            Some(event) = manager_event_rx.recv() => {
                match event {
                    ManagerEvent::PeerConnected(peer) => {
                        peer_retry_state.entry(peer).or_default().record_success();
                    }
                    ManagerEvent::PeerExited(peer) => {
                        if drop_peer_sender(peer, &mut peer_senders, &mut peer_order) {
                            peer_retry_state.entry(peer).or_default().record_failure(current_unix_timestamp());
                        }
                    }
                }
            }
            command = command_rx.recv() => {
                let Some(command) = command else {
                    break;
                };

                if peer_order.is_empty() {
                    match command {
                        ClientCommand::RequestTx { reply, .. } => {
                            let _ = reply.send(Err(anyhow!("no bitcoin peers connected")));
                        }
                        ClientCommand::RequestBlock { reply, .. } => {
                            let _ = reply.send(Err(anyhow!("no bitcoin peers connected")));
                        }
                        ClientCommand::BroadcastTx { reply, .. } => {
                            let _ = reply.send(Err(anyhow!("no bitcoin peers connected")));
                        }
                    }
                    continue;
                }

                match command {
                    ClientCommand::RequestTx { txid, reply } => {
                        shared.pending.lock().unwrap().entry(txid).or_default().push(reply);
                        if !send_to_available_peer(
                            &mut peer_senders,
                            &mut peer_order,
                            &mut next_peer,
                            &mut peer_retry_state,
                            || PeerCommand::RequestTx(txid),
                        ) {
                            if let Some(waiters) = shared.pending.lock().unwrap().remove(&txid) {
                                for waiter in waiters {
                                    let _ = waiter.send(Err(anyhow!("bitcoin peer channel closed")));
                                }
                            }
                        }
                    }
                    ClientCommand::RequestBlock { block_hash, reply } => {
                        shared.pending_blocks.lock().unwrap().entry(block_hash).or_default().push(reply);
                        if !send_to_available_peer(
                            &mut peer_senders,
                            &mut peer_order,
                            &mut next_peer,
                            &mut peer_retry_state,
                            || PeerCommand::RequestBlock(block_hash),
                        ) {
                            if let Some(waiters) = shared.pending_blocks.lock().unwrap().remove(&block_hash) {
                                for waiter in waiters {
                                    let _ = waiter.send(Err(anyhow!("bitcoin peer channel closed")));
                                }
                            }
                        }
                    }
                    ClientCommand::BroadcastTx { transaction, reply } => {
                        let txid = transaction.compute_txid();
                        let mut ok = false;
                        for peer in peer_order.clone() {
                            let Some(sender) = peer_senders.get(&peer).cloned() else {
                                continue;
                            };
                            if sender.send(PeerCommand::BroadcastTx(transaction.clone())).is_ok() {
                                ok = true;
                            } else {
                                drop_peer_sender(peer, &mut peer_senders, &mut peer_order);
                                peer_retry_state.entry(peer).or_default().record_failure(current_unix_timestamp());
                            }
                        }
                        let _ = if ok {
                            reply.send(Ok(txid))
                        } else {
                            reply.send(Err(anyhow!("failed to forward bitcoin transaction to any peer")))
                        };
                    }
                }

                if peer_senders.len() < config.target_peers.max(1) {
                    maintain_peer_pool(
                        &config,
                        &preferred_peers,
                        &shared,
                        &manager_event_tx,
                        &mut peer_senders,
                        &mut peer_order,
                        &mut peer_retry_state,
                    );
                }
            }
        }
    }
}

fn collect_connection_candidates(
    preferred_peers: &[SocketAddr],
    known_peers: &HashSet<SocketAddr>,
) -> Vec<SocketAddr> {
    let mut out = Vec::with_capacity(preferred_peers.len() + known_peers.len());
    let mut seen = HashSet::new();

    for peer in preferred_peers {
        if seen.insert(*peer) {
            out.push(*peer);
        }
    }

    let mut learned: Vec<_> = known_peers.iter().copied().collect();
    learned.sort_unstable();
    for peer in learned {
        if seen.insert(peer) {
            out.push(peer);
        }
    }

    out
}

fn drop_peer_sender(
    peer: SocketAddr,
    peer_senders: &mut HashMap<SocketAddr, mpsc::UnboundedSender<PeerCommand>>,
    peer_order: &mut Vec<SocketAddr>,
) -> bool {
    let removed = peer_senders.remove(&peer).is_some();
    if removed {
        peer_order.retain(|candidate| *candidate != peer);
    }
    removed
}

fn maintain_peer_pool(
    config: &BitcoinConfig,
    preferred_peers: &[SocketAddr],
    shared: &Arc<SharedState>,
    manager_event_tx: &mpsc::UnboundedSender<ManagerEvent>,
    peer_senders: &mut HashMap<SocketAddr, mpsc::UnboundedSender<PeerCommand>>,
    peer_order: &mut Vec<SocketAddr>,
    peer_retry_state: &mut HashMap<SocketAddr, BitcoinPeerRetryState>,
) {
    let target = config.target_peers.max(1);
    let stable_target = target.min(DEFAULT_STABLE_TARGET_PEERS.max(1));
    let now = current_unix_timestamp();

    for peer in preferred_peers.iter().copied().take(stable_target) {
        if peer_senders.len() >= target {
            return;
        }
        if peer_senders.contains_key(&peer) {
            continue;
        }
        if !peer_retry_state.get(&peer).copied().unwrap_or_default().eligible(now) {
            continue;
        }
        if let Ok(sender) = spawn_peer(peer, config, shared.clone(), manager_event_tx.clone()) {
            peer_senders.insert(peer, sender);
            peer_order.push(peer);
        }
    }

    if peer_senders.len() >= target {
        return;
    }

    let known_peers = shared.known_bitcoin_peers.lock().unwrap().clone();
    for peer in collect_connection_candidates(preferred_peers, &known_peers) {
        if peer_senders.len() >= target {
            return;
        }
        if peer_senders.contains_key(&peer) {
            continue;
        }
        if !peer_retry_state.get(&peer).copied().unwrap_or_default().eligible(now) {
            continue;
        }
        if let Ok(sender) = spawn_peer(peer, config, shared.clone(), manager_event_tx.clone()) {
            peer_senders.insert(peer, sender);
            peer_order.push(peer);
        }
    }
}

fn send_to_available_peer<F>(
    peer_senders: &mut HashMap<SocketAddr, mpsc::UnboundedSender<PeerCommand>>,
    peer_order: &mut Vec<SocketAddr>,
    next_peer: &mut usize,
    peer_retry_state: &mut HashMap<SocketAddr, BitcoinPeerRetryState>,
    mut command: F,
) -> bool
where
    F: FnMut() -> PeerCommand,
{
    let attempts = peer_order.len();
    for _ in 0..attempts {
        if peer_order.is_empty() {
            break;
        }
        let idx = *next_peer % peer_order.len();
        *next_peer = next_peer.wrapping_add(1);
        let peer = peer_order[idx];
        let Some(sender) = peer_senders.get(&peer).cloned() else {
            drop_peer_sender(peer, peer_senders, peer_order);
            continue;
        };
        if sender.send(command()).is_ok() {
            return true;
        }
        drop_peer_sender(peer, peer_senders, peer_order);
        peer_retry_state.entry(peer).or_default().record_failure(current_unix_timestamp());
    }
    false
}

fn spawn_peer(
    peer: SocketAddr,
    config: &BitcoinConfig,
    shared: Arc<SharedState>,
    manager_event_tx: mpsc::UnboundedSender<ManagerEvent>,
) -> Result<mpsc::UnboundedSender<PeerCommand>> {
    let (peer_tx, peer_rx) = mpsc::unbounded_channel();
    let network = config.network;
    let connect_timeout = config.connect_timeout;
    let user_agent = config.user_agent.clone();
    tokio::task::spawn_blocking(move || {
        if let Err(e) = peer_worker(
            peer,
            network,
            connect_timeout,
            &user_agent,
            peer_rx,
            shared,
            manager_event_tx.clone(),
        ) {
            warn!(peer = %peer, "bitcoin peer worker exited: {e}");
        }
        let _ = manager_event_tx.send(ManagerEvent::PeerExited(peer));
    });
    Ok(peer_tx)
}

fn peer_worker(
    peer: SocketAddr,
    network: BitcoinNetwork,
    connect_timeout: Duration,
    user_agent: &str,
    mut peer_rx: mpsc::UnboundedReceiver<PeerCommand>,
    shared: Arc<SharedState>,
    manager_event_tx: mpsc::UnboundedSender<ManagerEvent>,
) -> Result<()> {
    let mut stream = TcpStream::connect_timeout(&peer, connect_timeout)
        .with_context(|| format!("connect to bitcoin peer {peer}"))?;
    stream
        .set_read_timeout(Some(READ_TIMEOUT))
        .context("set bitcoin peer read timeout")?;
    stream
        .set_write_timeout(Some(connect_timeout))
        .context("set bitcoin peer write timeout")?;

    handshake(&mut stream, network, peer, user_agent)?;
    shared.known_bitcoin_peers.lock().unwrap().insert(peer);
    let _peer_guard = ConnectedPeerGuard::new(
        shared.connected_peers.clone(),
        shared.active_peers.clone(),
        peer,
    );
    info!(peer = %peer, "bitcoin peer connected");
    let _ = manager_event_tx.send(ManagerEvent::PeerConnected(peer));

    loop {
        while let Ok(command) = peer_rx.try_recv() {
            match command {
                PeerCommand::RequestTx(txid) => {
                    send_message(
                        &mut stream,
                        network,
                        NetworkMessage::GetData(vec![Inventory::Transaction(txid)]),
                    )?;
                }
                PeerCommand::RequestBlock(block_hash) => {
                    send_message(
                        &mut stream,
                        network,
                        NetworkMessage::GetData(vec![Inventory::Block(block_hash)]),
                    )?;
                }
                PeerCommand::BroadcastTx(transaction) => {
                    send_message(&mut stream, network, NetworkMessage::Tx(transaction))?;
                }
            }
        }

        match RawNetworkMessage::consensus_decode(&mut stream) {
            Ok(message) => {
                handle_incoming(peer, network, &mut stream, message.into_payload(), &shared)?
            }
            Err(bitcoin::consensus::encode::Error::Io(ref err))
                if matches!(
                    err.kind(),
                    BitcoinIoErrorKind::WouldBlock | BitcoinIoErrorKind::TimedOut
                ) =>
            {
                continue;
            }
            Err(e) => return Err(anyhow!(e).context("decode bitcoin network message")),
        }
    }
}

fn handle_incoming(
    peer: SocketAddr,
    network: BitcoinNetwork,
    stream: &mut TcpStream,
    message: NetworkMessage,
    shared: &Arc<SharedState>,
) -> Result<()> {
    match message {
        NetworkMessage::Version(_) => {
            send_message(stream, network, NetworkMessage::Verack)?;
        }
        NetworkMessage::Addr(addresses) => {
            let mut known_peers = shared.known_bitcoin_peers.lock().unwrap();
            known_peers.extend(
                addresses
                    .into_iter()
                    .filter_map(|(_, address)| address.socket_addr().ok()),
            );
        }
        NetworkMessage::AddrV2(addresses) => {
            let mut known_peers = shared.known_bitcoin_peers.lock().unwrap();
            known_peers.extend(
                addresses
                    .into_iter()
                    .filter_map(|address| address.socket_addr().ok()),
            );
        }
        NetworkMessage::Ping(nonce) => {
            send_message(stream, network, NetworkMessage::Pong(nonce))?;
        }
        NetworkMessage::Inv(inventory) => {
            let tx_inventory: Vec<_> = inventory
                .into_iter()
                .filter(|item| matches!(item, Inventory::Transaction(_)))
                .collect();
            if !tx_inventory.is_empty() {
                send_message(stream, network, NetworkMessage::GetData(tx_inventory))?;
            }
        }
        NetworkMessage::Headers(headers) => {
            let last_inserted = {
                let mut chain = shared.header_chain.lock().unwrap();
                chain.append_headers(&headers)?
            };
            if headers.len() == 2000 {
                let locator = last_inserted
                    .or_else(|| headers.last().map(|header| header.block_hash()))
                    .unwrap_or_else(|| shared.header_chain.lock().unwrap().best_hash());
                send_message(
                    stream,
                    network,
                    NetworkMessage::GetHeaders(GetHeadersMessage::new(
                        vec![locator],
                        BlockHash::all_zeros(),
                    )),
                )?;
            }
        }
        NetworkMessage::Tx(transaction) => {
            let txid = transaction.compute_txid();
            {
                let mut cache = shared.cache.lock().unwrap();
                if cache.len() >= MAX_CACHED_TXS {
                    if let Some(first_key) = cache.keys().next().cloned() {
                        cache.remove(&first_key);
                    }
                }
                cache.insert(txid, transaction.clone());
            }
            let observed = ObservedTransaction {
                txid,
                transaction: transaction.clone(),
                peer,
            };
            let _ = shared.incoming_txs.send(observed);
            if let Some(waiters) = shared.pending.lock().unwrap().remove(&txid) {
                for waiter in waiters {
                    let _ = waiter.send(Ok(Some(transaction.clone())));
                }
            }
        }
        NetworkMessage::Block(block) => {
            let block_hash = block.block_hash();
            {
                let mut cache = shared.block_cache.lock().unwrap();
                if cache.len() >= MAX_CACHED_BLOCKS {
                    if let Some(first_key) = cache.keys().next().cloned() {
                        cache.remove(&first_key);
                    }
                }
                cache.insert(block_hash, block.clone());
            }
            if let Some(waiters) = shared.pending_blocks.lock().unwrap().remove(&block_hash) {
                for waiter in waiters {
                    let _ = waiter.send(Ok(Some(block.clone())));
                }
            }
        }
        NetworkMessage::NotFound(inventory) => {
            let mut pending = shared.pending.lock().unwrap();
            let mut pending_blocks = shared.pending_blocks.lock().unwrap();
            for item in inventory {
                match item {
                    Inventory::Transaction(txid) => {
                        if let Some(waiters) = pending.remove(&txid) {
                            for waiter in waiters {
                                let _ = waiter.send(Ok(None));
                            }
                        }
                    }
                    Inventory::Block(block_hash) => {
                        if let Some(waiters) = pending_blocks.remove(&block_hash) {
                            for waiter in waiters {
                                let _ = waiter.send(Ok(None));
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
        _ => {}
    }
    Ok(())
}

fn handshake(
    stream: &mut TcpStream,
    network: BitcoinNetwork,
    peer: SocketAddr,
    user_agent: &str,
) -> Result<()> {
    let receiver = Address::new(&peer, ServiceFlags::NONE);
    let sender = Address::new(
        &SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        ServiceFlags::NONE,
    );
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let nonce = rand::thread_rng().gen::<u64>();
    let version = VersionMessage::new(
        ServiceFlags::NONE,
        timestamp,
        receiver,
        sender,
        nonce,
        user_agent.to_string(),
        0,
    );
    send_message(stream, network, NetworkMessage::Version(version))?;

    let mut saw_version = false;
    let mut saw_verack = false;
    while !saw_version || !saw_verack {
        match RawNetworkMessage::consensus_decode(stream) {
            Ok(message) => match message.into_payload() {
                NetworkMessage::Version(_) => {
                    saw_version = true;
                    send_message(stream, network, NetworkMessage::Verack)?;
                }
                NetworkMessage::Verack => {
                    saw_verack = true;
                }
                NetworkMessage::Ping(nonce) => {
                    send_message(stream, network, NetworkMessage::Pong(nonce))?;
                }
                _ => {}
            },
            Err(bitcoin::consensus::encode::Error::Io(ref err))
                if matches!(
                    err.kind(),
                    BitcoinIoErrorKind::WouldBlock | BitcoinIoErrorKind::TimedOut
                ) =>
            {
                return Err(anyhow!("timed out during bitcoin handshake with {peer}"));
            }
            Err(e) => return Err(anyhow!(e).context("decode bitcoin handshake message")),
        }
    }

    send_message(stream, network, NetworkMessage::WtxidRelay)?;
    send_message(stream, network, NetworkMessage::SendAddrV2)?;
    send_message(stream, network, NetworkMessage::SendHeaders)?;
    send_message(stream, network, NetworkMessage::MemPool)?;
    send_message(stream, network, NetworkMessage::GetAddr)?;
    send_message(
        stream,
        network,
        NetworkMessage::GetHeaders(GetHeadersMessage::new(
            vec![genesis_block(network.bitcoin_network()).block_hash()],
            BlockHash::all_zeros(),
        )),
    )?;
    Ok(())
}

fn compute_merkle_proof(block: &Block, txid: Txid) -> Option<(u32, Vec<[u8; 32]>)> {
    let mut layer: Vec<[u8; 32]> = block
        .txdata
        .iter()
        .map(|transaction| transaction.compute_txid().to_byte_array())
        .collect();
    let mut index = layer
        .iter()
        .position(|current| *current == txid.to_byte_array())?;
    let merkle_index = index as u32;
    let mut proof = Vec::new();

    while layer.len() > 1 {
        if layer.len() % 2 == 1 {
            let last = *layer.last().unwrap();
            layer.push(last);
        }

        let sibling_index = if index % 2 == 0 { index + 1 } else { index - 1 };
        proof.push(layer[sibling_index]);

        let mut next_layer = Vec::with_capacity(layer.len() / 2);
        for pair in layer.chunks(2) {
            let mut data = Vec::with_capacity(64);
            data.extend_from_slice(&pair[0]);
            data.extend_from_slice(&pair[1]);
            next_layer.push(sha256d::Hash::hash(&data).to_byte_array());
        }
        index /= 2;
        layer = next_layer;
    }

    let root = TxMerkleNode::from_byte_array(layer[0]);
    if root != block.header.merkle_root {
        return None;
    }
    Some((merkle_index, proof))
}

fn send_message(
    stream: &mut TcpStream,
    network: BitcoinNetwork,
    payload: NetworkMessage,
) -> Result<()> {
    let raw = RawNetworkMessage::new(network.magic(), payload);
    let bytes = serialize(&raw);
    std::io::Write::write_all(stream, &bytes).context("write bitcoin network message")?;
    std::io::Write::flush(stream).context("flush bitcoin network message")?;
    Ok(())
}

struct ConnectedPeerGuard {
    connected_peers: Arc<AtomicUsize>,
    active_peers: Arc<Mutex<HashSet<SocketAddr>>>,
    peer: SocketAddr,
}

impl ConnectedPeerGuard {
    fn new(
        connected_peers: Arc<AtomicUsize>,
        active_peers: Arc<Mutex<HashSet<SocketAddr>>>,
        peer: SocketAddr,
    ) -> Self {
        connected_peers.fetch_add(1, Ordering::Relaxed);
        active_peers.lock().unwrap().insert(peer);
        Self {
            connected_peers,
            active_peers,
            peer,
        }
    }
}

impl Drop for ConnectedPeerGuard {
    fn drop(&mut self) {
        self.connected_peers.fetch_sub(1, Ordering::Relaxed);
        self.active_peers.lock().unwrap().remove(&self.peer);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_seed_node(seed_byte: u8, addr: &str, last_seen_unix: u64) -> VessSeedNode {
        let seed = [seed_byte; 64];
        let (_, mesh_address) = vess_mesh::generate_mesh_keys_from_seed(&seed, 0);
        let contact = vess_mesh::MeshCarrierContact::UdpSocket {
            addr: addr.to_string(),
            mesh_address,
        };
        VessSeedNode {
            node_id: contact.node_id().unwrap().to_string(),
            contact: vess_mesh::encode_mesh_contact_string(&contact).unwrap(),
            last_seen_unix,
        }
    }

    #[test]
    fn vess_seed_node_deserializes_without_freshness_field() {
        let node: VessSeedNode =
            serde_json::from_str(r#"{"node_id":"peer-a","contact":"tcp:peer-a@127.0.0.1:9001"}"#)
                .unwrap();

        assert_eq!(node.node_id, "peer-a");
        assert_eq!(node.contact, "tcp:peer-a@127.0.0.1:9001");
        assert!(node.last_seen_unix > 0);
    }

    #[test]
    fn snapshot_known_vess_nodes_orders_by_recency() {
        let known_vess_nodes = Arc::new(Mutex::new(HashMap::new()));
        let local_vess_node = Arc::new(Mutex::new(None));
        let now = current_unix_timestamp();

        upsert_known_vess_node(
            &known_vess_nodes,
            test_seed_node(1, "93.184.216.34:9001", now.saturating_sub(20)),
            false,
        );
        let newer = test_seed_node(2, "1.1.1.1:9002", now.saturating_sub(10));
        let newer_node_id = newer.node_id.clone();
        upsert_known_vess_node(&known_vess_nodes, newer, false);

        let snapshot = snapshot_known_vess_nodes(&known_vess_nodes, &local_vess_node);
        assert_eq!(snapshot.len(), 2);
        assert_eq!(snapshot[0].node_id, newer_node_id);
        assert_eq!(snapshot[0].last_seen_unix, now.saturating_sub(10));
        assert_eq!(snapshot[1].last_seen_unix, now.saturating_sub(20));
    }

    #[test]
    fn stale_and_future_dated_seed_nodes_are_rejected() {
        let known_vess_nodes = Arc::new(Mutex::new(HashMap::new()));
        let now = current_unix_timestamp();

        upsert_known_vess_node(
            &known_vess_nodes,
            test_seed_node(3, "93.184.216.35:9003", now.saturating_sub(MAX_VESS_SEED_NODE_AGE_SECS + 1)),
            false,
        );
        upsert_known_vess_node(
            &known_vess_nodes,
            test_seed_node(4, "93.184.216.36:9004", now.saturating_add(MAX_VESS_SEED_NODE_FUTURE_SKEW_SECS + 1)),
            false,
        );

        assert!(known_vess_nodes.lock().unwrap().is_empty());
    }

    #[test]
    fn equal_timestamp_seed_contact_conflict_does_not_replace_existing_node() {
        let known_vess_nodes = Arc::new(Mutex::new(HashMap::new()));
        let now = current_unix_timestamp();
        let existing = test_seed_node(5, "93.184.216.37:9005", now);
        let mut conflicting = test_seed_node(6, "93.184.216.38:9006", now);
        conflicting.node_id = existing.node_id.clone();

        upsert_known_vess_node(&known_vess_nodes, existing.clone(), false);
        upsert_known_vess_node(&known_vess_nodes, conflicting, false);

        let stored = known_vess_nodes
            .lock()
            .unwrap()
            .get(&existing.node_id)
            .cloned()
            .unwrap();
        assert_eq!(stored.contact, existing.contact);
    }

    #[test]
    fn probe_state_applies_backoff_and_success_reset() {
        let mut state = VessSeedProbeState::default();

        state.mark_attempt(10);
        assert!(!state.eligible(10));

        state.record_failure(10);
        assert_eq!(state.consecutive_failures, 1);
        assert_eq!(
            state.next_allowed_unix,
            10 + DEFAULT_VESS_SEED_FAILURE_REPROBE_INTERVAL.as_secs()
        );

        state.record_failure(20);
        assert_eq!(state.consecutive_failures, 2);
        assert_eq!(
            state.next_allowed_unix,
            20 + DEFAULT_VESS_SEED_FAILURE_REPROBE_INTERVAL.as_secs() * 2
        );

        state.record_success(30);
        assert_eq!(state.consecutive_failures, 0);
        assert_eq!(state.last_success_unix, 30);
        assert_eq!(
            state.next_allowed_unix,
            30 + DEFAULT_VESS_SEED_SUCCESS_REPROBE_INTERVAL.as_secs()
        );
    }

    #[test]
    fn due_probe_peers_skip_backed_off_entries_and_order_oldest_first() {
        let peer_a: SocketAddr = "127.0.0.1:8333".parse().unwrap();
        let peer_b: SocketAddr = "127.0.0.2:8333".parse().unwrap();
        let peer_c: SocketAddr = "127.0.0.3:8333".parse().unwrap();
        let known = HashSet::from([peer_a, peer_b, peer_c]);

        let mut states = HashMap::new();
        states.insert(
            peer_a,
            VessSeedProbeState {
                last_attempt_unix: 5,
                next_allowed_unix: 0,
                last_success_unix: 0,
                consecutive_failures: 0,
            },
        );
        states.insert(
            peer_b,
            VessSeedProbeState {
                last_attempt_unix: 15,
                next_allowed_unix: 0,
                last_success_unix: 0,
                consecutive_failures: 0,
            },
        );
        states.insert(
            peer_c,
            VessSeedProbeState {
                last_attempt_unix: 1,
                next_allowed_unix: 60,
                last_success_unix: 0,
                consecutive_failures: 1,
            },
        );

        let due = due_vess_seed_probe_peers(&known, &states, 30);
        assert_eq!(due, vec![peer_a, peer_b]);
    }

    #[test]
    fn collect_connection_candidates_prioritizes_preferred_peers_without_duplicates() {
        let stable_a: SocketAddr = "127.0.0.1:8333".parse().unwrap();
        let stable_b: SocketAddr = "127.0.0.2:8333".parse().unwrap();
        let learned_a: SocketAddr = "127.0.0.3:8333".parse().unwrap();
        let learned_b: SocketAddr = "127.0.0.4:8333".parse().unwrap();

        let candidates = collect_connection_candidates(
            &[stable_a, stable_b],
            &HashSet::from([stable_b, learned_b, learned_a]),
        );

        assert_eq!(candidates, vec![stable_a, stable_b, learned_a, learned_b]);
    }

    #[test]
    fn known_bitcoin_peer_match_is_ip_based() {
        let peer: SocketAddr = "203.0.113.9:42111".parse().unwrap();
        let known = HashSet::from([
            "203.0.113.9:8333".parse().unwrap(),
            "198.51.100.4:8333".parse().unwrap(),
        ]);

        assert!(known_bitcoin_peer_matches_ip(peer, &known));
    }

    #[test]
    fn seed_request_rejects_unknown_or_rate_limited_peers() {
        let peer: SocketAddr = "203.0.113.10:42000".parse().unwrap();
        let known = HashSet::from(["203.0.113.10:8333".parse().unwrap()]);
        let mut windows = HashMap::new();

        for _ in 0..MAX_VESS_SEED_REQUESTS_PER_MINUTE {
            assert!(should_accept_vess_seed_request(peer, &known, &mut windows, 100));
        }
        assert!(!should_accept_vess_seed_request(peer, &known, &mut windows, 100));

        let unknown_peer: SocketAddr = "203.0.113.11:42000".parse().unwrap();
        assert!(!should_accept_vess_seed_request(
            unknown_peer,
            &known,
            &mut HashMap::new(),
            100,
        ));
    }
}
