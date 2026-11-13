//! Wire protocols: one length-framed binary envelope shared by peer gossip and the local RPC.
//!
//! Frame: `magic u32 | version u16 | kind u16 | length u32 | checksum [u8; 8] | payload`.
//! The checksum is the first 8 bytes of `BLAKE3(domain || whole header || payload)`, so corrupt or
//! mis-framed traffic is rejected before it is parsed.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, ToSocketAddrs};
use std::time::Duration;

use vess_core::codec::{Decode, Encode, Reader, Writer};
use vess_core::constants::{
    CONNECT_TIMEOUT_MS, HANDSHAKE_TIMEOUT_MS, MAX_NETWORK_FRAME_BYTES, MAX_TRANSACTION_BYTES,
    P2P_MAGIC, PROTOCOL_VERSION, READ_TIMEOUT_MS, RPC_MAGIC, WRITE_TIMEOUT_MS,
};
use vess_core::hash::{self, DOM_NETWORK_FRAME, DOM_RPC_FRAME};
use vess_core::{
    Account, AccountId, BlockHeader, CodecError, Hash, StateUpdate, Transaction, Transfer,
};

pub mod secure;

#[derive(Debug)]
pub enum NetError {
    Io(String),
    Codec(CodecError),
    Protocol(&'static str),
    /// The read deadline passed with no frame available; the caller may keep the connection.
    Timeout,
}

impl std::fmt::Display for NetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NetError::Io(e) => write!(f, "io error: {e}"),
            NetError::Codec(e) => write!(f, "malformed message: {e}"),
            NetError::Protocol(what) => write!(f, "protocol violation: {what}"),
            NetError::Timeout => f.write_str("read timed out"),
        }
    }
}

impl std::error::Error for NetError {}

impl From<std::io::Error> for NetError {
    fn from(e: std::io::Error) -> Self {
        match e.kind() {
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut => NetError::Timeout,
            _ => NetError::Io(e.to_string()),
        }
    }
}

impl From<CodecError> for NetError {
    fn from(e: CodecError) -> Self {
        NetError::Codec(e)
    }
}

fn checksum(domain: &[u8], header: &[u8], payload: &[u8]) -> [u8; 8] {
    let digest = hash::tagged(domain, &[header, payload]);
    let mut out = [0u8; 8];
    out.copy_from_slice(&digest[..8]);
    out
}

pub fn write_frame<W: Write>(
    stream: &mut W,
    magic: u32,
    kind: u16,
    payload: &[u8],
) -> Result<(), NetError> {
    if payload.len() > MAX_NETWORK_FRAME_BYTES {
        return Err(NetError::Protocol("frame too large"));
    }
    let domain = if magic == RPC_MAGIC {
        DOM_RPC_FRAME
    } else {
        DOM_NETWORK_FRAME
    };
    let length = payload.len() as u32;

    let mut header = Vec::with_capacity(12);
    header.extend_from_slice(&magic.to_be_bytes());
    header.extend_from_slice(&PROTOCOL_VERSION.to_be_bytes());
    header.extend_from_slice(&kind.to_be_bytes());
    header.extend_from_slice(&length.to_be_bytes());

    stream.write_all(&header)?;
    stream.write_all(&checksum(domain, &header, payload))?;
    stream.write_all(payload)?;
    stream.flush()?;
    Ok(())
}

pub fn read_frame<R: Read>(
    stream: &mut R,
    magic: u32,
    max_payload: usize,
) -> Result<(u16, Vec<u8>), NetError> {
    // Wait for the first byte separately: a timeout here only means the peer is idle, while a
    // timeout in the middle of a frame means the stream is desynchronised and must be dropped.
    let mut first = [0u8; 1];
    match stream.read(&mut first) {
        Ok(0) => return Err(NetError::Io("peer closed the connection".into())),
        Ok(_) => {}
        Err(e)
            if matches!(
                e.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            ) =>
        {
            return Err(NetError::Timeout);
        }
        Err(e) => return Err(NetError::Io(e.to_string())),
    }

    let truncated = |e: std::io::Error| NetError::Io(format!("truncated frame: {e}"));

    let mut fixed = [0u8; 12];
    fixed[0] = first[0];
    stream.read_exact(&mut fixed[1..]).map_err(truncated)?;

    let got_magic = u32::from_be_bytes([fixed[0], fixed[1], fixed[2], fixed[3]]);
    if got_magic != magic {
        return Err(NetError::Protocol("bad magic"));
    }
    let version = u16::from_be_bytes([fixed[4], fixed[5]]);
    if version != PROTOCOL_VERSION {
        return Err(NetError::Protocol("unsupported frame version"));
    }
    let kind = u16::from_be_bytes([fixed[6], fixed[7]]);
    let length = u32::from_be_bytes([fixed[8], fixed[9], fixed[10], fixed[11]]) as usize;
    if length > max_payload || length > MAX_NETWORK_FRAME_BYTES {
        return Err(NetError::Protocol("frame length over the maximum"));
    }

    let mut expected = [0u8; 8];
    stream.read_exact(&mut expected).map_err(truncated)?;
    let mut payload = vec![0u8; length];
    stream.read_exact(&mut payload).map_err(truncated)?;

    let domain = if magic == RPC_MAGIC {
        DOM_RPC_FRAME
    } else {
        DOM_NETWORK_FRAME
    };
    if checksum(domain, &fixed, &payload) != expected {
        return Err(NetError::Protocol("frame checksum mismatch"));
    }
    Ok((kind, payload))
}

/// Override the read deadline of a streaming connection (sessions poll on a short tick).
pub fn set_read_timeout(stream: &TcpStream, millis: u64) -> Result<(), NetError> {
    stream.set_read_timeout(Some(Duration::from_millis(millis)))?;
    Ok(())
}

pub fn configure(stream: &TcpStream) -> Result<(), NetError> {
    stream.set_read_timeout(Some(Duration::from_millis(READ_TIMEOUT_MS)))?;
    stream.set_write_timeout(Some(Duration::from_millis(WRITE_TIMEOUT_MS)))?;
    stream.set_nodelay(true)?;
    Ok(())
}

pub fn connect(addr: &str) -> Result<TcpStream, NetError> {
    let mut last = String::from("no address resolved");
    for socket in addr.to_socket_addrs()? {
        match TcpStream::connect_timeout(&socket, Duration::from_millis(CONNECT_TIMEOUT_MS)) {
            Ok(stream) => {
                configure(&stream)?;
                return Ok(stream);
            }
            Err(e) => last = e.to_string(),
        }
    }
    Err(NetError::Io(last))
}

// ------------------------------------------------------------------------ RPC

pub mod rpc {
    pub use super::{
        AccountInfo, BlockInfo, BlockQuery, ProofInfo, Reply, ReplyBody, Request, RpcClient,
        StatusInfo, TemplateInfo, TransactionInfo, serve_rpc,
    };
}

pub mod rpc_kind {
    pub const STATUS: u16 = 1;
    pub const BALANCE: u16 = 2;
    pub const TEMPLATE: u16 = 3;
    pub const SUBMIT_BLOCK: u16 = 4;
    pub const SUBMIT_TRANSFER: u16 = 5;
    pub const SUBMIT_STATE_UPDATE: u16 = 6;
    pub const PROOF: u16 = 8;
    pub const STOP: u16 = 9;
    pub const BLOCK: u16 = 10;
    pub const TRANSACTION: u16 = 11;
    /// Long-poll: reply as soon as the tip differs from the one the caller names.
    pub const WAIT_FOR_TIP: u16 = 12;
    /// Long-poll: reply as soon as an account differs from the state the caller last saw.
    pub const WAIT_FOR_ACCOUNT: u16 = 13;
}

/// How a caller names a block: by main-chain height or by id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockQuery {
    Height(u64),
    Id(Hash),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    Status,
    Balance(AccountId),
    Template(AccountId),
    SubmitBlock(Vec<u8>),
    SubmitTransfer(Transfer),
    SubmitStateUpdate(StateUpdate),
    Proof(AccountId),
    Block(BlockQuery),
    Transaction(Hash),
    /// Block until the tip changes (or `timeout_ms` elapses), so a client can follow the chain
    /// without polling. Answered immediately when `after` is not the current tip.
    WaitForTip {
        after: Hash,
        timeout_ms: u32,
    },
    /// Block until `account` differs from `since` (or `timeout_ms` elapses), then return the current
    /// state. This is the primitive a wallet wants: one call, no guessed poll interval, and it stays
    /// quiet on blocks that do not concern it.
    WaitForAccount {
        account: AccountId,
        since: AccountInfo,
        timeout_ms: u32,
    },
    Stop,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct StatusInfo {
    pub network: u8,
    pub height: u64,
    pub tip: Hash,
    pub chain_work: u128,
    pub mempool_transactions: u32,
    pub total_supply: u64,
    pub next_reward: u64,
    pub next_dev_fee: u64,
    pub next_timestamp: u64,
    pub peers_inbound: u32,
    pub peers_outbound: u32,
    /// Addresses currently refused. Persisted, so this survives a restart.
    pub bans: u32,
    /// Configured retention: `0` means "keep everything" for that half.
    pub prune_blocks: u64,
    pub prune_headers: u64,
    /// Lowest height still stored, so an operator can see this node is not archival.
    pub oldest_body_height: u64,
    pub oldest_header_height: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AccountInfo {
    /// Whether the account exists in the state at all. A missing account reports zero balances, so
    /// without this flag "one unit of nothing" and "does not exist" would be indistinguishable.
    pub exists: bool,
    pub balance: u64,
    pub next_nonce: u64,
    pub state_hash: Hash,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TemplateInfo {
    pub header: BlockHeader,
    pub height: u64,
    pub reward: u64,
    pub transactions: Vec<Transaction>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofInfo {
    pub root: Hash,
    pub value: Option<Vec<u8>>,
    pub siblings: Vec<Hash>,
}

/// A block as seen by a wallet, explorer, or an exchange scanning deposits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockInfo {
    pub id: Hash,
    pub height: u64,
    pub timestamp_unix: u64,
    pub state_root: Hash,
    pub chain_work: u128,
    pub transaction_ids: Vec<Hash>,
}

/// What the node can say about a transaction's inclusion.
pub mod tx_status {
    /// Never seen: the id is unknown here.
    pub const UNKNOWN: u8 = 0;
    /// Accepted and waiting in the mempool.
    pub const PENDING: u8 = 1;
    /// In a block on the main chain, verified against our own headers.
    pub const MINED: u8 = 2;
    /// In a block that is not on the main chain, and no longer pending.
    pub const ORPHANED: u8 = 3;
    /// Mined at a known height that is now below our pruned header window, so membership cannot be
    /// re-verified here. Confirmations are still reported from the stored height.
    pub const PRUNED: u8 = 4;

    pub fn name(status: u8) -> &'static str {
        match status {
            PENDING => "pending",
            MINED => "mined",
            ORPHANED => "orphaned",
            PRUNED => "pruned",
            _ => "unknown",
        }
    }
}

/// Where a transaction is right now, how deep its block is, and what it actually does.
///
/// The content matters as much as the position: a scanner watching for deposits has only a list of
/// ids from `BlockInfo`, so without sender/recipient/amount it could see that a balance moved but
/// not who moved it or by how much.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TransactionInfo {
    pub transaction_id: Hash,
    pub in_mempool: bool,
    pub block_id: Option<Hash>,
    pub height: Option<u64>,
    /// Blocks on top of the one that carries it, counting that block as 1.
    pub confirmations: u64,
    /// One of [`tx_status`]. Reported rather than inferred by the caller, because "unknown",
    /// "pending", "mined", "orphaned" and "outside our pruned window" are five different answers
    /// and used to look like one.
    pub status: u8,
    /// `TRANSACTION_KIND_*`, or `0` when the node has never seen this transaction.
    pub kind: u8,
    /// The account that signed it. Zero when unknown.
    pub sender_id: AccountId,
    /// Who is paid. Zero for a state update, which pays nobody.
    pub recipient_id: AccountId,
    /// Amount transferred. `0` for a state update.
    pub amount: u64,
    pub fee: u64,
    /// The new account commitment of a state update. Zero for a transfer.
    pub new_state_hash: Hash,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReplyBody {
    Empty,
    Status(StatusInfo),
    Account(AccountInfo),
    Template(TemplateInfo),
    Accepted(Hash),
    Proof(ProofInfo),
    Block(BlockInfo),
    Transaction(TransactionInfo),
    /// The tip a `WaitForTip` settled on, whether it changed or the wait timed out.
    Tip {
        tip: Hash,
        height: u64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reply {
    pub reason: u16,
    pub body: ReplyBody,
}

impl Reply {
    pub fn ok(body: ReplyBody) -> Reply {
        Reply { reason: 0, body }
    }

    pub fn reject(reason: u16) -> Reply {
        Reply {
            reason,
            body: ReplyBody::Empty,
        }
    }

    pub fn is_ok(&self) -> bool {
        self.reason == 0
    }
}

fn encode_transfer_fields(w: &mut Writer, t: &Transfer) {
    t.encode(w);
}

fn encode_transaction_list(w: &mut Writer, txs: &[Transaction]) {
    w.u32(txs.len() as u32);
    for tx in txs {
        tx.encode_into(w);
    }
}

fn decode_transaction_list(r: &mut Reader<'_>) -> Result<Vec<Transaction>, CodecError> {
    let count = r.u32()? as usize;
    if count > r.remaining() {
        return Err(CodecError::LengthTooLarge);
    }
    let mut out = Vec::with_capacity(count.min(1_024));
    for _ in 0..count {
        out.push(Transaction::decode_from(r, MAX_TRANSACTION_BYTES)?);
    }
    Ok(out)
}

impl Encode for Request {
    fn encode(&self, w: &mut Writer) {
        match self {
            Request::Status => w.u8(rpc_kind::STATUS as u8),
            Request::Balance(id) => {
                w.u8(rpc_kind::BALANCE as u8);
                w.fixed(id);
            }
            Request::Template(id) => {
                w.u8(rpc_kind::TEMPLATE as u8);
                w.fixed(id);
            }
            Request::SubmitBlock(bytes) => {
                w.u8(rpc_kind::SUBMIT_BLOCK as u8);
                let _ = w.var_bytes(bytes);
            }
            Request::SubmitTransfer(t) => {
                w.u8(rpc_kind::SUBMIT_TRANSFER as u8);
                encode_transfer_fields(w, t);
            }
            Request::SubmitStateUpdate(t) => {
                w.u8(rpc_kind::SUBMIT_STATE_UPDATE as u8);
                t.encode(w);
            }
            Request::Proof(id) => {
                w.u8(rpc_kind::PROOF as u8);
                w.fixed(id);
            }
            Request::Block(query) => {
                w.u8(rpc_kind::BLOCK as u8);
                match query {
                    BlockQuery::Height(height) => {
                        w.u8(0);
                        w.u64(*height);
                    }
                    BlockQuery::Id(id) => {
                        w.u8(1);
                        w.fixed(id);
                    }
                }
            }
            Request::Transaction(id) => {
                w.u8(rpc_kind::TRANSACTION as u8);
                w.fixed(id);
            }
            Request::WaitForTip { after, timeout_ms } => {
                w.u8(rpc_kind::WAIT_FOR_TIP as u8);
                w.fixed(after);
                w.u32(*timeout_ms);
            }
            Request::WaitForAccount {
                account,
                since,
                timeout_ms,
            } => {
                w.u8(rpc_kind::WAIT_FOR_ACCOUNT as u8);
                w.fixed(account);
                w.u8(u8::from(since.exists));
                w.u64(since.balance);
                w.u64(since.next_nonce);
                w.fixed(&since.state_hash);
                w.u32(*timeout_ms);
            }
            Request::Stop => w.u8(rpc_kind::STOP as u8),
        }
    }
}

impl Decode for Request {
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        let kind = r.u8()?;
        Ok(match kind as u16 {
            rpc_kind::STATUS => Request::Status,
            rpc_kind::BALANCE => Request::Balance(r.array()?),
            rpc_kind::TEMPLATE => Request::Template(r.array()?),
            rpc_kind::SUBMIT_BLOCK => {
                Request::SubmitBlock(r.var_bytes(MAX_NETWORK_FRAME_BYTES)?.to_vec())
            }
            rpc_kind::SUBMIT_TRANSFER => Request::SubmitTransfer(Transfer::decode(r)?),
            rpc_kind::SUBMIT_STATE_UPDATE => Request::SubmitStateUpdate(StateUpdate::decode(r)?),
            rpc_kind::PROOF => Request::Proof(r.array()?),
            rpc_kind::BLOCK => {
                let tag = r.u8()?;
                match tag {
                    0 => Request::Block(BlockQuery::Height(r.u64()?)),
                    1 => Request::Block(BlockQuery::Id(r.array()?)),
                    _ => return Err(CodecError::UnknownVersion),
                }
            }
            rpc_kind::TRANSACTION => Request::Transaction(r.array()?),
            rpc_kind::WAIT_FOR_TIP => Request::WaitForTip {
                after: r.array()?,
                timeout_ms: r.u32()?,
            },
            rpc_kind::WAIT_FOR_ACCOUNT => Request::WaitForAccount {
                account: r.array()?,
                since: AccountInfo {
                    exists: r.u8()? != 0,
                    balance: r.u64()?,
                    next_nonce: r.u64()?,
                    state_hash: r.array()?,
                },
                timeout_ms: r.u32()?,
            },
            rpc_kind::STOP => Request::Stop,
            _ => return Err(CodecError::UnknownVersion),
        })
    }
}

impl Encode for Reply {
    fn encode(&self, w: &mut Writer) {
        w.u16(self.reason);
        match &self.body {
            ReplyBody::Empty => w.u8(0),
            ReplyBody::Status(s) => {
                w.u8(1);
                w.u8(s.network);
                w.u64(s.height);
                w.fixed(&s.tip);
                w.bytes(&s.chain_work.to_be_bytes());
                w.u32(s.mempool_transactions);
                w.u64(s.total_supply);
                w.u64(s.next_reward);
                w.u64(s.next_dev_fee);
                w.u64(s.next_timestamp);
                w.u32(s.peers_inbound);
                w.u32(s.peers_outbound);
                w.u32(s.bans);
                w.u64(s.prune_blocks);
                w.u64(s.prune_headers);
                w.u64(s.oldest_body_height);
                w.u64(s.oldest_header_height);
            }
            ReplyBody::Account(a) => {
                w.u8(2);
                w.u8(u8::from(a.exists));
                w.u64(a.balance);
                w.u64(a.next_nonce);
                w.fixed(&a.state_hash);
            }
            ReplyBody::Template(t) => {
                w.u8(3);
                w.fixed(&t.header.canonical());
                w.u64(t.height);
                w.u64(t.reward);
                encode_transaction_list(w, &t.transactions);
            }
            ReplyBody::Accepted(id) => {
                w.u8(4);
                w.fixed(id);
            }
            ReplyBody::Proof(p) => {
                w.u8(5);
                w.fixed(&p.root);
                match &p.value {
                    Some(value) => {
                        w.u8(1);
                        let _ = w.var_bytes(value);
                    }
                    None => w.u8(0),
                }
                w.u32(p.siblings.len() as u32);
                for sibling in &p.siblings {
                    w.fixed(sibling);
                }
            }
            ReplyBody::Block(b) => {
                w.u8(6);
                w.fixed(&b.id);
                w.u64(b.height);
                w.u64(b.timestamp_unix);
                w.fixed(&b.state_root);
                w.bytes(&b.chain_work.to_be_bytes());
                w.u32(b.transaction_ids.len() as u32);
                for id in &b.transaction_ids {
                    w.fixed(id);
                }
            }
            ReplyBody::Transaction(t) => {
                w.u8(7);
                w.fixed(&t.transaction_id);
                w.u8(u8::from(t.in_mempool));
                match (&t.block_id, t.height) {
                    (Some(block_id), Some(height)) => {
                        w.u8(1);
                        w.fixed(block_id);
                        w.u64(height);
                        w.u64(t.confirmations);
                    }
                    _ => w.u8(0),
                }
                w.u8(t.kind);
                w.fixed(&t.sender_id);
                w.fixed(&t.recipient_id);
                w.u64(t.amount);
                w.u64(t.fee);
                w.fixed(&t.new_state_hash);
                w.u8(t.status);
            }
            ReplyBody::Tip { tip, height } => {
                w.u8(8);
                w.fixed(tip);
                w.u64(*height);
            }
        }
    }
}

impl Decode for Reply {
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        let reason = r.u16()?;
        let tag = r.u8()?;
        let body = match tag {
            0 => ReplyBody::Empty,
            1 => {
                let network = r.u8()?;
                let height = r.u64()?;
                let tip = r.array()?;
                let mut work = [0u8; 16];
                work.copy_from_slice(r.bytes(16)?);
                ReplyBody::Status(StatusInfo {
                    network,
                    height,
                    tip,
                    chain_work: u128::from_be_bytes(work),
                    mempool_transactions: r.u32()?,
                    total_supply: r.u64()?,
                    next_reward: r.u64()?,
                    next_dev_fee: r.u64()?,
                    next_timestamp: r.u64()?,
                    peers_inbound: r.u32()?,
                    peers_outbound: r.u32()?,
                    bans: r.u32()?,
                    prune_blocks: r.u64()?,
                    prune_headers: r.u64()?,
                    oldest_body_height: r.u64()?,
                    oldest_header_height: r.u64()?,
                })
            }
            2 => ReplyBody::Account(AccountInfo {
                exists: r.u8()? != 0,
                balance: r.u64()?,
                next_nonce: r.u64()?,
                state_hash: r.array()?,
            }),
            3 => ReplyBody::Template(TemplateInfo {
                header: BlockHeader::decode(r.bytes(vess_core::constants::BLOCK_HEADER_BYTES)?)?,
                height: r.u64()?,
                reward: r.u64()?,
                transactions: decode_transaction_list(r)?,
            }),
            4 => ReplyBody::Accepted(r.array()?),
            5 => {
                let root = r.array()?;
                let present = r.u8()?;
                let value = if present == 1 {
                    Some(r.var_bytes(MAX_NETWORK_FRAME_BYTES)?.to_vec())
                } else {
                    None
                };
                let count = r.u32()? as usize;
                if count > r.remaining() / 32 {
                    return Err(CodecError::LengthTooLarge);
                }
                let mut siblings = Vec::with_capacity(count);
                for _ in 0..count {
                    siblings.push(r.array()?);
                }
                ReplyBody::Proof(ProofInfo {
                    root,
                    value,
                    siblings,
                })
            }
            6 => {
                let id = r.array()?;
                let height = r.u64()?;
                let timestamp_unix = r.u64()?;
                let state_root = r.array()?;
                let mut work = [0u8; 16];
                work.copy_from_slice(r.bytes(16)?);
                let count = r.u32()? as usize;
                if count > r.remaining() / 32 {
                    return Err(CodecError::LengthTooLarge);
                }
                let mut transaction_ids = Vec::with_capacity(count);
                for _ in 0..count {
                    transaction_ids.push(r.array()?);
                }
                ReplyBody::Block(BlockInfo {
                    id,
                    height,
                    timestamp_unix,
                    state_root,
                    chain_work: u128::from_be_bytes(work),
                    transaction_ids,
                })
            }
            7 => {
                let transaction_id = r.array()?;
                let in_mempool = r.u8()? == 1;
                let has_block = r.u8()? == 1;
                let (block_id, height, confirmations) = if has_block {
                    let block_id = r.array()?;
                    let height = r.u64()?;
                    let confirmations = r.u64()?;
                    (Some(block_id), Some(height), confirmations)
                } else {
                    (None, None, 0)
                };
                ReplyBody::Transaction(TransactionInfo {
                    transaction_id,
                    in_mempool,
                    block_id,
                    height,
                    confirmations,
                    kind: r.u8()?,
                    sender_id: r.array()?,
                    recipient_id: r.array()?,
                    amount: r.u64()?,
                    fee: r.u64()?,
                    new_state_hash: r.array()?,
                    status: r.u8()?,
                })
            }
            8 => ReplyBody::Tip {
                tip: r.array()?,
                height: r.u64()?,
            },
            _ => return Err(CodecError::UnknownVersion),
        };
        Ok(Reply { reason, body })
    }
}

pub struct RpcClient {
    stream: TcpStream,
}

impl RpcClient {
    pub fn connect(addr: &str) -> Result<RpcClient, NetError> {
        let stream = connect(addr)?;
        Ok(RpcClient { stream })
    }

    pub fn call(&mut self, request: &Request) -> Result<Reply, NetError> {
        let mut w = Writer::new();
        request.encode(&mut w);
        write_frame(&mut self.stream, RPC_MAGIC, 1, w.as_slice())?;
        let (_, payload) = read_frame(&mut self.stream, RPC_MAGIC, MAX_NETWORK_FRAME_BYTES)?;
        let mut r = Reader::new(&payload);
        let reply = Reply::decode(&mut r)?;
        r.finish()?;
        Ok(reply)
    }
}

/// Serve RPC requests on a listener until the process ends. One thread per connection.
pub fn serve_rpc<F>(listener: TcpListener, handler: F) -> std::io::Result<()>
where
    F: Fn(Request) -> Reply + Send + Sync + 'static,
{
    let handler = std::sync::Arc::new(handler);
    for incoming in listener.incoming() {
        let stream = match incoming {
            Ok(s) => s,
            Err(_) => continue,
        };
        let handler = handler.clone();
        std::thread::spawn(move || {
            let _ = configure(&stream);
            let mut stream = stream;
            loop {
                let (kind, payload) =
                    match read_frame(&mut stream, RPC_MAGIC, MAX_NETWORK_FRAME_BYTES) {
                        Ok(v) => v,
                        Err(_) => return,
                    };
                if kind != 1 {
                    return;
                }
                let mut r = Reader::new(&payload);
                let request = match Request::decode(&mut r) {
                    Ok(v) => v,
                    Err(_) => return,
                };
                let stop = matches!(request, Request::Stop);
                let reply = handler(request);
                let mut w = Writer::new();
                reply.encode(&mut w);
                if write_frame(&mut stream, RPC_MAGIC, 1, w.as_slice()).is_err() {
                    return;
                }
                if stop {
                    return;
                }
            }
        });
    }
    Ok(())
}

// ------------------------------------------------------------------------ P2P

pub mod p2p_kind {
    pub const HELLO: u16 = 1;
    pub const HELLO_ACK: u16 = 2;
    pub const PING: u16 = 3;
    pub const PONG: u16 = 4;
    pub const GET_HEADERS: u16 = 5;
    pub const HEADERS: u16 = 6;
    pub const GET_BLOCK: u16 = 7;
    pub const BLOCK: u16 = 8;
    pub const INV: u16 = 9;
    pub const TX: u16 = 10;
    pub const DISCONNECT: u16 = 11;
    pub const NOT_FOUND: u16 = 12;
    pub const GET_PENDING: u16 = 13;
    pub const PENDING: u16 = 14;
    /// A block announced by header plus short transaction ids, so the receiver can rebuild the body
    /// from its own mempool (§18.2).
    pub const CMPCTBLOCK: u16 = 15;
    /// Request a state snapshot: the sender's whole live state, so a node that cannot replay
    /// history (its peer pruned it) can still join at the tip.
    pub const GET_STATE: u16 = 16;
    /// One chunk of a state snapshot. A snapshot is `Start`, zero or more `Accounts` batches, then
    /// `End`.
    pub const STATE: u16 = 17;
    /// Ask a peer for addresses it has successfully connected to.
    pub const GET_ADDR: u16 = 18;
    /// Answer to `GET_ADDR`: `u32` count, then `(var_bytes addr, [u8; 32] static key)` entries.
    pub const ADDR: u16 = 19;
}

/// Most addresses one `ADDR` message may carry. A peer that sends more is rejected rather than
/// trusted, because the list is unauthenticated and cheap to fabricate.
pub const MAX_ADDR_ENTRIES: usize = 16;
/// Longest accepted `host:port` string. IPv6 literals are the awkward case; 64 is generous.
pub const MAX_ADDR_BYTES: usize = 64;

/// One gossiped peer: where to dial it, and the Noise static key it must prove.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressEntry {
    pub addr: String,
    pub static_key: [u8; 32],
}

impl AddressEntry {
    pub fn encode(&self, w: &mut Writer) -> Result<(), CodecError> {
        if self.addr.len() > MAX_ADDR_BYTES {
            return Err(CodecError::InvalidValue);
        }
        w.var_bytes(self.addr.as_bytes())?;
        w.fixed(&self.static_key);
        Ok(())
    }

    pub fn decode(r: &mut Reader<'_>) -> Result<AddressEntry, CodecError> {
        let raw = r.var_bytes(MAX_ADDR_BYTES)?;
        let addr = core::str::from_utf8(raw).map_err(|_| CodecError::InvalidValue)?;
        Ok(AddressEntry {
            addr: addr.to_string(),
            static_key: r.array()?,
        })
    }
}

/// `ADDR` payload: a count followed by entries.
pub fn encode_addresses(entries: &[AddressEntry]) -> Vec<u8> {
    let mut w = Writer::new();
    w.u32(entries.len() as u32);
    for entry in entries {
        // Encoding cannot fail here: entries are built from validated strings.
        let _ = entry.encode(&mut w);
    }
    w.into_vec()
}

/// Decode an `ADDR` payload, refusing oversized lists and trailing bytes.
pub fn decode_addresses(payload: &[u8]) -> Result<Vec<AddressEntry>, CodecError> {
    let mut r = Reader::new(payload);
    let count = r.u32()? as usize;
    if count > MAX_ADDR_ENTRIES {
        return Err(CodecError::LengthTooLarge);
    }
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        out.push(AddressEntry::decode(&mut r)?);
    }
    r.finish()?;
    Ok(out)
}

/// One frame of a state snapshot.
///
/// A snapshot transfers the *live* state, not history, so any node can serve one — including a node
/// that has pruned every block. It is verifiable because `state_root` commits to the account set: the
/// receiver rebuilds the state and compares roots.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SnapshotFrame {
    Start { height: u64, accounts: u32 },
    Accounts(Vec<(AccountId, Account)>),
    End { accounts: u32 },
}

/// Records per frame; a peer that sends more than this is dropped rather than trusted.
pub const MAX_SNAPSHOT_ENTRIES_PER_FRAME: usize = 100_000;
/// Total records a single snapshot may carry.
pub const MAX_SNAPSHOT_ENTRIES: u64 = 50_000_000;

impl SnapshotFrame {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        match self {
            SnapshotFrame::Start { height, accounts } => {
                w.u8(0);
                w.u64(*height);
                w.u32(*accounts);
            }
            SnapshotFrame::Accounts(items) => {
                w.u8(1);
                w.u32(items.len() as u32);
                for (id, account) in items {
                    w.fixed(id);
                    // `Account` is self-delimiting, so no length prefix is needed.
                    account.encode(&mut w);
                }
            }
            SnapshotFrame::End { accounts } => {
                w.u8(2);
                w.u32(*accounts);
            }
        }
        w.into_vec()
    }

    pub fn decode(bytes: &[u8]) -> Result<SnapshotFrame, CodecError> {
        let mut r = Reader::new(bytes);
        let frame = match r.u8()? {
            0 => SnapshotFrame::Start {
                height: r.u64()?,
                accounts: r.u32()?,
            },
            1 => {
                let count = r.u32()? as usize;
                if count > MAX_SNAPSHOT_ENTRIES_PER_FRAME {
                    return Err(CodecError::LengthTooLarge);
                }
                let mut items = Vec::with_capacity(count);
                for _ in 0..count {
                    let id: AccountId = r.array()?;
                    let account = Account::decode(&mut r)?;
                    items.push((id, account));
                }
                SnapshotFrame::Accounts(items)
            }
            2 => SnapshotFrame::End { accounts: r.u32()? },
            _ => return Err(CodecError::UnknownVersion),
        };
        r.finish()?;
        Ok(frame)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Handshake {
    pub protocol_version: u16,
    pub chain_id: Hash,
    pub genesis_id: Hash,
    pub best_id: Hash,
    pub best_height: u64,
    pub best_work: u128,
    pub listen_port: u16,
    pub connection_nonce: [u8; 32],
    /// Lowest block this peer can still serve, so a syncing node can tell an impossible catch-up
    /// apart from a slow one instead of retrying forever.
    pub oldest_body_height: u64,
    pub oldest_header_height: u64,
}

impl Handshake {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u16(self.protocol_version);
        w.fixed(&self.chain_id);
        w.fixed(&self.genesis_id);
        w.fixed(&self.best_id);
        w.u64(self.best_height);
        w.bytes(&self.best_work.to_be_bytes());
        w.u16(self.listen_port);
        w.fixed(&self.connection_nonce);
        w.u64(self.oldest_body_height);
        w.u64(self.oldest_header_height);
        w.into_vec()
    }

    pub fn decode(r: &mut Reader<'_>) -> Result<Handshake, CodecError> {
        let mut work = [0u8; 16];
        let protocol_version = r.u16()?;
        let chain_id = r.array()?;
        let genesis_id = r.array()?;
        let best_id = r.array()?;
        let best_height = r.u64()?;
        work.copy_from_slice(r.bytes(16)?);
        Ok(Handshake {
            protocol_version,
            chain_id,
            genesis_id,
            best_id,
            best_height,
            best_work: u128::from_be_bytes(work),
            listen_port: r.u16()?,
            connection_nonce: r.array()?,
            oldest_body_height: r.u64()?,
            oldest_header_height: r.u64()?,
        })
    }
}

/// Verify that a peer speaks the same protocol on the same chain.
pub fn check_handshake(ours: &Handshake, theirs: &Handshake) -> Result<(), NetError> {
    if theirs.protocol_version != PROTOCOL_VERSION {
        return Err(NetError::Protocol("peer protocol version mismatch"));
    }
    if ours.chain_id != theirs.chain_id {
        return Err(NetError::Protocol("peer is on another chain id"));
    }
    if ours.genesis_id != theirs.genesis_id {
        return Err(NetError::Protocol("peer has a different genesis"));
    }
    if ours.connection_nonce == theirs.connection_nonce {
        return Err(NetError::Protocol("self connection"));
    }
    Ok(())
}

pub struct Peer {
    pub stream: secure::SecureStream,
    /// The peer's Noise static key, proven during the handshake.
    pub static_key: [u8; 32],
}

impl Peer {
    /// Dial a peer, encrypt the transport, and complete the protocol handshake.
    pub fn connect(
        addr: &str,
        ours: &Handshake,
        static_key: &[u8; 32],
        chain_id: &[u8; 32],
    ) -> Result<(Peer, Handshake), NetError> {
        let raw = connect(addr)?;
        configure(&raw)?;
        let (mut stream, peer_key) = secure::SecureStream::connect(raw, static_key, chain_id)?;
        write_frame(&mut stream, P2P_MAGIC, p2p_kind::HELLO, &ours.encode())?;
        let (kind, payload) = read_frame(&mut stream, P2P_MAGIC, MAX_NETWORK_FRAME_BYTES)?;
        if kind != p2p_kind::HELLO_ACK && kind != p2p_kind::HELLO {
            return Err(NetError::Protocol("expected HELLO_ACK"));
        }
        let mut r = Reader::new(&payload);
        let theirs = Handshake::decode(&mut r)?;
        check_handshake(ours, &theirs)?;
        write_frame(&mut stream, P2P_MAGIC, p2p_kind::HELLO_ACK, &ours.encode())?;
        Ok((
            Peer {
                stream,
                static_key: peer_key,
            },
            theirs,
        ))
    }

    pub fn send(&mut self, kind: u16, payload: &[u8]) -> Result<(), NetError> {
        write_frame(&mut self.stream, P2P_MAGIC, kind, payload)
    }

    pub fn recv(&mut self) -> Result<(u16, Vec<u8>), NetError> {
        read_frame(&mut self.stream, P2P_MAGIC, MAX_NETWORK_FRAME_BYTES)
    }

    pub fn send_block(&mut self, block: &[u8]) -> Result<(), NetError> {
        let mut w = Writer::new();
        let _ = w.var_bytes(block);
        self.send(p2p_kind::BLOCK, w.as_slice())
    }

    pub fn send_transaction(&mut self, tx: &Transaction) -> Result<(), NetError> {
        self.send(p2p_kind::TX, &tx.canonical())
    }
}

pub fn encode_headers(headers: &[BlockHeader]) -> Vec<u8> {
    let mut w = Writer::new();
    w.u32(headers.len() as u32);
    for header in headers {
        w.fixed(&header.canonical());
    }
    w.into_vec()
}

pub fn decode_headers(payload: &[u8]) -> Result<Vec<BlockHeader>, NetError> {
    let mut r = Reader::new(payload);
    let count = r.u32()? as usize;
    if count > r.remaining() / vess_core::constants::BLOCK_HEADER_BYTES {
        return Err(NetError::Codec(CodecError::LengthTooLarge));
    }
    let mut headers = Vec::with_capacity(count);
    for _ in 0..count {
        headers.push(BlockHeader::decode(
            r.bytes(vess_core::constants::BLOCK_HEADER_BYTES)?,
        )?);
    }
    Ok(headers)
}

/// Build the handshake this node advertises. `connection_nonce` must be a *per-node* constant: both
/// ends of a self-connection compare it, so a fresh value per call would never detect one.
#[allow(clippy::too_many_arguments)]
pub fn local_handshake(
    chain_id: Hash,
    genesis_id: Hash,
    best_id: Hash,
    best_height: u64,
    best_work: u128,
    listen_port: u16,
    oldest_body_height: u64,
    oldest_header_height: u64,
    connection_nonce: [u8; 32],
) -> Handshake {
    Handshake {
        protocol_version: PROTOCOL_VERSION,
        chain_id,
        genesis_id,
        best_id,
        best_height,
        best_work,
        listen_port,
        connection_nonce,
        oldest_body_height,
        oldest_header_height,
    }
}

/// Unused placeholder kept out of the public API surface.
const _: fn(&mut TcpStream) -> Result<(), NetError> = |s| {
    s.set_read_timeout(Some(Duration::from_millis(HANDSHAKE_TIMEOUT_MS)))
        .map_err(Into::into)
};

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    fn pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = std::thread::spawn(move || TcpStream::connect(addr).unwrap());
        let (server, _) = listener.accept().unwrap();
        let client = handle.join().unwrap();
        (server, client)
    }

    #[test]
    fn frames_round_trip_and_detect_corruption() {
        let (mut server, mut client) = pair();
        write_frame(&mut client, RPC_MAGIC, 7, b"hello frame").unwrap();
        let (kind, payload) = read_frame(&mut server, RPC_MAGIC, 1_024).unwrap();
        assert_eq!(kind, 7);
        assert_eq!(payload, b"hello frame");

        // A corrupted payload fails the checksum.
        write_frame(&mut client, RPC_MAGIC, 7, b"payload").unwrap();
        let (_, _) = read_frame(&mut server, RPC_MAGIC, 1_024).unwrap();
        let mut raw = Vec::new();
        raw.extend_from_slice(&RPC_MAGIC.to_be_bytes());
        raw.extend_from_slice(&PROTOCOL_VERSION.to_be_bytes());
        raw.extend_from_slice(&1u16.to_be_bytes());
        raw.extend_from_slice(&3u32.to_be_bytes());
        raw.extend_from_slice(&[0u8; 8]);
        raw.extend_from_slice(b"abc");
        client.write_all(&raw).unwrap();
        assert!(matches!(
            read_frame(&mut server, RPC_MAGIC, 1_024),
            Err(NetError::Protocol(_))
        ));
    }

    #[test]
    fn oversized_frames_are_rejected_before_allocation() {
        let (mut server, mut client) = pair();
        let mut raw = Vec::new();
        raw.extend_from_slice(&RPC_MAGIC.to_be_bytes());
        raw.extend_from_slice(&PROTOCOL_VERSION.to_be_bytes());
        raw.extend_from_slice(&1u16.to_be_bytes());
        raw.extend_from_slice(&u32::MAX.to_be_bytes());
        raw.extend_from_slice(&[0u8; 8]);
        client.write_all(&raw).unwrap();
        assert!(matches!(
            read_frame(&mut server, RPC_MAGIC, 1_024),
            Err(NetError::Protocol(_))
        ));
    }

    #[test]
    fn request_and_reply_round_trip() {
        let requests = vec![
            Request::Status,
            Request::Balance([1u8; 32]),
            Request::SubmitBlock(vec![1, 2, 3]),
            Request::WaitForTip {
                after: [4u8; 32],
                timeout_ms: 25_000,
            },
            Request::Stop,
        ];
        for request in requests {
            let mut w = Writer::new();
            request.encode(&mut w);
            let mut r = Reader::new(w.as_slice());
            assert_eq!(Request::decode(&mut r).unwrap(), request);
            r.finish().unwrap();
        }

        let replies = vec![
            Reply::reject(7),
            Reply::ok(ReplyBody::Account(AccountInfo {
                exists: true,
                balance: 5,
                next_nonce: 7,
                state_hash: [8u8; 32],
            })),
            Reply::ok(ReplyBody::Accepted([9u8; 32])),
            Reply::ok(ReplyBody::Tip {
                tip: [7u8; 32],
                height: 42,
            }),
            // Content travels with position: a transfer says who paid whom, a state update commits
            // to a new hash, and an unknown transaction carries neither.
            Reply::ok(ReplyBody::Transaction(TransactionInfo {
                transaction_id: [1u8; 32],
                in_mempool: false,
                block_id: Some([2u8; 32]),
                height: Some(9),
                confirmations: 3,
                kind: 1,
                sender_id: [3u8; 32],
                recipient_id: [4u8; 32],
                amount: 55,
                fee: 2,
                new_state_hash: [0u8; 32],
                status: 2,
            })),
            Reply::ok(ReplyBody::Transaction(TransactionInfo {
                transaction_id: [5u8; 32],
                kind: 2,
                sender_id: [6u8; 32],
                fee: 1,
                new_state_hash: [9u8; 32],
                ..TransactionInfo::default()
            })),
            Reply::ok(ReplyBody::Transaction(TransactionInfo {
                transaction_id: [5u8; 32],
                ..TransactionInfo::default()
            })),
        ];
        for reply in replies {
            let mut w = Writer::new();
            reply.encode(&mut w);
            let mut r = Reader::new(w.as_slice());
            assert_eq!(Reply::decode(&mut r).unwrap(), reply);
            r.finish().unwrap();
        }
    }

    #[test]
    fn handshake_rejects_foreign_chains_and_self_connections() {
        let ours = Handshake {
            protocol_version: PROTOCOL_VERSION,
            chain_id: [1u8; 32],
            genesis_id: [2u8; 32],
            best_id: [3u8; 32],
            best_height: 0,
            best_work: 0,
            listen_port: 0,
            connection_nonce: [4u8; 32],
            oldest_body_height: 0,
            oldest_header_height: 0,
        };
        assert!(check_handshake(&ours, &ours).is_err());

        let mut theirs = ours.clone();
        theirs.connection_nonce = [5u8; 32];
        assert!(check_handshake(&ours, &theirs).is_ok());

        theirs.chain_id = [9u8; 32];
        assert!(check_handshake(&ours, &theirs).is_err());
    }
}
#[test]
fn snapshot_frames_round_trip_and_reject_garbage() {
    let account = Account {
        next_nonce: 7,
        balance: 1_250,
        state_hash: [0x11; 32],
    };
    let frames = [
        SnapshotFrame::Start {
            height: 42,
            accounts: 1,
        },
        SnapshotFrame::Accounts(vec![([0x22u8; 32], account)]),
        SnapshotFrame::End { accounts: 1 },
    ];
    for frame in frames {
        let bytes = frame.encode();
        assert_eq!(SnapshotFrame::decode(&bytes).unwrap(), frame);
        // Every truncation is a clean error, not a panic.
        for length in 0..bytes.len() {
            assert!(SnapshotFrame::decode(&bytes[..length]).is_err());
        }
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(SnapshotFrame::decode(&trailing).is_err());
    }

    assert!(SnapshotFrame::decode(&[9]).is_err());
    // A batch larger than the frame budget is refused before allocating.
    let mut oversized = Writer::new();
    oversized.u8(1);
    oversized.u32(MAX_SNAPSHOT_ENTRIES_PER_FRAME as u32 + 1);
    assert!(SnapshotFrame::decode(oversized.as_slice()).is_err());
}
