//! Transactional persistence on `redb`: one ACID write transaction per block.
//!
//! Every value is a canonical-codec blob; there is no text or JSON anywhere. A reopened store
//! re-validates every stored header (PoW, target, timestamps) instead of trusting the file.

use std::path::Path;

use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};
use vess_consensus::chain::Chain;
use vess_consensus::{ConsensusError, ValidatedBlock, check_header};
use vess_core::codec::{Decode, Encode, Reader, Writer};
use vess_core::constants::{
    BLOCK_HEADER_BYTES, DEFAULT_PRUNE_BLOCKS, DEFAULT_PRUNE_HEADERS, DEFAULT_PRUNE_UNDO,
    DIFFICULTY_WINDOW_BLOCKS, NetworkProfile, PRUNE_FLOOR_BLOCKS,
};
use vess_core::{Account, AccountId, BlockHeader, CodecError, Hash};
use vess_state::{State, StateChange, UndoLog};

const ACCOUNTS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("accounts");
const HEADERS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("headers");
const BODIES: TableDefinition<&[u8], &[u8]> = TableDefinition::new("bodies");
/// First byte of a `BODIES` value that stores the block *without* its header. The header is already
/// in `HEADERS`, and a canonical header begins with its version (`0x00`), so this marker is
/// unambiguous against records written before bodies were trimmed.
const BODY_WITHOUT_HEADER: u8 = 0x01;

/// Decode a `HEADERS` record: canonical header, height, chain work.
fn decode_header_record(record: &[u8]) -> Result<(BlockHeader, u64, u128), StorageError> {
    if record.len() < BLOCK_HEADER_BYTES + 24 {
        return Err(StorageError::Corrupt("header record"));
    }
    let header = BlockHeader::decode(&record[..BLOCK_HEADER_BYTES])?;
    let mut height = [0u8; 8];
    height.copy_from_slice(&record[BLOCK_HEADER_BYTES..BLOCK_HEADER_BYTES + 8]);
    let mut work = [0u8; 16];
    work.copy_from_slice(&record[BLOCK_HEADER_BYTES + 8..BLOCK_HEADER_BYTES + 24]);
    Ok((
        header,
        u64::from_be_bytes(height),
        u128::from_be_bytes(work),
    ))
}

/// Encode a block body the way `BODIES` stores it: the header is dropped because `HEADERS` holds it.
fn encode_body_record(block: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(block.len().saturating_sub(BLOCK_HEADER_BYTES) + 1);
    if block.len() >= BLOCK_HEADER_BYTES {
        out.push(BODY_WITHOUT_HEADER);
        out.extend_from_slice(&block[BLOCK_HEADER_BYTES..]);
    } else {
        // Not a whole block; store it verbatim so nothing is silently lost.
        out.extend_from_slice(block);
    }
    out
}
const UNDO: TableDefinition<&[u8], &[u8]> = TableDefinition::new("undo");
const PENDING: TableDefinition<&[u8], &[u8]> = TableDefinition::new("pending");
const META: TableDefinition<&[u8], &[u8]> = TableDefinition::new("meta");
/// `height (u64 BE) || block id` -> empty. Gives range scans by height, which is what pruning needs
/// because `HEADERS` is keyed by id.
const HEIGHT_INDEX: TableDefinition<&[u8], &[u8]> = TableDefinition::new("height_index");
/// transaction id -> id of the block that carries it. Append-only: a stale entry for a block that was
/// later abandoned is filtered by the caller, which checks the block against the main chain.
const TX_INDEX: TableDefinition<&[u8], &[u8]> = TableDefinition::new("tx_index");

const META_SCHEMA: &[u8] = b"schema_version";
const META_NETWORK: &[u8] = b"network";
const META_TIP: &[u8] = b"tip";
const META_PRUNE_BLOCKS: &[u8] = b"prune_blocks";
const META_PRUNE_HEADERS: &[u8] = b"prune_headers";
const META_PRUNE_UNDO: &[u8] = b"prune_undo";
const META_OLDEST_BODY: &[u8] = b"oldest_body_height";
const META_OLDEST_HEADER: &[u8] = b"oldest_header_height";
const META_OLDEST_UNDO: &[u8] = b"oldest_undo_height";
const META_SNAPSHOT_VERIFICATION: &[u8] = b"snapshot_verification";

/// A snapshot whose history is being independently verified.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SnapshotVerification {
    pub height: u64,
    pub block_id: Hash,
    pub status: SnapshotVerificationStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnapshotVerificationStatus {
    Pending,
    Verified,
    Invalid,
}

impl SnapshotVerification {
    fn encode(self) -> [u8; 41] {
        let mut bytes = [0; 41];
        bytes[..8].copy_from_slice(&self.height.to_be_bytes());
        bytes[8..40].copy_from_slice(&self.block_id);
        bytes[40] = match self.status {
            SnapshotVerificationStatus::Pending => 0,
            SnapshotVerificationStatus::Verified => 1,
            SnapshotVerificationStatus::Invalid => 2,
        };
        bytes
    }

    fn decode(bytes: &[u8]) -> Result<Self, StorageError> {
        if bytes.len() != 41 {
            return Err(StorageError::Corrupt("snapshot verification"));
        }
        let height = u64::from_be_bytes(bytes[..8].try_into().unwrap());
        let block_id = bytes[8..40].try_into().unwrap();
        let status = match bytes[40] {
            0 => SnapshotVerificationStatus::Pending,
            1 => SnapshotVerificationStatus::Verified,
            2 => SnapshotVerificationStatus::Invalid,
            _ => return Err(StorageError::Corrupt("snapshot verification status")),
        };
        Ok(Self {
            height,
            block_id,
            status,
        })
    }
}

/// How much history this node keeps. Every field is counted in blocks below the tip and `0` means
/// "keep everything", so an archival node is simply `PrunePolicy::none()`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrunePolicy {
    /// Blocks whose bodies are deleted.
    pub blocks: u64,
    /// Blocks whose headers are deleted. Headers are 234 bytes, so this is normally left high.
    pub headers: u64,
    /// Blocks whose undo records are deleted. Only reorgs can read an undo record, so this can be
    /// far shorter than `blocks`: an archival node keeps every body and still drops the reorg log.
    pub undo: u64,
}

impl PrunePolicy {
    /// Keep everything: a full archival node.
    pub const fn none() -> PrunePolicy {
        PrunePolicy {
            blocks: 0,
            headers: 0,
            undo: 0,
        }
    }

    pub const fn new(blocks: u64, headers: u64) -> PrunePolicy {
        PrunePolicy {
            blocks,
            headers,
            undo: DEFAULT_PRUNE_UNDO,
        }
    }

    /// Keep undo records for `undo` blocks instead of the default.
    pub const fn with_undo(mut self, undo: u64) -> PrunePolicy {
        self.undo = undo;
        self
    }

    /// Bodies and headers are what make a node archival; a short undo window does not.
    pub fn is_archival(&self) -> bool {
        self.blocks == 0 && self.headers == 0
    }
}

/// What one pruning pass removed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PruneReport {
    pub bodies_removed: u64,
    pub headers_removed: u64,
    pub undo_removed: u64,
    /// Bodies below this height no longer exist. `0` means nothing has been pruned.
    pub oldest_body_height: u64,
    pub oldest_header_height: u64,
    pub oldest_undo_height: u64,
}

pub const SCHEMA_VERSION: u32 = 3;

#[derive(Debug)]
pub enum StorageError {
    Db(String),
    Codec(CodecError),
    Consensus(ConsensusError),
    SchemaMismatch { found: u32, expected: u32 },
    WrongNetwork { found: u8, expected: u8 },
    Corrupt(&'static str),
}

impl std::fmt::Display for StorageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StorageError::Db(e) => write!(f, "database error: {e}"),
            StorageError::Codec(e) => write!(f, "undecodable stored value: {e}"),
            StorageError::Consensus(e) => write!(f, "stored header failed validation: {e}"),
            StorageError::SchemaMismatch { found, expected } => {
                write!(
                    f,
                    "database schema version {found} does not match {expected}"
                )
            }
            StorageError::WrongNetwork { found, expected } => {
                write!(
                    f,
                    "database belongs to network {found}, expected {expected}"
                )
            }
            StorageError::Corrupt(what) => write!(f, "corrupt database: {what}"),
        }
    }
}

impl std::error::Error for StorageError {}

impl From<CodecError> for StorageError {
    fn from(e: CodecError) -> Self {
        StorageError::Codec(e)
    }
}

impl From<ConsensusError> for StorageError {
    fn from(e: ConsensusError) -> Self {
        StorageError::Consensus(e)
    }
}

fn db<E: std::fmt::Display>(e: E) -> StorageError {
    StorageError::Db(e.to_string())
}

/// `height (u64 BE) || block id`, the key of `HEIGHT_INDEX`.
fn height_key(height: u64, id: &Hash) -> [u8; 40] {
    let mut key = [0u8; 40];
    key[..8].copy_from_slice(&height.to_be_bytes());
    key[8..].copy_from_slice(id);
    key
}

/// The height below which history may be deleted for `keep` blocks of retention.
///
/// The result is never inside the `PRUNE_FLOOR_BLOCKS` window, and never lower than what has already
/// been pruned, so a second pass with a longer retention is a no-op instead of a regression.
fn prune_cutoff(tip_height: u64, keep: u64, floor: u64, already_pruned_to: u64) -> u64 {
    if keep == 0 {
        return 0;
    }
    let by_policy = tip_height.saturating_sub(keep);
    let by_floor = tip_height.saturating_sub(floor);
    let target = by_policy.min(by_floor);
    if target <= already_pruned_to {
        already_pruned_to
    } else {
        target
    }
}

pub struct Store {
    db: Database,
    network: NetworkProfile,
}

/// Decode a `TX_INDEX` value: `block_id (32) ‖ height (8, be)`, or a legacy bare `block_id`.
fn decode_tx_location(bytes: &[u8]) -> Option<(Hash, Option<u64>)> {
    match bytes.len() {
        40 => {
            let mut id = [0u8; 32];
            id.copy_from_slice(&bytes[..32]);
            let mut height = [0u8; 8];
            height.copy_from_slice(&bytes[32..]);
            Some((id, Some(u64::from_be_bytes(height))))
        }
        // Written before the height was stored. The block is still known; the depth is not.
        32 => {
            let mut id = [0u8; 32];
            id.copy_from_slice(bytes);
            Some((id, None))
        }
        _ => None,
    }
}

/// Delete every row in a table inside an open write transaction.
fn clear_table(
    write: &redb::WriteTransaction,
    table: TableDefinition<&[u8], &[u8]>,
) -> Result<(), StorageError> {
    let mut table = write.open_table(table).map_err(db)?;
    let keys: Vec<Vec<u8>> = table
        .iter()
        .map_err(db)?
        .map(|entry| entry.map(|(key, _)| key.value().to_vec()).map_err(db))
        .collect::<Result<_, _>>()?;
    for key in keys {
        table.remove(&key[..]).map_err(db)?;
    }
    Ok(())
}

impl Store {
    pub fn open(path: &Path, network: NetworkProfile) -> Result<Store, StorageError> {
        let db = Database::create(path).map_err(db)?;
        let store = Store { db, network };
        store.ensure_schema()?;
        Ok(store)
    }

    pub fn network(&self) -> NetworkProfile {
        self.network
    }

    fn ensure_schema(&self) -> Result<(), StorageError> {
        let write = self.db.begin_write().map_err(db)?;
        {
            let mut meta = write.open_table(META).map_err(db)?;
            // Opening a table in a write transaction creates it; every table must exist
            // before any read transaction touches it.
            write.open_table(ACCOUNTS).map_err(db)?;
            write.open_table(HEADERS).map_err(db)?;
            write.open_table(BODIES).map_err(db)?;
            write.open_table(UNDO).map_err(db)?;
            write.open_table(PENDING).map_err(db)?;
            write.open_table(TX_INDEX).map_err(db)?;
            write.open_table(HEIGHT_INDEX).map_err(db)?;

            let existing = meta
                .get(META_SCHEMA)
                .map_err(db)?
                .map(|v| v.value().to_vec());
            match existing {
                None => {
                    meta.insert(META_SCHEMA, &SCHEMA_VERSION.to_be_bytes()[..])
                        .map_err(db)?;
                    meta.insert(META_NETWORK, &[self.network.network][..])
                        .map_err(db)?;
                }
                Some(bytes) => {
                    if bytes.len() != 4 {
                        return Err(StorageError::Corrupt("schema version"));
                    }
                    let mut found = [0u8; 4];
                    found.copy_from_slice(&bytes);
                    let found = u32::from_be_bytes(found);
                    if found != SCHEMA_VERSION {
                        return Err(StorageError::SchemaMismatch {
                            found,
                            expected: SCHEMA_VERSION,
                        });
                    }
                    let net = meta
                        .get(META_NETWORK)
                        .map_err(db)?
                        .map(|v| v.value().to_vec())
                        .ok_or(StorageError::Corrupt("missing network"))?;
                    if net.len() != 1 || net[0] != self.network.network {
                        return Err(StorageError::WrongNetwork {
                            found: net.first().copied().unwrap_or(u8::MAX),
                            expected: self.network.network,
                        });
                    }
                }
            }
        }
        write.commit().map_err(db)?;
        Ok(())
    }

    /// Rebuild the header chain, re-validating every stored header.
    pub fn load_chain(&self) -> Result<Chain, StorageError> {
        let read = self.db.begin_read().map_err(db)?;
        let mut rows: Vec<(u64, Vec<u8>, u128)> = Vec::new();
        {
            let table = read.open_table(HEADERS).map_err(db)?;
            for entry in table.iter().map_err(db)? {
                let (_key, value) = entry.map_err(db)?;
                let bytes = value.value();
                if bytes.len() < BLOCK_HEADER_BYTES + 24 {
                    return Err(StorageError::Corrupt("header record"));
                }
                let mut height = [0u8; 8];
                height.copy_from_slice(&bytes[BLOCK_HEADER_BYTES..BLOCK_HEADER_BYTES + 8]);
                let mut work = [0u8; 16];
                work.copy_from_slice(&bytes[BLOCK_HEADER_BYTES + 8..BLOCK_HEADER_BYTES + 24]);
                rows.push((
                    u64::from_be_bytes(height),
                    bytes[..BLOCK_HEADER_BYTES].to_vec(),
                    u128::from_be_bytes(work),
                ));
            }
        }
        rows.sort_by_key(|(height, _, _)| *height);

        let oldest = self.oldest_header_height()?;
        if oldest > 1 {
            // The prefix is gone, so headers cannot be validated against their parents here. They
            // were validated when they were written; `Node::open` re-validates the recent tail,
            // which is the part a corruption would have to pass through to matter.
            let mut chain = Chain::empty(self.network);
            for (height, bytes, work) in rows {
                let header = BlockHeader::decode(&bytes)?;
                chain.adopt(header, height, work);
            }
            chain.finish_loading();
            // Re-check the recent tail. Older headers are trusted from the database, where they
            // were validated at commit time; a corruption that mattered would have to reach the
            // tip, and the tail is re-checked from far enough back to have a full retarget window.
            let tip = chain.best_height();
            if tip >= oldest + DIFFICULTY_WINDOW_BLOCKS {
                let start = tip
                    .saturating_sub(PRUNE_FLOOR_BLOCKS)
                    .max(oldest + DIFFICULTY_WINDOW_BLOCKS);
                for height in start..=tip {
                    let Some(header) = chain.main_header_at(height) else {
                        return Err(StorageError::Corrupt("pruned header gap"));
                    };
                    check_header(&chain, &self.network, &header, true)?;
                }
            }
            return Ok(chain);
        }

        let mut chain = Chain::new(self.network);
        for (height, bytes, _) in rows {
            if height == 0 {
                continue; // genesis is seeded by `Chain::new`
            }
            let header = BlockHeader::decode(&bytes)?;
            // Validate against the parents already adopted above, then store without re-selecting
            // the best tip: `insert` rebuilds the main chain on every header, which makes loading
            // quadratic. `finish_loading` picks the tip once, after the last header.
            let meta = chain.validate_header(&header)?;
            chain.adopt(header, meta.height, meta.chain_work);
        }
        chain.finish_loading();
        // Headers below the prune boundary are gone from disk, so they must be gone from memory
        // too: a chain that claims headers it cannot serve would answer peers with ghosts.
        chain.prune_below(oldest);
        Ok(chain)
    }

    pub fn load_state(&self) -> Result<State, StorageError> {
        let read = self.db.begin_read().map_err(db)?;

        let mut accounts = Vec::new();
        {
            let table = read.open_table(ACCOUNTS).map_err(db)?;
            for entry in table.iter().map_err(db)? {
                let (key, value) = entry.map_err(db)?;
                let id: AccountId = key
                    .value()
                    .try_into()
                    .map_err(|_| StorageError::Corrupt("account key"))?;
                let mut r = Reader::new(value.value());
                let account = Account::decode(&mut r)?;
                r.finish()?;
                accounts.push((id, account));
            }
        }

        Ok(State::restore(accounts))
    }

    pub fn tip(&self) -> Result<Option<Hash>, StorageError> {
        let read = self.db.begin_read().map_err(db)?;
        let table = read.open_table(META).map_err(db)?;
        match table.get(META_TIP).map_err(db)? {
            Some(v) => {
                let id: Hash = v
                    .value()
                    .try_into()
                    .map_err(|_| StorageError::Corrupt("tip"))?;
                Ok(Some(id))
            }
            None => Ok(None),
        }
    }

    /// Clear a dedicated replay database so verification can restart on another branch.
    pub fn reset_replay(&self) -> Result<(), StorageError> {
        let write = self.db.begin_write().map_err(db)?;
        for table in [
            ACCOUNTS,
            HEADERS,
            BODIES,
            UNDO,
            HEIGHT_INDEX,
            TX_INDEX,
            PENDING,
        ] {
            clear_table(&write, table)?;
        }
        {
            let mut meta = write.open_table(META).map_err(db)?;
            meta.remove(META_TIP).map_err(db)?;
        }
        write.commit().map_err(db)?;
        Ok(())
    }

    pub fn snapshot_verification(&self) -> Result<Option<SnapshotVerification>, StorageError> {
        let read = self.db.begin_read().map_err(db)?;
        let meta = read.open_table(META).map_err(db)?;
        meta.get(META_SNAPSHOT_VERIFICATION)
            .map_err(db)?
            .map(|value| SnapshotVerification::decode(value.value()))
            .transpose()
    }

    pub fn begin_snapshot_verification(
        &self,
        verification: SnapshotVerification,
    ) -> Result<(), StorageError> {
        let write = self.db.begin_write().map_err(db)?;
        {
            let mut meta = write.open_table(META).map_err(db)?;
            if meta.get(META_SNAPSHOT_VERIFICATION).map_err(db)?.is_some() {
                return Err(StorageError::Corrupt(
                    "snapshot verification already exists",
                ));
            }
            let record = verification.encode();
            meta.insert(META_SNAPSHOT_VERIFICATION, &record[..])
                .map_err(db)?;
        }
        write.commit().map_err(db)?;
        Ok(())
    }

    /// Update the verification outcome only if it still refers to the same snapshot.
    pub fn finish_snapshot_verification(
        &self,
        expected: SnapshotVerification,
        status: SnapshotVerificationStatus,
    ) -> Result<bool, StorageError> {
        let write = self.db.begin_write().map_err(db)?;
        let updated;
        {
            let mut meta = write.open_table(META).map_err(db)?;
            let current = meta
                .get(META_SNAPSHOT_VERIFICATION)
                .map_err(db)?
                .map(|value| SnapshotVerification::decode(value.value()))
                .transpose()?;
            updated = current == Some(expected);
            if updated {
                let record = SnapshotVerification { status, ..expected }.encode();
                meta.insert(META_SNAPSHOT_VERIFICATION, &record[..])
                    .map_err(db)?;
            }
        }
        write.commit().map_err(db)?;
        Ok(updated)
    }

    /// The block that carried this transaction, if any block ever did.
    pub fn transaction_block(&self, txid: &Hash) -> Result<Option<Hash>, StorageError> {
        Ok(self
            .transaction_location(txid)?
            .map(|(block_id, _)| block_id))
    }

    /// Where a transaction was mined, with the height recorded at index time.
    ///
    /// The height is stored beside the block id so that confirmations survive header pruning and a
    /// snapshot install: without it a deeply buried transaction on a pruned node looked exactly like
    /// one nobody had ever seen, which is the wrong answer for an exchange asking about a deposit.
    /// Entries written before the format carried a height decode as `None`.
    pub fn transaction_location(
        &self,
        txid: &Hash,
    ) -> Result<Option<(Hash, Option<u64>)>, StorageError> {
        let read = self.db.begin_read().map_err(db)?;
        let table = read.open_table(TX_INDEX).map_err(db)?;
        Ok(table
            .get(&txid[..])
            .map_err(db)?
            .and_then(|value| decode_tx_location(value.value())))
    }

    pub fn body(&self, id: &Hash) -> Result<Option<Vec<u8>>, StorageError> {
        let read = self.db.begin_read().map_err(db)?;
        let table = read.open_table(BODIES).map_err(db)?;
        match table.get(&id[..]).map_err(db)? {
            None => Ok(None),
            Some(value) => {
                let value = value.value();
                // Newer records omit the header because `HEADERS` already holds it; older ones kept
                // the whole block. A canonical header starts with its version (`0x00 0x..`), so the
                // marker byte cannot be confused with a legacy record.
                if value.first() != Some(&BODY_WITHOUT_HEADER) {
                    return Ok(Some(value.to_vec()));
                }
                let headers = read.open_table(HEADERS).map_err(db)?;
                let Some(record) = headers.get(&id[..]).map_err(db)? else {
                    return Err(StorageError::Corrupt("body without its header"));
                };
                let record = record.value();
                if record.len() < BLOCK_HEADER_BYTES {
                    return Err(StorageError::Corrupt("header record"));
                }
                let mut block = Vec::with_capacity(BLOCK_HEADER_BYTES + value.len() - 1);
                block.extend_from_slice(&record[..BLOCK_HEADER_BYTES]);
                block.extend_from_slice(&value[1..]);
                Ok(Some(block))
            }
        }
    }

    /// A stored header with its position, so a node that keeps only a window of headers in memory can
    /// still serve and validate the rest from disk.
    pub fn header_record(
        &self,
        id: &Hash,
    ) -> Result<Option<(BlockHeader, u64, u128)>, StorageError> {
        let read = self.db.begin_read().map_err(db)?;
        let headers = read.open_table(HEADERS).map_err(db)?;
        let Some(record) = headers.get(&id[..]).map_err(db)? else {
            return Ok(None);
        };
        Ok(Some(decode_header_record(record.value())?))
    }

    /// The same record, addressed by main-chain height.
    pub fn header_at_height(
        &self,
        height: u64,
    ) -> Result<Option<(BlockHeader, u64, u128)>, StorageError> {
        let read = self.db.begin_read().map_err(db)?;
        let heights = read.open_table(HEIGHT_INDEX).map_err(db)?;
        let start = height_key(height, &[0u8; 32]);
        let end = height_key(height.saturating_add(1), &[0u8; 32]);
        let Some(entry) = heights.range(&start[..]..&end[..]).map_err(db)?.next() else {
            return Ok(None);
        };
        let key = entry.map_err(db)?.0.value().to_vec();
        if key.len() != 40 {
            return Err(StorageError::Corrupt("height index key"));
        }
        let mut id = [0u8; 32];
        id.copy_from_slice(&key[8..]);
        drop(heights);
        drop(read);
        self.header_record(&id)
    }

    pub fn undo(&self, id: &Hash) -> Result<Option<UndoLog>, StorageError> {
        let read = self.db.begin_read().map_err(db)?;
        let table = read.open_table(UNDO).map_err(db)?;
        match table.get(&id[..]).map_err(db)? {
            Some(v) => {
                let mut r = Reader::new(v.value());
                let log = UndoLog::read_from(&mut r)?;
                r.finish()?;
                Ok(Some(log))
            }
            None => Ok(None),
        }
    }

    /// Persist one fully validated block: accounts, header, body, and undo all become durable in a
    /// single transaction, or not at all.
    pub fn commit_block(&self, block: &ValidatedBlock, body: &[u8]) -> Result<(), StorageError> {
        let id = block.header.id();
        let write = self.db.begin_write().map_err(db)?;
        {
            let mut accounts = write.open_table(ACCOUNTS).map_err(db)?;
            for change in block.undo.changes() {
                match change {
                    StateChange::Account(account_id, _) => match block.state.account(account_id) {
                        Some(account) => {
                            let mut w = Writer::new();
                            account.encode(&mut w);
                            accounts.insert(&account_id[..], w.as_slice()).map_err(db)?;
                        }
                        None => {
                            accounts.remove(&account_id[..]).map_err(db)?;
                        }
                    },
                }
            }

            let mut header_record = Writer::new();
            header_record.fixed(&block.header.canonical());
            header_record.u64(block.height);
            header_record.bytes(&block.chain_work.to_be_bytes());
            write
                .open_table(HEADERS)
                .map_err(db)?
                .insert(&id[..], header_record.as_slice())
                .map_err(db)?;

            write
                .open_table(BODIES)
                .map_err(db)?
                .insert(&id[..], encode_body_record(body).as_slice())
                .map_err(db)?;

            write
                .open_table(HEIGHT_INDEX)
                .map_err(db)?
                .insert(&height_key(block.height, &id)[..], &[][..])
                .map_err(db)?;

            let mut undo_bytes = Writer::new();
            block.undo.write_to(&mut undo_bytes);
            write
                .open_table(UNDO)
                .map_err(db)?
                .insert(&id[..], undo_bytes.as_slice())
                .map_err(db)?;

            {
                let mut index = write.open_table(TX_INDEX).map_err(db)?;
                for tx in &block.transactions {
                    // Block id plus the height, so confirmations do not depend on the header
                    // surviving pruning.
                    let mut location = Writer::new();
                    location.fixed(&id);
                    location.u64(block.height);
                    index
                        .insert(&tx.id()[..], location.as_slice())
                        .map_err(db)?;
                }
            }

            let mut meta = write.open_table(META).map_err(db)?;
            // Extend the recorded tip only when this block builds directly on it.
            let current_tip = meta.get(META_TIP).map_err(db)?.map(|v| v.value().to_vec());
            let extends = match current_tip {
                None => true,
                Some(bytes) => bytes.as_slice() == block.header.previous_block_id,
            };
            if extends {
                meta.insert(META_TIP, &id[..]).map_err(db)?;
            }
        }
        write.commit().map_err(db)?;
        Ok(())
    }

    /// Record a header without a body. Snapshot sync walks the header chain first, because the
    /// snapshot is anchored to a header and the bodies may not exist on the peer at all.
    pub fn put_header(
        &self,
        header: &BlockHeader,
        height: u64,
        chain_work: u128,
    ) -> Result<(), StorageError> {
        let id = header.id();
        let write = self.db.begin_write().map_err(db)?;
        {
            let mut record = Writer::new();
            record.fixed(&header.canonical());
            record.u64(height);
            record.bytes(&chain_work.to_be_bytes());
            write
                .open_table(HEADERS)
                .map_err(db)?
                .insert(&id[..], record.as_slice())
                .map_err(db)?;
            write
                .open_table(HEIGHT_INDEX)
                .map_err(db)?
                .insert(&height_key(height, &id)[..], &[][..])
                .map_err(db)?;
        }
        write.commit().map_err(db)?;
        Ok(())
    }

    /// Record a block index entry (header + body) without touching account state. Used for blocks
    /// that are valid but not on the best chain yet.
    pub fn put_block_index(
        &self,
        header: &BlockHeader,
        height: u64,
        chain_work: u128,
        body: &[u8],
    ) -> Result<(), StorageError> {
        let id = header.id();
        let write = self.db.begin_write().map_err(db)?;
        {
            let mut record = Writer::new();
            record.fixed(&header.canonical());
            record.u64(height);
            record.bytes(&chain_work.to_be_bytes());
            write
                .open_table(HEADERS)
                .map_err(db)?
                .insert(&id[..], record.as_slice())
                .map_err(db)?;
            write
                .open_table(BODIES)
                .map_err(db)?
                .insert(&id[..], encode_body_record(body).as_slice())
                .map_err(db)?;
            write
                .open_table(HEIGHT_INDEX)
                .map_err(db)?
                .insert(&height_key(height, &id)[..], &[][..])
                .map_err(db)?;
        }
        write.commit().map_err(db)?;
        Ok(())
    }

    /// Rewrite the whole account view in one transaction. Used after a reorganization, where
    /// incremental diffs would be relative to the wrong parent.
    pub fn replace_state(&self, state: &State, tip: &Hash) -> Result<(), StorageError> {
        let write = self.db.begin_write().map_err(db)?;
        {
            {
                let mut accounts = write.open_table(ACCOUNTS).map_err(db)?;
                let stale: Vec<Vec<u8>> = accounts
                    .iter()
                    .map_err(db)?
                    .filter_map(|entry| entry.ok().map(|(k, _)| k.value().to_vec()))
                    .collect();
                for key in stale {
                    accounts.remove(&key[..]).map_err(db)?;
                }
                for (id, account) in state.accounts_iter() {
                    let mut w = Writer::new();
                    account.encode(&mut w);
                    accounts.insert(&id[..], w.as_slice()).map_err(db)?;
                }
            }
            let mut meta = write.open_table(META).map_err(db)?;
            meta.insert(META_TIP, &tip[..]).map_err(db)?;
        }
        write.commit().map_err(db)?;
        Ok(())
    }

    pub fn set_tip(&self, id: &Hash) -> Result<(), StorageError> {
        let write = self.db.begin_write().map_err(db)?;
        {
            let mut meta = write.open_table(META).map_err(db)?;
            meta.insert(META_TIP, &id[..]).map_err(db)?;
        }
        write.commit().map_err(db)?;
        Ok(())
    }

    /// Replace the entire live state with a snapshot verified against the header at `height`.
    ///
    /// This is the one operation that writes state without applying a block, so the caller must have
    /// already checked `state.root() == header.state_root` for that header. Everything that can only
    /// be interpreted relative to the blocks that produced the old state — undo records, bodies,
    /// the transaction index — is dropped, because the node no longer holds the history those blocks
    /// belong to. Headers and the height index are kept: they were validated as a chain and are what
    /// the snapshot is anchored to.
    pub fn install_snapshot(
        &self,
        header: &BlockHeader,
        height: u64,
        state: &State,
    ) -> Result<(), StorageError> {
        let id = header.id();
        let write = self.db.begin_write().map_err(db)?;
        {
            clear_table(&write, ACCOUNTS)?;
            let mut accounts = write.open_table(ACCOUNTS).map_err(db)?;
            for (account_id, account) in state.accounts_iter() {
                let mut w = Writer::new();
                account.encode(&mut w);
                accounts.insert(&account_id[..], w.as_slice()).map_err(db)?;
            }

            // Undo logs describe transitions out of a state that no longer exists.
            clear_table(&write, UNDO)?;
            clear_table(&write, BODIES)?;
            clear_table(&write, TX_INDEX)?;

            let mut meta = write.open_table(META).map_err(db)?;
            meta.insert(META_TIP, &id[..]).map_err(db)?;
            let verification = SnapshotVerification {
                height,
                block_id: id,
                status: SnapshotVerificationStatus::Pending,
            }
            .encode();
            meta.insert(META_SNAPSHOT_VERIFICATION, &verification[..])
                .map_err(db)?;
            // Nothing below the snapshot can ever be served, and no undo exists for it.
            let oldest = height.saturating_add(1);
            meta.insert(META_OLDEST_BODY, &oldest.to_be_bytes()[..])
                .map_err(db)?;
        }
        write.commit().map_err(db)?;
        Ok(())
    }

    /// The pruning policy recorded in this database, or the defaults for a database that has none.
    ///
    /// The defaults are deliberately not "keep everything": a node that keeps every body forever is
    /// the exception, and an operator who wants it says so (`--prune-blocks 0 --prune-headers 0`).
    pub fn prune_policy(&self) -> Result<PrunePolicy, StorageError> {
        let read = self.db.begin_read().map_err(db)?;
        let meta = read.open_table(META).map_err(db)?;
        let get = |key: &[u8]| -> Result<Option<u64>, StorageError> {
            Ok(meta.get(key).map_err(db)?.and_then(|value| {
                let bytes = value.value();
                (bytes.len() == 8).then(|| {
                    let mut word = [0u8; 8];
                    word.copy_from_slice(bytes);
                    u64::from_be_bytes(word)
                })
            }))
        };
        Ok(PrunePolicy {
            blocks: get(META_PRUNE_BLOCKS)?.unwrap_or(DEFAULT_PRUNE_BLOCKS),
            headers: get(META_PRUNE_HEADERS)?.unwrap_or(DEFAULT_PRUNE_HEADERS),
            undo: get(META_PRUNE_UNDO)?.unwrap_or(DEFAULT_PRUNE_UNDO),
        })
    }

    /// Record the policy. Pruning is destructive, so the choice is stored next to the data it affects:
    /// a later run that omits the flags keeps pruning exactly as before instead of silently keeping
    /// (or losing) more history than intended.
    pub fn set_prune_policy(&self, policy: PrunePolicy) -> Result<(), StorageError> {
        let write = self.db.begin_write().map_err(db)?;
        {
            let mut meta = write.open_table(META).map_err(db)?;
            meta.insert(META_PRUNE_BLOCKS, &policy.blocks.to_be_bytes()[..])
                .map_err(db)?;
            meta.insert(META_PRUNE_HEADERS, &policy.headers.to_be_bytes()[..])
                .map_err(db)?;
            meta.insert(META_PRUNE_UNDO, &policy.undo.to_be_bytes()[..])
                .map_err(db)?;
        }
        write.commit().map_err(db)?;
        Ok(())
    }

    /// The lowest height whose body still exists (0 when nothing has been pruned).
    pub fn oldest_body_height(&self) -> Result<u64, StorageError> {
        self.meta_u64(META_OLDEST_BODY)
            .map(|value| value.unwrap_or(0))
    }

    /// The lowest height whose header still exists (1 once header pruning has run; genesis stays).
    pub fn oldest_header_height(&self) -> Result<u64, StorageError> {
        self.meta_u64(META_OLDEST_HEADER)
            .map(|value| value.unwrap_or(0))
    }

    /// The lowest height whose undo record still exists (0 when nothing has been pruned).
    pub fn oldest_undo_height(&self) -> Result<u64, StorageError> {
        self.meta_u64(META_OLDEST_UNDO)
            .map(|value| value.unwrap_or(0))
    }

    fn meta_u64(&self, key: &[u8]) -> Result<Option<u64>, StorageError> {
        let read = self.db.begin_read().map_err(db)?;
        let meta = read.open_table(META).map_err(db)?;
        Ok(meta.get(key).map_err(db)?.and_then(|value| {
            let bytes = value.value();
            (bytes.len() == 8).then(|| {
                let mut word = [0u8; 8];
                word.copy_from_slice(bytes);
                u64::from_be_bytes(word)
            })
        }))
    }

    fn set_meta_u64(
        &self,
        meta: &mut redb::Table<'_, &[u8], &[u8]>,
        key: &[u8],
        value: u64,
    ) -> Result<(), StorageError> {
        meta.insert(key, &value.to_be_bytes()[..]).map_err(db)?;
        Ok(())
    }

    /// Delete history older than the policy allows, in one transaction.
    ///
    /// `blocks` controls bodies and their undo records together: without a body there is nothing to
    /// rewind or replay, so keeping one without the other would be useless. `headers` is separate
    /// because headers are cheap and are what makes the chain verifiable. Nothing inside
    /// `PRUNE_FLOOR_BLOCKS` of the tip is ever touched, and `0` disables that half entirely.
    pub fn prune(&self, tip_height: u64, policy: PrunePolicy) -> Result<PruneReport, StorageError> {
        let body_cutoff = prune_cutoff(
            tip_height,
            policy.blocks,
            PRUNE_FLOOR_BLOCKS,
            self.oldest_body_height()?,
        );
        let header_cutoff = prune_cutoff(
            tip_height,
            policy.headers,
            PRUNE_FLOOR_BLOCKS,
            self.oldest_header_height()?,
        );
        let undo_cutoff = prune_cutoff(
            tip_height,
            policy.undo,
            PRUNE_FLOOR_BLOCKS,
            self.oldest_undo_height()?,
        );

        let mut report = PruneReport {
            oldest_body_height: self.oldest_body_height()?,
            oldest_header_height: self.oldest_header_height()?,
            oldest_undo_height: self.oldest_undo_height()?,
            ..PruneReport::default()
        };
        let bodies_done = body_cutoff == 0 || body_cutoff <= report.oldest_body_height;
        let headers_done = header_cutoff == 0 || header_cutoff <= report.oldest_header_height;
        let undo_done = undo_cutoff == 0 || undo_cutoff <= report.oldest_undo_height;
        if bodies_done && headers_done && undo_done {
            return Ok(report);
        }

        let upper = body_cutoff.max(header_cutoff).max(undo_cutoff);
        let write = self.db.begin_write().map_err(db)?;
        {
            let rows: Vec<(u64, Hash)> = {
                let heights = write.open_table(HEIGHT_INDEX).map_err(db)?;
                let start = height_key(0, &[0u8; 32]);
                let end = height_key(upper, &[0u8; 32]);
                let mut rows = Vec::new();
                for entry in heights.range(&start[..]..&end[..]).map_err(db)? {
                    let (key, _) = entry.map_err(db)?;
                    let key = key.value();
                    if key.len() != 40 {
                        continue;
                    }
                    let mut height = [0u8; 8];
                    height.copy_from_slice(&key[..8]);
                    let mut id = [0u8; 32];
                    id.copy_from_slice(&key[8..]);
                    rows.push((u64::from_be_bytes(height), id));
                }
                rows
            };

            let mut bodies = write.open_table(BODIES).map_err(db)?;
            let mut undo = write.open_table(UNDO).map_err(db)?;
            let mut headers = write.open_table(HEADERS).map_err(db)?;
            let mut heights = write.open_table(HEIGHT_INDEX).map_err(db)?;

            for (height, id) in rows {
                if body_cutoff > 0 && height < body_cutoff {
                    bodies.remove(&id[..]).map_err(db)?;
                    report.bodies_removed += 1;
                }
                if undo_cutoff > 0 && height < undo_cutoff {
                    undo.remove(&id[..]).map_err(db)?;
                    report.undo_removed += 1;
                }
                if header_cutoff > 0 && height < header_cutoff {
                    headers.remove(&id[..]).map_err(db)?;
                    heights.remove(&height_key(height, &id)[..]).map_err(db)?;
                    report.headers_removed += 1;
                }
            }

            let mut meta = write.open_table(META).map_err(db)?;
            if body_cutoff > 0 {
                report.oldest_body_height = report.oldest_body_height.max(body_cutoff);
                self.set_meta_u64(&mut meta, META_OLDEST_BODY, report.oldest_body_height)?;
            }
            if header_cutoff > 0 {
                report.oldest_header_height = report.oldest_header_height.max(header_cutoff);
                self.set_meta_u64(&mut meta, META_OLDEST_HEADER, report.oldest_header_height)?;
            }
            if undo_cutoff > 0 {
                report.oldest_undo_height = report.oldest_undo_height.max(undo_cutoff);
                self.set_meta_u64(&mut meta, META_OLDEST_UNDO, report.oldest_undo_height)?;
            }
        }
        write.commit().map_err(db)?;
        Ok(report)
    }

    // ------------------------------------------------------------ mempool persistence

    /// Remember an admitted transaction so it survives a restart.
    pub fn put_pending(&self, id: &Hash, bytes: &[u8]) -> Result<(), StorageError> {
        self.update_pending(&[], Some((id, bytes)))
    }

    /// Atomically remove old entries and optionally add their replacement.
    pub fn update_pending(
        &self,
        removed: &[Hash],
        added: Option<(&Hash, &[u8])>,
    ) -> Result<(), StorageError> {
        let write = self.db.begin_write().map_err(db)?;
        {
            let mut table = write.open_table(PENDING).map_err(db)?;
            for id in removed {
                table.remove(&id[..]).map_err(db)?;
            }
            if let Some((id, bytes)) = added {
                table.insert(&id[..], bytes).map_err(db)?;
            }
        }
        write.commit().map_err(db)?;
        Ok(())
    }

    pub fn remove_pending(&self, id: &Hash) -> Result<(), StorageError> {
        self.update_pending(&[*id], None)
    }

    /// Replace the pending table with the pool restored against the current state.
    pub fn replace_pending(&self, entries: &[(Hash, Vec<u8>)]) -> Result<(), StorageError> {
        let write = self.db.begin_write().map_err(db)?;
        {
            let mut table = write.open_table(PENDING).map_err(db)?;
            let keys: Vec<Vec<u8>> = table
                .iter()
                .map_err(db)?
                .map(|entry| entry.map(|(key, _)| key.value().to_vec()).map_err(db))
                .collect::<Result<_, _>>()?;
            for key in keys {
                table.remove(key.as_slice()).map_err(db)?;
            }
            for (id, bytes) in entries {
                table.insert(&id[..], bytes.as_slice()).map_err(db)?;
            }
        }
        write.commit().map_err(db)?;
        Ok(())
    }

    pub fn load_pending(&self) -> Result<Vec<Vec<u8>>, StorageError> {
        let read = self.db.begin_read().map_err(db)?;
        let table = read.open_table(PENDING).map_err(db)?;
        let mut out = Vec::new();
        for entry in table.iter().map_err(db)? {
            let (_, value) = entry.map_err(db)?;
            out.push(value.value().to_vec());
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vess_consensus::build_template;
    use vess_core::constants::GENESIS_REWARD;

    /// What a block at genesis difficulty pays its miner.
    const MINED: u64 = GENESIS_REWARD - GENESIS_REWARD / 100;

    struct TempDb {
        path: std::path::PathBuf,
    }

    impl TempDb {
        fn new() -> TempDb {
            use std::sync::atomic::{AtomicU64, Ordering};
            static COUNTER: AtomicU64 = AtomicU64::new(0);
            let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "vess-store-{}-{}-{}.redb",
                std::process::id(),
                nanos,
                unique
            ));
            TempDb { path }
        }
    }

    impl Drop for TempDb {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
        }
    }

    fn network() -> NetworkProfile {
        NetworkProfile::DEVNET
    }

    const MINER: [u8; 32] = [0x11u8; 32];

    fn mine_blocks(store: &Store, count: u64) -> (Chain, State) {
        let mut chain = store.load_chain().unwrap();
        let mut state = store.load_state().unwrap();

        for _ in 0..count {
            let timestamp =
                chain.best_header().timestamp_unix_ms + vess_core::constants::TARGET_BLOCK_MS;
            let mut template = build_template(
                &chain,
                &network(),
                &chain.best_id(),
                &state,
                &MINER,
                timestamp,
                &[],
            )
            .unwrap();
            assert!(template.mine(20_000_000));
            let bytes = template.encode();
            let validated =
                vess_consensus::validate_block(&chain, &network(), &state, &bytes).unwrap();
            store.commit_block(&validated, &bytes).unwrap();
            state = validated.state.clone();
            chain.insert(validated.header).unwrap();
        }
        (chain, state)
    }

    // ---------------------------------------------------------------- pruning

    #[test]
    fn the_transaction_index_remembers_where_and_when() {
        // A legacy entry (no height) must still resolve to its block, and a new one must carry the
        // height so confirmations survive pruning.
        let db = TempDb::new();
        let store = Store::open(&db.path, network()).unwrap();
        let (chain, _) = mine_blocks(&store, 2);
        let height = chain.best_height();
        let body = store.body(&chain.best_id()).unwrap().expect("a body");
        let (_, transactions) = vess_consensus::split_block(&body).unwrap();

        if let Some(tx) = transactions.first() {
            let (block_id, stored) = store.transaction_location(&tx.id()).unwrap().unwrap();
            assert_eq!(block_id, chain.best_id());
            assert_eq!(stored, Some(height), "the height is recorded at index time");
            assert_eq!(store.transaction_block(&tx.id()).unwrap(), Some(block_id));
        }

        // Decoding is total over both layouts, and rejects anything else.
        let mut legacy = Vec::new();
        legacy.extend_from_slice(&[7u8; 32]);
        assert_eq!(decode_tx_location(&legacy), Some(([7u8; 32], None)));
        let mut modern = legacy.clone();
        modern.extend_from_slice(&9u64.to_be_bytes());
        assert_eq!(decode_tx_location(&modern), Some(([7u8; 32], Some(9))));
        assert_eq!(decode_tx_location(&[1, 2, 3]), None);
        assert_eq!(decode_tx_location(&[]), None);
        assert_eq!(store.transaction_location(&[0xEEu8; 32]).unwrap(), None);
    }

    /// Mine a chain, prune it, and check both what survived and that the node keeps working.
    #[test]
    fn pruning_keeps_the_configured_window_and_still_loads() {
        let temp = TempDb::new();
        let store = Store::open(&temp.path, network()).unwrap();
        let (chain, state) = mine_blocks(&store, 290);
        let tip_height = chain.best_height();
        let tip = chain.best_id();
        let root = state.root();
        let floor = tip_height - PRUNE_FLOOR_BLOCKS;
        let id_at = |height: u64| chain.main_header_at(height).unwrap().id();

        // Archival: nothing is removed, whatever the tip is.
        let report = store.prune(tip_height, PrunePolicy::none()).unwrap();
        assert_eq!(report.bodies_removed, 0);
        assert_eq!(report.headers_removed, 0);
        assert_eq!(store.oldest_body_height().unwrap(), 0);

        // A retention longer than the chain removes nothing: there is nothing old enough yet.
        let report = store.prune(tip_height, PrunePolicy::new(1_000, 0)).unwrap();
        assert_eq!(report.bodies_removed, 0);

        // Bodies and undo go together, and never inside the safety floor. Genesis has no stored body
        // and no height-index row, so the removable range is heights 1..floor.
        let report = store.prune(tip_height, PrunePolicy::new(10, 0)).unwrap();
        assert_eq!(
            report.bodies_removed,
            floor - 1,
            "the floor bounds what may be pruned"
        );
        assert_eq!(store.oldest_body_height().unwrap(), floor);
        assert_eq!(store.oldest_header_height().unwrap(), 0);
        assert!(store.body(&id_at(0)).unwrap().is_none());
        assert!(store.undo(&id_at(0)).unwrap().is_none());
        assert!(store.body(&id_at(floor)).unwrap().is_some());
        assert!(store.body(&id_at(tip_height)).unwrap().is_some());

        // A huge header window still prunes nothing beyond the same floor.
        let report = store
            .prune(tip_height, PrunePolicy::new(10, 100_000))
            .unwrap();
        assert_eq!(report.headers_removed, 0);
        assert_eq!(store.oldest_header_height().unwrap(), 0);

        // Keeping every body but only some headers is a legal mixture: the earlier pass already
        // removed bodies below the floor, and this pass must not touch any body at all.
        let report = store.prune(tip_height, PrunePolicy::new(0, 100)).unwrap();
        assert_eq!(report.headers_removed, floor - 1);
        assert_eq!(report.bodies_removed, 0);
        assert_eq!(store.oldest_header_height().unwrap(), floor);
        assert!(
            store.body(&id_at(floor)).unwrap().is_some(),
            "bodies untouched"
        );

        // Policy is stored with the data, so a restart keeps the same behaviour.
        store.set_prune_policy(PrunePolicy::new(64, 128)).unwrap();
        drop(store);

        let store = Store::open(&temp.path, network()).unwrap();
        assert_eq!(store.prune_policy().unwrap(), PrunePolicy::new(64, 128));
        assert_eq!(store.oldest_body_height().unwrap(), floor);
        assert_eq!(store.oldest_header_height().unwrap(), floor);
        assert_eq!(store.load_state().unwrap().root(), root);

        // The chain still loads from its oldest retained header and accepts the next block.
        let loaded = store.load_chain().unwrap();
        assert_eq!(loaded.best_id(), tip);
        assert_eq!(loaded.oldest_main_height(), floor);
        assert!(loaded.main_header_at(0).is_none());
        mine_blocks(&store, 1);
        assert_eq!(store.load_chain().unwrap().best_height(), tip_height + 1);
    }

    /// Undo records are the only thing a reorg reads, so they carry their own retention window: an
    /// archival node keeps every body and still drops the reorg log it can never reach.
    #[test]
    fn undo_retention_is_independent_of_bodies() {
        let temp = TempDb::new();
        let store = Store::open(&temp.path, network()).unwrap();
        let (chain, _) = mine_blocks(&store, 290);
        let tip_height = chain.best_height();
        let floor = tip_height - PRUNE_FLOOR_BLOCKS;
        let id_at = |height: u64| chain.main_header_at(height).unwrap().id();

        // Keep every body, keep undo only inside the reorg window.
        let policy = PrunePolicy::new(0, 0).with_undo(PRUNE_FLOOR_BLOCKS);
        let report = store.prune(tip_height, policy).unwrap();
        assert_eq!(report.bodies_removed, 0, "archival bodies survive");
        assert_eq!(report.undo_removed, floor - 1);
        assert_eq!(store.oldest_body_height().unwrap(), 0);
        assert_eq!(store.oldest_undo_height().unwrap(), floor);
        // Genesis carries neither a body nor an undo record, so the removable range starts at 1.
        assert!(store.body(&id_at(1)).unwrap().is_some());
        assert!(store.undo(&id_at(1)).unwrap().is_none());
        assert!(store.undo(&id_at(floor)).unwrap().is_some());

        // A later pass with the same policy does nothing, and bodies are still untouched.
        let report = store.prune(tip_height, policy).unwrap();
        assert_eq!(report.undo_removed, 0);
        assert_eq!(report.bodies_removed, 0);

        // The window is stored with the data.
        store.set_prune_policy(policy).unwrap();
        drop(store);
        let store = Store::open(&temp.path, network()).unwrap();
        assert_eq!(store.prune_policy().unwrap(), policy);
        assert_eq!(store.prune_policy().unwrap().undo, PRUNE_FLOOR_BLOCKS);
    }
    #[test]
    fn default_retention_and_saved_policy_are_distinct() {
        let temp = TempDb::new();
        let store = Store::open(&temp.path, network()).unwrap();
        assert_eq!(store.prune_policy().unwrap().blocks, 16_384);
        store
            .set_prune_policy(PrunePolicy::new(1_024, DEFAULT_PRUNE_HEADERS))
            .unwrap();
        drop(store);

        let store = Store::open(&temp.path, network()).unwrap();
        assert_eq!(store.prune_policy().unwrap().blocks, 1_024);
    }

    #[test]
    fn commit_and_reopen_preserves_the_whole_state() {
        let temp = TempDb::new();
        let store = Store::open(&temp.path, network()).unwrap();
        assert_eq!(store.tip().unwrap(), None);
        assert_eq!(store.load_chain().unwrap().best_height(), 0);

        let (chain, state) = mine_blocks(&store, 3);
        assert_eq!(chain.best_height(), 3);
        let root = state.root();
        let tip = chain.best_id();
        let balance = state.balance(&MINER);
        assert_eq!(balance, 3 * MINED);
        assert_eq!(store.tip().unwrap(), Some(tip));
        drop(store);

        // Reopen: headers are re-validated, state is rebuilt, nothing is trusted blindly.
        let store = Store::open(&temp.path, network()).unwrap();
        let chain = store.load_chain().unwrap();
        let state = store.load_state().unwrap();
        assert_eq!(chain.best_height(), 3);
        assert_eq!(chain.best_id(), tip);
        assert_eq!(state.root(), root);
        assert_eq!(state.balance(&MINER), balance);
        assert!(store.body(&tip).unwrap().is_some());
        assert!(store.undo(&tip).unwrap().is_some());
    }

    /// The header already lives in `HEADERS`, so `BODIES` stores only what follows it. Reads must
    /// still hand back a whole block, and a legacy record must keep working.
    #[test]
    fn bodies_do_not_store_a_second_copy_of_the_header() {
        let temp = TempDb::new();
        let store = Store::open(&temp.path, network()).unwrap();
        let (chain, _) = mine_blocks(&store, 2);
        let tip = chain.best_id();
        let block = store.body(&tip).unwrap().expect("stored body");
        let header = chain.main_header_at(2).unwrap().canonical();
        assert_eq!(&block[..BLOCK_HEADER_BYTES], &header[..]);

        let record = {
            let read = store.db.begin_read().unwrap();
            let table = read.open_table(BODIES).unwrap();
            table.get(&tip[..]).unwrap().unwrap().value().to_vec()
        };
        assert_eq!(
            record.len(),
            block.len() - BLOCK_HEADER_BYTES + 1,
            "only the body and one marker byte are stored"
        );
        assert_eq!(record[0], BODY_WITHOUT_HEADER);
        assert_eq!(&record[1..], &block[BLOCK_HEADER_BYTES..]);
    }

    /// A record written before bodies were trimmed holds the whole block and must still be readable.
    #[test]
    fn a_legacy_whole_block_body_is_still_returned() {
        let temp = TempDb::new();
        let store = Store::open(&temp.path, network()).unwrap();
        let (chain, _) = mine_blocks(&store, 1);
        let tip = chain.best_id();
        let block = store.body(&tip).unwrap().expect("stored body");

        {
            let write = store.db.begin_write().unwrap();
            write
                .open_table(BODIES)
                .unwrap()
                .insert(&tip[..], block.as_slice())
                .unwrap();
            write.commit().unwrap();
        }
        assert_eq!(store.body(&tip).unwrap().unwrap(), block);
    }

    /// A process that dies mid-life must still find its last committed block.
    ///
    /// This re-executes the test binary as a child, has the child commit blocks and then `abort()`
    /// (skipping every destructor and every clean shutdown path), and opens the same database in the
    /// parent. That is a real crash, not a simulated one.
    #[test]
    fn a_committed_block_survives_a_crash() {
        const CHILD: &str = "VESS_CRASH_CHILD";
        const DB: &str = "VESS_CRASH_DB";

        if std::env::var(CHILD).is_ok() {
            let path = std::env::var(DB).expect("child needs a database path");
            let store = Store::open(std::path::Path::new(&path), network()).unwrap();
            let (chain, state) = mine_blocks(&store, 2);
            let mut record = Vec::new();
            record.extend_from_slice(&chain.best_id());
            record.extend_from_slice(&state.root());
            std::fs::write(format!("{path}.expect"), record).unwrap();
            std::process::abort();
        }

        let temp = TempDb::new();
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("tests::a_committed_block_survives_a_crash")
            .env(CHILD, "1")
            .env(DB, &temp.path)
            .output()
            .expect("re-run the test binary");
        assert!(
            !status.status.success(),
            "the child was supposed to die without cleaning up"
        );

        let expectation = std::fs::read(format!("{}.expect", temp.path.display())).unwrap();
        let expected_tip: [u8; 32] = expectation[..32].try_into().unwrap();
        let expected_root: [u8; 32] = expectation[32..64].try_into().unwrap();

        // The lock died with the child, and the committed blocks are intact.
        let store = Store::open(&temp.path, network()).unwrap();
        assert_eq!(store.tip().unwrap(), Some(expected_tip));
        let chain = store.load_chain().unwrap();
        let state = store.load_state().unwrap();
        assert_eq!(chain.best_height(), 2);
        assert_eq!(state.root(), expected_root);
        assert_eq!(state.balance(&MINER), 2 * MINED);
        assert!(store.undo(&expected_tip).unwrap().is_some());
        // And the node can keep building on what it found.
        mine_blocks(&store, 1);
        assert_eq!(store.load_chain().unwrap().best_height(), 3);
    }

    #[test]
    fn commit_is_durable_immediately() {
        let temp = TempDb::new();
        let store = Store::open(&temp.path, network()).unwrap();
        let (chain, state) = mine_blocks(&store, 1);

        let timestamp = chain.best_header().timestamp_unix_ms + 1;
        let mut template = build_template(
            &chain,
            &network(),
            &chain.best_id(),
            &state,
            &MINER,
            timestamp,
            &[],
        )
        .unwrap();
        assert!(template.mine(20_000_000));
        let bytes = template.encode();
        let validated = vess_consensus::validate_block(&chain, &network(), &state, &bytes).unwrap();
        store.commit_block(&validated, &bytes).unwrap();
        drop(store);

        let reopened = Store::open(&temp.path, network()).unwrap();
        assert_eq!(reopened.load_chain().unwrap().best_height(), 2);
        assert_eq!(
            reopened.load_state().unwrap().root(),
            validated.state.root()
        );
        assert_eq!(reopened.tip().unwrap(), Some(validated.header.id()));
    }

    #[test]
    fn opening_a_database_from_another_network_fails_loudly() {
        let temp = TempDb::new();
        {
            let _store = Store::open(&temp.path, NetworkProfile::DEVNET).unwrap();
        }
        let err = Store::open(&temp.path, NetworkProfile::TESTNET)
            .err()
            .unwrap();
        assert!(matches!(err, StorageError::WrongNetwork { .. }));
    }

    #[test]
    fn opening_a_pre_millisecond_database_fails_loudly() {
        let temp = TempDb::new();
        {
            let store = Store::open(&temp.path, network()).unwrap();
            let write = store.db.begin_write().unwrap();
            {
                let mut meta = write.open_table(META).unwrap();
                meta.insert(META_SCHEMA, &1u32.to_be_bytes()[..]).unwrap();
            }
            write.commit().unwrap();
        }
        assert!(matches!(
            Store::open(&temp.path, network()),
            Err(StorageError::SchemaMismatch {
                found: 1,
                expected: 3
            })
        ));
    }

    #[test]
    fn undo_round_trips_through_storage() {
        let temp = TempDb::new();
        let store = Store::open(&temp.path, network()).unwrap();
        let (chain, state) = mine_blocks(&store, 2);
        let tip = chain.best_id();

        // Unwinding the tip's undo restores the state after block 1.
        let mut rewound = state.clone();
        rewound.apply_undo(store.undo(&tip).unwrap().unwrap());
        assert_ne!(rewound.root(), state.root());
        assert_eq!(rewound.balance(&MINER), MINED);

        // And unwinding block 1 restores genesis exactly.
        let first = chain.main_header_at(1).unwrap().id();
        rewound.apply_undo(store.undo(&first).unwrap().unwrap());
        assert_eq!(rewound.root(), vess_consensus::empty_state_root());
        assert_eq!(rewound.account_count(), 0);
    }
}
