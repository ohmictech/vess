//! Archival block files.
//!
//! History is the one thing a node cannot recompute, so it is stored in a form that can be copied,
//! checked and repaired without running a node: a directory of deterministic chunk files plus a
//! manifest of their hashes. Chunks are content-addressed and self-delimiting, so a mirror only has
//! to compare hashes to know its copy is intact.
//!
//! Erasure coding is the opposite of compression: `encode` writes `k` data shards and `m` parity
//! shards, each roughly `size/k`, and any `k` of the `k + m` rebuild the file. That makes losing
//! most of a mirror set survivable without making the data smaller — block bodies are signatures and
//! public keys, which do not compress.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use vess_consensus::{encode_body, split_block};
use vess_core::hash;
use vess_core::{Hash, Transaction};

/// Blocks per chunk file. Small enough to checksum and repair quickly, large enough that the
/// per-file overhead disappears.
pub const BLOCKS_PER_CHUNK: u64 = 1_000;

const DOM_CHUNK: &[u8] = b"VESS-ARCHIVE-CHUNK-V1";
const MANIFEST: &str = "manifest.txt";
const MAGIC: &str = "vess-archive 1";

pub fn chunk_hash(bytes: &[u8]) -> Hash {
    hash::tagged(DOM_CHUNK, &[bytes])
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn parse_hex(value: &str) -> Result<Vec<u8>, String> {
    if !value.len().is_multiple_of(2) {
        return Err(format!("odd-length hex: {value}"));
    }
    (0..value.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&value[i..i + 2], 16).map_err(|_| format!("bad hex: {value}")))
        .collect()
}

/// Encode one chunk: `u32` length prefix plus the canonical block bytes, repeated.
fn encode_chunk(blocks: &[(u64, Vec<u8>)]) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    for (_, bytes) in blocks {
        let len = u32::try_from(bytes.len()).map_err(|_| "block too large to archive")?;
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(bytes);
    }
    Ok(out)
}

fn decode_chunk(bytes: &[u8]) -> Result<Vec<Vec<u8>>, String> {
    let mut blocks = Vec::new();
    let mut rest = bytes;
    while !rest.is_empty() {
        if rest.len() < 4 {
            return Err("truncated chunk record".into());
        }
        let mut len = [0u8; 4];
        len.copy_from_slice(&rest[..4]);
        let len = u32::from_be_bytes(len) as usize;
        let start: usize = 4;
        let end = start
            .checked_add(len)
            .filter(|end| *end <= rest.len())
            .ok_or("chunk record length exceeds the file")?;
        blocks.push(rest[start..end].to_vec());
        rest = &rest[end..];
    }
    Ok(blocks)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Chunk {
    pub file: String,
    pub hash: Hash,
    pub blocks: u64,
    pub first: u64,
    pub last: u64,
    /// The id of the block before `first`, so a mirror can prove the chunks form one chain.
    pub previous: Hash,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Manifest {
    pub network: u8,
    pub chunks: Vec<Chunk>,
}

impl Manifest {
    pub fn total_blocks(&self) -> u64 {
        self.chunks.iter().map(|chunk| chunk.blocks).sum()
    }

    fn render(&self) -> String {
        let mut out = format!(
            "{MAGIC}\nnetwork={}\nchunks={}\n",
            self.network,
            self.chunks.len()
        );
        for chunk in &self.chunks {
            out.push_str(&format!(
                "file={} hash={} previous={} blocks={} first={} last={}\n",
                chunk.file,
                hex(&chunk.hash),
                hex(&chunk.previous),
                chunk.blocks,
                chunk.first,
                chunk.last
            ));
        }
        out
    }

    fn parse(text: &str) -> Result<Manifest, String> {
        let mut lines = text.lines();
        if lines.next().map(str::trim) != Some(MAGIC) {
            return Err("not a vess archive manifest".into());
        }
        let mut network = 0u8;
        let mut chunks = Vec::new();
        for line in lines {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let mut fields = BTreeMap::new();
            for pair in line.split_whitespace() {
                let (key, value) = pair
                    .split_once('=')
                    .ok_or_else(|| format!("malformed manifest line: {line}"))?;
                fields.insert(key, value);
            }
            let get = |key: &str| {
                fields
                    .get(key)
                    .copied()
                    .ok_or_else(|| format!("manifest line missing {key}: {line}"))
            };
            match get("file") {
                Ok(file) => {
                    let number = |key: &str| -> Result<u64, String> {
                        get(key)?
                            .parse()
                            .map_err(|_| format!("manifest {key} is not a number: {line}"))
                    };
                    chunks.push(Chunk {
                        file: file.to_string(),
                        hash: parse_hex(get("hash")?)?
                            .try_into()
                            .map_err(|_| "manifest hash is not 32 bytes")?,
                        previous: parse_hex(get("previous")?)?
                            .try_into()
                            .map_err(|_| "manifest previous id is not 32 bytes")?,
                        blocks: number("blocks")?,
                        first: number("first")?,
                        last: number("last")?,
                    });
                }
                Err(_) => {
                    if let Some(value) = fields.get("network") {
                        network = value
                            .parse()
                            .map_err(|_| "manifest network is not a number")?;
                    }
                }
            }
        }
        Ok(Manifest { network, chunks })
    }
}

/// What an export wrote.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportSummary {
    pub chunks: usize,
    pub blocks: u64,
    pub bytes: u64,
    pub first: u64,
    pub last: u64,
}

fn chunk_name(first: u64, last: u64) -> String {
    format!("vess-{first:010}-{last:010}.blk")
}

/// Write every body in `from..=to` as chunk files plus a manifest.
///
/// `body_at` yields the stored body for a height, which is how a pruned node exports only the part of
/// history it still holds; the caller is expected to clamp the range to that window.
pub fn export(
    out: &Path,
    network: u8,
    from: u64,
    to: u64,
    mut body_at: impl FnMut(u64) -> Result<Option<Vec<u8>>, String>,
) -> Result<ExportSummary, String> {
    fs::create_dir_all(out).map_err(|e| format!("creating {}: {e}", out.display()))?;
    let mut manifest = Manifest {
        network,
        chunks: Vec::new(),
    };
    let mut summary = ExportSummary {
        chunks: 0,
        blocks: 0,
        bytes: 0,
        first: from,
        last: to,
    };
    let mut height = from;
    while height <= to {
        let last = (height + BLOCKS_PER_CHUNK - 1).min(to);
        let mut blocks = Vec::new();
        for h in height..=last {
            let Some(body) = body_at(h)? else {
                return Err(format!("no stored body at height {h}"));
            };
            blocks.push((h, body));
        }
        if blocks.is_empty() {
            break;
        }
        let bytes = encode_chunk(&blocks)?;
        let file = chunk_name(height, last);
        fs::write(out.join(&file), &bytes).map_err(|e| format!("writing {file}: {e}"))?;
        summary.bytes += bytes.len() as u64;
        summary.blocks += blocks.len() as u64;
        summary.chunks += 1;
        let first_header = split_block(&blocks[0].1)
            .map_err(|e| format!("invalid block at height {height}: {e}"))?
            .0;
        manifest.chunks.push(Chunk {
            file,
            hash: chunk_hash(&bytes),
            blocks: blocks.len() as u64,
            first: height,
            last,
            previous: first_header.previous_block_id,
        });
        height = last + 1;
    }
    fs::write(out.join(MANIFEST), manifest.render())
        .map_err(|e| format!("writing manifest: {e}"))?;
    Ok(summary)
}

/// What a verification pass saw.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VerifySummary {
    pub chunks: u64,
    pub blocks: u64,
}

/// Check every chunk against the manifest and itself: file hash, framing, and the block chain links
/// inside each file. No node, no database, no state — this is what a mirror runs.
pub fn verify(dir: &Path) -> Result<VerifySummary, String> {
    let manifest = read_manifest(dir)?;
    let mut summary = VerifySummary::default();
    let mut linked: Option<u64> = None;
    for chunk in &manifest.chunks {
        let bytes =
            fs::read(dir.join(&chunk.file)).map_err(|e| format!("reading {}: {e}", chunk.file))?;
        if chunk_hash(&bytes) != chunk.hash {
            return Err(format!("{} does not match the manifest hash", chunk.file));
        }
        let blocks = decode_chunk(&bytes)?;
        if blocks.len() as u64 != chunk.blocks {
            return Err(format!(
                "{} holds {} blocks, manifest says {}",
                chunk.file,
                blocks.len(),
                chunk.blocks
            ));
        }
        // Chunks must be one contiguous chain, including across file boundaries.
        if let Some(previous_last) = linked
            && chunk.first != previous_last + 1
        {
            return Err(format!(
                "{} starts at height {}, but the previous chunk ended at {previous_last}",
                chunk.file, chunk.first
            ));
        }
        let mut previous: Option<Hash> = None;
        for body in &blocks {
            let (header, transactions) = split_block(body)
                .map_err(|e| format!("{} holds an invalid block: {e}", chunk.file))?;
            let expected = previous.unwrap_or(chunk.previous);
            if header.previous_block_id != expected {
                return Err(format!("{} breaks the block chain", chunk.file));
            }
            // The body must re-encode to exactly what was stored, so nothing rides along unhashed.
            let canonical = encode_body(&transactions)
                .map_err(|e| format!("{} holds an unencodable body: {e}", chunk.file))?;
            if canonical != body[vess_core::constants::BLOCK_HEADER_BYTES..] {
                return Err(format!("{} holds a non-canonical body", chunk.file));
            }
            previous = Some(header.id());
        }
        linked = Some(chunk.last);
        summary.chunks += 1;
        summary.blocks += blocks.len() as u64;
    }
    Ok(summary)
}

fn read_manifest(dir: &Path) -> Result<Manifest, String> {
    let text = fs::read_to_string(dir.join(MANIFEST))
        .map_err(|e| format!("reading manifest in {}: {e}", dir.display()))?;
    Manifest::parse(&text)
}

/// One shard set on disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShardSet {
    pub file: String,
    pub hash: Hash,
    pub length: u64,
    pub data: usize,
    pub parity: usize,
    pub shard_len: usize,
    pub shards: Vec<String>,
}

impl ShardSet {
    pub fn total(&self) -> usize {
        self.data + self.parity
    }
}

const SHARD_MANIFEST: &str = "shards.txt";

fn render_shards(sets: &[ShardSet]) -> String {
    let mut out = format!(
        "{MAGIC}\nparity-scheme=reed-solomon\ngroups={}\n",
        sets.len()
    );
    for set in sets {
        out.push_str(&format!(
            "file={} hash={} length={} data={} parity={} shard_len={}\n",
            set.file,
            hex(&set.hash),
            set.length,
            set.data,
            set.parity,
            set.shard_len
        ));
        for shard in &set.shards {
            out.push_str(&format!("shard={shard}\n"));
        }
    }
    out
}

fn parse_shards(text: &str) -> Result<Vec<ShardSet>, String> {
    let mut lines = text.lines();
    if lines.next().map(str::trim) != Some(MAGIC) {
        return Err("not a vess shard manifest".into());
    }

    fn finish(
        file: Option<String>,
        hash: Option<String>,
        length: Option<String>,
        data: Option<String>,
        parity: Option<String>,
        shard_len: Option<String>,
        shards: Vec<String>,
    ) -> Result<ShardSet, String> {
        let file = file.ok_or("shard group without a file")?;
        let number = |value: Option<String>, what: &str| -> Result<u64, String> {
            value
                .ok_or_else(|| format!("shard group {file} missing {what}"))?
                .parse()
                .map_err(|_| format!("shard {what} is not a number"))
        };
        Ok(ShardSet {
            hash: parse_hex(&hash.ok_or_else(|| format!("shard group {file} missing hash"))?)?
                .try_into()
                .map_err(|_| "shard hash is not 32 bytes")?,
            length: number(length, "length")?,
            data: number(data, "data")? as usize,
            parity: number(parity, "parity")? as usize,
            shard_len: number(shard_len, "shard_len")? as usize,
            file,
            shards,
        })
    }

    #[derive(Default)]
    struct Group {
        file: Option<String>,
        hash: Option<String>,
        length: Option<String>,
        data: Option<String>,
        parity: Option<String>,
        shard_len: Option<String>,
        shards: Vec<String>,
    }

    let mut sets = Vec::new();
    let mut group = Group::default();
    for line in lines {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        // A group header is one line of several `key=value` pairs; each shard is its own line.
        for pair in line.split_whitespace() {
            let (key, value) = pair
                .split_once('=')
                .ok_or_else(|| format!("malformed shard line: {line}"))?;
            match key {
                "file" => {
                    if group.file.is_some() {
                        sets.push(finish(
                            group.file.take(),
                            group.hash.take(),
                            group.length.take(),
                            group.data.take(),
                            group.parity.take(),
                            group.shard_len.take(),
                            std::mem::take(&mut group.shards),
                        )?);
                    }
                    group.file = Some(value.to_string());
                }
                "hash" => group.hash = Some(value.to_string()),
                "length" => group.length = Some(value.to_string()),
                "data" => group.data = Some(value.to_string()),
                "parity" => group.parity = Some(value.to_string()),
                "shard_len" => group.shard_len = Some(value.to_string()),
                "shard" => group.shards.push(value.to_string()),
                // Top-level counters and the scheme marker.
                _ => {}
            }
        }
    }
    if group.file.is_some() {
        sets.push(finish(
            group.file.take(),
            group.hash.take(),
            group.length.take(),
            group.data.take(),
            group.parity.take(),
            group.shard_len.take(),
            std::mem::take(&mut group.shards),
        )?);
    }
    Ok(sets)
}

fn shard_name(file: &str, index: usize) -> String {
    format!("{file}.shard{index}")
}

/// Erasure-code every chunk in `dir` into `dir/shards`.
///
/// `data` shards plus `parity` shards per file; any `data` of them rebuild it. Cost is
/// `(data + parity) / data` times the archive size on disk, spread across as many holders as there
/// are shards.
pub fn encode(dir: &Path, data: usize, parity: usize) -> Result<Vec<ShardSet>, String> {
    if data == 0 || parity == 0 || data + parity > 255 {
        return Err("need 1..=255 data+parity shards, with at least one of each".into());
    }
    let manifest = read_manifest(dir)?;
    let shards_dir = dir.join("shards");
    fs::create_dir_all(&shards_dir).map_err(|e| format!("creating shards dir: {e}"))?;
    let coder = reed_solomon_erasure::galois_8::ReedSolomon::new(data, parity)
        .map_err(|e| format!("reed-solomon parameters: {e}"))?;

    let mut sets = Vec::new();
    for chunk in &manifest.chunks {
        let bytes =
            fs::read(dir.join(&chunk.file)).map_err(|e| format!("reading {}: {e}", chunk.file))?;
        if chunk_hash(&bytes) != chunk.hash {
            return Err(format!("{} does not match the manifest hash", chunk.file));
        }
        let shard_len = bytes.len().div_ceil(data);
        let mut shards: Vec<Vec<u8>> = Vec::with_capacity(data + parity);
        for index in 0..data {
            let start = index * shard_len;
            let end = (start + shard_len).min(bytes.len());
            let mut shard = vec![0u8; shard_len];
            if start < bytes.len() {
                shard[..end - start].copy_from_slice(&bytes[start..end]);
            }
            shards.push(shard);
        }
        for _ in 0..parity {
            shards.push(vec![0u8; shard_len]);
        }
        coder
            .encode(&mut shards)
            .map_err(|e| format!("encoding {}: {e}", chunk.file))?;
        let mut names = Vec::new();
        for (index, shard) in shards.iter().enumerate() {
            let name = shard_name(&chunk.file, index);
            fs::write(shards_dir.join(&name), shard)
                .map_err(|e| format!("writing shard {name}: {e}"))?;
            names.push(name);
        }
        sets.push(ShardSet {
            file: chunk.file.clone(),
            hash: chunk.hash,
            length: bytes.len() as u64,
            data,
            parity,
            shard_len,
            shards: names,
        });
    }
    fs::write(shards_dir.join(SHARD_MANIFEST), render_shards(&sets))
        .map_err(|e| format!("writing shard manifest: {e}"))?;
    Ok(sets)
}

/// Rebuild every file in a shard directory into `out`, then check it against its recorded hash.
pub fn decode(shards_dir: &Path, out: &Path) -> Result<Vec<PathBuf>, String> {
    let text = fs::read_to_string(shards_dir.join(SHARD_MANIFEST))
        .map_err(|e| format!("reading shard manifest: {e}"))?;
    let sets = parse_shards(&text)?;
    fs::create_dir_all(out).map_err(|e| format!("creating {}: {e}", out.display()))?;
    let mut written = Vec::new();
    for set in &sets {
        if set.shards.len() != set.total() {
            return Err(format!(
                "{} lists {} shards, expected {}",
                set.file,
                set.shards.len(),
                set.total()
            ));
        }
        let coder = reed_solomon_erasure::galois_8::ReedSolomon::new(set.data, set.parity)
            .map_err(|e| format!("reed-solomon parameters: {e}"))?;
        let mut shards: Vec<Option<Vec<u8>>> = Vec::with_capacity(set.total());
        let mut present = 0usize;
        for name in &set.shards {
            match fs::read(shards_dir.join(name)) {
                Ok(bytes) if bytes.len() == set.shard_len => {
                    shards.push(Some(bytes));
                    present += 1;
                }
                _ => shards.push(None),
            }
        }
        if present < set.data {
            return Err(format!(
                "{} has {present} of {set} shards; {data} are needed",
                set.file,
                set = set.total(),
                data = set.data
            ));
        }
        coder
            .reconstruct(&mut shards)
            .map_err(|e| format!("reconstructing {}: {e}", set.file))?;
        let mut bytes = Vec::with_capacity(set.shard_len * set.data);
        for shard in shards.into_iter().take(set.data) {
            bytes.extend_from_slice(&shard.ok_or("reconstruction left a hole")?);
        }
        bytes.truncate(set.length as usize);
        if chunk_hash(&bytes) != set.hash {
            return Err(format!(
                "reconstructed {} does not match its hash",
                set.file
            ));
        }
        let path = out.join(&set.file);
        fs::write(&path, &bytes).map_err(|e| format!("writing {}: {e}", set.file))?;
        written.push(path);
    }
    Ok(written)
}

/// Bodies for a height, as the exporter needs them.
pub fn bodies_between(
    blocks: impl IntoIterator<Item = (u64, Vec<u8>)>,
) -> impl FnMut(u64) -> Result<Option<Vec<u8>>, String> {
    let mut map: BTreeMap<u64, Vec<u8>> = blocks.into_iter().collect();
    move |height| Ok(map.remove(&height))
}

/// Whether a body's transactions re-encode canonically, used by tests and mirrors.
pub fn canonical_body(transactions: &[Transaction]) -> Result<Vec<u8>, String> {
    encode_body(transactions).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "vess-archive-{}-{}-{name}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).unwrap();
        path
    }

    /// Fake but self-consistent blocks: real headers, linked, empty bodies.
    fn fake_blocks(from: u64, to: u64) -> Vec<(u64, Vec<u8>)> {
        use vess_core::constants::{BLOCK_HEADER_BYTES, NetworkProfile, PROTOCOL_VERSION};
        let network = NetworkProfile::DEVNET;
        let mut out = Vec::new();
        let mut previous = [0u8; 32];
        for height in from..=to {
            let header = vess_core::BlockHeader {
                version: PROTOCOL_VERSION,
                chain_id: hash::chain_id(network.network),
                previous_block_id: previous,
                transaction_root: hash::empty_tx_root(),
                state_root: hash::state_root(&hash::empty_tx_root()),
                timestamp_unix_ms: 1_700_000_000_000 + height,
                target: network.genesis_target,
                payout_account_id: [1u8; 32],
                security_nonce: [0u8; 32],
            };
            previous = header.id();
            let mut bytes = header.canonical().to_vec();
            bytes.extend(encode_body(&[]).unwrap());
            debug_assert_eq!(bytes.len(), BLOCK_HEADER_BYTES + 4);
            out.push((height, bytes));
        }
        out
    }

    #[test]
    fn export_then_verify_round_trips_and_detects_damage() {
        let dir = temp("export");
        let blocks = fake_blocks(0, 2_499);
        let bodies: BTreeMap<u64, Vec<u8>> = blocks.iter().cloned().collect();
        let summary = export(&dir, 0, 0, 2_499, |height| Ok(bodies.get(&height).cloned())).unwrap();
        assert_eq!(summary.chunks, 3);
        assert_eq!(summary.blocks, 2_500);

        let verified = verify(&dir).unwrap();
        assert_eq!(verified.chunks, 3);
        assert_eq!(verified.blocks, 2_500);

        // Flip one byte in a chunk: verification must name it.
        let chunk = dir.join("vess-0000001000-0000001999.blk");
        let mut bytes = fs::read(&chunk).unwrap();
        bytes[10] ^= 0x01;
        fs::write(&chunk, &bytes).unwrap();
        let error = verify(&dir).unwrap_err();
        assert!(error.contains("vess-0000001000-0000001999.blk"), "{error}");
    }

    #[test]
    fn erasure_coding_rebuilds_after_losing_shards() {
        let dir = temp("shards");
        let blocks = fake_blocks(0, 1_999);
        let bodies: BTreeMap<u64, Vec<u8>> = blocks.iter().cloned().collect();
        export(&dir, 0, 0, 1_999, |height| Ok(bodies.get(&height).cloned())).unwrap();

        let sets = encode(&dir, 4, 2).unwrap();
        assert_eq!(sets.len(), 2);
        // Each of 6 shards is ~1/4 of the chunk: spreading beats mirroring.
        let shard_len = sets[0].shard_len as u64;
        assert!(shard_len * 6 >= sets[0].length);

        // Destroy two shards per file, including the whole "second half" of the set.
        for set in &sets {
            fs::remove_file(dir.join("shards").join(&set.shards[1])).unwrap();
            fs::remove_file(dir.join("shards").join(&set.shards[5])).unwrap();
        }
        let out = dir.join("rebuilt");
        let written = decode(&dir.join("shards"), &out).unwrap();
        assert_eq!(written.len(), 2);
        for set in &sets {
            let original = fs::read(dir.join(&set.file)).unwrap();
            let rebuilt = fs::read(out.join(&set.file)).unwrap();
            assert_eq!(original, rebuilt, "{} must rebuild byte for byte", set.file);
        }
        // The rebuilt archive still verifies on its own.
        fs::copy(dir.join(MANIFEST), out.join(MANIFEST)).unwrap();
        assert_eq!(verify(&out).unwrap().blocks, 2_000);
    }
}
