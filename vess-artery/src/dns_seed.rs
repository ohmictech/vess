//! DNS seed resolution for bootstrap peer discovery.
//!
//! Nodes query `_vess.<domain>` for TXT records containing bootstrap
//! EndpointIds. Uses hickory-resolver for pure-Rust, cross-platform
//! DNS resolution — no external binaries required.
//!
//! Expected TXT record format:
//!   `_vess.example.com  TXT  "node=<base32_endpoint_id>"`
//!
//! Multiple TXT records may be published for redundancy.

use anyhow::{Context, Result};
use hickory_resolver::proto::rr::RData;
use hickory_resolver::TokioResolver;
use tracing::info;

/// Default DNS seed domain. Nodes query this automatically unless
/// `--no-seed` is passed.
pub const DEFAULT_SEED_DOMAIN: &str = "node.vess.network";

/// Name of the seeds file that lives alongside the artery state.
pub const SEEDS_FILENAME: &str = "seeds.txt";

/// Default seeds file content, written on first run.
const DEFAULT_SEEDS_CONTENT: &str = "\
# Vess DNS seed domains — one per line.
# Nodes resolve _vess.<domain> TXT records at startup to find bootstrap peers.
# Lines starting with # are comments. Blank lines are ignored.
#
# You can add community-run seed domains below the defaults.

node.vess.network
";

/// Prefix inside each TXT record value that precedes the EndpointId.
const NODE_PREFIX: &str = "node=";

/// Resolve DNS TXT records at `_vess.<domain>` and return the raw
/// EndpointId strings found within.
///
/// Records that do not start with `node=` are silently skipped so
/// that the TXT RRset can carry other metadata in the future.
pub async fn resolve_seeds(domain: &str) -> Result<Vec<String>> {
    let lookup_name = format!("_vess.{domain}");
    info!(dns = %lookup_name, "resolving DNS seed");

    let records = resolve_txt(&lookup_name)
        .await
        .with_context(|| format!("DNS seed lookup failed for {lookup_name}"))?;

    let mut peers = Vec::new();
    for txt in &records {
        let txt = txt.trim();
        if let Some(id_str) = txt.strip_prefix(NODE_PREFIX) {
            let id_str = id_str.trim();
            if !id_str.is_empty() {
                peers.push(id_str.to_string());
            }
        }
    }

    info!(count = peers.len(), dns = %lookup_name, "resolved DNS seed peers");
    Ok(peers)
}

// ── TXT resolution via hickory-resolver (pure Rust, cross-platform) ─

async fn resolve_txt(name: &str) -> Result<Vec<String>> {
    let resolver: TokioResolver = TokioResolver::builder_tokio()
        .map_err(|e| anyhow::anyhow!("failed to create DNS resolver: {e}"))?
        .build()?;

    let response = resolver
        .txt_lookup(name)
        .await
        .map_err(|e| anyhow::anyhow!("TXT lookup failed for {name}: {e}"))?;

    let mut records = Vec::new();
    for record in response.answers() {
        if let RData::TXT(ref txt) = record.data {
            let value: String = txt
                .txt_data
                .iter()
                .map(|chunk| String::from_utf8_lossy(chunk).into_owned())
                .collect();
            if !value.is_empty() {
                records.push(value);
            }
        }
    }

    Ok(records)
}

// ── Seeds file ─────────────────────────────────────────────────────

/// Load DNS seed domains from `seeds.txt` in the given directory.
///
/// If the file doesn't exist, it is created with sensible defaults
/// (including `node.vess.network`). Users can add community seed
/// domains by editing this file — it is read fresh on every startup.
///
/// Format: one domain per line, `#` comments, blank lines ignored.
pub fn load_seeds_file(state_dir: &std::path::Path) -> Vec<String> {
    let path = state_dir.join(SEEDS_FILENAME);

    // Create the default file if it doesn't exist yet.
    if !path.exists() {
        if let Err(e) = std::fs::create_dir_all(state_dir) {
            info!(error = %e, "could not create state dir for seeds.txt");
            return vec![DEFAULT_SEED_DOMAIN.to_string()];
        }
        if let Err(e) = std::fs::write(&path, DEFAULT_SEEDS_CONTENT) {
            info!(error = %e, "could not write default seeds.txt");
            return vec![DEFAULT_SEED_DOMAIN.to_string()];
        }
        info!(path = %path.display(), "created default seeds.txt");
    }

    // Read and parse.
    match std::fs::read_to_string(&path) {
        Ok(content) => {
            let seeds: Vec<String> = content
                .lines()
                .map(|l| l.trim())
                .filter(|l| !l.is_empty() && !l.starts_with('#'))
                .map(|l| l.to_string())
                .collect();
            info!(count = seeds.len(), path = %path.display(), "loaded seeds.txt");
            if seeds.is_empty() {
                vec![DEFAULT_SEED_DOMAIN.to_string()]
            } else {
                seeds
            }
        }
        Err(e) => {
            info!(error = %e, "could not read seeds.txt — using default seed");
            vec![DEFAULT_SEED_DOMAIN.to_string()]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_node_prefix() {
        let txt = "node=abc123def456";
        assert_eq!(txt.strip_prefix(NODE_PREFIX), Some("abc123def456"));
    }

    #[test]
    fn skip_non_node_records() {
        let txt = "v=spf1 include:example.com ~all";
        assert!(txt.strip_prefix(NODE_PREFIX).is_none());
    }

    #[test]
    fn trim_whitespace() {
        let txt = "  node=  abc123  ";
        let id = txt.trim().strip_prefix(NODE_PREFIX).unwrap().trim();
        assert_eq!(id, "abc123");
    }

    #[test]
    fn load_seeds_file_creates_default() {
        let dir = tempfile::tempdir().unwrap();
        let seeds = load_seeds_file(dir.path());
        assert!(seeds.contains(&DEFAULT_SEED_DOMAIN.to_string()));
        assert!(dir.path().join(SEEDS_FILENAME).exists());
    }

    #[test]
    fn load_seeds_file_reads_custom() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join(SEEDS_FILENAME),
            "# comment\nnode.vess.network\ncustom.example.com\n\n",
        )
        .unwrap();
        let seeds = load_seeds_file(dir.path());
        assert_eq!(
            seeds,
            vec![
                "node.vess.network".to_string(),
                "custom.example.com".to_string(),
            ]
        );
    }

    #[test]
    fn load_seeds_file_empty_falls_back() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(SEEDS_FILENAME), "# only comments\n").unwrap();
        let seeds = load_seeds_file(dir.path());
        assert_eq!(seeds, vec![DEFAULT_SEED_DOMAIN.to_string()]);
    }
}
