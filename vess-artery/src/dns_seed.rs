//! DNS seed resolution for bootstrap peer discovery.
//!
//! Nodes query `_vess.<domain>` for TXT records containing bootstrap
//! mesh contacts. Uses hickory-resolver for pure-Rust, cross-platform
//! DNS resolution — no external binaries required.
//!
//! Expected TXT record format:
//!   `_vess.example.com  TXT  "contact=<hex(compact MeshCarrierContact)>"`
//!
//! Multiple TXT records may be published for redundancy.

use anyhow::{Context, Result};
use hickory_resolver::proto::rr::RData;
use hickory_resolver::TokioResolver;
use tracing::info;

use crate::mesh_contact::{decode_contact_bytes, encode_contact_bytes, encode_contact_string};
use vess_mesh::{validate_public_mesh_contact, MeshCarrierContact};

/// Name of the seeds file that lives alongside the artery state.
pub const SEEDS_FILENAME: &str = "seeds.txt";

/// Default seeds file content, written on first run.
const DEFAULT_SEEDS_CONTENT: &str = "\
# Vess DNS seed domains — one per line.
# Nodes resolve _vess.<domain> TXT records at startup to find bootstrap peers.
# Lines starting with # are comments. Blank lines are ignored.
#
# Add one or more community-run seed domains below.
";

/// Prefix inside each TXT record value that precedes the serialized mesh contact.
const CONTACT_PREFIX: &str = "contact=";

/// Encode a serialized mesh contact into the TXT-safe record format used by Vess DNS seeds.
pub fn encode_seed_contact_record(contact: &MeshCarrierContact) -> Result<String> {
    validate_public_mesh_contact(contact)?;
    let contact_bytes = encode_contact_bytes(contact)?;
    Ok(format!("{CONTACT_PREFIX}{}", hex_encode(&contact_bytes)))
}

/// Resolve DNS TXT records at `_vess.<domain>` and return serialized
/// mesh contact strings found within.
///
/// Records that do not start with `contact=` are silently skipped so
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
        if let Some(contact_hex) = txt.strip_prefix(CONTACT_PREFIX) {
            let contact_hex = contact_hex.trim();
            if contact_hex.is_empty() {
                continue;
            }

            let contact_bytes = match hex_decode(contact_hex) {
                Ok(bytes) => bytes,
                Err(error) => {
                    info!(dns = %lookup_name, %error, "skipping invalid DNS seed contact record");
                    continue;
                }
            };

            let contact = match decode_contact_bytes(&contact_bytes) {
                Ok(contact) => contact,
                Err(error) => {
                    info!(dns = %lookup_name, %error, "skipping undecodable DNS seed contact");
                    continue;
                }
            };

            if let Err(error) = validate_public_mesh_contact(&contact) {
                info!(dns = %lookup_name, %error, "skipping non-public DNS seed contact");
                continue;
            }

            match encode_contact_string(&contact) {
                Ok(contact_str) => peers.push(contact_str),
                Err(error) => {
                    info!(dns = %lookup_name, %error, "skipping unencodable DNS seed contact");
                }
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

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn hex_decode(value: &str) -> std::result::Result<Vec<u8>, String> {
    if !value.len().is_multiple_of(2) {
        return Err("odd-length hex string".to_string());
    }

    (0..value.len())
        .step_by(2)
        .map(|index| {
            u8::from_str_radix(&value[index..index + 2], 16)
                .map_err(|error| format!("invalid hex at offset {index}: {error}"))
        })
        .collect()
}

// ── Seeds file ─────────────────────────────────────────────────────

/// Load DNS seed domains from `seeds.txt` in the given directory.
///
/// If the file doesn't exist, it is created with comments only. Users can
/// add community seed domains by editing this file — it is read fresh on
/// every startup.
///
/// Format: one domain per line, `#` comments, blank lines ignored.
pub fn load_seeds_file(state_dir: &std::path::Path) -> Vec<String> {
    let path = state_dir.join(SEEDS_FILENAME);

    // Create the default file if it doesn't exist yet.
    if !path.exists() {
        if let Err(e) = std::fs::create_dir_all(state_dir) {
            info!(error = %e, "could not create state dir for seeds.txt");
            return Vec::new();
        }
        if let Err(e) = std::fs::write(&path, DEFAULT_SEEDS_CONTENT) {
            info!(error = %e, "could not write default seeds.txt");
            return Vec::new();
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
            seeds
        }
        Err(e) => {
            info!(error = %e, "could not read seeds.txt");
            Vec::new()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vess_mesh::MeshCarrierContact;

    #[test]
    fn encode_seed_contact_round_trips() {
        let (_, mesh_address) = vess_mesh::generate_mesh_keys_from_seed(&[7u8; 64], 1);
        let contact = MeshCarrierContact::UdpSocket {
            addr: "93.184.216.34:9444".to_string(),
            mesh_address,
        };

        let txt = encode_seed_contact_record(&contact).unwrap();
        let encoded = txt.trim().strip_prefix(CONTACT_PREFIX).unwrap();
        let decoded = decode_contact_bytes(&hex_decode(encoded).unwrap()).unwrap();
        assert_eq!(decoded, contact);
    }

    #[test]
    fn skip_non_contact_records() {
        let txt = "v=spf1 include:example.com ~all";
        assert!(txt.strip_prefix(CONTACT_PREFIX).is_none());
    }

    #[test]
    fn trim_whitespace() {
        let txt = "  contact=  abcd  ";
        let encoded = txt.trim().strip_prefix(CONTACT_PREFIX).unwrap().trim();
        assert_eq!(encoded, "abcd");
    }

    #[test]
    fn load_seeds_file_creates_default() {
        let dir = tempfile::tempdir().unwrap();
        let seeds = load_seeds_file(dir.path());
        assert!(seeds.is_empty());
        assert!(dir.path().join(SEEDS_FILENAME).exists());
    }

    #[test]
    fn load_seeds_file_reads_custom() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join(SEEDS_FILENAME),
            "# comment\nseed-a.example.com\nseed-b.example.com\n\n",
        )
        .unwrap();
        let seeds = load_seeds_file(dir.path());
        assert_eq!(
            seeds,
            vec![
                "seed-a.example.com".to_string(),
                "seed-b.example.com".to_string(),
            ]
        );
    }

    #[test]
    fn load_seeds_file_empty_returns_empty() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(SEEDS_FILENAME), "# only comments\n").unwrap();
        let seeds = load_seeds_file(dir.path());
        assert!(seeds.is_empty());
    }
}
