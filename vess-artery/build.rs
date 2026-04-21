//! Build script for vess-artery.
//!
//! Computes a deterministic `PROTOCOL_VERSION_HASH` — a Blake3 Merkle root
//! over every `.rs` source file in the workspace.  The hash changes whenever
//! any protocol-relevant code is modified, enabling peers to prove they are
//! running an authorised build during the handshake.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

/// Recursively collect `.rs` files under `dir`, recording their
/// workspace-relative path (forward-slash normalised) for deterministic
/// ordering across platforms.
fn collect_rs_files(dir: &Path, root: &Path, out: &mut Vec<(String, PathBuf)>) {
    if !dir.is_dir() {
        return;
    }
    let dir_name = dir.file_name().unwrap_or_default().to_str().unwrap_or("");
    if dir_name == "target" || dir_name.starts_with('.') {
        return;
    }

    let mut entries: Vec<_> = fs::read_dir(dir).unwrap().filter_map(|e| e.ok()).collect();
    entries.sort_by_key(|e| e.file_name());

    for entry in entries {
        let path = entry.path();
        if path.is_dir() {
            collect_rs_files(&path, root, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            let rel = path.strip_prefix(root).unwrap();
            let key = rel.to_str().unwrap().replace('\\', "/");
            out.push((key, path));
        }
    }
}

/// Build a Blake3 Merkle tree from leaf hashes and return the root.
fn merkle_root(hashes: &[[u8; 32]]) -> [u8; 32] {
    if hashes.is_empty() {
        return [0u8; 32];
    }
    if hashes.len() == 1 {
        return hashes[0];
    }
    let mut next_level = Vec::new();
    for chunk in hashes.chunks(2) {
        let mut h = blake3::Hasher::new();
        h.update(&chunk[0]);
        if chunk.len() > 1 {
            h.update(&chunk[1]);
        } else {
            // Odd leaf — duplicate.
            h.update(&chunk[0]);
        }
        next_level.push(*h.finalize().as_bytes());
    }
    merkle_root(&next_level)
}

fn main() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = manifest_dir.parent().unwrap();

    let crate_dirs = [
        "vess-vascular",
        "vess-foundry",
        "vess-stealth",
        "vess-tag",
        "vess-artery",
        "vess-kloak",
        "vess-protocol",
    ];

    let mut files = Vec::new();
    for crate_name in &crate_dirs {
        let src = workspace_root.join(crate_name).join("src");
        collect_rs_files(&src, workspace_root, &mut files);
    }

    // Sort by normalised relative path for cross-platform determinism.
    files.sort_by(|a, b| a.0.cmp(&b.0));

    // Hash each file's path + contents so that the set of files is
    // committed, not just the contents.  An attacker who adds, removes,
    // or renames a .rs file will produce a different hash even if the
    // file bodies happen to collide.
    let leaf_hashes: Vec<[u8; 32]> = files
        .iter()
        .map(|(rel_path, abs_path)| {
            let content = fs::read(abs_path).unwrap();
            let mut h = blake3::Hasher::new();
            // Domain-separate: commit the normalised relative path first,
            // then the file bytes.  This binds the filename to its content.
            h.update(rel_path.as_bytes());
            h.update(&content);
            *h.finalize().as_bytes()
        })
        .collect();

    // Commit the exact file count as an additional leaf so that any
    // added or removed .rs file changes the root — even if somehow
    // the Merkle tree shape stayed the same.
    let mut count_hasher = blake3::Hasher::new();
    count_hasher.update(b"vess-file-count:");
    count_hasher.update(&(files.len() as u64).to_le_bytes());
    let count_hash = *count_hasher.finalize().as_bytes();

    let mut all_leaves = leaf_hashes;
    all_leaves.push(count_hash);

    let root = merkle_root(&all_leaves);

    // ── Parse versions.txt for previous version hashes ────────────
    let versions_file = manifest_dir.join("versions.txt");
    println!("cargo:rerun-if-changed={}", versions_file.display());

    let prev_hashes: Vec<[u8; 32]> = if versions_file.exists() {
        fs::read_to_string(&versions_file)
            .unwrap()
            .lines()
            .filter_map(|line| {
                let trimmed = line.trim();
                if trimmed.is_empty() || trimmed.starts_with('#') {
                    return None;
                }
                if trimmed.len() != 64 {
                    panic!(
                        "versions.txt: invalid hash length ({} chars, expected 64): {}",
                        trimmed.len(),
                        trimmed
                    );
                }
                let mut bytes = [0u8; 32];
                for (i, byte) in bytes.iter_mut().enumerate() {
                    *byte =
                        u8::from_str_radix(&trimmed[i * 2..i * 2 + 2], 16).unwrap_or_else(|_| {
                            panic!("versions.txt: invalid hex at byte {i}: {trimmed}")
                        });
                }
                // Skip if it matches the current build hash (already included).
                if bytes == root {
                    return None;
                }
                Some(bytes)
            })
            .collect()
    } else {
        Vec::new()
    };

    // Write generated constants.
    let out_dir = std::env::var("OUT_DIR").unwrap();
    let dest = Path::new(&out_dir).join("version_hash.rs");
    let mut f = fs::File::create(&dest).unwrap();
    writeln!(
        f,
        "/// Protocol version hash — Blake3 Merkle root of all workspace source files."
    )
    .unwrap();
    writeln!(f, "/// Computed at build time by `vess-artery/build.rs`.").unwrap();
    writeln!(f, "pub const PROTOCOL_VERSION_HASH: [u8; 32] = {root:?};").unwrap();
    writeln!(f).unwrap();
    writeln!(
        f,
        "/// Previous version hashes loaded from `versions.txt` at build time."
    )
    .unwrap();
    writeln!(
        f,
        "/// These allow peers running older builds to be accepted during rolling upgrades."
    )
    .unwrap();
    write!(f, "pub const PREVIOUS_VERSION_HASHES: &[[u8; 32]] = &[").unwrap();
    for h in &prev_hashes {
        write!(f, "{h:?},").unwrap();
    }
    writeln!(f, "];").unwrap();

    // Re-run whenever any source file changes.
    for (_, path) in &files {
        println!("cargo:rerun-if-changed={}", path.display());
    }
}
