//! Generate the testnet dev-fund ML-DSA-65 keypair.
//!
//! Prints (pubkey, seed, blake3 pubkey hash) and writes them to
//! dev-key-testnet.hex (repo root by default; override with DEV_KEY_OUT).
//! The pubkey hash goes into `DEV_PUBKEY_HASH` in vess-crypto/src/lib.rs;
//! the seed is the dev fund's secret — keep it out of git.

use vess_crypto::{dsa_generate, dsa_pubkey_hash};

fn to_hex(b: &[u8]) -> String {
    b.iter().map(|b| format!("{:02x}", b)).collect()
}

fn main() {
    let (pk, seed) = dsa_generate();
    let hash = dsa_pubkey_hash(&pk);
    println!("pubkey ({} bytes): {}", pk.len(), to_hex(&pk));
    println!("seed ({} bytes):   {}", seed.len(), to_hex(&seed));
    println!("pubkey_hash:       {}", to_hex(&hash));
    let path = std::env::var("DEV_KEY_OUT").unwrap_or_else(|_| "dev-key-testnet.hex".to_string());
    let contents = format!(
        "# vess testnet dev fund keypair (ML-DSA-65). seed is SECRET.\npubkey={}\nseed={}\npubkey_hash={}\n",
        to_hex(&pk), to_hex(&seed), to_hex(&hash)
    );
    std::fs::write(&path, &contents).expect("write dev key file");
    eprintln!("wrote {}", path);
}
