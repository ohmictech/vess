//! Generate a random Ethereum keypair for testnet mining.
//! Usage: cargo run -p vess-miner --example gen_key -- --out /path/to/sepolia.key
//!
//! Writes a gitignored file containing:
//!   private_key = 0x...
//!   address      = 0x...

use std::path::PathBuf;

use alloy::signers::local::PrivateKeySigner;
use clap::Parser;

#[derive(Parser)]
struct Args {
    /// Output file path (default: sepolia.key next to the example)
    #[arg(long, default_value = "sepolia.key")]
    out: PathBuf,
}

fn main() {
    let args = Args::parse();

    let signer = PrivateKeySigner::random();
    let addr = signer.address();
    let pk_hex = format!("0x{}", hex::encode(signer.to_bytes()));
    let addr_hex = format!("0x{}", hex::encode(addr.0));

    let content = format!(
        "# Vess testnet keypair — DO NOT COMMIT — KEEP SECRET\n\
         # Fund this address with Sepolia ETH from a faucet, then put the\n\
         # private key in your deploy secrets.\n\n\
         private_key = {pk_hex}\n\
         address      = {addr_hex}\n"
    );

    std::fs::write(&args.out, &content)
        .unwrap_or_else(|e| panic!("failed to write {}: {e}", args.out.display()));

    println!("Wrote keypair to {}", args.out.display());
    println!("  private_key = {pk_hex}");
    println!("  address      = {addr_hex}");
    println!("\nFund this address with Sepolia ETH, then:");
    println!("  1. Put the private key in a GitHub secret DEPLOYER_PRIVATE_KEY");
    println!("  2. Or use it with cast/cargo-stylus to deploy");
}
