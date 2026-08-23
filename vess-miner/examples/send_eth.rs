//! One-shot ETH transfer helper (testnet gas funding).
//!
//! Sends ETH from the key in --key-file to --to. Useful for funding the
//! miner's auto-generated gas address (miner.address) from the deployer.
//!
//! Usage:
//!   cargo run --example send_eth -- \
//!     --to 0x<MINER_GAS_ADDRESS> \
//!     --value-eth 0.0005 \
//!     [--rpc https://sepolia-rollup.arbitrum.io/rpc] \
//!     [--key-file sepolia.key]

use alloy::{
    network::EthereumWallet,
    primitives::{utils::parse_ether, Address, TxHash, U256},
    providers::{Provider, ProviderBuilder},
    signers::local::PrivateKeySigner,
};
use anyhow::{Context, Result};
use clap::Parser;

#[derive(Parser)]
#[command(name = "vess-send-eth", about = "Send testnet ETH from a key file")]
struct Args {
    /// Destination address.
    #[arg(long)]
    to: String,
    /// Amount of ETH to send (default 0.0005).
    #[arg(long, default_value = "0.0005")]
    value_eth: String,
    /// Arbitrum RPC endpoint.
    #[arg(long, default_value = "https://sepolia-rollup.arbitrum.io/rpc")]
    rpc: String,
    /// File containing the private key (bare hex, or `private_key = 0x...`).
    #[arg(long, default_value = "sepolia.key")]
    key_file: String,
}

/// Load a private key from a file, supporting both a bare hex key and the
/// `private_key = 0x...` line used by sepolia.key.
fn load_key(path: &str) -> Result<String> {
    let contents = std::fs::read_to_string(path).context("reading key file")?;
    if let Some(line) = contents.lines().find(|l| l.contains("private_key")) {
        let val = line.split('=').nth(1).unwrap_or("").trim();
        return Ok(val.to_string());
    }
    Ok(contents.trim().to_string())
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let key_hex = load_key(&args.key_file)?;
    let signer: PrivateKeySigner = key_hex.parse().context("invalid private key")?;
    let from = signer.address();
    let to: Address = args.to.parse().context("invalid --to")?;
    let value: U256 = parse_ether(&args.value_eth).context("invalid --value-eth")?;

    println!("from: 0x{}", hex::encode(from.0));
    println!("to:   0x{}", hex::encode(to.0));
    println!("value: {} ETH", args.value_eth);

    let wallet = EthereumWallet::from(signer);
    let provider = ProviderBuilder::new()
        .wallet(wallet)
        .connect(&args.rpc)
        .await
        .context("connecting to RPC")?;
    let chain_id = provider.get_chain_id().await.context("fetching chain id")?;
    println!("connected: chain_id={chain_id}");

    let balance = provider
        .get_balance(from)
        .await
        .context("fetching balance")?;
    println!("balance: {} wei", balance);
    if balance < value {
        anyhow::bail!("insufficient balance to send {value} wei");
    }

    let nonce = provider
        .get_transaction_count(from)
        .await
        .context("fetching nonce")?;
    let tx = alloy::rpc::types::TransactionRequest::default()
        .to(to)
        .from(from)
        .nonce(nonce)
        .value(value)
        .gas_limit(50_000);

    let pending = provider.send_transaction(tx).await.context("sending tx")?;
    let tx_hash: TxHash = *pending.tx_hash();
    println!("tx: 0x{}", hex::encode(tx_hash.0));

    let receipt = pending.get_receipt().await.context("waiting for receipt")?;
    if receipt.status() {
        println!(
            "SENT OK in block {}",
            receipt.block_number.unwrap_or_default()
        );
        Ok(())
    } else {
        anyhow::bail!("transfer reverted on-chain");
    }
}
