//! One-shot init tool for the Vess contract.
//!
//! Calls `init(owner, chain_name)` on a freshly deployed contract to set the
//! owner and the chain binding (`chain_hash = blake3(chain_name)`). Without
//! this, the stored `chain_hash` is zero and every `mint` reverts with
//! "wrong chain".
//!
//! Usage:
//!   cargo run --example init_contract -- \
//!     --contract 0x<DEPLOYED_ADDRESS> \
//!     [--rpc https://sepolia-rollup.arbitrum.io/rpc] \
//!     [--key-file sepolia.key] \
//!     [--chain arbitrum] \
//!     [--owner 0x...]      (defaults to the signer's own address)

use alloy::{
    network::EthereumWallet,
    primitives::{Address, TxHash},
    providers::{Provider, ProviderBuilder},
    signers::local::PrivateKeySigner,
};
use alloy_sol_types::SolCall;
use anyhow::{Context, Result};
use clap::Parser;

alloy_sol_types::sol! {
    /// The on-chain ABI: `init(address initial_owner, string chain_name)`.
    function init(address initial_owner, string chain_name) external;

    /// Read helper to confirm whether the contract is already initialized.
    function owner() external view returns (address);
}

#[derive(Parser)]
#[command(name = "vess-init", about = "Initialize the deployed Vess contract")]
struct Args {
    /// Deployed Vess contract address (from the deploy step output).
    #[arg(long)]
    contract: String,
    /// Arbitrum RPC endpoint.
    #[arg(long, default_value = "https://sepolia-rollup.arbitrum.io/rpc")]
    rpc: String,
    /// File containing the private key. Accepts either a bare hex key or a
    /// `sepolia.key`-style `private_key = 0x...` line.
    #[arg(long, default_value = "sepolia.key")]
    key_file: String,
    /// Chain name bound into the contract. Must match the miner's `chain` and
    /// the chain the proofs are solved against.
    #[arg(long, default_value = "arbitrum")]
    chain: String,
    /// Owner to set (defaults to the signer's address, i.e. the deployer).
    #[arg(long)]
    owner: Option<String>,
    /// Proceed even if the contract already has an owner.
    #[arg(long)]
    force: bool,
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
    let signer_addr = signer.address();
    println!("signer: 0x{}", hex::encode(signer_addr.0));

    let owner: Address = match &args.owner {
        Some(o) => o.parse().context("invalid --owner")?,
        None => signer_addr,
    };
    let contract: Address = args.contract.parse().context("invalid --contract")?;

    let wallet = EthereumWallet::from(signer);
    let provider = ProviderBuilder::new()
        .wallet(wallet)
        .connect(&args.rpc)
        .await
        .context("connecting to RPC")?;
    let chain_id = provider.get_chain_id().await.context("fetching chain id")?;
    println!("connected: chain_id={chain_id} rpc={}", args.rpc);
    println!("contract: 0x{}", hex::encode(contract.0));

    // Sanity check: is the contract already initialized?
    let owner_call = ownerCall {}.abi_encode();
    let query = alloy::rpc::types::TransactionRequest::default()
        .to(contract)
        .input(owner_call.into());
    if let Ok(data) = provider.call(query).await {
        let current = if data.len() >= 32 {
            Address::from_slice(&data[12..32])
        } else {
            Address::ZERO
        };
        println!("current owner: 0x{}", hex::encode(current.0));
        if current != Address::ZERO && !args.force {
            anyhow::bail!(
                "contract already initialized (owner set). Use --force to re-init anyway."
            );
        }
    }

    let ch = vess_crypto::chain_hash(&args.chain);
    println!(
        "will bind chain \"{}\" -> chain_hash 0x{}",
        args.chain,
        hex::encode(ch)
    );
    println!("owner: 0x{}", hex::encode(owner.0));

    let nonce = provider
        .get_transaction_count(signer_addr)
        .await
        .context("fetching nonce")?;
    let calldata = initCall {
        initial_owner: owner,
        chain_name: args.chain.clone(),
    }
    .abi_encode();
    let tx = alloy::rpc::types::TransactionRequest::default()
        .to(contract)
        .from(signer_addr)
        .nonce(nonce)
        .gas_limit(150_000)
        .input(calldata.into());

    let pending = provider
        .send_transaction(tx)
        .await
        .context("sending init tx")?;
    let tx_hash: TxHash = *pending.tx_hash();
    println!("init tx: 0x{}", hex::encode(tx_hash.0));

    let receipt = pending
        .get_receipt()
        .await
        .context("waiting for receipt")?;
    if receipt.status() {
        println!(
            "INIT OK in block {}",
            receipt.block_number.unwrap_or_default()
        );
        println!("Contract is ready to mint. Configure miner.toml and run the miner.");
        Ok(())
    } else {
        anyhow::bail!("init reverted on-chain — check the contract and RPC");
    }
}
