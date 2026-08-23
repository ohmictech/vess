//! Comprehensive ERC-20 test suite against the deployed Vess contract.
//!
//! Uses eth_call for read/simulate tests and ONE real `approve` tx (with the
//! signer from --key-file) to prove state changes persist on-chain.
//!
//! Tests: name, symbol, decimals, totalSupply, balanceOf, allowance,
//! approve (sim + real tx + readback), transfer (0-balance revert),
//! transferFrom (no-allowance revert), mint (zero-proof revert).
//!
//! Usage:
//!   cargo run --example erc_test -p vess-miner -- \
//!     --contract 0xeb605251d8edd018af266990774acb9d6b72e35c \
//!     [--key-file sepolia.key]

use alloy::{
    network::EthereumWallet,
    primitives::{Address, Bytes, FixedBytes, U256},
    providers::{Provider, ProviderBuilder},
    signers::local::PrivateKeySigner,
    transports::RpcError,
};
use alloy_sol_types::SolCall;
use anyhow::{Context, Result};
use clap::Parser;

alloy_sol_types::sol! {
    function name() external view returns (string);
    function symbol() external view returns (string);
    function decimals() external view returns (uint8);
    function totalSupply() external view returns (uint256);
    function balanceOf(address account) external view returns (uint256);
    function allowance(address owner, address spender) external view returns (uint256);
    function approve(address spender, uint256 value) external returns (bool);
    function transfer(address to, uint256 value) external returns (bool);
    function transferFrom(address from, address to, uint256 value) external returns (bool);
    function mint(bytes32 chain_hash, uint32 diff_bits, bytes32 address, uint64 timestamp, uint64 nonce, uint32[42] proof) external returns (bool);
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
}

#[derive(Parser)]
#[command(name = "vess-erc-test")]
struct Args {
    /// Deployed Vess contract address.
    #[arg(long)]
    contract: String,
    /// Arbitrum RPC endpoint.
    #[arg(long, default_value = "https://sepolia-rollup.arbitrum.io/rpc")]
    rpc: String,
    /// File containing the signer private key (for the real approve tx).
    #[arg(long, default_value = "sepolia.key")]
    key_file: String,
    /// Skip the real approve transaction (eth_call only).
    #[arg(long)]
    simulate_only: bool,
}

/// Load a private key from a file: bare hex or `private_key = 0x...`.
fn load_key(path: &str) -> Result<String> {
    let contents = std::fs::read_to_string(path).context("reading key file")?;
    if let Some(line) = contents.lines().find(|l| l.contains("private_key")) {
        let val = line.split('=').nth(1).unwrap_or("").trim();
        return Ok(val.to_string());
    }
    Ok(contents.trim().to_string())
}

fn decode_revert(data: &[u8]) -> String {
    if data.len() >= 4 && data[..4] == [0x08, 0xc3, 0x79, 0xa0] {
        if data.len() >= 68 {
            // ABI: selector | offset(32B) | len(32B) | string (32B-aligned).
            let len = u32::from_be_bytes(data[64..68].try_into().unwrap()) as usize;
            let start = 68;
            if start + len <= data.len() {
                return String::from_utf8_lossy(&data[start..start + len]).to_string();
            }
        }
        format!("Error(string) with {} bytes", data.len())
    } else if data.is_empty() {
        "empty revert data".into()
    } else {
        String::from_utf8_lossy(data).into_owned()
    }
}

fn show(label: &str, result: Result<Bytes, alloy::transports::TransportError>) {
    match result {
        Ok(data) => {
            let hex = hex::encode(&data);
            // Pretty-print common fixed-size words as big-endian numbers.
            if hex.len() == 64 {
                let v = U256::from_be_slice(&data);
                println!("{label}: OK  {v}  (0x{hex})");
            } else {
                println!("{label}: OK  ({} bytes) 0x{hex}", data.len());
            }
        }
        Err(RpcError::ErrorResp(payload)) => {
            let data = payload.as_revert_data().unwrap_or_default();
            if data.is_empty() {
                println!("{label}: REVERT (no data): {}", payload.message);
            } else {
                println!("{label}: REVERT {}", decode_revert(&data));
            }
        }
        Err(e) => println!("{label}: CALL ERROR {e:?}"),
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let contract: Address = args.contract.parse().context("invalid --contract")?;

    let key_hex = load_key(&args.key_file)?;
    let signer: PrivateKeySigner = key_hex.parse().context("invalid private key")?;
    let from = signer.address();
    let wallet = EthereumWallet::from(signer);

    let provider = ProviderBuilder::new()
        .wallet(wallet)
        .connect(&args.rpc)
        .await
        .context("connecting")?;

    println!("signer: 0x{}", hex::encode(from.0));
    println!("contract: {contract}");
    println!();

    let spender: Address = "0xeef2bb9537aa616d892ab63ae6ea897a374b8fe8"
        .parse()
        .unwrap();
    let dead: Address = "0x00000000000000000000000000000000deadbeef"
        .parse()
        .unwrap();

    let call_tx = |calldata: Vec<u8>| {
        alloy::rpc::types::TransactionRequest::default()
            .from(from)
            .to(contract)
            .input(calldata.into())
    };

    // ── metadata ──────────────────────────────────────────────────────
    show(
        "name()",
        provider.call(call_tx(nameCall {}.abi_encode())).await,
    );
    show(
        "symbol()",
        provider.call(call_tx(symbolCall {}.abi_encode())).await,
    );
    show(
        "decimals()",
        provider.call(call_tx(decimalsCall {}.abi_encode())).await,
    );
    show(
        "totalSupply()",
        provider
            .call(call_tx(totalSupplyCall {}.abi_encode()))
            .await,
    );
    show(
        "balanceOf(signer)",
        provider
            .call(call_tx(balanceOfCall { account: from }.abi_encode()))
            .await,
    );
    show(
        "allowance(signer, spender) [before]",
        provider
            .call(call_tx(
                allowanceCall {
                    owner: from,
                    spender,
                }
                .abi_encode(),
            ))
            .await,
    );

    // ── approve: simulate via eth_call (exercises storage write) ───────
    show(
        "approve(spender,1000) [eth_call sim]",
        provider
            .call(call_tx(
                approveCall {
                    spender,
                    value: U256::from(1000),
                }
                .abi_encode(),
            ))
            .await,
    );

    // ── approve: REAL tx to prove persistence ──────────────────────────
    if args.simulate_only {
        println!();
        println!("skipping real approve tx (--simulate-only)");
    } else {
        let tx = alloy::rpc::types::TransactionRequest::default()
            .to(contract)
            .from(from)
            .gas_limit(150_000u64)
            .input(
                approveCall {
                    spender,
                    value: U256::from(1000),
                }
                .abi_encode()
                .into(),
            );
        match provider.send_transaction(tx).await {
            Ok(pending) => {
                let tx_hash = *pending.tx_hash();
                println!();
                println!("approve tx sent: 0x{}", hex::encode(tx_hash.0));
                match pending.get_receipt().await {
                    Ok(rc) if rc.status() => {
                        println!(
                            "approve CONFIRMED in block {}",
                            rc.block_number.unwrap_or_default()
                        );
                        let after = provider
                            .call(call_tx(
                                allowanceCall {
                                    owner: from,
                                    spender,
                                }
                                .abi_encode(),
                            ))
                            .await;
                        show("allowance(signer, spender) [after real approve]", after);
                    }
                    Ok(_) => {
                        println!("approve tx REVERTED (status=false)");
                        // replay for reason
                        let r = provider
                            .call(call_tx(
                                approveCall {
                                    spender,
                                    value: U256::from(1000),
                                }
                                .abi_encode(),
                            ))
                            .await;
                        show("approve [replay]", r);
                    }
                    Err(e) => println!("waiting for approve receipt failed: {e:?}"),
                }
            }
            Err(e) => println!("sending approve tx failed: {e:?}"),
        }
    }

    // ── transfer / transferFrom / mint error paths ────────────────────
    show(
        "transfer(dead,1) [0 balance -> insufficient balance]",
        provider
            .call(call_tx(
                transferCall {
                    to: dead,
                    value: U256::from(1),
                }
                .abi_encode(),
            ))
            .await,
    );
    show(
        "transferFrom(from,dead,1) [no allowance -> insufficient allowance]",
        provider
            .call(call_tx(
                transferFromCall {
                    from,
                    to: dead,
                    value: U256::from(1),
                }
                .abi_encode(),
            ))
            .await,
    );

    // mint with zeroed proof -> verify rejects -> Err("invalid cuckatoo proof")
    let chain_h = vess_crypto::chain_hash("arbitrum");
    let mut addr_32 = [0u8; 32];
    addr_32[..20].copy_from_slice(from.as_slice());
    let ts = 1786403491u64;
    let proof = [0u32; 42];
    show(
        "mint(zero proof) [invalid cuckatoo proof]",
        provider
            .call(call_tx(
                mintCall {
                    chain_hash: FixedBytes(chain_h),
                    diff_bits: 0,
                    address: FixedBytes(addr_32),
                    timestamp: ts,
                    nonce: 41,
                    proof,
                }
                .abi_encode(),
            ))
            .await,
    );

    Ok(())
}
