//! Diagnostic: confirm the `Err(Vec<u8>)` return path from a `&mut self`
//! Stylus function surfaces readable revert data on-chain (it does — the
//! reason comes back as raw bytes; earlier "empty revert" reports were a
//! tooling bug: RawValue::get() keeps the JSON quotes, breaking hex decode).
//!
//! Uses eth_call so nothing is committed. Calls:
//!   transfer(...)    -> should revert "insufficient balance" (from has 0 VESS)
//!   transferFrom(..) -> should revert "insufficient allowance"
//!   init(...) again  -> should revert "already initialized" (already done)
//!   mint(zero proof) -> confirm the trap we're chasing
//!
//! Usage:
//!   cargo run --example check_err -- --contract 0x8d6b81e32162d16fda91b7465ba9ec0d0c4e0588

use alloy::{
    primitives::{Address, Bytes, FixedBytes, U256},
    providers::{Provider, ProviderBuilder},
    transports::RpcError,
};
use alloy_sol_types::SolCall;
use anyhow::{Context, Result};
use clap::Parser;

alloy_sol_types::sol! {
    function transfer(address to, uint256 value) external returns (bool);
    function transferFrom(address from, address to, uint256 value) external returns (bool);
    function approve(address spender, uint256 value) external returns (bool);
    function init(address initial_owner, string chain_name) external;
    function mint(bytes32 chain_hash, uint32 diff_bits, bytes32 address, uint64 timestamp, uint64 nonce, uint32[42] proof) external returns (bool);
}

#[derive(Parser)]
#[command(name = "vess-check-err")]
struct Args {
    /// Deployed Vess contract address.
    #[arg(long)]
    contract: String,
    /// Arbitrum RPC endpoint.
    #[arg(long, default_value = "https://sepolia-rollup.arbitrum.io/rpc")]
    rpc: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let contract: Address = args.contract.parse().context("invalid --contract")?;
    let provider = ProviderBuilder::new()
        .connect(&args.rpc)
        .await
        .context("connecting")?;

    // A caller that owns no VESS and has never approved anything.
    let from: Address = "0x973dff3d05e5c78e2f9baa839b6e311261733c09"
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

    /// Decode `Error(string)` or raw revert bytes into a readable string.
    fn decode_revert(data: &[u8]) -> String {
        if data.len() >= 4 && data[..4] == [0x08, 0xc3, 0x79, 0xa0] {
            if data.len() >= 68 {
                // ABI: selector | offset(32B) | len(32B) | string (32B-aligned).
                // The value sits in the LAST 4 bytes of each 32-byte word.
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
            // Stylus `Result<T, Vec<u8>>` errors are raw bytes.
            String::from_utf8_lossy(data).into_owned()
        }
    }

    fn show(label: &str, result: Result<Bytes, alloy::transports::TransportError>) {
        match result {
            Ok(data) => println!("{label}: OK ({} bytes) 0x{}", data.len(), hex::encode(&data)),
            Err(RpcError::ErrorResp(payload)) => {
                // RawValue::get() keeps the JSON quotes — use as_revert_data().
                let data = payload.as_revert_data().unwrap_or_default();
                if data.is_empty() {
                    println!("{label}: REVERT (no data): {}", payload.message);
                } else {
                    println!(
                        "{label}: REVERT hex=0x{} decoded=[{}]",
                        hex::encode(&data),
                        decode_revert(&data)
                    );
                }
            }
            Err(e) => println!("{label}: CALL ERROR {e:?}"),
        }
    }

    // approve: Ok path with storage WRITE + event log (mirrors mint success)
    let r = provider
        .call(call_tx(approveCall {
            spender: dead,
            value: U256::from(1000),
        }
        .abi_encode()))
        .await;
    show("approve(dead,1000) [expect OK=true]", r);

    // transfer: from has 0 balance -> _transfer returns Err("insufficient balance")
    let r = provider
        .call(call_tx(transferCall { to: dead, value: U256::from(1) }.abi_encode()))
        .await;
    show("transfer(dead,1) [expect insufficient balance]", r);

    // transferFrom: no allowance -> Err("insufficient allowance")
    let r = provider
        .call(call_tx(
            transferFromCall {
                from,
                to: dead,
                value: U256::from(1),
            }
            .abi_encode(),
        ))
        .await;
    show("transferFrom(from,dead,1) [expect insufficient allowance]", r);

    // init again: owner already set -> Err("already initialized")
    let r = provider
        .call(call_tx(initCall {
            initial_owner: from,
            chain_name: "arbitrum".to_string(),
        }
        .abi_encode()))
        .await;
    show("init again [expect already initialized]", r);

    // mint with zeroed proof -> verify returns false -> Err("invalid cuckatoo proof")
    let chain_h = vess_crypto::chain_hash("arbitrum");
    let mut addr_32 = [0u8; 32];
    addr_32[..20].copy_from_slice(from.as_slice());
    let ts = 1786403491u64;
    let proof = [0u32; 42];
    let r = provider
        .call(call_tx(mintCall {
            chain_hash: FixedBytes(chain_h),
            diff_bits: 0,
            address: FixedBytes(addr_32),
            timestamp: ts,
            nonce: 41,
            proof,
        }
        .abi_encode()))
        .await;
    show("mint(zero proof) [expect invalid cuckatoo proof]", r);

    Ok(())
}
