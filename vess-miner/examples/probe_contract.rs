//! Call the contract's bisection probes and show their results.
//!
//! Each probe is called via eth_call. A readable result — or a readable revert
//! reason — means that layer of the mint path works. Stylus surfaces
//! `Err(Vec<u8>)` as raw revert bytes (not ABI-wrapped `Error(string)`).

use alloy::{
    primitives::{Address, Bytes, FixedBytes},
    providers::{Provider, ProviderBuilder},
    transports::RpcError,
};use alloy_sol_types::SolCall;
use anyhow::{Context, Result};
use clap::Parser;

alloy_sol_types::sol! {
    function probe() external view returns (bool);
    function probeChain() external view returns (bytes32);
    function probeHeader(bytes32 chain_hash, uint32 diff_bits, bytes32 address, uint64 timestamp, uint64 nonce) external view returns (bytes32);
    function probeVerify(bytes32 chain_hash, uint32 diff_bits, bytes32 address, uint64 timestamp, uint64 nonce, uint32[42] proof) external view returns (bool);
    function probeTs() external view returns (uint64);
    function probeNull(bytes32 chain_hash, uint32 diff_bits, bytes32 address, uint64 timestamp, uint64 nonce) external view returns (bool);
    function probeMutChecks(bytes32 chain_hash, uint32 diff_bits, bytes32 address, uint64 timestamp, uint64 nonce) external returns (bool);
    function mint(bytes32 chain_hash, uint32 diff_bits, bytes32 address, uint64 timestamp, uint64 nonce, uint32[42] proof) external returns (bool);
}

#[derive(Parser)]
#[command(name = "vess-probe", about = "Run contract probes")]
struct Args {
    #[arg(long)]
    contract: String,
    #[arg(long, default_value = "https://sepolia-rollup.arbitrum.io/rpc")]
    rpc: String,
}

/// Decode `Error(string)` or raw revert bytes into a readable string.
fn decode_revert(data: &[u8]) -> String {
    if data.len() >= 4 && data[..4] == [0x08, 0xc3, 0x79, 0xa0] {
        if data.len() >= 68 {
            let len = u32::from_be_bytes(data[36..40].try_into().unwrap()) as usize;
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
        Ok(data) => println!(
            "{label}: OK ({} bytes) 0x{}",
            data.len(),
            hex::encode(&data)
        ),
        Err(RpcError::ErrorResp(payload)) => {
            // RawValue::get() keeps the JSON quotes — use as_revert_data().
            let data = payload.as_revert_data().unwrap_or_default();
            if data.is_empty() {
                println!("{label}: REVERT (no data): {}", payload.message);
            } else {
                println!("{label}: REVERT readable -> {}", decode_revert(&data));
            }
        }
        Err(e) => println!("{label}: CALL ERROR {e:?}"),
    }
}
#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let contract: Address = args.contract.parse().context("invalid --contract")?;
    let provider = ProviderBuilder::new()
        .connect(&args.rpc)
        .await
        .context("connecting")?;

    let chain_h = vess_crypto::chain_hash("arbitrum");
    let mut addr_32 = [0u8; 32];
    let reward: Address = "0x973dff3d05e5c78e2f9baa839b6e311261733c09"
        .parse()
        .unwrap();
    addr_32[..20].copy_from_slice(reward.as_slice());

    let ts = 1786403491u64;
    let nonce = 41u64;
    let proof = [0u32; vess_crypto::cuckoo::CYCLE_LENGTH];
    // Ascending proof exercises verify's HEAVY path (siphash, edge gen,
    // heap alloc, degree check) instead of short-circuiting on 0>=0.
    let mut asc = [0u32; vess_crypto::cuckoo::CYCLE_LENGTH];
    for (i, a) in asc.iter_mut().enumerate() {
        *a = i as u32;
    }

    let call_tx = |calldata: Vec<u8>| {
        alloy::rpc::types::TransactionRequest::default()
            .to(contract)
            .input(calldata.into())
    };

    show(
        "probe()",
        provider.call(call_tx(probeCall {}.abi_encode())).await,
    );
    show(
        "probeChain()",
        provider.call(call_tx(probeChainCall {}.abi_encode())).await,
    );
    show(
        "probeHeader(...)",
        provider
            .call(call_tx(
                probeHeaderCall {
                    chain_hash: FixedBytes(chain_h),
                    diff_bits: 0,
                    address: FixedBytes(addr_32),
                    timestamp: ts,
                    nonce,
                }
                .abi_encode(),
            ))
            .await,
    );
    show(
        "probeVerify(...zeroed proof, short-circuit)...",
        provider
            .call(call_tx(
                probeVerifyCall {
                    chain_hash: FixedBytes(chain_h),
                    diff_bits: 0,
                    address: FixedBytes(addr_32),
                    timestamp: ts,
                    nonce,
                    proof,
                }
                .abi_encode(),
            ))
            .await,
    );
    show(
        "probeVerify(...ascending proof, heavy path)...",
        provider
            .call(call_tx(
                probeVerifyCall {
                    chain_hash: FixedBytes(chain_h),
                    diff_bits: 0,
                    address: FixedBytes(addr_32),
                    timestamp: ts,
                    nonce,
                    proof: asc,
                }
                .abi_encode(),
            ))
            .await,
    );
    show(
        "probeTs()",
        provider.call(call_tx(probeTsCall {}.abi_encode())).await,
    );
    show(
        "probeNull(...)",
        provider
            .call(call_tx(
                probeNullCall {
                    chain_hash: FixedBytes(chain_h),
                    diff_bits: 0,
                    address: FixedBytes(addr_32),
                    timestamp: ts,
                    nonce,
                }
                .abi_encode(),
            ))
            .await,
    );
    show(
        "probeMutChecks(...)",
        provider
            .call(call_tx(
                probeMutChecksCall {
                    chain_hash: FixedBytes(chain_h),
                    diff_bits: 0,
                    address: FixedBytes(addr_32),
                    timestamp: ts,
                    nonce,
                }
                .abi_encode(),
            ))
            .await,
    );
    show(
        "mint(...zero proof...)",
        provider
            .call(call_tx(
                mintCall {
                    chain_hash: FixedBytes(chain_h),
                    diff_bits: 0,
                    address: FixedBytes(addr_32),
                    timestamp: ts,
                    nonce,
                    proof,
                }
                .abi_encode(),
            ))
            .await,
    );
    Ok(())
}
