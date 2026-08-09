//! Diagnostic: replay a mint via eth_call and print the exact revert reason.
//!
//! Rebuilds the Cuckatoo header for given (chain, reward, ts, nonce), solves it,
//! and simulates `mint(...)` against the deployed contract. If it reverts, the
//! ABI-encoded revert string is decoded and printed.
//!
//! Usage:
//!   cargo run --example debug_mint -- \
//!     [--ts 1786403491] [--nonce 41] [--diff 0] \
//!     [--reward 0x973dff3d05e5c78e2f9baa839b6e311261733c09] \
//!     [--contract 0x2e5d89a229cbd17efb0a731d26232f88c3746aa9] \
//!     [--chain arbitrum]

use alloy::{
    primitives::{Address, FixedBytes, U256},
    providers::{Provider, ProviderBuilder},
    transports::RpcError,
};
use alloy_sol_types::SolCall;
use anyhow::{Context, Result};
use clap::Parser;
use vess_crypto::{chain_hash, cuckoo};

alloy_sol_types::sol! {
    function mint(
        bytes32 chain_hash,
        uint32 diff_bits,
        bytes32 address,
        uint64 timestamp,
        uint64 nonce,
        bytes calldata proof
    ) external returns (bool);

    function approve(address spender, uint256 value) external returns (bool);
    function transfer(address to, uint256 value) external returns (bool);
}

#[derive(Parser)]
#[command(name = "vess-debug-mint", about = "Simulate a mint and show the revert reason")]
struct Args {
    #[arg(long, default_value = "0x2e5d89a229cbd17efb0a731d26232f88c3746aa9")]
    contract: String,
    #[arg(long, default_value = "https://sepolia-rollup.arbitrum.io/rpc")]
    rpc: String,
    #[arg(long, default_value = "arbitrum")]
    chain: String,
    #[arg(long, default_value = "0x973dff3d05e5c78e2f9baa839b6e311261733c09")]
    reward: String,
    #[arg(long, default_value = "0")]
    diff: u32,
    #[arg(long)]
    ts: u64,
    #[arg(long)]
    nonce: u64,
}

/// Decode `Error(string)` revert data (selector 0x08c379a0).
fn decode_revert(data: &[u8]) -> String {
    if data.len() >= 4 && data[..4] == [0x08, 0xc3, 0x79, 0xa0] {
        if data.len() >= 68 {
            let len = u32::from_be_bytes(data[36..40].try_into().unwrap()) as usize;
            let start = 68;
            if start + len <= data.len() {
                return String::from_utf8_lossy(&data[start..start + len]).to_string();
            }
        }
        format!("Error(string) with {} bytes of data", data.len())
    } else {
        format!("0x{}", hex::encode(data))
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let chain_h = chain_hash(&args.chain);
    println!("chain={} chain_hash=0x{}", args.chain, hex::encode(chain_h));

    // 32-byte chain-agnostic address: first 20 bytes = reward, rest zero.
    let reward: Address = args.reward.parse().context("invalid --reward")?;
    let mut addr_32 = [0u8; 32];
    addr_32[..20].copy_from_slice(reward.as_slice());

    let header = cuckoo::mint_header(&chain_h, args.diff, &addr_32, args.ts, args.nonce);
    println!("header=0x{}", hex::encode(header));

    let proof = cuckoo::solve(&header, cuckoo::CYCLE_LENGTH, cuckoo::EDGE_BITS)
        .expect("no 42-cycle found in this graph");
    println!("solved {} nonces: {:?}", proof.len(), proof);
    assert!(
        cuckoo::verify(&header, &proof, cuckoo::CYCLE_LENGTH, cuckoo::EDGE_BITS),
        "local verify failed!"
    );
    println!("local verify OK");

    // Encode the proof as LE u32 bytes, exactly like the miner submits.
    let mut proof_bytes = Vec::with_capacity(cuckoo::CYCLE_LENGTH * 4);
    for n in &proof {
        proof_bytes.extend_from_slice(&n.to_le_bytes());
    }

    let contract: Address = args.contract.parse().context("invalid --contract")?;
    let provider = ProviderBuilder::new()
        .connect(&args.rpc)
        .await
        .context("connecting to RPC")?;

    let call = mintCall {
        chain_hash: FixedBytes(chain_h),
        diff_bits: args.diff,
        address: FixedBytes(addr_32),
        timestamp: args.ts,
        nonce: args.nonce,
        proof: proof_bytes.into(),
    };
    let calldata = call.abi_encode();

    // Compare the miner's selector against the canonical mint selector.
    let canon = alloy::primitives::keccak256(
        b"mint(bytes32,uint32,bytes32,uint64,uint64,bytes)",
    );
    println!(
        "miner mintCall selector : 0x{}",
        hex::encode(&calldata[..4])
    );
    println!(
        "canonical mint selector : 0x{}",
        hex::encode(&canon[..4])
    );
    let tx = alloy::rpc::types::TransactionRequest::default()
        .to(contract)
        .input(calldata.into());

    println!("simulating mint(ts={}, nonce={}) ...", args.ts, args.nonce);
    match provider.call(tx).await {
        Ok(data) => println!(
            "MINT ACCEPTED (simulated) — return {} bytes: 0x{}",
            data.len(),
            hex::encode(&data)
        ),
        Err(RpcError::ErrorResp(payload)) => {
            println!("RAW ERROR payload: {payload:#?}");
            match payload.data.as_ref() {
                Some(raw) => {
                    let hex_str = raw.get();
                    let bytes = hex::decode(hex_str.trim_start_matches("0x"))
                        .unwrap_or_default();
                    println!("REVERT: {}", decode_revert(&bytes));
                }
                None => println!("REVERT (no data): {}", payload.message),
            }
        }
        Err(e) => println!("CALL ERROR: {e:?}"),
    }

    // Disambiguation: simulate a mint with a bogus (zeroed) proof of the same
    // length. If the contract dispatches `mint` correctly, it should revert
    // with a readable "invalid cuckatoo proof". An empty revert here means the
    // function isn't being dispatched (selector/ABI mismatch).
    println!("simulating mint with BOGUS (zeroed) proof ...");
    let bogus = mintCall {
        chain_hash: FixedBytes(chain_h),
        diff_bits: args.diff,
        address: FixedBytes(addr_32),
        timestamp: args.ts,
        nonce: args.nonce,
        proof: vec![0u8; cuckoo::CYCLE_LENGTH * 4].into(),
    };
    let bogus_tx = alloy::rpc::types::TransactionRequest::default()
        .to(contract)
        .input(bogus.abi_encode().into());
    match provider.call(bogus_tx).await {
        Ok(data) => println!(
            "BOGUS MINT ACCEPTED?! return {} bytes: 0x{}",
            data.len(),
            hex::encode(&data)
        ),
        Err(RpcError::ErrorResp(payload)) => match payload.data.as_ref() {
            Some(raw) => {
                let hex_str = raw.get();
                let bytes = hex::decode(hex_str.trim_start_matches("0x"))
                    .unwrap_or_default();
                println!("BOGUS REVERT: {}", decode_revert(&bytes));
            }
            None => println!("BOGUS REVERT (no data): {}", payload.message),
        },
        Err(e) => println!("BOGUS CALL ERROR: {e:?}"),
    }

    // Third probe: wrong-length proof (1 byte). This hits the `bad proof
    // length` check BEFORE verify. Readable error => dispatch works and the
    // panic is inside verify. Empty revert => dispatch/panic earlier.
    println!("simulating mint with 1-byte proof ...");
    let short = mintCall {
        chain_hash: FixedBytes(chain_h),
        diff_bits: args.diff,
        address: FixedBytes(addr_32),
        timestamp: args.ts,
        nonce: args.nonce,
        proof: vec![0u8; 1].into(),
    };
    let short_tx = alloy::rpc::types::TransactionRequest::default()
        .to(contract)
        .input(short.abi_encode().into());
    match provider.call(short_tx).await {
        Ok(data) => println!(
            "SHORT MINT ACCEPTED?! return {} bytes: 0x{}",
            data.len(),
            hex::encode(&data)
        ),
        Err(RpcError::ErrorResp(payload)) => match payload.data.as_ref() {
            Some(raw) => {
                let hex_str = raw.get();
                let bytes = hex::decode(hex_str.trim_start_matches("0x"))
                    .unwrap_or_default();
                println!("SHORT REVERT: {}", decode_revert(&bytes));
            }
            None => println!("SHORT REVERT (no data): {}", payload.message),
        },
        Err(e) => println!("SHORT CALL ERROR: {e:?}"),
    }

    // Control probes: does the contract's dispatch + revert mechanism work at
    // all outside of mint? approve should SUCCEED (returns true). transfer to
    // a non-zero address from the zero sender should revert with a readable
    // "insufficient balance".
    let approve = approveCall {
        spender: Address::repeat_byte(0x11),
        value: U256::ZERO,
    };
    let approve_tx = alloy::rpc::types::TransactionRequest::default()
        .to(contract)
        .input(approve.abi_encode().into());
    match provider.call(approve_tx).await {
        Ok(data) => println!("APPROVE OK: 0x{}", hex::encode(&data)),
        Err(RpcError::ErrorResp(payload)) => {
            let msg = payload.data.as_ref().map(|r| {
                let b = hex::decode(r.get().trim_start_matches("0x")).unwrap_or_default();
                decode_revert(&b)
            });
            println!("APPROVE REVERT: {}", msg.unwrap_or_else(|| payload.message.to_string()));
        }
        Err(e) => println!("APPROVE CALL ERROR: {e:?}"),
    }

    let transfer = transferCall {
        to: Address::repeat_byte(0x22),
        value: U256::from(1u64),
    };
    let transfer_tx = alloy::rpc::types::TransactionRequest::default()
        .to(contract)
        .input(transfer.abi_encode().into());
    match provider.call(transfer_tx).await {
        Ok(data) => println!("TRANSFER OK (unexpected): 0x{}", hex::encode(&data)),
        Err(RpcError::ErrorResp(payload)) => {
            let msg = payload.data.as_ref().map(|r| {
                let b = hex::decode(r.get().trim_start_matches("0x")).unwrap_or_default();
                decode_revert(&b)
            });
            println!(
                "TRANSFER REVERT: {}",
                msg.unwrap_or_else(|| payload.message.to_string())
            );
        }
        Err(e) => println!("TRANSFER CALL ERROR: {e:?}"),
    }
    Ok(())
}
