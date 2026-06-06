# Vess Node Deployment Guide

This document describes how to deploy a Vess artery node from local
development through to internet-facing production.

## Profiles

Vess ships with five built-in deployment profiles selectable via
`vess node --profile <name>` (or the `--testnet` shorthand):

| Profile     | `allow_unsafe` | Bitcoin Network | Use case                          |
|-------------|:--------------:|:---------------:|-----------------------------------|
| development | yes            | regtest         | Local single-node testing         |
| test        | yes            | regtest         | Multi-node integration tests      |
| testnet     | no             | signet          | Public testnet (zero-config)      |
| staging     | no             | mainnet         | Pre-production staging environment |
| production  | no             | mainnet         | Public internet-facing node       |

Quick-start for public testnet:
```bash
vess node --testnet
```

Production profile enforces:
- `allow_private_bitcoin_seed_contact = false`
- `reset_transient_peer_state = false`
- Config audit warnings printed at startup

### Profile-specific defaults

| Flag/Default        | dev/test  | testnet    | staging/prod |
|---------------------|-----------|------------|--------------|
| Faucet enabled      | yes       | no         | no           |
| Bitcoin network     | regtest   | signet     | mainnet      |
| DHT namespace       | vess-v1   | vess-testnet-v1 | vess-v1  |
| Seed peers          | none      | built-in   | none         |
| Unsafe operations   | allowed   | forbidden  | forbidden    |
| Mesh bind address   | 0.0.0.0:0 | 0.0.0.0:0  | 0.0.0.0:0    |

## Staged Canary Rollout

When deploying a new version to production, follow this staged sequence:

### Stage 1 — Local

```bash
# Build the binary
cargo build --release -p vess-cli

# Run a local development node
vess node --profile dev --rpc-port 9400
```

Verify: the node starts, peers discover each other, payments flow.

### Stage 2 — Staging (private testnet)

```bash
# Start a staging node with known bootstrap peers
vess node --profile staging \
  --bootstrap "<peer1-contact>,<peer2-contact>" \
  --bind "0.0.0.0:19000" \
  --rpc-port 9400
```

Verify for at least 24 hours:
- No unexpected crashes or restarts
- Peer count stabilises
- Wallet operations (send/receive) complete within expected latency
- No banishment waves or routing anomalies

### Stage 3 — Canary (single production node)

Run ONE production node before scaling:

```bash
vess node --profile production \
  --bootstrap "<existing-peer-contact>" \
  --bind "0.0.0.0:19000" \
  --rpc-port 9400 \
  --wallet /path/to/wallet.json \
  --wallet-password <password>
```

Monitor for 48–72 hours:
- Check `vess health` for peer quality and reputation
- Check `vess events` for banishments, conflicts, seed sync
- Verify Bitcoin burn acceptance is working
- Test wallet recovery from backup

### Stage 4 — Production rollout

Once the canary is stable, add more production nodes gradually.
Keep at least one node at the previous version as a rollback target
for 48 hours after the last new node joins.

## Reproducible Builds

### Prerequisites

- Rust toolchain (pinned in `rust-toolchain.toml`: stable)
- `Cargo.lock` committed to the repository

### Build

```bash
# Standard release build
cargo build --release -p vess-cli

# The binary is at target/release/vess-cli (or vess-cli.exe on Windows)
```

### Verifying reproducibility

```bash
# Build twice and compare
cargo build --release -p vess-cli
cp target/release/vess-cli target/release/vess-cli.first
cargo clean
cargo build --release -p vess-cli
diff target/release/vess-cli target/release/vess-cli.first
```

If the binaries match, the build is reproducible. Differences can arise from:
- Compiler version changes (pinned by `rust-toolchain.toml`)
- File modification timestamps embedded by the build system
- Build path dependencies

CI runs a reproducibility check automatically on every push.

### Build Script

A convenience build script is available:

```bash
# Windows (PowerShell)
.\scripts\build-vess.ps1

# Linux / macOS
./scripts/build-vess.sh
```

Output: `dist/vess` (or `dist/vess.exe` on Windows).

## Config Audits

On startup, the node prints warnings for any configuration that is
unsafe for the selected profile. Run `vess node --profile production`
and check the startup logs for audit warnings.

To manually audit a configuration:

```rust
use vess_artery::node_runner::{NodeConfig, DeploymentProfile};

let config = NodeConfig {
    profile: DeploymentProfile::Production,
    // ... other fields
};
for warning in config.audit() {
    eprintln!("config audit: {warning}");
}
```

## Rollback

If a new deployment causes issues:

1. Stop the node (Ctrl+C or `kill <pid>`)
2. Restore the previous binary from backup
3. Restore the previous `state.json` from auto-backup
   (`~/.vess-artery/state.json`)
4. Restart the node

Auto-backups are created every ~6 hours in `<wallet_dir>/backups/`
and on clean shutdown.
