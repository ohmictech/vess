# Vess Mobile — Shared Rust FFI

UniFFI-powered Rust crate that exposes the Vess wallet and node
to Android (Kotlin) and iOS (Swift). This crate is the single source
of truth for the mobile FFI surface.

**Platform wrappers:** [`vess-android`](../vess-android) | [`vess-ios`](../vess-ios)

## API Surface

All functions are decorated with `#[uniffi::export]` and auto-generated
into Kotlin and Swift bindings:

| Function | Returns |
|---|---|
| `create_wallet(tag, name, password)` | `WalletInfo` |
| `recover_wallet(words, name, password)` | `WalletInfo` |
| `start_node(config)` | `NodeStatus` |
| `stop_node()` | — |
| `is_node_running()` | `bool` |
| `get_balance()` | `Balance` |
| `send_payment(amount, recipient, memo?)` | `PaymentResult` |
| `get_notifications()` | `Vec<Notification>` |
| `lookup_tag(tag)` | `TagInfo` |
| `register_tag(tag)` | — |
| `get_status()` | `NodeStatus` |
| `get_stealth_address()` | `String` |

## Generating Bindings

### Kotlin (Android)

```bash
cargo build --release --target aarch64-linux-android
cargo run --bin uniffi-bindgen -- generate \
    --library target/aarch64-linux-android/release/libvess_core.so \
    --language kotlin \
    --out-dir ../vess-android/kotlin
```

### Swift (iOS)

```bash
cargo build --release --target aarch64-apple-ios
cargo run --bin uniffi-bindgen -- generate \
    --library target/aarch64-apple-ios/release/libvess_core.a \
    --language swift \
    --out-dir ../vess-ios/Sources/VessCore
```

## Architecture

```
vess-mobile (Rust)          vess-android            vess-ios
┌──────────────────┐       ┌──────────────┐       ┌──────────────┐
│ lib.rs            │       │ kotlin/       │       │ Sources/      │
│ ┌──────────────┐  │       │ vess_core.kt  │       │ vess_core.swift│
│ │#[uniffi::export]│──▶│ (generated)  │       │ (generated)   │
│ │ 12 functions  │  │       │ VessCore.kt   │       │ VessCore.swift │
│ └──────────────┘  │       │ (wrapper)     │       │ (wrapper)     │
└──────────────────┘       └──────────────┘       └──────────────┘
```
