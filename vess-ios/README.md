# Vess iOS

iOS platform wrapper for the Vess protocol.

The shared Rust FFI lives in [`../vess-mobile`](../vess-mobile) — this
crate contains only iOS-specific code: Xcode project, Swift wrappers,
and the iOS app shell.

## Directory Layout

```
vess-ios/
├── Sources/
│   └── VessCore/
│       ├── vess_core.swift    # Auto-generated UniFFI bindings (from vess-mobile)
│       └── VessCoreWrapper.swift  # Hand-written convenience wrappers
├── build-ios.sh               # Cross-compile script for iOS targets
├── VessCore.xcodeproj/        # Xcode project (optional)
└── README.md
```

## Building

1. Install iOS Rust targets:
   ```bash
   rustup target add aarch64-apple-ios aarch64-apple-ios-sim
   ```

2. Build the shared Rust library:
   ```bash
   cd ../vess-mobile
   cargo build --release --target aarch64-apple-ios
   ```

3. Generate Swift bindings:
   ```bash
   cd ../vess-mobile
   cargo run --bin uniffi-bindgen -- generate \
       --library target/aarch64-apple-ios/release/libvess_core.a \
       --language swift \
       --out-dir ../vess-ios/Sources/VessCore
   ```

4. Add the generated Swift file + the static library to your Xcode project.

## Swift Usage

```swift
import VessCore

// Initialize
let info = try createWallet(tag: "alice", walletName: "my-wallet", password: "password123")
print("Recovery phrase: \(info.recoveryPhrase)")

// Start the node
let config = NodeConfig(
    testnet: true,
    kNeighbors: 4,
    maxHops: 3,
    stateDir: nil,
    walletPath: info.walletPath,
    walletPassword: "password123",
    rpcPort: 9400,
    bindAddress: nil,
    bootstrapPeers: []
)
let status = try startNode(config: config)

// Check balance
let balance = try getBalance()
print("Balance: \(balance.total) Vess")

// Stop
try stopNode()
```
