//! Bin target required by `cargo stylus` 0.10.7: the deploy/verify flows run
//! `cargo run --features export-abi -- <cmd>` to check for a constructor.
//! Without a bin target that call fails with
//! "a bin target must be available for `cargo run`".
//!
//! This contract has NO constructor (init is a regular method), so the bin
//! intentionally prints nothing -> the constructor check returns None.
//!
//! It does NOT link the lib crate: keeping the lib `crate-type = ["cdylib"]`
//! only is what keeps the on-chain wasm small (~64 KB / ~19 KB compressed).
//! Adding `rlib` (which a lib-linking bin would require) inflates the wasm to
//! ~104 KB / ~29 KB compressed, over the ~24 KB single-chunk Stylus limit.

#![cfg_attr(not(any(test, feature = "export-abi")), no_main)]

#[cfg(not(any(test, feature = "export-abi")))]
#[unsafe(no_mangle)]
pub extern "C" fn main() {}

#[cfg(feature = "export-abi")]
fn main() {}
