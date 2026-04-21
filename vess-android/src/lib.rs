//! Vess Android JNI bridge.
//!
//! Exposes native functions called by VessNode.kt.  Each `Java_*` symbol maps
//! 1-to-1 to an `external fun` declaration in the Kotlin companion object.
//!
//! Build for Android:
//!   cargo install cargo-ndk
//!   cargo ndk -t arm64-v8a -t armeabi-v7a \
//!       --output-dir ../android_host/app/src/main/jniLibs \
//!       build --release
#![allow(non_snake_case)]

use std::sync::{Mutex, OnceLock};

use jni::objects::{JClass, JString};
use jni::sys::{jboolean, jint, jlong, jstring, JNI_FALSE, JNI_TRUE};
use jni::JNIEnv;

// ── Shared node state ──────────────────────────────────────────────────────

struct NodeState {
    running: bool,
    node_id: String,
    // TODO: store tokio::runtime::Runtime + artery NodeHandle here once
    // cross-compilation is wired up.  Rough shape:
    //
    //   rt: tokio::runtime::Runtime,
    //   handle: vess_artery::NodeHandle,
}

static NODE: OnceLock<Mutex<NodeState>> = OnceLock::new();

fn node() -> &'static Mutex<NodeState> {
    NODE.get_or_init(|| {
        Mutex::new(NodeState {
            running: false,
            node_id: String::new(),
        })
    })
}

// ── JNI entry points ───────────────────────────────────────────────────────

/// Start the Vess node with `dataDir` as persistent storage root.
/// Returns JNI_TRUE on success, JNI_FALSE on failure.
#[no_mangle]
pub extern "system" fn Java_com_vess_app_VessNode_nativeStartNode<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    data_dir: JString<'local>,
) -> jboolean {
    let dir: String = match env.get_string(&data_dir) {
        Ok(s) => s.into(),
        Err(_) => return JNI_FALSE,
    };

    let mut n = match node().lock() {
        Ok(g) => g,
        Err(_) => return JNI_FALSE,
    };
    if n.running {
        return JNI_TRUE;
    }

    // TODO: build tokio runtime, call vess_artery::start(config) with dir,
    //       store the runtime/handle in NodeState so it stays alive.
    tracing::info!(data_dir = %dir, "vess node starting (stub)");
    n.running = true;
    n.node_id = "stub-node-id".to_string(); // TODO: real node_id from artery

    JNI_TRUE
}

/// Gracefully shut down the running node.
#[no_mangle]
pub extern "system" fn Java_com_vess_app_VessNode_nativeStopNode<'local>(
    _env: JNIEnv<'local>,
    _class: JClass<'local>,
) {
    if let Ok(mut n) = node().lock() {
        // TODO: call runtime.block_on(handle.shutdown())
        n.running = false;
    }
}

/// Returns the node's public ID as a hex string, or "" if not running.
#[no_mangle]
pub extern "system" fn Java_com_vess_app_VessNode_nativeGetNodeId<'local>(
    env: JNIEnv<'local>,
    _class: JClass<'local>,
) -> jstring {
    let id = node()
        .lock()
        .map(|n| n.node_id.clone())
        .unwrap_or_default();
    // new_string can only fail on OOM — treat as empty string.
    env.new_string(&id)
        .unwrap_or_else(|_| env.new_string("").unwrap())
        .into_raw()
}

/// Returns the wallet balance in whole VESS units, or 0 if not running / no wallet.
#[no_mangle]
pub extern "system" fn Java_com_vess_app_VessNode_nativeGetBalance<'local>(
    _env: JNIEnv<'local>,
    _class: JClass<'local>,
) -> jlong {
    // TODO: query ArteryState::wallet::billfold::balance() via stored handle
    0
}

/// Returns connected peer count, or -1 if the node is not running.
#[no_mangle]
pub extern "system" fn Java_com_vess_app_VessNode_nativeGetPeerCount<'local>(
    _env: JNIEnv<'local>,
    _class: JClass<'local>,
) -> jint {
    match node().lock() {
        Ok(n) if n.running => 0, // TODO: real peer count from routing table
        _ => -1,
    }
}
