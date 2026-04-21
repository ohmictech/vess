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
use jni::JNIEnv;// ── Shared node state ──────────────────────────────────────────────────────

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

/// Make a JSON-RPC call to the local artery node's RPC server.
/// `request_json` is a single JSON object; returns the response JSON string or
/// an error JSON object `{"error": "..."}` on failure.
#[no_mangle]
pub extern "system" fn Java_com_vess_app_VessNode_nativeRpc<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    port: jint,
    request_json: JString<'local>,
) -> jstring {
    let req: String = match env.get_string(&request_json) {
        Ok(s) => s.into(),
        Err(_) => return err_string(&mut env, "invalid request string"),
    };

    // Synchronous loopback TCP call on a temporary thread-local runtime.
    let result: anyhow::Result<String> = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        rt.block_on(async move {
            use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
            use tokio::net::TcpStream;

            let addr = format!("127.0.0.1:{port}");
            let stream = TcpStream::connect(&addr).await?;
            let (reader, mut writer) = stream.into_split();
            let mut buf = BufReader::new(reader);
            let mut req_bytes = req.into_bytes();
            req_bytes.push(b'\n');
            writer.write_all(&req_bytes).await?;
            let mut line = String::new();
            buf.read_line(&mut line).await?;
            Ok(line.trim().to_string())
        })
    })
    .join()
    .unwrap_or_else(|_| Err(anyhow::anyhow!("thread panicked")));

    let s = match result {
        Ok(s) => s,
        Err(e) => format!("{{\"error\":\"{e}\"}}"),
    };
    env.new_string(&s)
        .unwrap_or_else(|_| env.new_string("{}").unwrap())
        .into_raw()
}

/// Initialise a new wallet: derives keys, computes tag PoW, sends TagRegister.
/// Returns a JSON object `{"ok":bool, "recovery_phrase":"...", "error":"..."}`.
/// Long-running (~10 s due to Argon2id PoW) — call from a background thread.
#[no_mangle]
pub extern "system" fn Java_com_vess_app_VessNode_nativeWalletInit<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    data_dir: JString<'local>,
    tag_str: JString<'local>,
) -> jstring {
    let _dir: String = match env.get_string(&data_dir) {
        Ok(s) => s.into(),
        Err(_) => return err_string(&mut env, "invalid data_dir"),
    };
    let _tag: String = match env.get_string(&tag_str) {
        Ok(s) => s.into(),
        Err(_) => return err_string(&mut env, "invalid tag"),
    };

    // TODO: call vess_kloak::recovery::RecoveryPhrase::generate(),
    //   derive keys, compute vess_tag::compute_tag_pow(), build TagRegister,
    //   send via VessNode JNI handle, save WalletFile to data_dir/wallet.json.
    let resp = r#"{"ok":false,"error":"wallet init not yet wired to artery (TODO)"}"#;
    env.new_string(resp)
        .unwrap_or_else(|_| env.new_string("{}").unwrap())
        .into_raw()
}

/// Recover a wallet from a 5-word recovery phrase and 5-digit PIN.
/// Returns `{"ok":bool, "balance":N, "recovered_bills":N, "error":"..."}`.
/// Long-running — call from a background thread.
#[no_mangle]
pub extern "system" fn Java_com_vess_app_VessNode_nativeWalletRecover<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    data_dir: JString<'local>,
    words: JString<'local>,
    pin: JString<'local>,
) -> jstring {
    let _dir: String = match env.get_string(&data_dir) {
        Ok(s) => s.into(),
        Err(_) => return err_string(&mut env, "invalid data_dir"),
    };
    let _words: String = match env.get_string(&words) {
        Ok(s) => s.into(),
        Err(_) => return err_string(&mut env, "invalid words"),
    };
    let _pin: String = match env.get_string(&pin) {
        Ok(s) => s.into(),
        Err(_) => return err_string(&mut env, "invalid pin"),
    };

    // TODO: call vess_kloak recovery path, fetch manifest from network,
    //   reconstruct billfold, save WalletFile.
    let resp = r#"{"ok":false,"error":"wallet recovery not yet wired to artery (TODO)"}"#;
    env.new_string(resp)
        .unwrap_or_else(|_| env.new_string("{}").unwrap())
        .into_raw()
}

/// Run one mint iteration.  Returns JSON `{"ok":true,"hit":bool,"solves":N,"attempts":N}`.
/// Runs synchronously — always call from a background thread.  Caller loops
/// until `should_stop` is set; each call is one VM execution + difficulty check.
#[no_mangle]
pub extern "system" fn Java_com_vess_app_VessNode_nativeMintStep<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    data_dir: JString<'local>,
) -> jstring {
    let _dir: String = match env.get_string(&data_dir) {
        Ok(s) => s.into(),
        Err(_) => return err_string(&mut env, "invalid data_dir"),
    };

    // TODO: call vess_foundry::mint::mine_flow() for one step,
    //   persist session file in data_dir, return progress JSON.
    let resp = r#"{"ok":false,"error":"mint not yet wired (TODO)"}"#;
    env.new_string(resp)
        .unwrap_or_else(|_| env.new_string("{}").unwrap())
        .into_raw()
}

/// Aggregate accumulated mint solves into bills and broadcast OwnershipGenesis via RPC.
/// Returns `{"ok":bool,"bills":N,"balance":N,"error":"..."}`.
#[no_mangle]
pub extern "system" fn Java_com_vess_app_VessNode_nativeMintFinalize<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    data_dir: JString<'local>,
    rpc_port: jint,
) -> jstring {
    let _dir: String = match env.get_string(&data_dir) {
        Ok(s) => s.into(),
        Err(_) => return err_string(&mut env, "invalid data_dir"),
    };
    let _ = rpc_port;

    // TODO: call vess_foundry::mint::aggregate_solves(), broadcast
    //   OwnershipGenesis via nativeRpc, update manifest, save wallet.
    let resp = r#"{"ok":false,"error":"mint finalize not yet wired (TODO)"}"#;
    env.new_string(resp)
        .unwrap_or_else(|_| env.new_string("{}").unwrap())
        .into_raw()
}

// ── Helpers ────────────────────────────────────────────────────────────────

fn err_string(env: &mut JNIEnv<'_>, msg: &str) -> jstring {
    let s = format!("{{\"error\":\"{msg}\"}}");
    env.new_string(&s)
        .unwrap_or_else(|_| env.new_string("{}").unwrap())
        .into_raw()
}
