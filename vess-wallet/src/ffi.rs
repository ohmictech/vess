use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::net::SocketAddr;
use vess_crypto::{VessPayment, OwnerHash, SpendCondition};
use crate::Wallet;

pub const VESS_OK: i32 = 0;
#[allow(dead_code)]
pub const VESS_ERR_NO_FUNDS: i32 = -1;
pub const VESS_ERR_NETWORK: i32 = -2;
pub const VESS_ERR_INVALID: i32 = -3;
const MAX_FFI_BUFFER: usize = 16 * 1024 * 1024;
const MAX_FFI_OUTPUTS: usize = 5;

fn c_string<'a>(ptr: *const c_char) -> Option<&'a str> {
    if ptr.is_null() { return None; }
    unsafe { CStr::from_ptr(ptr).to_str().ok() }
}

fn byte_slice<'a>(ptr: *const u8, len: u32) -> Option<&'a [u8]> {
    let len = len as usize;
    if len > MAX_FFI_BUFFER || (ptr.is_null() && len != 0) { return None; }
    Some(if len == 0 { &[] } else { unsafe { std::slice::from_raw_parts(ptr, len) } })
}

macro_rules! wallet_mut {
    ($wallet:expr, $fallback:expr) => {{
        if $wallet.is_null() { return $fallback; }
        unsafe { &mut *$wallet }
    }};
}

macro_rules! wallet_ref {
    ($wallet:expr, $fallback:expr) => {{
        if $wallet.is_null() { return $fallback; }
        unsafe { &*$wallet }
    }};
}

fn outputs_from_ffi(
    hashes: *const u8,
    amounts: *const u64,
    hashlocks: *const u8,
    expires_ats: *const u64,
    count: u32,
) -> Option<Vec<(OwnerHash, u64, Option<SpendCondition>)>> {
    let count = count as usize;
    if count == 0 || count > MAX_FFI_OUTPUTS || hashes.is_null() || amounts.is_null()
        || hashlocks.is_null() || expires_ats.is_null() {
        return None;
    }
    let hashes = unsafe { std::slice::from_raw_parts(hashes as *const OwnerHash, count) };
    let amounts = unsafe { std::slice::from_raw_parts(amounts, count) };
    let hashlocks = unsafe { std::slice::from_raw_parts(hashlocks, count.checked_mul(32)?) };
    let expires_ats = unsafe { std::slice::from_raw_parts(expires_ats, count) };
    Some((0..count).map(|i| {
        let hashlock = hashlocks[i * 32..(i + 1) * 32].try_into().ok()?;
        let condition = if hashlock == [0u8; 32] && expires_ats[i] == 0 {
            None
        } else {
            Some(SpendCondition { hashlock, expires_at: expires_ats[i] })
        };
        Some((hashes[i], amounts[i], condition))
    }).collect::<Option<Vec<_>>>()?)
}

// ---- lifecycle ----

#[no_mangle]
pub extern "C" fn vess_wallet_new(password: *const c_char) -> *mut Wallet {
    let Some(password) = c_string(password) else { return std::ptr::null_mut(); };
    let pw = password.as_bytes();
    Box::into_raw(Box::new(Wallet::new(pw)))
}

#[no_mangle]
pub extern "C" fn vess_wallet_free(wallet: *mut Wallet) {
    if wallet.is_null() { return; }
    unsafe { drop(Box::from_raw(wallet)); }
}

#[no_mangle]
pub extern "C" fn vess_wallet_load(data: *const u8, data_len: u32, password: *const c_char) -> *mut Wallet {
    let Some(password) = c_string(password) else { return std::ptr::null_mut(); };
    let Some(bytes) = byte_slice(data, data_len) else { return std::ptr::null_mut(); };
    let pw = password.as_bytes();
    match Wallet::load(bytes, pw) {
        Some(w) => Box::into_raw(Box::new(w)),
        None => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "C" fn vess_wallet_save(wallet: *mut Wallet, out_len: *mut u32) -> *mut u8 {
    if out_len.is_null() { return std::ptr::null_mut(); }
    let w = wallet_ref!(wallet, std::ptr::null_mut());
    let data = w.save();
    unsafe { *out_len = data.len() as u32; }
    let ptr = data.as_ptr();
    std::mem::forget(data);
    ptr as *mut u8
}

// ---- network ----

#[no_mangle]
pub extern "C" fn vess_wallet_connect(wallet: *mut Wallet, addr: *const c_char, out_len: *mut u32) -> *const c_char {
    if out_len.is_null() { return std::ptr::null(); }
    let w = wallet_mut!(wallet, std::ptr::null());
    let Some(addr_str) = c_string(addr) else { return std::ptr::null(); };
    if let Ok(sa) = addr_str.parse::<SocketAddr>() {
        let init = w.connect(sa);
        let hex = hex::encode(&init);
        unsafe { *out_len = hex.len() as u32; }
        CString::new(hex).unwrap().into_raw()
    } else {
        std::ptr::null()
    }
}

#[no_mangle]
pub extern "C" fn vess_wallet_connect_full(wallet: *mut Wallet, addr: *const c_char) -> i32 {
    let w = wallet_mut!(wallet, VESS_ERR_INVALID);
    let Some(addr_str) = c_string(addr) else { return VESS_ERR_INVALID; };
    if let Ok(sa) = addr_str.parse::<SocketAddr>() {
        if w.connect_full(sa) { VESS_OK } else { VESS_ERR_NETWORK }
    } else {
        VESS_ERR_INVALID
    }
}

#[no_mangle]
pub extern "C" fn vess_wallet_handshake(wallet: *mut Wallet, data: *const u8, len: u32) -> i32 {
    let w = wallet_mut!(wallet, VESS_ERR_INVALID);
    let Some(bytes) = byte_slice(data, len) else { return VESS_ERR_INVALID; };
    if w.handshake_complete(bytes) { VESS_OK } else { VESS_ERR_NETWORK }
}

#[no_mangle]
pub extern "C" fn vess_wallet_bind(wallet: *mut Wallet) -> i32 {
    let w = wallet_mut!(wallet, VESS_ERR_INVALID);
    if w.bind().is_ok() { VESS_OK } else { VESS_ERR_NETWORK }
}

#[no_mangle]
pub extern "C" fn vess_wallet_connected(wallet: *mut Wallet) -> i32 {
    let w = wallet_ref!(wallet, 0);
    if w.connected() { 1 } else { 0 }
}

// ---- invoices ----

#[no_mangle]
pub extern "C" fn vess_wallet_build_invoice(
    wallet: *mut Wallet, amount: u64, memo: *const c_char,
    hashlock: *const u8, expires_at: u64,
    out_len: *mut u32,
) -> *const c_char {
    if out_len.is_null() { return std::ptr::null(); }
    let w = wallet_mut!(wallet, std::ptr::null());
    let m = if memo.is_null() { None } else { c_string(memo) };
    let amt = if amount == 0 { None } else { Some(amount) };
    let hl: Option<&[u8; 32]> = if hashlock.is_null() { None } else {
        if hashlock.is_null() { return std::ptr::null(); }
        Some(unsafe { &*(hashlock as *const [u8; 32]) })
    };
    let exp = if expires_at == 0 { None } else { Some(expires_at) };
    let url = w.build_invoice(amt, m, hl, exp);
    unsafe { *out_len = url.len() as u32; }
    CString::new(url).unwrap().into_raw()
}

// ---- payments ----

#[no_mangle]
pub extern "C" fn vess_wallet_build_payment(
    wallet: *mut Wallet, hashes: *const u8, amounts: *const u64,
    hashlock_preimages: *const u8, expires_ats: *const u64,
    count: u32, out_len: *mut u32,
) -> *mut u8 {
    if out_len.is_null() { return std::ptr::null_mut(); }
    let w = wallet_mut!(wallet, std::ptr::null_mut());
    let Some(outputs) = outputs_from_ffi(hashes, amounts, hashlock_preimages, expires_ats, count) else { return std::ptr::null_mut(); };
    if let Some(p) = w.build_payment(&outputs) {
        let data = p.encode();
        unsafe { *out_len = data.len() as u32; }
        let ptr = data.as_ptr();
        std::mem::forget(data);
        ptr as *mut u8
    } else {
        std::ptr::null_mut()
    }
}

#[no_mangle]
pub extern "C" fn vess_wallet_export_payment(
    wallet: *mut Wallet, hashes: *const u8, amounts: *const u64,
    hashlock_preimages: *const u8, expires_ats: *const u64,
    count: u32, out_len: *mut u32,
) -> *mut u8 {
    if out_len.is_null() { return std::ptr::null_mut(); }
    let w = wallet_mut!(wallet, std::ptr::null_mut());
    let Some(outputs) = outputs_from_ffi(hashes, amounts, hashlock_preimages, expires_ats, count) else { return std::ptr::null_mut(); };
    if let Some(data) = w.export_payment(&outputs) {
        unsafe { *out_len = data.len() as u32; }
        let ptr = data.as_ptr();
        std::mem::forget(data);
        ptr as *mut u8
    } else {
        std::ptr::null_mut()
    }
}

#[no_mangle]
pub extern "C" fn vess_wallet_claim_payment(wallet: *mut Wallet, payment: *const u8, len: u32) -> i32 {
    let w = wallet_mut!(wallet, VESS_ERR_INVALID);
    let Some(bytes) = byte_slice(payment, len) else { return VESS_ERR_INVALID; };
    let mut pos = 0;
    match VessPayment::decode(bytes, &mut pos) {
        Some(p) => if w.claim_payment(&p) { VESS_OK } else { VESS_ERR_NETWORK },
        None => VESS_ERR_INVALID,
    }
}

#[no_mangle]
pub extern "C" fn vess_wallet_receive(wallet: *mut Wallet, payment: *const u8, len: u32) -> i32 {
    let w = wallet_mut!(wallet, VESS_ERR_INVALID);
    let Some(bytes) = byte_slice(payment, len) else { return VESS_ERR_INVALID; };
    let mut pos = 0;
    match VessPayment::decode(bytes, &mut pos) {
        Some(p) => { w.receive(p); VESS_OK }
        None => VESS_ERR_INVALID,
    }
}

#[no_mangle]
pub extern "C" fn vess_wallet_receive_blob(wallet: *mut Wallet, data: *const u8, len: u32) -> i32 {
    let w = wallet_mut!(wallet, VESS_ERR_INVALID);
    let Some(bytes) = byte_slice(data, len) else { return VESS_ERR_INVALID; };
    match w.receive_blob(bytes) {
        Some(_) => VESS_OK,
        None => VESS_ERR_INVALID,
    }
}

// ---- treasury & keys ----

#[no_mangle]
pub extern "C" fn vess_wallet_import_treasure(wallet: *mut Wallet, path: *const c_char) -> u32 {
    let w = wallet_mut!(wallet, 0);
    let Some(p) = c_string(path) else { return 0; };
    w.import_treasure(p) as u32
}

#[no_mangle]
pub extern "C" fn vess_wallet_import_keypair(wallet: *mut Wallet, pub_path: *const c_char, sec_path: *const c_char, out_hash: *mut u8) -> i32 {
    let w = wallet_mut!(wallet, VESS_ERR_INVALID);
    let Some(pubkey) = c_string(pub_path) else { return VESS_ERR_INVALID; };
    let Some(seckey) = c_string(sec_path) else { return VESS_ERR_INVALID; };
    match w.import_keypair_files(pubkey, seckey) {
        Some(oh) => {
            if !out_hash.is_null() {
                unsafe { std::ptr::copy_nonoverlapping(oh.as_ptr(), out_hash, 32); }
            }
            VESS_OK
        }
        None => VESS_ERR_INVALID,
    }
}

#[no_mangle]
pub extern "C" fn vess_wallet_import_preimage(wallet: *mut Wallet, vess_id: *const u8, preimage: *const u8) -> i32 {
    let w = wallet_mut!(wallet, VESS_ERR_INVALID);
    let Some(id) = byte_slice(vess_id, 32).and_then(|b| <[u8; 32]>::try_from(b).ok()) else {
        return VESS_ERR_INVALID;
    };
    let Some(preimage) = byte_slice(preimage, 32).and_then(|b| <[u8; 32]>::try_from(b).ok()) else {
        return VESS_ERR_INVALID;
    };
    w.import_preimage(&id, &preimage);
    VESS_OK
}

// ---- queries ----

#[no_mangle]
pub extern "C" fn vess_wallet_balance(wallet: *mut Wallet) -> u64 {
    let w = wallet_ref!(wallet, 0);
    w.balance()
}

#[no_mangle]
pub extern "C" fn vess_wallet_check(wallet: *mut Wallet, vess_id: *const u8) -> i32 {
    let w = wallet_mut!(wallet, VESS_ERR_INVALID);
    let Some(id_bytes) = byte_slice(vess_id, 32) else { return VESS_ERR_INVALID; };
    let Ok(id) = <[u8; 32]>::try_from(id_bytes) else { return VESS_ERR_INVALID; };
    if w.check(&id).unwrap_or(false) { VESS_OK } else { VESS_ERR_INVALID }
}

#[no_mangle]
pub extern "C" fn vess_wallet_sync(wallet: *mut Wallet, out_confirmed: *mut u32, out_remaining: *mut u32) -> u64 {
    let w = wallet_mut!(wallet, 0);
    let (confirmed, remaining) = w.sync();
    unsafe {
        if !out_confirmed.is_null() { *out_confirmed = confirmed as u32; }
        if !out_remaining.is_null() { *out_remaining = remaining as u32; }
    }
    w.balance()
}

#[no_mangle]
pub extern "C" fn vess_wallet_consolidate(wallet: *mut Wallet) -> u32 {
    let w = wallet_mut!(wallet, 0);
    w.consolidate() as u32
}

#[no_mangle]
pub extern "C" fn vess_wallet_keypair_count(wallet: *mut Wallet) -> u32 {
    let w = wallet_ref!(wallet, 0);
    w.keypair_count() as u32
}

#[no_mangle]
pub extern "C" fn vess_wallet_history_counts(wallet: *mut Wallet, out_built: *mut u32, out_received: *mut u32) {
    let w = wallet_ref!(wallet, ());
    let (built, received) = w.history_counts();
    unsafe {
        if !out_built.is_null() { *out_built = built as u32; }
        if !out_received.is_null() { *out_received = received as u32; }
    }
}

// ---- memory ----

#[no_mangle]
pub extern "C" fn vess_free_bytes(ptr: *mut u8, len: u32) {
    if ptr.is_null() { return; }
    unsafe { drop(Vec::from_raw_parts(ptr, len as usize, len as usize)); }
}

#[no_mangle]
pub extern "C" fn vess_free_string(ptr: *const c_char) {
    if ptr.is_null() { return; }
    unsafe { drop(CString::from_raw(ptr as *mut c_char)); }
}
