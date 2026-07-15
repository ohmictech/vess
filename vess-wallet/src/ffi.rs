use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::net::SocketAddr;
use vess_crypto::{VessPayment, OwnerHash, SpendCondition};
use crate::Wallet;

pub const VESS_OK: i32 = 0;
pub const VESS_ERR_NO_FUNDS: i32 = -1;
pub const VESS_ERR_NETWORK: i32 = -2;
pub const VESS_ERR_INVALID: i32 = -3;

#[no_mangle]
pub extern "C" fn vess_wallet_new(password: *const c_char) -> *mut Wallet {
    let pw = unsafe { CStr::from_ptr(password) }.to_bytes();
    Box::into_raw(Box::new(Wallet::new(pw)))
}

#[no_mangle]
pub extern "C" fn vess_wallet_free(wallet: *mut Wallet) {
    if wallet.is_null() { return; }
    unsafe { drop(Box::from_raw(wallet)); }
}

#[no_mangle]
pub extern "C" fn vess_wallet_load(data: *const u8, data_len: u32, password: *const c_char) -> *mut Wallet {
    let pw = unsafe { CStr::from_ptr(password) }.to_bytes();
    let bytes = unsafe { std::slice::from_raw_parts(data, data_len as usize) };
    match Wallet::load(bytes, pw) {
        Some(w) => Box::into_raw(Box::new(w)),
        None => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "C" fn vess_wallet_save(wallet: *mut Wallet, out_len: *mut u32) -> *mut u8 {
    let w = unsafe { &*wallet };
    let data = w.save();
    unsafe { *out_len = data.len() as u32; }
    let ptr = data.as_ptr();
    std::mem::forget(data);
    ptr as *mut u8
}

#[no_mangle]
pub extern "C" fn vess_wallet_connect(wallet: *mut Wallet, addr: *const c_char, out_len: *mut u32) -> *const c_char {
    let w = unsafe { &mut *wallet };
    let addr_str = unsafe { CStr::from_ptr(addr) }.to_str().unwrap_or("127.0.0.1:9876");
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
pub extern "C" fn vess_wallet_handshake(wallet: *mut Wallet, data: *const u8, len: u32) -> i32 {
    let w = unsafe { &mut *wallet };
    let bytes = unsafe { std::slice::from_raw_parts(data, len as usize) };
    if w.handshake_complete(bytes) { VESS_OK } else { VESS_ERR_NETWORK }
}

#[no_mangle]
pub extern "C" fn vess_wallet_bind(wallet: *mut Wallet) -> i32 {
    let w = unsafe { &mut *wallet };
    if w.bind().is_ok() { VESS_OK } else { VESS_ERR_NETWORK }
}

#[no_mangle]
pub extern "C" fn vess_wallet_build_invoice(wallet: *mut Wallet, amount: u64, memo: *const c_char, out_len: *mut u32) -> *const c_char {
    let w = unsafe { &mut *wallet };
    let m = if memo.is_null() { None } else { Some(unsafe { CStr::from_ptr(memo) }.to_str().unwrap_or("")) };
    let amt = if amount == 0 { None } else { Some(amount) };
    let url = w.build_invoice(amt, m, None, None);
    unsafe { *out_len = url.len() as u32; }
    CString::new(url).unwrap().into_raw()
}

#[no_mangle]
pub extern "C" fn vess_wallet_build_payment(wallet: *mut Wallet, hashes: *const u8, amounts: *const u64, count: u32, out_len: *mut u32) -> *mut u8 {
    let w = unsafe { &mut *wallet };
    let n = count as usize;
    let oh: &[OwnerHash] = unsafe { std::slice::from_raw_parts(hashes as *const OwnerHash, n) };
    let amt: &[u64] = unsafe { std::slice::from_raw_parts(amounts, n) };
    let outputs: Vec<(OwnerHash, u64, Option<SpendCondition>)> = oh.iter().zip(amt.iter()).map(|(h, a)| (*h, *a, None)).collect();
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
pub extern "C" fn vess_wallet_send(wallet: *mut Wallet, payment: *const u8, len: u32) -> i32 {
    let w = unsafe { &mut *wallet };
    let bytes = unsafe { std::slice::from_raw_parts(payment, len as usize) };
    let mut pos = 0;
    match VessPayment::decode(bytes, &mut pos) {
        Some(p) if w.send(&p) => VESS_OK,
        Some(_) => VESS_ERR_NO_FUNDS,
        None => VESS_ERR_INVALID,
    }
}

#[no_mangle]
pub extern "C" fn vess_wallet_balance(wallet: *mut Wallet) -> u64 {
    let w = unsafe { &*wallet };
    w.balance()
}

#[no_mangle]
pub extern "C" fn vess_wallet_receive(wallet: *mut Wallet, payment: *const u8, len: u32) -> i32 {
    let w = unsafe { &mut *wallet };
    let bytes = unsafe { std::slice::from_raw_parts(payment, len as usize) };
    let mut pos = 0;
    match VessPayment::decode(bytes, &mut pos) {
        Some(p) => { w.receive(p); VESS_OK }
        None => VESS_ERR_INVALID,
    }
}

#[no_mangle]
pub extern "C" fn vess_wallet_check(wallet: *mut Wallet, vess_id: *const u8) -> i32 {
    let w = unsafe { &mut *wallet };
    let id: [u8; 32] = unsafe { std::slice::from_raw_parts(vess_id, 32) }.try_into().unwrap();
    if w.check(&id).unwrap_or(false) { VESS_OK } else { VESS_ERR_INVALID }
}

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
