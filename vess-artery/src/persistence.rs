//! Persistence stub.
pub fn unhex_key(hex_str: &str) -> Option<[u8; 32]> {
    let bytes = hex::decode(hex_str).unwrap_or_default();
    let mut key = [0u8; 32];
    let len = bytes.len().min(32);
    key[..len].copy_from_slice(&bytes[..len]);
    Some(key)
}
pub fn hex_key(key: &[u8; 32]) -> String { hex::encode(&key[..8]) }