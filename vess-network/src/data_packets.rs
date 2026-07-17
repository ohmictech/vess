//! Bounded application-level UDP fragmentation for large encrypted frames.
//!
//! Fragments are transported as independent UDP datagrams. Callers fragment
//! complete authenticated transport frames at the socket boundary, then
//! reassemble before protocol-frame parsing.

use std::collections::HashMap;
use vess_crypto::random_bytes;

pub const FRAGMENT_TAG: u8 = 0xF0;
const VERSION: u8 = 1;
pub const MAX_FRAGMENT_PAYLOAD: usize = 1000;
pub const MAX_MESSAGE_SIZE: usize = 1024 * 1024;
const MAX_FRAGMENT_COUNT: usize = 2048;
const MAX_INCOMPLETE_MESSAGES: usize = 4;
const ASSEMBLY_TIMEOUT_TICKS: u64 = 6000;
const HEADER_LEN: usize = 1 + 1 + 16 + 2 + 2 + 4;

pub type MessageId = [u8; 16];

pub struct FragmentedMessage {
    pub id: Option<MessageId>,
    pub packets: Vec<Vec<u8>>,
}


#[derive(Clone, Debug)]
struct Fragment {
    id: MessageId,
    index: u16,
    count: u16,
    total_len: usize,
    payload: Vec<u8>,
}

struct PendingMessage {
    total_len: usize,
    count: u16,
    received: usize,
    created_at: u64,
    parts: Vec<Option<Vec<u8>>>,
}

/// Reassembles bounded fragment sets from one authenticated peer.
pub struct PacketReassembler {
    pending: HashMap<MessageId, PendingMessage>,
}

impl PacketReassembler {
    pub fn new() -> Self {
        Self { pending: HashMap::new() }
    }

    /// Add one decoded fragment. `Ok(None)` means that more fragments are
    /// needed; `Ok(Some(message))` is a complete logical message.
    pub fn push(&mut self, bytes: &[u8], tick: u64) -> Result<Option<(MessageId, Vec<u8>)>, ()> {
        self.evict_expired(tick);
        let fragment = decode_fragment(bytes)?;
        if !self.pending.contains_key(&fragment.id) && self.pending.len() >= MAX_INCOMPLETE_MESSAGES {
            return Err(());
        }
        let pending = self.pending.entry(fragment.id).or_insert_with(|| PendingMessage {
            total_len: fragment.total_len,
            count: fragment.count,
            received: 0,
            created_at: tick,
            parts: vec![None; fragment.count as usize],
        });
        if pending.total_len != fragment.total_len || pending.count != fragment.count {
            return Err(());
        }
        let slot = &mut pending.parts[fragment.index as usize];
        if let Some(existing) = slot {
            if existing != &fragment.payload { return Err(()); }
            return Ok(None);
        }
        pending.received += fragment.payload.len();
        if pending.received > pending.total_len { return Err(()); }
        *slot = Some(fragment.payload);
        if pending.parts.iter().any(Option::is_none) { return Ok(None); }

        let pending = self.pending.remove(&fragment.id).ok_or(())?;
        if pending.received != pending.total_len { return Err(()); }
        let mut message = Vec::with_capacity(pending.total_len);
        for part in pending.parts {
            message.extend_from_slice(&part.ok_or(())?);
        }
        (message.len() == pending.total_len).then_some((fragment.id, message)).ok_or(()).map(Some)
    }

    pub fn evict_expired(&mut self, tick: u64) {
        self.pending.retain(|_, message| tick.saturating_sub(message.created_at) < ASSEMBLY_TIMEOUT_TICKS);
    }
}

/// Return one datagram payload for small data or a bounded set of fragments
/// for larger logical messages.
pub fn fragment_message(message: &[u8]) -> Option<Vec<Vec<u8>>> {
    Some(fragment_with_id(message)?.packets)
}

/// Fragment a logical UDP frame and expose its ID when retransmission is
/// required. Small frames remain a single unfragmented packet.
pub fn fragment_with_id(message: &[u8]) -> Option<FragmentedMessage> {
    if message.len() > MAX_MESSAGE_SIZE { return None; }
    if message.len() <= MAX_FRAGMENT_PAYLOAD {
        return Some(FragmentedMessage { id: None, packets: vec![message.to_vec()] });
    }
    let count = message.len().div_ceil(MAX_FRAGMENT_PAYLOAD);
    if count > MAX_FRAGMENT_COUNT { return None; }
    let id = random_bytes::<16>();
    let mut packets = Vec::with_capacity(count);
    for (index, chunk) in message.chunks(MAX_FRAGMENT_PAYLOAD).enumerate() {
        let mut packet = Vec::with_capacity(HEADER_LEN + chunk.len());
        packet.push(FRAGMENT_TAG);
        packet.push(VERSION);
        packet.extend_from_slice(&id);
        packet.extend_from_slice(&(index as u16).to_le_bytes());
        packet.extend_from_slice(&(count as u16).to_le_bytes());
        packet.extend_from_slice(&(message.len() as u32).to_le_bytes());
        packet.extend_from_slice(chunk);
        packets.push(packet);
    }
    Some(FragmentedMessage { id: Some(id), packets })
}

pub fn is_fragment(bytes: &[u8]) -> bool {
    bytes.first().copied() == Some(FRAGMENT_TAG)
}


fn decode_fragment(bytes: &[u8]) -> Result<Fragment, ()> {
    if bytes.len() <= HEADER_LEN || bytes[0] != FRAGMENT_TAG || bytes[1] != VERSION { return Err(()); }
    let id = bytes[2..18].try_into().map_err(|_| ())?;
    let index = u16::from_le_bytes(bytes[18..20].try_into().map_err(|_| ())?);
    let count = u16::from_le_bytes(bytes[20..22].try_into().map_err(|_| ())?);
    let total_len = u32::from_le_bytes(bytes[22..26].try_into().map_err(|_| ())?) as usize;
    if count == 0 || count as usize > MAX_FRAGMENT_COUNT || index >= count
        || total_len <= MAX_FRAGMENT_PAYLOAD || total_len > MAX_MESSAGE_SIZE
        || bytes.len() - HEADER_LEN > MAX_FRAGMENT_PAYLOAD {
        return Err(());
    }
    Ok(Fragment { id, index, count, total_len, payload: bytes[HEADER_LEN..].to_vec() })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reassembles_out_of_order_fragments() {
        let message: Vec<u8> = (0..3500).map(|i| (i % 251) as u8).collect();
        let mut packets = fragment_message(&message).expect("within limit");
        assert!(packets.len() > 1);
        packets.reverse();
        let mut reassembler = PacketReassembler::new();
        let mut result = None;
        for packet in packets {
            if let Some((_, message)) = reassembler.push(&packet, 1).expect("valid packet") { result = Some(message); }
        }
        assert_eq!(result.as_deref(), Some(message.as_slice()));
    }

    #[test]
    fn rejects_inconsistent_duplicate_fragment() {
        let message = vec![7u8; 2000];
        let packets = fragment_message(&message).unwrap();
        let mut altered = packets[0].clone();
        *altered.last_mut().unwrap() ^= 1;
        let mut reassembler = PacketReassembler::new();
        assert!(reassembler.push(&packets[0], 1).is_ok());
        assert!(reassembler.push(&altered, 1).is_err());
    }

    #[test]
    fn incomplete_message_is_not_delivered() {
        let packets = fragment_message(&vec![3u8; 2500]).unwrap();
        let mut reassembler = PacketReassembler::new();
        assert_eq!(reassembler.push(&packets[0], 1).unwrap(), None);
        assert_eq!(reassembler.push(&packets[2], 1).unwrap(), None);
    }
}
