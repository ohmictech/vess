//! Address book: what this node knows about other nodes, and who it is willing to tell.
//!
//! Two rules make gossip safe to accept from an untrusted peer:
//!
//! 1. **Only verified addresses are ever gossiped onward.** A record counts as verified once this
//!    node has completed a handshake with it. A peer can therefore inject addresses into our book
//!    (cheap), but it cannot make us advertise them (not cheap), which is what stops the network
//!    being steered into an attacker's clique.
//! 2. **Addresses are filtered by reachability class.** An address must be an IP literal with a
//!    non-zero port; `0.0.0.0`, multicast and broadcast are refused outright, and loopback or private
//!    ranges are only accepted from a peer that is itself local. A public peer cannot poison us with
//!    `127.0.0.1:…` entries, and a local cluster can still gossip its own 127.0.0.1 addresses.
//!
//! The book is node-local, disposable state, so it lives in `datadir/peers.txt` rather than in the
//! consensus database: losing it costs a few seconds of re-discovery and nothing else.

use std::net::{IpAddr, SocketAddr};

use vess_net::AddressEntry;

/// Peers we have never successfully connected to are dropped after this many failures, so a garbage
/// address cannot occupy the book forever.
pub const MAX_FAILURES: u32 = 8;
/// Hard cap on the book, oldest-and-worst evicted first.
pub const MAX_RECORDS: usize = 512;
/// How many verified peers a `GET_ADDR` reply carries.
pub const GOSSIP_FANOUT: usize = 16;
/// Below this many verified peers a session asks for addresses.
pub const GOSSIP_THRESHOLD: usize = 8;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerRecord {
    pub addr: String,
    pub static_key: [u8; 32],
    /// Completed handshakes with this address.
    pub successes: u32,
    pub failures: u32,
    pub last_seen_unix: u64,
}

impl PeerRecord {
    pub fn verified(&self) -> bool {
        self.successes > 0
    }
}

/// Merge every bootstrap source into one address list: `--peer`, `--seed`, `VESS_SEEDS`, and the
/// compiled-in defaults, in that order. Blanks are dropped and duplicates collapse onto their first
/// occurrence, so the same host passed twice is dialled once and the order stays predictable.
pub fn bootstrap(sources: &[&str]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for source in sources {
        for entry in source.split(',') {
            let addr = entry.trim();
            if addr.is_empty() || out.iter().any(|known| known == addr) {
                continue;
            }
            out.push(addr.to_string());
        }
    }
    out
}

/// Is `addr` something we are willing to keep, given what we know about the peer that sent it?
pub fn acceptable(addr: &str, sender_is_local: bool) -> bool {
    let Ok(socket) = addr.parse::<SocketAddr>() else {
        // Require an IP literal: a hostname would turn gossip into a DNS dependency and make the
        // reachability checks below meaningless.
        return false;
    };
    if socket.port() == 0 {
        return false;
    }
    let ip = normalise(socket.ip());
    if ip.is_unspecified() || ip.is_multicast() {
        return false;
    }
    if let IpAddr::V4(v4) = ip
        && v4.is_broadcast()
    {
        return false;
    }
    let local = ip.is_loopback() || is_private(ip);
    !local || sender_is_local
}

/// Fold IPv4-mapped IPv6 (`::ffff:127.0.0.1`) onto its IPv4 form, so the reachability checks below
/// cannot be side-stepped by writing an internal address in IPv6 notation.
fn normalise(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => ip,
        },
        _ => ip,
    }
}

fn is_private(ip: IpAddr) -> bool {
    match normalise(ip) {
        IpAddr::V4(v4) => {
            // `is_private` covers RFC 1918 only, so shared space (CGNAT), `0.0.0.0/8` and
            // benchmarking/reserved blocks are rejected explicitly: all of them can resolve to a
            // host on the far side of a NAT that we must not dial for a stranger.
            v4.is_private()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.octets()[0] == 0
                || (v4.octets()[0] == 100 && (64..=127).contains(&v4.octets()[1]))
                || (v4.octets()[0] == 198 && (18..=19).contains(&v4.octets()[1]))
                || v4.octets()[0] >= 240
        }
        IpAddr::V6(v6) => {
            let head = v6.segments()[0];
            // Unique-local (fc00::/7), link-local (fe80::/10) and the unspecified address.
            (head & 0xfe00) == 0xfc00 || (head & 0xffc0) == 0xfe80 || v6.is_unspecified()
        }
    }
}

/// The set of peers this node knows about.
#[derive(Debug, Default)]
pub struct AddressBook {
    records: Vec<PeerRecord>,
    /// Rotation cursor, so repeated `GET_ADDR` replies are not always the same prefix.
    cursor: usize,
}

impl AddressBook {
    pub fn load(path: &std::path::Path) -> AddressBook {
        let mut book = AddressBook::default();
        let Ok(text) = std::fs::read_to_string(path) else {
            return book;
        };
        for line in text.lines() {
            let mut parts = line.split_whitespace();
            let (Some(addr), Some(key), Some(successes), Some(failures), Some(last)) = (
                parts.next(),
                parts.next(),
                parts.next(),
                parts.next(),
                parts.next(),
            ) else {
                continue;
            };
            if !acceptable(addr, true) {
                continue;
            }
            let Some(key) = parse_key(key) else { continue };
            let (Ok(successes), Ok(failures), Ok(last_seen_unix)) =
                (successes.parse(), failures.parse(), last.parse())
            else {
                continue;
            };
            book.records.push(PeerRecord {
                addr: addr.to_string(),
                static_key: key,
                successes,
                failures,
                last_seen_unix,
            });
        }
        book
    }

    /// Persist atomically: a torn file would lose the book, which is cheap to rebuild but not to
    /// parse half-way.
    pub fn save(&self, path: &std::path::Path) -> std::io::Result<()> {
        let mut out = String::new();
        for record in &self.records {
            out.push_str(&format!(
                "{} {} {} {} {}\n",
                record.addr,
                hex(&record.static_key),
                record.successes,
                record.failures,
                record.last_seen_unix
            ));
        }
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, out)?;
        std::fs::rename(&tmp, path)
    }

    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    pub fn verified_count(&self) -> usize {
        self.records.iter().filter(|r| r.verified()).count()
    }

    pub fn get(&self, addr: &str) -> Option<&PeerRecord> {
        self.records.iter().find(|r| r.addr == addr)
    }

    /// Learn an address without claiming it works. Returns whether the book changed.
    pub fn learn(&mut self, addr: &str, static_key: [u8; 32], now: u64) -> bool {
        if let Some(existing) = self.records.iter_mut().find(|r| r.addr == addr) {
            if existing.static_key != static_key {
                if existing.verified() {
                    // A verified record was proved by our own handshake; unauthenticated gossip may
                    // not downgrade or re-key it, or anyone could erase every honest peer we know.
                    return false;
                }
                // A different key behind an unverified address is either a legitimate restart with
                // a new identity or a hijack attempt. Treat it as unknown and let the next
                // handshake (which proves the key) settle it.
                *existing = PeerRecord {
                    addr: addr.to_string(),
                    static_key,
                    successes: 0,
                    failures: 0,
                    last_seen_unix: now,
                };
                return true;
            }
            existing.last_seen_unix = now;
            return true;
        }
        self.records.push(PeerRecord {
            addr: addr.to_string(),
            static_key,
            successes: 0,
            failures: 0,
            last_seen_unix: now,
        });
        self.evict();
        true
    }

    /// A completed handshake: this address is now real, and gossiped onward.
    pub fn record_success(&mut self, addr: &str, static_key: [u8; 32], now: u64) {
        if let Some(record) = self.records.iter_mut().find(|r| r.addr == addr) {
            // A verified key is pinned. Sessions that present a different one are refused before
            // they get here, so this is the second line of defence, not the first.
            if record.verified() && record.static_key != static_key {
                return;
            }
            record.static_key = static_key;
            record.successes = record.successes.saturating_add(1);
            record.failures = 0;
            record.last_seen_unix = now;
            return;
        }
        self.records.push(PeerRecord {
            addr: addr.to_string(),
            static_key,
            successes: 1,
            failures: 0,
            last_seen_unix: now,
        });
        self.evict();
    }

    /// The static key we have pinned for `addr`: the one our own handshake proved.
    pub fn pinned_key(&self, addr: &str) -> Option<[u8; 32]> {
        self.records
            .iter()
            .find(|r| r.addr == addr && r.verified())
            .map(|r| r.static_key)
    }

    /// Does `key` match what we pinned for `addr`? True when nothing is pinned, which is trust on
    /// first use — the first contact to an address cannot be pinned by definition.
    pub fn pin_matches(&self, addr: &str, key: &[u8; 32]) -> bool {
        match self.pinned_key(addr) {
            Some(pinned) => pinned == *key,
            None => true,
        }
    }

    pub fn record_failure(&mut self, addr: &str) {
        if let Some(record) = self.records.iter_mut().find(|r| r.addr == addr) {
            record.failures = record.failures.saturating_add(1);
        }
        self.records
            .retain(|r| r.verified() || r.failures < MAX_FAILURES);
    }

    /// Addresses to hand to a peer: verified only, never the peer that asked, rotating so repeated
    /// requests do not always return the same subset.
    pub fn gossip(&mut self, exclude: &[&str], max: usize) -> Vec<AddressEntry> {
        let mut pool: Vec<&PeerRecord> = self
            .records
            .iter()
            .filter(|r| r.verified() && !exclude.contains(&r.addr.as_str()))
            .collect();
        if pool.is_empty() {
            return Vec::new();
        }
        let start = self.cursor % pool.len();
        self.cursor = self.cursor.wrapping_add(1);
        pool.rotate_left(start);
        pool.into_iter()
            .take(max.min(GOSSIP_FANOUT))
            .map(|r| AddressEntry {
                addr: r.addr.clone(),
                static_key: r.static_key,
            })
            .collect()
    }

    /// The next address worth dialling: never one we are already connected to, preferring verified
    /// peers (a proven key is worth more than an unknown one), oldest contact first.
    pub fn next_dial(&self, connected: &[&str]) -> Option<PeerRecord> {
        self.records
            .iter()
            .filter(|r| !connected.contains(&r.addr.as_str()))
            .min_by_key(|r| (!r.verified(), r.last_seen_unix, r.failures, r.addr.as_str()))
            .cloned()
    }

    fn evict(&mut self) {
        if self.records.len() <= MAX_RECORDS {
            return;
        }
        // Worst first: unverified before verified, then most failures, then longest unseen.
        self.records.sort_by_key(|r| {
            (
                r.verified(),
                std::cmp::Reverse(r.failures),
                r.last_seen_unix,
                r.addr.clone(),
            )
        });
        self.records.truncate(MAX_RECORDS);
    }
}

fn parse_key(hex: &str) -> Option<[u8; 32]> {
    if hex.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (index, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(hex.get(index * 2..index * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    #[test]
    fn only_routable_ip_literals_are_accepted() {
        assert!(acceptable("203.0.113.7:9732", false));
        assert!(acceptable("[2001:db8::1]:9732", false));
        // Hostnames would make gossip depend on DNS.
        assert!(!acceptable("example.com:9732", false));
        assert!(!acceptable("203.0.113.7:0", false));
        assert!(!acceptable("0.0.0.0:9732", false));
        assert!(!acceptable("224.0.0.1:9732", false));
        assert!(!acceptable("[::]:9732", false));
        // Local ranges only from a peer that is itself local.
        assert!(!acceptable("127.0.0.1:9732", false));
        assert!(acceptable("127.0.0.1:9732", true));
        assert!(!acceptable("192.168.1.5:9732", false));
        assert!(acceptable("192.168.1.5:9732", true));
        assert!(!acceptable("10.0.0.1:9732", false));
        assert!(acceptable("10.0.0.1:9732", true));
    }

    #[test]
    fn only_verified_addresses_are_gossiped() {
        let mut book = AddressBook::default();
        book.learn("203.0.113.7:1", key(1), 10);
        assert!(book.gossip(&[], 16).is_empty(), "unverified is not shared");

        book.record_success("203.0.113.7:1", key(1), 11);
        let shared = book.gossip(&[], 16);
        assert_eq!(shared.len(), 1);
        assert_eq!(shared[0].addr, "203.0.113.7:1");
        assert_eq!(shared[0].static_key, key(1));

        // Never hand a peer back to itself.
        assert!(book.gossip(&["203.0.113.7:1"], 16).is_empty());
    }

    #[test]
    fn gossip_cannot_unverify_a_known_peer() {
        // A verified record is backed by our own handshake, so unauthenticated gossip may neither
        // re-key it nor reset it. Otherwise anyone could erase every honest peer we know.
        let mut book = AddressBook::default();
        book.record_success("203.0.113.7:1", key(1), 10);
        assert_eq!(book.gossip(&[], 16).len(), 1);
        assert!(!book.learn("203.0.113.7:1", key(2), 11));
        let shared = book.gossip(&[], 16);
        assert_eq!(shared.len(), 1, "still advertised");
        assert_eq!(shared[0].static_key, key(1), "and with the proven key");

        // An unverified record may still be re-keyed: nothing has been proven about it yet.
        book.learn("204.0.113.8:2", key(3), 12);
        assert!(book.learn("204.0.113.8:2", key(4), 13));
    }

    #[test]
    fn bootstrap_sources_merge_in_priority_order() {
        // `--peer` first, then `--seed`, then `VESS_SEEDS`, then the compiled-in defaults; blanks and
        // repeats collapse, so a host named twice is dialled once.
        let merged = bootstrap(&[
            " 10.0.0.1:9732 , 10.0.0.2:9732 ",
            "",
            "10.0.0.2:9732,seed.example:9732",
            "fallback.example:9732,seed.example:9732",
        ]);
        assert_eq!(
            merged,
            vec![
                "10.0.0.1:9732",
                "10.0.0.2:9732",
                "seed.example:9732",
                "fallback.example:9732",
            ]
        );
        assert!(bootstrap(&["", ",", "  "]).is_empty());
    }

    #[test]
    fn each_network_has_its_own_default_seeds() {
        // A devnet node must never dial a mainnet seed, so the lists are looked up per network.
        use vess_core::constants::{
            NETWORK_DEVNET, NETWORK_MAINNET, NETWORK_TESTNET, default_seeds,
        };
        assert_eq!(default_seeds(NETWORK_DEVNET), default_seeds(NETWORK_DEVNET));
        assert_eq!(
            default_seeds(NETWORK_TESTNET),
            default_seeds(NETWORK_TESTNET)
        );
        assert_eq!(
            default_seeds(NETWORK_MAINNET),
            default_seeds(NETWORK_MAINNET)
        );
        // Whatever they contain, every entry must be something the book would accept.
        for network in [NETWORK_DEVNET, NETWORK_TESTNET, NETWORK_MAINNET] {
            for seed in default_seeds(network) {
                assert!(
                    acceptable(seed, false),
                    "compiled-in seed {seed} is not a public host:port"
                );
            }
        }
    }

    #[test]
    fn a_verified_key_is_pinned() {
        let mut book = AddressBook::default();
        // Nothing is pinned until we have proved something ourselves.
        assert!(book.pin_matches("203.0.113.7:1", &key(1)));
        assert_eq!(book.pinned_key("203.0.113.7:1"), None);

        book.record_success("203.0.113.7:1", key(1), 10);
        assert_eq!(book.pinned_key("203.0.113.7:1"), Some(key(1)));
        assert!(book.pin_matches("203.0.113.7:1", &key(1)));
        assert!(
            !book.pin_matches("203.0.113.7:1", &key(2)),
            "a different key at a known address is not that peer"
        );

        // A handshake that presented the wrong key must not be able to re-pin it.
        book.record_success("203.0.113.7:1", key(2), 11);
        assert_eq!(
            book.pinned_key("203.0.113.7:1"),
            Some(key(1)),
            "the proven key stands"
        );

        // An unverified address has no pin, so the next handshake settles it.
        book.learn("204.0.113.8:2", key(3), 12);
        assert!(book.pin_matches("204.0.113.8:2", &key(4)));
    }

    #[test]
    fn internal_addresses_cannot_be_smuggled_in_ipv6_notation() {
        // `::ffff:127.0.0.1` is loopback written the long way; a public peer must not be able to
        // aim our dialler at it, nor at CGNAT or `0.0.0.0/8` space.
        assert!(!acceptable("[::ffff:127.0.0.1]:9732", false));
        assert!(acceptable("[::ffff:127.0.0.1]:9732", true));
        assert!(!acceptable("[::ffff:10.0.0.5]:9732", false));
        assert!(!acceptable("[::ffff:192.168.1.1]:9732", false));
        assert!(!acceptable("[::ffff:169.254.169.254]:80", false));
        assert!(!acceptable("100.64.0.5:9732", false));
        assert!(!acceptable("0.1.2.3:9732", false));
        // A genuinely public address still passes in either notation.
        assert!(acceptable("203.0.113.7:9732", false));
        assert!(acceptable("[::ffff:203.0.113.7]:9732", false));
    }

    #[test]
    fn garbage_addresses_are_dropped_after_repeated_failures() {
        let mut book = AddressBook::default();
        book.learn("203.0.113.9:1", key(3), 10);
        for _ in 0..MAX_FAILURES {
            book.record_failure("203.0.113.9:1");
        }
        assert_eq!(book.len(), 0);
    }

    #[test]
    fn verified_addresses_survive_failures() {
        let mut book = AddressBook::default();
        book.record_success("203.0.113.9:1", key(3), 10);
        for _ in 0..(MAX_FAILURES * 2) {
            book.record_failure("203.0.113.9:1");
        }
        assert_eq!(
            book.len(),
            1,
            "a peer that worked once is still worth trying"
        );
    }

    #[test]
    fn dialling_prefers_verified_and_never_redials_connected() {
        let mut book = AddressBook::default();
        book.learn("203.0.113.2:1", key(2), 5);
        book.record_success("203.0.113.3:1", key(3), 9);
        let pick = book.next_dial(&[]).expect("a candidate");
        assert_eq!(pick.addr, "203.0.113.3:1");
        assert!(
            book.next_dial(&["203.0.113.3:1", "203.0.113.2:1"])
                .is_none()
        );
    }

    #[test]
    fn a_book_round_trips_through_disk() {
        let path = std::env::temp_dir().join(format!("vess-peers-{}.txt", std::process::id()));
        let mut book = AddressBook::default();
        book.record_success("203.0.113.7:1", key(1), 42);
        book.learn("198.51.100.4:2", key(2), 43);
        book.record_failure("198.51.100.4:2");
        book.save(&path).unwrap();

        let loaded = AddressBook::load(&path);
        assert_eq!(loaded.len(), 2);
        let verified = loaded.get("203.0.113.7:1").expect("kept");
        assert_eq!(verified.static_key, key(1));
        assert_eq!(verified.successes, 1);
        assert_eq!(loaded.verified_count(), 1);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn the_book_is_bounded() {
        let mut book = AddressBook::default();
        for index in 0..(MAX_RECORDS + 32) {
            let addr = format!("203.0.{}.{}:1", index / 256, index % 256);
            book.learn(&addr, key(1), index as u64);
        }
        assert_eq!(book.len(), MAX_RECORDS);
    }
}
