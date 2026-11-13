//! Encrypted transport: Noise_XX over the TCP socket, before any frame is written.
//!
//! Every byte of the peer protocol — handshake, inventory, blocks, snapshots — travels inside a
//! Noise transport session, so an observer on the path sees only ciphertext and cannot tell a
//! transaction from a ping. `Noise_XX` authenticates both sides with static X25519 keys and gives
//! forward secrecy; the static keys are exchanged during the handshake, so a caller that does not
//! already know the peer's key learns it here (trust on first use) and one that does can compare it
//! against what it expected.
//!
//! The prologue binds the session to this chain and to the transport version, so a peer on another
//! network — or one speaking an older framing — fails the handshake instead of mis-parsing frames.
//!
//! Above this layer nothing changes: [`SecureStream`] implements [`Read`] and [`Write`] as a byte
//! stream, and the existing frame codec works on it unchanged.

use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net::TcpStream;

use snow::{Builder, HandshakeState, TransportState};

use crate::NetError;

/// Bumped whenever the encrypted framing or the handshake changes. Carried in the prologue, so
/// mismatched peers fail immediately rather than after a garbage frame.
pub const TRANSPORT_VERSION: u16 = 1;

/// Noise pattern: mutual authentication with ephemeral keys, so both directions are forward secret.
const PARAMS: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";
/// A Noise transport message is at most 65 535 bytes including the 16-byte tag; each record is
/// prefixed with its own 2-byte length so a plaintext write of any size can be chunked.
const MAX_CHUNK: usize = 65_535 - 16 - 2;

/// The prologue both sides must agree on: transport version plus the chain they are on.
pub fn prologue(chain_id: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + 32);
    out.extend_from_slice(b"VESS-NOISE");
    out.extend_from_slice(&TRANSPORT_VERSION.to_be_bytes());
    out.extend_from_slice(chain_id);
    out
}

fn builder<'a>(static_key: &'a [u8; 32], prologue: &'a [u8]) -> Result<Builder<'a>, NetError> {
    let builder = Builder::new(
        PARAMS
            .parse()
            .map_err(|_| NetError::Protocol("noise params"))?,
    )
    .local_private_key(static_key)
    .map_err(|_| NetError::Protocol("noise key"))?;
    builder.prologue(prologue).map_err(noise_err)
}

fn noise_err(e: snow::Error) -> NetError {
    NetError::Protocol(match e {
        snow::Error::Decrypt => "noise: decrypt failed",
        snow::Error::Input => "noise: bad input",
        _ => "noise: handshake failed",
    })
}

/// An established, encrypted connection. Reads and writes are plaintext to the caller.
pub struct SecureStream {
    inner: TcpStream,
    state: TransportState,
    /// Decrypted bytes not yet consumed by the caller.
    plain: VecDeque<u8>,
    /// Plaintext waiting to be encrypted on the next flush.
    pending: Vec<u8>,
}

impl SecureStream {
    /// Dial a peer: run the handshake as the initiator, then return the session and whatever static
    /// key the peer proved it holds.
    pub fn connect(
        mut stream: TcpStream,
        static_key: &[u8; 32],
        chain_id: &[u8; 32],
    ) -> Result<(SecureStream, [u8; 32]), NetError> {
        let prologue = prologue(chain_id);
        let mut handshake =
            builder(static_key, &prologue).and_then(|b| b.build_initiator().map_err(noise_err))?;
        let peer = run_handshake(&mut stream, &mut handshake, true)?;
        Ok((SecureStream::finish(stream, handshake), peer))
    }

    /// Accept a peer: run the handshake as the responder.
    pub fn accept(
        mut stream: TcpStream,
        static_key: &[u8; 32],
        chain_id: &[u8; 32],
    ) -> Result<(SecureStream, [u8; 32]), NetError> {
        let prologue = prologue(chain_id);
        let mut handshake =
            builder(static_key, &prologue).and_then(|b| b.build_responder().map_err(noise_err))?;
        let peer = run_handshake(&mut stream, &mut handshake, false)?;
        Ok((SecureStream::finish(stream, handshake), peer))
    }

    fn finish(stream: TcpStream, handshake: HandshakeState) -> SecureStream {
        SecureStream {
            inner: stream,
            state: handshake
                .into_transport_mode()
                .expect("handshake completed"),
            plain: VecDeque::new(),
            pending: Vec::new(),
        }
    }

    /// The underlying socket, for addresses.
    pub fn get_ref(&self) -> &TcpStream {
        &self.inner
    }

    pub fn set_read_timeout(&self, millis: u64) -> std::io::Result<()> {
        self.inner
            .set_read_timeout(Some(std::time::Duration::from_millis(millis)))
    }

    fn encrypt_chunk(&mut self, chunk: &[u8]) -> std::io::Result<()> {
        let mut buf = vec![0u8; MAX_CHUNK + 16];
        let len = self
            .state
            .write_message(chunk, &mut buf)
            .map_err(|_| std::io::Error::other("noise encrypt"))?;
        self.inner
            .write_all(&u16::try_from(len).expect("chunk fits in u16").to_be_bytes())?;
        self.inner.write_all(&buf[..len])
    }

    fn write_records(&mut self) -> std::io::Result<()> {
        while !self.pending.is_empty() {
            let end = MAX_CHUNK.min(self.pending.len());
            let chunk: Vec<u8> = self.pending.drain(..end).collect();
            self.encrypt_chunk(&chunk)?;
        }
        Ok(())
    }

    fn read_record(&mut self) -> std::io::Result<()> {
        let mut len_bytes = [0u8; 2];
        self.inner.read_exact(&mut len_bytes)?;
        let len = usize::from(u16::from_be_bytes(len_bytes));
        let mut ciphertext = vec![0u8; len];
        self.inner.read_exact(&mut ciphertext)?;
        let mut plain = vec![0u8; len];
        let n = self
            .state
            .read_message(&ciphertext, &mut plain)
            .map_err(|_| std::io::Error::other("noise decrypt"))?;
        self.plain.extend(&plain[..n]);
        Ok(())
    }
}

impl Read for SecureStream {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        while self.plain.is_empty() {
            self.read_record()?;
        }
        let n = out.len().min(self.plain.len());
        for byte in out.iter_mut().take(n) {
            *byte = self.plain.pop_front().expect("non-empty");
        }
        Ok(n)
    }
}

impl Write for SecureStream {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        self.pending.extend_from_slice(data);
        // Encrypt eagerly once a whole record is buffered, so large bodies stream instead of
        // accumulating in memory.
        while self.pending.len() >= MAX_CHUNK {
            let chunk: Vec<u8> = self.pending.drain(..MAX_CHUNK).collect();
            self.encrypt_chunk(&chunk)?;
        }
        Ok(data.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.write_records()?;
        self.inner.flush()
    }
}

/// Drive the three-message XX handshake and return the peer's static key.
fn run_handshake(
    stream: &mut TcpStream,
    handshake: &mut HandshakeState,
    initiator: bool,
) -> Result<[u8; 32], NetError> {
    let mut buf = vec![0u8; 65_535];
    // -> e
    if initiator {
        let n = handshake.write_message(&[], &mut buf)?;
        stream.write_all(
            &u16::try_from(n)
                .expect("handshake message fits")
                .to_be_bytes(),
        )?;
        stream.write_all(&buf[..n])?;
    }
    // <- e, ee, s, es   (and for the responder, the first message is read first)
    if !initiator {
        let mut len = [0u8; 2];
        stream.read_exact(&mut len)?;
        let n = usize::from(u16::from_be_bytes(len));
        let mut msg = vec![0u8; n];
        stream.read_exact(&mut msg)?;
        handshake.read_message(&msg, &mut buf)?;
        let n = handshake.write_message(&[], &mut buf)?;
        stream.write_all(
            &u16::try_from(n)
                .expect("handshake message fits")
                .to_be_bytes(),
        )?;
        stream.write_all(&buf[..n])?;
    } else {
        let mut len = [0u8; 2];
        stream.read_exact(&mut len)?;
        let n = usize::from(u16::from_be_bytes(len));
        let mut msg = vec![0u8; n];
        stream.read_exact(&mut msg)?;
        handshake.read_message(&msg, &mut buf)?;
    }
    // -> s, se
    if initiator {
        let n = handshake.write_message(&[], &mut buf)?;
        stream.write_all(
            &u16::try_from(n)
                .expect("handshake message fits")
                .to_be_bytes(),
        )?;
        stream.write_all(&buf[..n])?;
    } else {
        let mut len = [0u8; 2];
        stream.read_exact(&mut len)?;
        let n = usize::from(u16::from_be_bytes(len));
        let mut msg = vec![0u8; n];
        stream.read_exact(&mut msg)?;
        handshake.read_message(&msg, &mut buf)?;
    }
    if !handshake.is_handshake_finished() {
        return Err(NetError::Protocol("noise: handshake incomplete"));
    }
    let remote = handshake
        .get_remote_static()
        .ok_or(NetError::Protocol("noise: no peer key"))?;
    let mut key = [0u8; 32];
    key.copy_from_slice(remote);
    Ok(key)
}

impl From<snow::Error> for NetError {
    fn from(e: snow::Error) -> Self {
        noise_err(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    fn chain() -> [u8; 32] {
        [7u8; 32]
    }

    fn pair() -> (SecureStream, SecureStream) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server_key = [1u8; 32];
        let client_key = [2u8; 32];
        let handle = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let (session, _) =
                SecureStream::accept(stream, &server_key, &chain()).expect("server handshake");
            session
        });
        let stream = TcpStream::connect(addr).unwrap();
        let (client, peer) =
            SecureStream::connect(stream, &client_key, &chain()).expect("client handshake");
        // X25519 public keys are derived from the secrets, so the peer key is not the secret.
        assert_ne!(peer, client_key);
        (client, handle.join().unwrap())
    }

    #[test]
    fn a_session_round_trips_and_hides_the_payload() {
        let (mut client, mut server) = pair();
        client.write_all(b"hello over noise").unwrap();
        client.flush().unwrap();
        let mut buf = [0u8; 16];
        server.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"hello over noise");

        // The other direction, and a body larger than one Noise record. The writer has to run
        // concurrently: 200 KB will not fit in a socket buffer, so writing and reading in one thread
        // would deadlock on the data structure under test rather than on the network.
        let big = vec![0xABu8; 200_000];
        let expected = big.clone();
        let writer = std::thread::spawn(move || {
            server.write_all(&big).unwrap();
            server.flush().unwrap();
        });
        let mut back = vec![0u8; expected.len()];
        client.read_exact(&mut back).unwrap();
        writer.join().unwrap();
        assert_eq!(back, expected);
    }

    /// Pinning relies on a peer's static key being stable, not on any particular value: the same
    /// secret must be seen as the same public key on every connection.
    #[test]
    fn the_peer_static_key_is_stable_across_connections() {
        let server_key = [9u8; 32];
        let mut seen_by_client = Vec::new();
        let mut seen_by_server = Vec::new();
        for _ in 0..2 {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = listener.local_addr().unwrap();
            let handle = std::thread::spawn(move || {
                let (stream, _) = listener.accept().unwrap();
                let (_, peer) =
                    SecureStream::accept(stream, &server_key, &chain()).expect("accept");
                peer
            });
            let stream = TcpStream::connect(addr).unwrap();
            let (_, seen) = SecureStream::connect(stream, &[3u8; 32], &chain()).expect("connect");
            seen_by_client.push(seen);
            seen_by_server.push(handle.join().unwrap());
        }
        assert_eq!(seen_by_client[0], seen_by_client[1]);
        assert_eq!(seen_by_server[0], seen_by_server[1]);
        assert_ne!(
            seen_by_client[0], seen_by_server[0],
            "each side must report the other's key"
        );
    }

    #[test]
    fn a_different_chain_fails_the_handshake() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            SecureStream::accept(stream, &[1u8; 32], &[1u8; 32]).is_err()
        });
        let stream = TcpStream::connect(addr).unwrap();
        assert!(SecureStream::connect(stream, &[2u8; 32], &[2u8; 32]).is_err());
        assert!(handle.join().unwrap(), "the server must reject too");
    }
}
