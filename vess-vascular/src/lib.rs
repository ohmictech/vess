//! **vess-vascular** — QUIC transport layer for the Vess protocol.
//!
//! Wraps an Iroh endpoint with length-prefixed message framing over
//! QUIC bistreams. Supports both fire-and-forget and request/response
//! patterns. ALPN: `vess/pulse/0`.

use std::sync::Arc;

use anyhow::{Context, Result};
use iroh::endpoint::{Connection, ConnectionState, Incoming, presets};
use iroh::{Endpoint, EndpointAddr, EndpointId};
use iroh::address_lookup::mdns::MdnsAddressLookup;
use tracing::{info, warn};
use vess_protocol::PulseMessage;

/// ALPN protocol identifier for Vess Pulse exchange.
pub const VESS_ALPN: &[u8] = b"vess/pulse/0";

/// Maximum size of a single Pulse payload (16 MiB).
///
/// OwnershipGenesis messages carry STARK proofs with 80 Merkle-path
/// query openings; a SampledAggregateProof is ~14 MiB constant.
const MAX_PULSE_SIZE: usize = 16 * 1024 * 1024;

/// A Vess network node backed by an Iroh QUIC endpoint.
///
/// Supports both fire-and-forget and request/response messaging patterns
/// over length-prefixed QUIC bistreams.
#[derive(Clone)]
pub struct VessNode {
    endpoint: Endpoint,
}

impl VessNode {
    /// Spawns a new node, binding to an OS-assigned port with the N0 relay preset.
    /// Enables mDNS for LAN peer discovery (works without internet).
    pub async fn spawn() -> Result<Self> {
        let endpoint = Endpoint::builder(presets::N0)
            .address_lookup(MdnsAddressLookup::builder())
            .alpns(vec![VESS_ALPN.to_vec()])
            .bind()
            .await
            .context("failed to bind iroh endpoint")?;

        let id = endpoint.id();
        info!(%id, "vess node online");

        Ok(Self { endpoint })
    }

    /// Returns this node's endpoint ID (public key).
    pub fn id(&self) -> EndpointId {
        self.endpoint.id()
    }

    /// Returns the full endpoint address for sharing with peers.
    pub fn addr(&self) -> EndpointAddr {
        self.endpoint.addr()
    }

    /// Waits until the node has connected to at least one relay server and is
    /// reachable for incoming connections through NAT traversal.
    pub async fn wait_online(&self) {
        self.endpoint.online().await;
    }

    /// Sends a binary Pulse to a remote peer. Ignores any response.
    pub async fn send_pulse(
        &self,
        target: impl Into<EndpointAddr>,
        payload: &[u8],
    ) -> Result<()> {
        self.send_pulse_with_response(target, payload).await?;
        Ok(())
    }

    /// Sends a binary Pulse and returns the peer's response bytes.
    ///
    /// Returns an empty `Vec` if the peer acknowledged without a response.
    pub async fn send_pulse_with_response(
        &self,
        target: impl Into<EndpointAddr>,
        payload: &[u8],
    ) -> Result<Vec<u8>> {
        let conn = self
            .endpoint
            .connect(target, VESS_ALPN)
            .await
            .context("connect to peer")?;

        write_pulse(&conn, payload).await
    }

    /// Sends a Pulse using 0-RTT if a cached session ticket is available.
    ///
    /// Falls back to a full handshake when no ticket exists (first connection).
    /// **Warning:** 0-RTT data is vulnerable to replay attacks — only use for
    /// idempotent operations like tag lookups.
    pub async fn send_pulse_0rtt(
        &self,
        target: impl Into<EndpointAddr>,
        payload: &[u8],
    ) -> Result<()> {
        use iroh::endpoint::ConnectOptions;

        let connecting = self
            .endpoint
            .connect_with_opts(target, VESS_ALPN, ConnectOptions::default())
            .await
            .context("start 0-RTT connection")?;

        match connecting.into_0rtt() {
            Ok(conn) => {
                info!("0-RTT handshake succeeded");
                write_pulse(&conn, payload).await?;
                Ok(())
            }
            Err(connecting) => {
                info!("0-RTT unavailable, performing full handshake");
                let conn = connecting.await.context("full handshake failed")?;
                write_pulse(&conn, payload).await?;
                Ok(())
            }
        }
    }

    /// Listens for incoming Pulses indefinitely (fire-and-forget).
    ///
    /// `on_pulse` is invoked for every successfully received Pulse with the
    /// sender's [`EndpointId`] and the raw payload bytes.
    pub async fn listen(
        &self,
        on_pulse: impl Fn(EndpointId, Vec<u8>) + Send + Sync + 'static,
    ) -> Result<()> {
        self.listen_with_response(move |peer, payload| {
            on_pulse(peer, payload);
            Vec::new()
        })
        .await
    }

    /// Listens for incoming Pulses with response capability.
    ///
    /// The callback returns response bytes to send back to the sender.
    /// Return an empty `Vec` for a simple acknowledgement with no data.
    pub async fn listen_with_response(
        &self,
        on_pulse: impl Fn(EndpointId, Vec<u8>) -> Vec<u8> + Send + Sync + 'static,
    ) -> Result<()> {
        let handler = Arc::new(on_pulse);
        info!("listening for pulses");

        loop {
            let incoming = self
                .endpoint
                .accept()
                .await
                .context("endpoint closed")?;

            let h = handler.clone();
            tokio::spawn(async move {
                if let Err(e) = handle_incoming(incoming, h).await {
                    warn!(error = %e, "failed to handle incoming pulse");
                }
            });
        }
    }

    /// Gracefully shuts down the endpoint.
    pub async fn shutdown(&self) {
        self.endpoint.close().await;
    }

    // ── Typed pulse methods (protocol-level) ───────────────────

    /// Send a typed [`PulseMessage`] to a remote peer. Ignores response.
    pub async fn send_message(
        &self,
        target: impl Into<EndpointAddr>,
        msg: &PulseMessage,
    ) -> Result<()> {
        self.send_message_with_response(target, msg).await?;
        Ok(())
    }

    /// Send a typed [`PulseMessage`] and receive a typed response.
    ///
    /// Returns `None` if the peer acknowledged without a response payload.
    pub async fn send_message_with_response(
        &self,
        target: impl Into<EndpointAddr>,
        msg: &PulseMessage,
    ) -> Result<Option<PulseMessage>> {
        let bytes = msg.to_bytes().context("serialize PulseMessage")?;
        let response = self.send_pulse_with_response(target, &bytes).await?;
        if response.is_empty() {
            return Ok(None);
        }
        let resp_msg = PulseMessage::from_bytes(&response)
            .context("deserialize response PulseMessage")?;
        Ok(Some(resp_msg))
    }

    /// Send multiple [`PulseMessage`]s to the same peer over a single QUIC
    /// connection, multiplexing on separate bistreams.
    ///
    /// Opens one connection and reuses it for all messages, avoiding
    /// per-message handshake overhead.  Errors on individual messages are
    /// logged but do not abort the batch.
    pub async fn send_messages_to_peer(
        &self,
        target: impl Into<EndpointAddr>,
        msgs: &[PulseMessage],
    ) -> Result<()> {
        if msgs.is_empty() {
            return Ok(());
        }
        let conn = self
            .endpoint
            .connect(target, VESS_ALPN)
            .await
            .context("connect to peer for batch send")?;

        for msg in msgs {
            let bytes = match msg.to_bytes() {
                Ok(b) => b,
                Err(e) => {
                    warn!(error = %e, "failed to serialize batch message, skipping");
                    continue;
                }
            };
            if let Err(e) = write_pulse(&conn, &bytes).await {
                warn!(error = %e, "batch send: message failed, continuing");
            }
        }
        Ok(())
    }

    /// Listen for incoming [`PulseMessage`]s (fire-and-forget).
    ///
    /// Deserializes each raw pulse into a typed message before invoking
    /// the callback. Invalid messages are logged and skipped.
    pub async fn listen_messages(
        &self,
        on_message: impl Fn(EndpointId, PulseMessage) + Send + Sync + 'static,
    ) -> Result<()> {
        self.listen(move |peer, payload| {
            match PulseMessage::from_bytes(&payload) {
                Ok(msg) => on_message(peer, msg),
                Err(e) => warn!(%peer, error = %e, "invalid pulse message"),
            }
        })
        .await
    }

    /// Listen for incoming [`PulseMessage`]s with response capability.
    ///
    /// The callback may return a response message to send back to the sender.
    /// Return `None` for a simple acknowledgement.
    pub async fn listen_messages_with_response(
        &self,
        on_message: impl Fn(EndpointId, PulseMessage) -> Option<PulseMessage> + Send + Sync + 'static,
    ) -> Result<()> {
        self.listen_with_response(move |peer, payload| {
            match PulseMessage::from_bytes(&payload) {
                Ok(msg) => match on_message(peer, msg) {
                    Some(resp) => resp.to_bytes().unwrap_or_default(),
                    None => Vec::new(),
                },
                Err(e) => {
                    warn!(%peer, error = %e, "invalid pulse message");
                    Vec::new()
                }
            }
        })
        .await
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Writes a length-prefixed Pulse and reads back a length-prefixed response.
///
/// Wire format:
///   Request:  `[u32 BE payload_len][payload bytes]`
///   Response: `[u32 BE response_len][response bytes]`
///   (response_len = 0 means acknowledged, no data)
async fn write_pulse<S: ConnectionState>(
    conn: &Connection<S>,
    payload: &[u8],
) -> Result<Vec<u8>> {
    let (mut tx, mut rx) = conn.open_bi().await.context("open bi stream")?;

    // Length-prefixed framing: [u32 BE length][payload]
    let len = (payload.len() as u32).to_be_bytes();
    tx.write_all(&len).await.context("write length prefix")?;
    tx.write_all(payload).await.context("write payload")?;
    tx.finish().context("finish send stream")?;

    // Read length-prefixed response
    let mut resp_len_buf = [0u8; 4];
    rx.read_exact(&mut resp_len_buf)
        .await
        .context("read response length")?;
    let resp_len = u32::from_be_bytes(resp_len_buf) as usize;

    if resp_len == 0 {
        info!(bytes = payload.len(), "pulse acknowledged");
        return Ok(Vec::new());
    }

    anyhow::ensure!(
        resp_len <= MAX_PULSE_SIZE,
        "response too large: {resp_len} bytes"
    );

    let mut response = vec![0u8; resp_len];
    rx.read_exact(&mut response)
        .await
        .context("read response payload")?;

    info!(
        bytes = payload.len(),
        response_bytes = resp_len,
        "pulse delivered with response"
    );
    Ok(response)
}

/// Handles a single incoming connection: reads one Pulse, calls the handler,
/// sends a length-prefixed response back.
async fn handle_incoming(
    incoming: Incoming,
    on_pulse: Arc<dyn Fn(EndpointId, Vec<u8>) -> Vec<u8> + Send + Sync>,
) -> Result<()> {
    let conn = incoming.await.context("accept connection")?;
    let peer = conn.remote_id();

    let (mut tx, mut rx) = conn.accept_bi().await.context("accept bi stream")?;

    // Read length prefix
    let mut len_buf = [0u8; 4];
    rx.read_exact(&mut len_buf).await.context("read length")?;
    let len = u32::from_be_bytes(len_buf) as usize;
    anyhow::ensure!(len <= MAX_PULSE_SIZE, "pulse too large: {len} bytes");

    // Read payload
    let mut payload = vec![0u8; len];
    rx.read_exact(&mut payload).await.context("read payload")?;

    info!(%peer, bytes = len, "pulse received");
    let response = on_pulse(peer, payload);

    // Send length-prefixed response
    let resp_len = (response.len() as u32).to_be_bytes();
    tx.write_all(&resp_len)
        .await
        .context("write response length")?;
    if !response.is_empty() {
        tx.write_all(&response)
            .await
            .context("write response payload")?;
    }
    tx.finish().context("finish response stream")?;

    // Wait for the remote to signal it has finished reading by closing
    // its side. Without this, dropping `conn` sends CONNECTION_CLOSE
    // which can preempt in-flight stream data on the wire.
    let _ = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        conn.closed(),
    )
    .await;

    Ok(())
}
