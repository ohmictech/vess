//! **vess-vascular** — Mesh pulse transport facade for the Vess protocol.
//!
//! Exposes the active PQ mesh-backed pulse node used by the artery runtime
//! and CLI flows.

use std::sync::Arc;
use std::{
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    time::Duration,
};

use anyhow::{anyhow, Context, Result};
use rand::RngCore;
use tracing::warn;
use vess_mesh::{MeshCarrier, MeshCarrierContact, MeshNodeId, MeshPeer, PqUdpMeshCarrier};
use vess_protocol::PulseMessage;

const MESH_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Vess pulse node backed by the PQ mesh carrier.
#[derive(Clone)]
pub struct MeshPulseNode {
    carrier: PqUdpMeshCarrier,
}

impl MeshPulseNode {
    /// Bind a PQ mesh-backed pulse node from a deterministic seed.
    pub async fn bind_from_seed(
        bind_addr: SocketAddr,
        seed: &[u8; 64],
        epoch: u64,
    ) -> Result<Self> {
        let carrier = PqUdpMeshCarrier::bind_from_seed(bind_addr, seed, epoch).await?;
        Ok(Self { carrier })
    }

    /// Spawn a local PQ mesh-backed pulse node with a random seed.
    pub async fn spawn() -> Result<Self> {
        let mut seed = [0u8; 64];
        rand::thread_rng().fill_bytes(&mut seed);
        Self::bind_from_seed(
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)),
            &seed,
            0,
        )
        .await
    }

    pub fn id(&self) -> MeshNodeId {
        self.carrier.mesh_address().node_id
    }

    pub fn contact(&self) -> MeshCarrierContact {
        self.carrier.local_contact()
    }

    pub async fn send_message(
        &self,
        target: &MeshCarrierContact,
        msg: &PulseMessage,
    ) -> Result<()> {
        self.send_message_with_response(target, msg).await?;
        Ok(())
    }

    pub async fn wait_online(&self) {
        self.carrier.wait_online().await;
    }

    pub async fn shutdown(&self) {}

    pub async fn register_with_rendezvous(
        &self,
        rendezvous_addr: SocketAddr,
    ) -> Result<SocketAddr> {
        tokio::time::timeout(
            MESH_REQUEST_TIMEOUT,
            self.carrier.register_with_rendezvous(rendezvous_addr),
        )
        .await
        .map_err(|_| anyhow!("mesh rendezvous registration timed out"))?
    }

    pub async fn register_with_relay(&self, relay_addr: SocketAddr) -> Result<SocketAddr> {
        tokio::time::timeout(
            MESH_REQUEST_TIMEOUT,
            self.carrier.register_with_relay(relay_addr),
        )
        .await
        .map_err(|_| anyhow!("mesh relay registration timed out"))?
    }

    pub async fn send_message_with_response(
        &self,
        target: &MeshCarrierContact,
        msg: &PulseMessage,
    ) -> Result<Option<PulseMessage>> {
        let bytes = msg.to_bytes().context("serialize PulseMessage")?;
        let response = tokio::time::timeout(
            MESH_REQUEST_TIMEOUT,
            self.carrier.send_with_response(target, &bytes),
        )
        .await
        .map_err(|_| anyhow!("mesh request timed out"))??;
        if response.is_empty() {
            return Ok(None);
        }
        let resp_msg =
            PulseMessage::from_bytes(&response).context("deserialize response PulseMessage")?;
        Ok(Some(resp_msg))
    }

    pub async fn send_message_with_response_via_rendezvous(
        &self,
        rendezvous_addr: SocketAddr,
        target_node_id: MeshNodeId,
        msg: &PulseMessage,
    ) -> Result<Option<PulseMessage>> {
        let bytes = msg.to_bytes().context("serialize PulseMessage")?;
        let response = tokio::time::timeout(
            MESH_REQUEST_TIMEOUT,
            self.carrier
                .send_with_response_via_rendezvous(rendezvous_addr, target_node_id, &bytes),
        )
        .await
        .map_err(|_| anyhow!("mesh rendezvous request timed out"))??;
        if response.is_empty() {
            return Ok(None);
        }
        let resp_msg =
            PulseMessage::from_bytes(&response).context("deserialize response PulseMessage")?;
        Ok(Some(resp_msg))
    }

    pub async fn send_message_with_response_via_relay(
        &self,
        relay_addr: SocketAddr,
        target: &MeshCarrierContact,
        msg: &PulseMessage,
    ) -> Result<Option<PulseMessage>> {
        let bytes = msg.to_bytes().context("serialize PulseMessage")?;
        let response = tokio::time::timeout(
            MESH_REQUEST_TIMEOUT,
            self.carrier
                .send_with_response_via_relay(relay_addr, target, &bytes),
        )
        .await
        .map_err(|_| anyhow!("mesh relay request timed out"))??;
        if response.is_empty() {
            return Ok(None);
        }
        let resp_msg =
            PulseMessage::from_bytes(&response).context("deserialize response PulseMessage")?;
        Ok(Some(resp_msg))
    }

    pub async fn send_raw_pulses_to_peer(
        &self,
        target: &MeshCarrierContact,
        payloads: &[Arc<Vec<u8>>],
    ) -> Result<()> {
        for payload in payloads {
            let _ = tokio::time::timeout(
                MESH_REQUEST_TIMEOUT,
                self.carrier.send_with_response(target, payload.as_slice()),
            )
            .await
            .map_err(|_| anyhow!("mesh raw pulse send timed out"))??;
        }
        Ok(())
    }

    pub async fn listen_messages_with_response(
        &self,
        on_message: impl Fn(MeshPeer, PulseMessage) -> Option<PulseMessage> + Send + Sync + 'static,
    ) -> Result<()> {
        self.carrier
            .listen_with_response(
                move |peer, payload| match PulseMessage::from_bytes(&payload) {
                    Ok(msg) => match on_message(peer, msg) {
                        Some(resp) => resp.to_bytes().unwrap_or_default(),
                        None => Vec::new(),
                    },
                    Err(error) => {
                        warn!(error = %error, "invalid mesh pulse message");
                        Vec::new()
                    }
                },
            )
            .await
    }
}
