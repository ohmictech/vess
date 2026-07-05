//! Vess relay server — transparent UDP packet forwarding for NAT traversal.
//!
//! Peers behind symmetric NATs that can't hole-punch register with this
//! server, which forwards their traffic transparently as Forward/Deliver
//! envelopes.  All payloads (including route handshakes) are end-to-end
//! encrypted — the relay never sees plaintext.
//!
//! Usage:
//!   vess-relay --bind 0.0.0.0:9446

use anyhow::Context;
use clap::Parser;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

#[derive(Parser)]
#[command(name = "vess-relay", about = "Vess mesh relay server for NAT traversal")]
struct Args {
    /// UDP address to bind (default: 0.0.0.0:9446).
    #[arg(long, default_value = "0.0.0.0:9446")]
    bind: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .init();

    let args = Args::parse();
    let bind_addr: std::net::SocketAddr = args.bind.parse().context("invalid --bind address")?;

    tracing::info!(%bind_addr, "starting Vess relay server");

    let relay = vess_mesh::MeshRelayServer::bind(bind_addr).await?;
    relay.run().await?;

    Ok(())
}
