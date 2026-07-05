//! Vess rendezvous server — UDP-based peer introduction for NAT hole punching.
//!
//! Peers register their observed address, then request introductions to
//! other peers by node ID.  The server coordinates simultaneous outbound
//! packets (PunchRequest → PunchReady + PunchNotify) to create NAT bindings
//! on both sides, enabling direct peer-to-peer UDP communication.
//!
//! Usage:
//!   vess-rendezvous --bind 0.0.0.0:9445

use anyhow::Context;
use clap::Parser;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

#[derive(Parser)]
#[command(name = "vess-rendezvous", about = "Vess mesh rendezvous server for NAT hole punching")]
struct Args {
    /// UDP address to bind (default: 0.0.0.0:9445).
    #[arg(long, default_value = "0.0.0.0:9445")]
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

    tracing::info!(%bind_addr, "starting Vess rendezvous server");

    let rendezvous = vess_mesh::MeshRendezvousServer::bind(bind_addr).await?;
    rendezvous.run().await?;

    Ok(())
}
