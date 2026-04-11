//! Candy-Spoof **server** binary.
//!
//! Listens for incoming tunnel connections from clients and forwards each
//! SOCKS5 CONNECT session to the requested TCP destination.
//!
//! Usage:
//!   cargo run --bin server -- --config config/server.toml

use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use clap::Parser;

use candy_spoof::config::Config;
use candy_spoof::raw_socket::{RawReceiver, RawSender};
use candy_spoof::smux::SmuxServer;
use candy_spoof::tunnel::{PeerAddr, TunnelManager};

#[derive(Parser, Debug)]
#[command(name = "server", about = "Candy-Spoof server (tunnel endpoint)")]
struct Args {
    /// Path to the TOML configuration file.
    #[arg(short, long, default_value = "config/server.toml")]
    config: String,

    /// Override log level.
    #[arg(short, long)]
    log_level: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let level = args.log_level.as_deref().unwrap_or("info");
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(level)).init();

    let cfg = Arc::new(Config::from_file(&args.config)?);

    log::info!(
        "Candy-Spoof server starting | real={} spoof={} peer={}",
        cfg.real_ip,
        cfg.spoofed_ip,
        cfg.peer_real_ip
    );

    let sender = RawSender::spawn()?;

    let mut allowed = cfg.allowed_peers.clone();
    allowed.push(cfg.peer_real_ip);
    allowed.push(cfg.peer_spoofed_ip);
    let mut receiver = RawReceiver::spawn(cfg.data_port, cfg.icmp_id, allowed)?;

    let peer_addr = PeerAddr {
        local_spoof: cfg.pick_spoofed_ip(),
        peer_real:   cfg.peer_real_ip,
        data_port:   cfg.data_port,
        icmp_id:     cfg.icmp_id,
        is_server:   true,
    };
    let manager = TunnelManager::new(sender, peer_addr, cfg.clone());
    let smux = SmuxServer::new(cfg.clone(), manager.clone()).await?;

    // ── Periodic housekeeping ────────────────────────────────────────────────
    let mgr_tick = manager.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_millis(100));
        loop {
            interval.tick().await;
            if let Err(e) = mgr_tick.tick().await {
                log::warn!("tick: {}", e);
            }
        }
    });

    // ── Main receive loop ────────────────────────────────────────────────────
    loop {
        let incoming = match receiver.recv().await {
            Some(p) => p,
            None    => break,
        };

        if !cfg.is_peer_allowed(&incoming.src_ip) {
            log::trace!("dropping packet from disallowed IP {}", incoming.src_ip);
            continue;
        }

        match manager
            .handle_incoming(incoming.src_ip, incoming.pkt)
            .await
        {
            Ok(Some((syn_pkt, src_ip))) => {
                // New tunnel request – accept it and spawn a session handler.
                let smux2 = smux.clone();
                tokio::spawn(async move {
                    if let Err(e) = smux2.attach_syn(syn_pkt, src_ip).await {
                        log::warn!("session error: {}", e);
                    }
                });
            }
            Ok(None) => {}
            Err(e) => log::warn!("handle_incoming: {}", e),
        }
    }

    Ok(())
}
