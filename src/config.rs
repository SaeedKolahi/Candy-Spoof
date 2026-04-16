//! Configuration types for Candy-Spoof.
//!
//! Both client and server share this configuration schema. Load with
//! `Config::from_file("config/client.toml")`.

use std::net::Ipv4Addr;
use serde::Deserialize;

/// Top-level configuration loaded from a TOML file.
#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    /// The real (physical) IPv4 address of this node.
    pub real_ip: Ipv4Addr,

    /// The real IPv4 address of the remote peer.
    pub peer_real_ip: Ipv4Addr,

    /// The spoofed source IP this node puts in outgoing packets.
    pub spoofed_ip: Ipv4Addr,

    /// The spoofed source IP the peer uses (expected in incoming packets).
    pub peer_spoofed_ip: Ipv4Addr,

    /// If false, outbound packets are sent with the real source IP (kernel-chosen),
    /// instead of spoofing `spoofed_ip`. Useful for asymmetric deployments where
    /// only one side can spoof and the other must use a backchannel.
    #[serde(default)]
    pub spoof_outbound: bool,

    /// Optional pool of spoofed IPs for rotation.  If empty, `spoofed_ip` is
    /// always used.
    #[serde(default)]
    pub spoofed_ip_pool: Vec<Ipv4Addr>,

    /// UDP destination port used for the data channel.
    pub data_port: u16,

    /// ICMP echo identifier used to distinguish Candy-Spoof control packets
    /// from regular ping traffic.
    pub icmp_id: u16,

    /// Whitelist of peer real IPs whose packets are accepted. In addition to
    /// `peer_real_ip`, any address in this list is trusted.
    #[serde(default)]
    pub allowed_peers: Vec<Ipv4Addr>,

    /// Number of independent parallel tunnels to maintain.
    #[serde(default = "default_tunnel_count")]
    pub tunnel_count: usize,

    /// Pre-shared key (hex string) used to authenticate packets.  Both sides
    /// must share the same key.
    pub pre_shared_key: String,

    /// Network interface name to bind raw sockets to (e.g. "eth0", "ens3").
    pub interface: String,

    /// Port for the local SOCKS5 proxy (client only, ignored on server).
    #[serde(default = "default_socks5_port")]
    pub socks5_port: u16,

    /// Maximum payload size per tunnel packet (bytes, default 1380).
    #[serde(default = "default_mtu")]
    pub mtu: usize,

    /// Initial congestion window in packets.
    #[serde(default = "default_cwnd")]
    pub initial_cwnd: f64,
}

fn default_tunnel_count() -> usize { 4 }
fn default_socks5_port() -> u16 { 1080 }
fn default_mtu() -> usize { 1380 }
fn default_cwnd() -> f64 { 10.0 }
impl Config {
    /// Load configuration from a TOML file.
    pub fn from_file(path: &str) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("Cannot read config '{}': {}", path, e))?;
        toml::from_str(&content)
            .map_err(|e| anyhow::anyhow!("Invalid config '{}': {}", path, e))
    }

    /// Returns true if `ip` is a trusted peer address.
    pub fn is_peer_allowed(&self, ip: &Ipv4Addr) -> bool {
        *ip == self.peer_real_ip
            || *ip == self.peer_spoofed_ip
            || self.allowed_peers.contains(ip)
    }

    /// Pick a (possibly random) spoofed source IP from the configured pool.
    /// Falls back to `spoofed_ip` when the pool is empty.
    pub fn pick_spoofed_ip(&self) -> Ipv4Addr {
        if self.spoofed_ip_pool.is_empty() {
            return self.spoofed_ip;
        }
        use rand::seq::SliceRandom;
        *self
            .spoofed_ip_pool
            .choose(&mut rand::thread_rng())
            .unwrap_or(&self.spoofed_ip)
    }

    /// Pick the source IP to use for outbound traffic, depending on
    /// `spoof_outbound`.
    pub fn pick_source_ip(&self) -> Ipv4Addr {
        if !self.spoof_outbound {
            self.real_ip
        } else {
            self.pick_spoofed_ip()
        }
    }
}
