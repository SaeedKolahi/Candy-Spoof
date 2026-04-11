# Candy-Spoof

> **⚠️ EDUCATIONAL PURPOSES ONLY**
> This software is provided for educational, research, and authorized security testing purposes only. Users are responsible for ensuring compliance with all applicable laws and regulations in their jurisdiction. Unauthorized use of IP spoofing may be illegal and unethical. The authors assume no liability for misuse of this software.

**Candy-Spoof** is a bidirectional IP spoofing tunnel designed for use in heavily censored networks. Both the client and server forge their source IP addresses, making traffic analysis and blocking significantly harder.

## Features

| Feature | Description |
|---------|-------------|
| Mutual IP spoofing | Both client and server use fake source addresses |
| Spoofed-IP pools | Rotate source addresses per session for better evasion |
| Data channel | Spoofed UDP with configurable port |
| Control channel | Spoofed ICMP Echo Request/Reply (looks like ping traffic) |
| Transport mode | Best-effort low-latency forwarding (no ARQ / no congestion control) |
| Stream multiplexing | SMUX-style framed multiplexing of many proxy streams over shared transport lanes |
| SOCKS5 proxy | Local proxy on port 1080 – route any app through the tunnel |
| Whitelist validation | Packets from unknown IPs are silently dropped |
| Dynamic parallel tunnels | Runtime scales active lanes from 1 up to `tunnel_count` as concurrent streams increase |
| Pre-shared key | Optional PSK for packet authentication |

## Prerequisites

- **Operating System**: Linux (requires raw socket support)
- **Permissions**: `CAP_NET_RAW` capability or root access
- **Compiler**: Rust 1.70 or later (edition 2021)

## Building from Source

Build the project using Cargo:

```bash
cargo build --release
```

The compiled binaries will be available at:
- Client: `target/release/client`
- Server: `target/release/server`

## Usage

### Running the Server

Start the server with the configuration file:

```bash
sudo ./target/release/server --config config/server.toml
```

Or during development:

```bash
sudo cargo run --bin server -- --config config/server.toml
```

### Running the Client

Start the client with the configuration file:

```bash
sudo ./target/release/client --config config/client.toml
```

After starting the client, configure your applications (browser, curl, etc.) to use the SOCKS5 proxy at `127.0.0.1:1080`.

## Configuration

| Field | Where | Description |
|-------|-------|-------------|
| `real_ip` | both | Your machine's actual IPv4 address |
| `peer_real_ip` | both | The peer's actual IPv4 address |
| `spoofed_ip` | both | The fake source IP for outgoing packets |
| `peer_spoofed_ip` | both | The fake source IP the peer uses |
| `spoofed_ip_pool` | both | Optional pool of source IPs to rotate |
| `data_port` | both | UDP port for the data channel (must match) |
| `icmp_id` | both | ICMP echo identifier (must match) |
| `pre_shared_key` | both | Secret for packet authentication (must match) |
| `allowed_peers` | both | Extra IPs to whitelist |
| `interface` | both | Network interface (e.g. `eth0`) |
| `socks5_port` | client | Local SOCKS5 proxy port (default `1080`) |
| `tunnel_count` | both | Max dynamic parallel lanes used by smux transport (default `4`) |
| `mtu` | both | Max payload bytes per packet (default `1380`) |

**Note**: Both client and server configurations must match on critical fields like `data_port`, `icmp_id`, and `pre_shared_key` for the tunnel to work properly.

Refer to `config/client.toml` and `config/server.toml` for complete configuration examples.

## How It Works

```
[Application]
     │  TCP (SOCKS5 CONNECT)
     ▼
[SOCKS5 Proxy – 127.0.0.1:1080]
     │  Candy-Spoof data (best-effort)
     ▼
[Raw UDP – src=spoofed_client_ip  dst=real_server_ip]
─── censored network ──────────────────────────────────
[Tunnel Manager – server demultiplexes by tunnel_id]
     │  TCP
     ▼
[Target Server]
     │
     ▼
[Raw UDP – src=spoofed_server_ip  dst=real_client_ip]
─── censored network ──────────────────────────────────
[Application receives response]
```

**Control Channel**: Control packets (SYN, SYN-ACK, Heartbeat) use ICMP Echo Request/Reply messages to blend with ordinary ping traffic, making detection more difficult.

## Transport Behavior

- **Best-effort forwarding** – data frames are forwarded without ARQ retransmission or congestion-window gating.
- **Low latency bias** – avoids ACK/NACK/timeout-based backpressure in the data path.

## Security Considerations

- **Minimize privileges**: Use `CAP_NET_RAW` capability instead of running as full root when possible
- **Protect credentials**: Keep `pre_shared_key` secret and rotate it regularly
- **Choose spoofed IPs carefully**: Use globally routable addresses that are not yours; CDN or public DNS addresses help blend traffic patterns
- **Be aware of limitations**: Ingress filtering (BCP 38) on upstream routers may block packets with spoofed source addresses
- **Legal compliance**: Ensure you have authorization to use this tool in your network environment

## Performance Tips

- Increase `tunnel_count` to allow more dynamic parallel transport lanes on busy links.
- Tune `mtu` to match path MTU (`tracepath` helps).
- Use a `spoofed_ip_pool` of 3–5 addresses to distribute traffic patterns.

## License

MIT
