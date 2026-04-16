# Asymmetric Deployment

This directory contains an interactive installer for the asymmetric deployment
mode used when only one side can spoof packets and the other side must send its
outbound traffic through a normal-IP backchannel such as Xray.

## What this installer does

- Prompts for the role: `iran-client` or `kharej-server`
- Prompts for the required IPs, interface, ports, PSK, and install paths
- Generates the Candy config file with clear prompts
- Sets `spoof_outbound = false` automatically for the Iran/Xray side
- Optionally generates an Xray backchannel config on the Iran side
- Writes a systemd service for the selected role

## Typical usage

Copy the repository to the target Linux server, then run:

```bash
chmod +x deploy/asym/setup-interactive.sh
sudo ./deploy/asym/setup-interactive.sh
```

The script will explain each value before asking for it.

## Notes

- This installer is for Linux hosts.
- `spoof_outbound` is not enabled by default in the main sample configs. The
  interactive installer sets it only when you explicitly choose the asymmetric
  Xray-backed client mode.
- If your Xray/VLESS egress IP changes over time, make sure the server-side
  `allowed_peers` includes the currently observed egress IP.
