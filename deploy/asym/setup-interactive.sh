#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BINARY_DIR="/opt/candy/bin"
CONFIG_DIR="/opt/candy/config"

require_root() {
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    echo "This installer must run as root."
    echo "Please run: sudo bash deploy/asym/setup-interactive.sh"
    exit 1
  fi
}

have_cmd() {
  command -v "$1" >/dev/null 2>&1
}

prompt() {
  local var_name="$1"
  local label="$2"
  local default_value="${3:-}"
  local answer=""
  if [[ -n "$default_value" ]]; then
    read -r -p "$label [$default_value]: " answer
    answer="${answer:-$default_value}"
  else
    read -r -p "$label: " answer
  fi
  printf -v "$var_name" '%s' "$answer"
}

prompt_required() {
  local var_name="$1"
  local label="$2"
  local answer=""
  while [[ -z "$answer" ]]; do
    read -r -p "$label: " answer
  done
  printf -v "$var_name" '%s' "$answer"
}

yes_no() {
  local var_name="$1"
  local label="$2"
  local default_value="${3:-y}"
  local answer=""
  read -r -p "$label [${default_value}]: " answer
  answer="${answer:-$default_value}"
  case "${answer,,}" in
    y|yes) printf -v "$var_name" '%s' "yes" ;;
    *) printf -v "$var_name" '%s' "no" ;;
  esac
}

get_effective_user() {
  if [[ -n "${SUDO_USER:-}" ]] && [[ "$SUDO_USER" != "root" ]]; then
    echo "$SUDO_USER"
  else
    echo "root"
  fi
}

install_dependencies() {
  if have_cmd cargo; then
    return
  fi

  if have_cmd apt-get; then
    apt-get update
    apt-get install -y build-essential pkg-config libssl-dev curl ca-certificates libcap2-bin python3 iproute2
  elif have_cmd dnf; then
    dnf install -y gcc gcc-c++ make pkgconf-pkg-config openssl-devel curl ca-certificates libcap python3 iproute
  else
    echo "No supported package manager found for automatic dependency install."
    echo "Please install Rust/cargo manually and rerun."
    exit 1
  fi

  if ! have_cmd cargo; then
    su - "$(get_effective_user)" -c 'curl https://sh.rustup.rs -sSf | sh -s -- -y'
  fi
}

build_and_install_binaries() {
  mkdir -p "$BINARY_DIR" "$CONFIG_DIR"

  local user_name
  user_name="$(get_effective_user)"
  local user_home
  user_home="$(eval echo "~$user_name")"
  local cargo_bin="$user_home/.cargo/bin/cargo"

  if [[ -x "$cargo_bin" ]]; then
    su - "$user_name" -c "cd \"$PROJECT_DIR\" && \"$cargo_bin\" build --release"
  elif have_cmd cargo; then
    su - "$user_name" -c "cd \"$PROJECT_DIR\" && cargo build --release"
  else
    echo "cargo not found after dependency installation."
    exit 1
  fi

  cp "$PROJECT_DIR/target/release/server" "$BINARY_DIR/server"
  cp "$PROJECT_DIR/target/release/client" "$BINARY_DIR/client"
  chmod +x "$BINARY_DIR/server" "$BINARY_DIR/client"
}

set_caps_if_possible() {
  if have_cmd setcap; then
    setcap cap_net_raw+ep "$BINARY_DIR/server" || true
    setcap cap_net_raw+ep "$BINARY_DIR/client" || true
  fi
}

autodetect_real_ip_and_interface() {
  local route_line=""
  route_line="$(ip -4 route get 1.1.1.1 2>/dev/null | tr -s ' ' || true)"

  REAL_IP=""
  INTERFACE=""
  if [[ -n "$route_line" ]]; then
    REAL_IP="$(awk '{for (i=1;i<=NF;i++) if ($i=="src") {print $(i+1); exit}}' <<<"$route_line")"
    INTERFACE="$(awk '{for (i=1;i<=NF;i++) if ($i=="dev") {print $(i+1); exit}}' <<<"$route_line")"
  fi

  if [[ -z "$REAL_IP" ]]; then
    prompt_required REAL_IP "This machine real IPv4"
  fi
  if [[ -z "$INTERFACE" ]]; then
    prompt_required INTERFACE "Network interface name"
  fi
}

extract_xray_outbound() {
  local source_path="$1"
  local result_json="$2"
  python3 - "$source_path" "$result_json" <<'PY'
import json
import sys

source_path = sys.argv[1]
result_path = sys.argv[2]

with open(source_path, "r", encoding="utf-8") as f:
    cfg = json.load(f)

outbounds = cfg.get("outbounds", [])
if not isinstance(outbounds, list):
    raise SystemExit("Invalid Xray config: outbounds must be a list")

selected = None
for ob in outbounds:
    if ob.get("protocol") in ("vless", "vmess"):
        selected = ob
        break
if selected is None and outbounds:
    selected = outbounds[0]
if selected is None:
    raise SystemExit("No outbound found in Xray config")

protocol = selected.get("protocol", "")
settings = selected.get("settings", {})

address = ""
if protocol in ("vless", "vmess"):
    nodes = settings.get("vnext", [])
    if nodes:
        address = nodes[0].get("address", "")

if not address:
    servers = settings.get("servers", [])
    if servers:
        address = servers[0].get("address", "")

if not address:
    raise SystemExit("Cannot extract outbound remote address from Xray config")

result = {
    "peer_real_ip_or_host": address,
    "outbound": selected,
}

with open(result_path, "w", encoding="utf-8") as f:
    json.dump(result, f, ensure_ascii=False)
PY
}

write_xray_backchannel_config() {
  local target_path="$1"
  local source_result="$2"
  python3 - "$target_path" "$source_result" "$DATA_PORT" <<'PY'
import json
import sys

target_path = sys.argv[1]
result_path = sys.argv[2]
data_port = int(sys.argv[3])

with open(result_path, "r", encoding="utf-8") as f:
    parsed = json.load(f)

outbound = parsed["outbound"]
if "tag" not in outbound:
    outbound["tag"] = "proxy-out"

config = {
    "log": {"loglevel": "warning"},
    "inbounds": [
        {
            "tag": "udp-in",
            "listen": "127.0.0.1",
            "port": 15470,
            "protocol": "dokodemo-door",
            "settings": {
                "address": parsed["peer_real_ip_or_host"],
                "port": data_port,
                "network": "udp",
            },
        }
    ],
    "outbounds": [outbound],
    "routing": {
        "rules": [
            {
                "type": "field",
                "inboundTag": ["udp-in"],
                "outboundTag": outbound["tag"],
            }
        ]
    },
}

with open(target_path, "w", encoding="utf-8") as f:
    json.dump(config, f, indent=2, ensure_ascii=False)
PY
}

write_client_config() {
  local path="$1"
  cat > "$path" <<EOF
real_ip = "$REAL_IP"
peer_real_ip = "$PEER_REAL_IP"
spoofed_ip = "$SPOOFED_IP"
peer_spoofed_ip = "$PEER_SPOOFED_IP"
spoof_outbound = $SPOOF_OUTBOUND
interface = "$INTERFACE"
data_port = $DATA_PORT
icmp_id = $ICMP_ID
pre_shared_key = "$PRE_SHARED_KEY"
allowed_peers = [$ALLOWED_PEERS]
socks5_port = $SOCKS5_PORT
EOF
}

write_server_config() {
  local path="$1"
  cat > "$path" <<EOF
real_ip = "$REAL_IP"
peer_real_ip = "$PEER_REAL_IP"
spoofed_ip = "$SPOOFED_IP"
peer_spoofed_ip = "$PEER_SPOOFED_IP"
spoof_outbound = $SPOOF_OUTBOUND
interface = "$INTERFACE"
data_port = $DATA_PORT
icmp_id = $ICMP_ID
pre_shared_key = "$PRE_SHARED_KEY"
allowed_peers = [$ALLOWED_PEERS]
EOF
}

write_service() {
  local path="$1"
  local description="$2"
  local exec_start="$3"
  cat > "$path" <<EOF
[Unit]
Description=$description
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$exec_start
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF
}

main() {
  require_root

  echo "Candy-Spoof interactive asymmetric installer"
  echo "Project directory: $PROJECT_DIR"
  echo "Binary directory: $BINARY_DIR"
  echo "Config directory: $CONFIG_DIR"
  echo
  echo "Choose the role for this server."
  echo "  iran-client  : client side, usually behind filtering, may use Xray backchannel"
  echo "  kharej-server: public server side"
  prompt_required ROLE "Role (iran-client/kharej-server)"

  install_dependencies
  build_and_install_binaries
  autodetect_real_ip_and_interface

  echo
  echo "Network identity"
  echo "Detected real IPv4: $REAL_IP"
  echo "Detected interface: $INTERFACE"
  prompt_required SPOOFED_IP "Spoofed IPv4 used by this machine"
  prompt_required PEER_SPOOFED_IP "Spoofed IPv4 expected from the peer"

  echo
  echo "Shared tunnel settings"
  prompt DATA_PORT "UDP data port" "47000"
  prompt ICMP_ID "ICMP identifier" "4242"
  prompt PRE_SHARED_KEY "Pre-shared key" "ChangeThisStrongPSK123"

  SOCKS5_PORT="1080"
  if [[ "$ROLE" == "iran-client" ]]; then
    prompt SOCKS5_PORT "SOCKS5 port" "1080"
  fi

  echo
  echo "Trusted extra peer IPs."
  echo "Enter a comma-separated list like: \"159.223.26.159\", \"45.135.195.90\""
  echo "Leave empty if none."
  prompt EXTRA_ALLOWED "Extra allowed peer IPs (comma-separated, no brackets)" ""
  if [[ -n "$EXTRA_ALLOWED" ]]; then
    ALLOWED_PEERS="$EXTRA_ALLOWED"
  else
    ALLOWED_PEERS=""
  fi

  XRAY_CONFIG_PATH=""
  SERVICE_PATH=""
  SPOOF_OUTBOUND=true

  if [[ "$ROLE" == "iran-client" ]]; then
    yes_no USE_XRAY "Use an Xray backchannel from existing config (VLESS/VMESS)" "y"
    if [[ "$USE_XRAY" == "yes" ]]; then
      SPOOF_OUTBOUND=false
      prompt_required XRAY_SOURCE_CONFIG "Path to existing Xray config JSON"
      XRAY_CONFIG_PATH="$CONFIG_DIR/xray-backchannel.json"
      PARSED_TMP="$(mktemp)"
      extract_xray_outbound "$XRAY_SOURCE_CONFIG" "$PARSED_TMP"
      PEER_REAL_IP="$(python3 - "$PARSED_TMP" <<'PY'
import json
import sys
with open(sys.argv[1], "r", encoding="utf-8") as f:
    print(json.load(f)["peer_real_ip_or_host"])
PY
)"
      write_xray_backchannel_config "$XRAY_CONFIG_PATH" "$PARSED_TMP"
      rm -f "$PARSED_TMP"
      echo "Peer real IPv4/host updated from Xray outbound: $PEER_REAL_IP"
    else
      prompt_required PEER_REAL_IP "Peer real IPv4 or hostname"
    fi

    CLIENT_CONFIG_PATH="$CONFIG_DIR/client-iran-asym.toml"
    write_client_config "$CLIENT_CONFIG_PATH"
    SERVICE_PATH="/etc/systemd/system/candy-client.service"
    write_service "$SERVICE_PATH" "Candy-Spoof client" "$BINARY_DIR/client --config $CLIENT_CONFIG_PATH"
  elif [[ "$ROLE" == "kharej-server" ]]; then
    prompt_required PEER_REAL_IP "Peer real IPv4 or hostname"
    SERVER_CONFIG_PATH="$CONFIG_DIR/server-kharej-asym.toml"
    write_server_config "$SERVER_CONFIG_PATH"
    SERVICE_PATH="/etc/systemd/system/candy-server.service"
    write_service "$SERVICE_PATH" "Candy-Spoof server" "$BINARY_DIR/server --config $SERVER_CONFIG_PATH"
  else
    echo "Invalid role: $ROLE"
    exit 1
  fi

  set_caps_if_possible
  systemctl daemon-reload
  systemctl enable --now "$(basename "$SERVICE_PATH")"

  echo
  echo "Done."
  echo "Role: $ROLE"
  echo "Service file: $SERVICE_PATH"
  if [[ -n "$XRAY_CONFIG_PATH" ]]; then
    echo "Xray config: $XRAY_CONFIG_PATH"
  fi
  echo "Service status:"
  systemctl --no-pager --full status "$(basename "$SERVICE_PATH")" || true
}

main "$@"
