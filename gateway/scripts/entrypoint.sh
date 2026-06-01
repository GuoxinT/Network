#!/usr/bin/env bash
set -euo pipefail

APP_DIR=/app
STATE_DIR="$APP_DIR/state"
CONFIG="$APP_DIR/config.json"
PKI="$STATE_DIR/pki"
CLIENT_DIR="$STATE_DIR/clients"
SERVER_CONF="$STATE_DIR/server.conf"
PUID="${PUID:-1000}"
PGID="${PGID:-1000}"

mkdir -p "$PKI" "$CLIENT_DIR"
chmod 755 "$STATE_DIR" "$CLIENT_DIR"
chmod 700 "$PKI"

server_host="$(jq -r '.server_host' "$CONFIG")"
listen_port="$(jq -r '.listen_port' "$CONFIG")"
proto="$(jq -r '.protocol // "udp"' "$CONFIG")"
vpn_cidr="$(jq -r '.vpn_cidr' "$CONFIG")"
dns="$(jq -r '.client_dns' "$CONFIG")"
iface="$(jq -r '.default_interface' "$CONFIG")"

vpn_net="${vpn_cidr%/*}"
vpn_prefix="${vpn_cidr#*/}"
if [ "$vpn_prefix" != "24" ]; then
  echo "Only /24 vpn_cidr is supported by this simple gateway." >&2
  exit 1
fi
vpn_base="${vpn_net%.*}"
vpn_network="$vpn_base.0"
vpn_mask="255.255.255.0"

make_ca() {
  openssl genrsa -out "$PKI/ca.key" 4096
  openssl req -x509 -new -nodes -key "$PKI/ca.key" -sha256 -days 3650 \
    -subj "/CN=LabVPN Gateway CA" -out "$PKI/ca.crt"
  chmod 600 "$PKI/ca.key"
}

make_cert() {
  local name="$1"
  local type="$2"
  openssl genrsa -out "$PKI/$name.key" 2048
  openssl req -new -key "$PKI/$name.key" -subj "/CN=$name" -out "$PKI/$name.csr"
  cat > "$PKI/$name.ext" <<EOF
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=$type
EOF
  openssl x509 -req -in "$PKI/$name.csr" -CA "$PKI/ca.crt" -CAkey "$PKI/ca.key" \
    -CAcreateserial -out "$PKI/$name.crt" -days 3650 -sha256 -extfile "$PKI/$name.ext"
  chmod 600 "$PKI/$name.key"
}

[ -f "$PKI/ca.crt" ] || make_ca
[ -f "$PKI/server.crt" ] || make_cert server serverAuth
[ -f "$PKI/ta.key" ] || openvpn --genkey secret "$PKI/ta.key"

cat > "$SERVER_CONF" <<EOF
port $listen_port
proto $proto
dev tun
topology subnet
server $vpn_network $vpn_mask
ifconfig-pool-persist $STATE_DIR/ipp.txt
ca $PKI/ca.crt
cert $PKI/server.crt
key $PKI/server.key
dh none
ecdh-curve prime256v1
tls-crypt $PKI/ta.key
keepalive 10 60
persist-key
persist-tun
user nobody
group nobody
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS ${dns%%,*}"
push "dhcp-option DNS ${dns##*, }"
cipher AES-256-GCM
data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305
auth SHA256
verb 3
EOF

for row in $(jq -r '.clients[] | @base64' "$CONFIG"); do
  client_json="$(printf '%s' "$row" | base64 -d)"
  name="$(printf '%s' "$client_json" | jq -r '.name')"
  address="$(printf '%s' "$client_json" | jq -r '.address')"
  safe="$(printf '%s' "$name" | tr -cd 'A-Za-z0-9_-')"
  if [ -z "$safe" ]; then
    echo "Invalid client name: $name" >&2
    exit 1
  fi

  [ -f "$PKI/$safe.crt" ] || make_cert "$safe" clientAuth
  echo "$safe,$address" >> "$STATE_DIR/ipp.new"

  ovpn="$CLIENT_DIR/$safe.ovpn"
  cat > "$ovpn" <<EOF
client
dev tun
proto $proto
remote $server_host $listen_port
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
cipher AES-256-GCM
data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305
auth SHA256
verb 3

<ca>
$(cat "$PKI/ca.crt")
</ca>
<cert>
$(sed -n '/BEGIN CERTIFICATE/,/END CERTIFICATE/p' "$PKI/$safe.crt")
</cert>
<key>
$(cat "$PKI/$safe.key")
</key>
<tls-crypt>
$(cat "$PKI/ta.key")
</tls-crypt>
EOF
  chmod 600 "$ovpn"
done
mv "$STATE_DIR/ipp.new" "$STATE_DIR/ipp.txt"
chown "$PUID:$PGID" "$STATE_DIR" "$CLIENT_DIR" "$CLIENT_DIR"/*.ovpn "$STATE_DIR/ipp.txt" "$SERVER_CONF" 2>/dev/null || true
chmod 755 "$STATE_DIR" "$CLIENT_DIR"
chmod 600 "$CLIENT_DIR"/*.ovpn

iptables -t nat -C POSTROUTING -s "$vpn_cidr" -o "$iface" -j MASQUERADE 2>/dev/null ||
  iptables -t nat -A POSTROUTING -s "$vpn_cidr" -o "$iface" -j MASQUERADE
iptables -C FORWARD -i tun0 -j ACCEPT 2>/dev/null || iptables -A FORWARD -i tun0 -j ACCEPT
iptables -C FORWARD -o tun0 -j ACCEPT 2>/dev/null || iptables -A FORWARD -o tun0 -j ACCEPT

cleanup() {
  iptables -t nat -D POSTROUTING -s "$vpn_cidr" -o "$iface" -j MASQUERADE 2>/dev/null || true
  iptables -D FORWARD -i tun0 -j ACCEPT 2>/dev/null || true
  iptables -D FORWARD -o tun0 -j ACCEPT 2>/dev/null || true
}
trap cleanup EXIT INT TERM

echo "OpenVPN gateway is running on $server_host:$listen_port/$proto"
exec openvpn --config "$SERVER_CONF"
