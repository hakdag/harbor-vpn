#!/usr/bin/env bash
# HyperVault Rust IKEv2/iPhone PoC — explicit, repeatable VPS recovery steps.
# Based on the successful 2026-10-24 Ubuntu 24.04 deployment. Review before running.
set -Eeuo pipefail
umask 077

PHASE="${1:-help}"
SOURCE_DIR="${SOURCE_DIR:-/opt/rust-vpn-poc-updated}"
SERVER_IP="${SERVER_IP:-139.162.156.48}"
PHONE_IP="${PHONE_IP:-}"                     # Current public IPv4 of test iPhone; required for network phase
WAN="${WAN:-eth0}"
DOMAIN="${DOMAIN:-vpn.hypervault.biz}"
POOL_START="${POOL_START:-10.77.0.10}"
POOL_END="${POOL_END:-10.77.0.20}"
SUBNET="${SUBNET:-10.77.0.0/24}"
UNIT=ikev2-iphone-poc.service
SECRET_DIR=/etc/ikev2lab
PUBLIC_DIR=/etc/ikev2
CONFIG="$PUBLIC_DIR/iphone-poc.toml"
BIN=/usr/local/libexec/ikev2d
PROVISION=/usr/local/libexec/ikev2-provision
CLEANUP=/usr/local/libexec/harbor-cleanup-xfrm.py
CERT_LIVE="/etc/letsencrypt/live/$DOMAIN"

say() { printf '\n==> %s\n' "$*"; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
need_root() { [[ $EUID -eq 0 ]] || die "Run with sudo/root for phase '$PHASE'."; }
need_file() { [[ -f "$1" ]] || die "Missing: $1"; }
need_cmd() { command -v "$1" >/dev/null || die "Missing command: $1"; }
valid_ipv4() { [[ $1 =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] && [[ $(awk -F. '{for(i=1;i<=4;i++)if($i>255)exit 1}' <<<"$1"; echo $?) == 0 ]]; }
preflight() {
  say 'Read-only preflight'
  printf 'Workspace: %s\nServer: %s\nDomain: %s\nWAN: %s\nPhone source IP: %s\n' "$SOURCE_DIR" "$SERVER_IP" "$DOMAIN" "$WAN" "${PHONE_IP:-NOT SET}"
  [[ -d "$SOURCE_DIR" ]] || die "Workspace not found: $SOURCE_DIR. Extract the archived source before continuing."
  need_file "$SOURCE_DIR/Cargo.lock"
  need_file "$SOURCE_DIR/tools/poc/network.py"
  need_file "$SOURCE_DIR/tools/poc/cleanup_xfrm.py"
  need_cmd systemctl; need_cmd python3; need_cmd openssl; need_cmd cargo
  valid_ipv4 "$SERVER_IP" || die 'SERVER_IP must be IPv4'
  ip -4 address show dev "$WAN" | grep -F "$SERVER_IP" >/dev/null || die "SERVER_IP not present on $WAN; check SERVER_IP/WAN."
  printf '\nSSH listeners (informational, no change):\n'; ss -ltn | grep -E ':7890[[:space:]]' || true
  printf '\nCurrent service (informational):\n'; systemctl is-active "$UNIT" || true
}

prepare() {
  need_root; preflight
  say 'Build updated Rust binaries on Ubuntu (not on Arch)'
  (cd "$SOURCE_DIR" && cargo build --release --locked -p ikev2d -p vpn-auth --example provision)
  need_file "$SOURCE_DIR/target/release/ikev2d"
  need_file "$SOURCE_DIR/target/release/examples/provision"
  say 'Create dedicated non-login service user and directories'
  if ! id ikev2lab >/dev/null 2>&1; then useradd --system --user-group --no-create-home --shell /usr/sbin/nologin ikev2lab; fi
  install -d -o root -g root -m 0700 "$SECRET_DIR"
  install -d -o root -g root -m 0755 "$PUBLIC_DIR"
  install -d -o root -g root -m 0755 /usr/local/libexec
  # Safely copy binary without replacing an executable in active use.
  if systemctl is-active --quiet "$UNIT"; then die "Service is running; stop it intentionally before replacing $BIN."; fi
  install -o root -g root -m 0755 "$SOURCE_DIR/target/release/ikev2d" "$BIN"
  install -o root -g root -m 0755 "$SOURCE_DIR/target/release/examples/provision" "$PROVISION"
  install -o root -g root -m 0755 "$SOURCE_DIR/tools/poc/cleanup_xfrm.py" "$CLEANUP"
  say 'Create master key only on first installation'
  if [[ ! -e "$SECRET_DIR/master.key" ]]; then
    openssl rand 32 > "$SECRET_DIR/master.key"
    chown root:root "$SECRET_DIR/master.key"; chmod 0600 "$SECRET_DIR/master.key"
    echo 'NEW MASTER KEY generated. Never restore an old verifiers.v1 with a different master.key.'
  else
    echo 'Existing master.key preserved without modification.'
  fi
  [[ $(stat -c '%s' "$SECRET_DIR/master.key") == 32 ]] || die 'master.key must contain exactly 32 bytes'
  say 'Stage existing certificate into root-only files; do not issue or renew certificates here'
  need_file "$CERT_LIVE/fullchain.pem"; need_file "$CERT_LIVE/privkey.pem"
  openssl verify -purpose sslserver -verify_hostname "$DOMAIN" -CAfile /etc/ssl/certs/ca-certificates.crt -untrusted "$CERT_LIVE/chain.pem" "$CERT_LIVE/cert.pem"
  install -o root -g root -m 0600 "$CERT_LIVE/fullchain.pem" "$SECRET_DIR/server-chain.pem"
  install -o root -g root -m 0600 "$CERT_LIVE/privkey.pem" "$SECRET_DIR/server-key.pem"
  say 'Write NONSECRET public config only if missing (leave existing site customizations unchanged)'
  if [[ ! -e "$CONFIG" ]]; then
    cat > "$CONFIG" <<EOF
[udp]
ike = "$SERVER_IP:500"
natt = "$SERVER_IP:4500"
[handshake]
max_request_bytes = 16384
max_response_bytes = 16384
max_pending = 64
per_source = 8
cookie_threshold = 32
[authentication]
enabled = true
[poc]
enabled = true
pool_start = "$POOL_START"
pool_end = "$POOL_END"
dns = ["1.1.1.1", "1.0.0.1"]
lifetime_secs = 1800
reqid_start = 65536
policy_priority = 10000
EOF
    chown root:root "$CONFIG"; chmod 0644 "$CONFIG"
  else
    echo "Existing $CONFIG preserved; inspect addresses before starting."
  fi
  say 'Verify service user can read public config'
  runuser -u ikev2lab -- test -r "$CONFIG" || die "ikev2lab cannot read $CONFIG"
  say 'Verify encrypted user database exists'
  if [[ ! -s "$SECRET_DIR/verifiers.v1" ]]; then
    cat <<EOF
ACTION REQUIRED: No encrypted verifier database at $SECRET_DIR/verifiers.v1.
Provision a disposable test user with the documented vpn-auth example utility,
using the SAME $SECRET_DIR/master.key, then ensure root:root 0600 permissions.
Consult $SOURCE_DIR/docs/iphone-poc.md for the exact provision CLI syntax.
Do not paste passwords here; use systemd-ask-password as documented.
Run 'sudo $0 unit' only after provisioning.
EOF
  else
    [[ $(stat -c '%a %U:%G' "$SECRET_DIR/verifiers.v1") == '600 root:root' ]] || die 'verifiers.v1 must be 0600 root:root'
    echo 'Existing encrypted verifier file preserved.'
  fi
  echo 'Prepare completed; firewall and systemd unit NOT installed or started.'
}

unit() {
  need_root; preflight
  for f in "$BIN" "$CLEANUP" "$CONFIG" "$SECRET_DIR/master.key" "$SECRET_DIR/server-key.pem" "$SECRET_DIR/server-chain.pem" "$SECRET_DIR/verifiers.v1"; do need_file "$f"; done
  [[ $(stat -c '%a %U:%G' "$SECRET_DIR") == '700 root:root' ]] || die 'Secret directory must be 0700 root:root'
  for f in master.key server-key.pem server-chain.pem verifiers.v1; do
    [[ $(stat -c '%a %U:%G' "$SECRET_DIR/$f") == '600 root:root' ]] || die "$f must be 0600 root:root"
  done
  [[ ! -e /etc/systemd/system/$UNIT ]] || die "Unit already exists. Refusing to overwrite: /etc/systemd/system/$UNIT"
  say 'Create reviewed systemd unit (nonroot + credentials handoff)'
  cat > "/etc/systemd/system/$UNIT" <<EOF
[Unit]
Description=Rust native iPhone IPv4 VPN PoC
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
User=ikev2lab
Group=ikev2lab
LoadCredential=master-key:$SECRET_DIR/master.key
LoadCredential=server-key:$SECRET_DIR/server-key.pem
LoadCredential=server-chain:$SECRET_DIR/server-chain.pem
LoadCredential=verifiers:$SECRET_DIR/verifiers.v1
ExecStart=$BIN --serve $CONFIG
ExecStopPost=/usr/bin/python3 $CLEANUP --reqid-start 65536 --apply
Restart=no
TimeoutStopSec=15
KillSignal=SIGTERM
LimitCORE=0
UMask=0077
NoNewPrivileges=yes
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
RestrictAddressFamilies=AF_INET AF_UNIX AF_NETLINK
[Install]
WantedBy=multi-user.target
EOF
  chown root:root "/etc/systemd/system/$UNIT"; chmod 0644 "/etc/systemd/system/$UNIT"
  systemctl daemon-reload
  systemd-analyze verify "/etc/systemd/system/$UNIT"
  echo "Unit installed but NOT enabled/started. Run '$0 network' then '$0 start'."
}

network() {
  need_root; preflight
  [[ -n "$PHONE_IP" ]] || die 'Set PHONE_IP to the current public IPv4 address of the iPhone.'
  valid_ipv4 "$PHONE_IP" || die 'PHONE_IP must be IPv4'
  need_cmd iptables
  say 'Apply project-owned scoped iptables chains/jumps; preserve SSH, UFW, Docker'
  python3 "$SOURCE_DIR/tools/poc/network.py" setup --wan "$WAN" --server-ip "$SERVER_IP" --phone-ip "$PHONE_IP" --subnet "$SUBNET" --apply
  echo 'Review OUTPUT; rules are tied to PHONE_IP, which may change between networks.'
}

start() {
  need_root; need_file "/etc/systemd/system/$UNIT"; need_file "$BIN"
  say 'Start VPN without enabling it at boot'
  systemctl start "$UNIT"
  systemctl status "$UNIT" --no-pager -l
}

verify() {
  need_root
  say 'Service state'; systemctl is-active "$UNIT"
  say 'IKEv2 UDP sockets'; ss -lunp | grep -E ':(500|4500)[[:space:]]' || true
  say 'Linux XFRM state/policy counts (not proof of end-to-end traffic)'
  ip xfrm state count; ip xfrm policy count
  say 'Recent service logs (may contain identifying network metadata)'
  journalctl -u "$UNIT" -n 15 --no-pager -o cat
}

case "$PHASE" in
  preflight) preflight;;
  prepare) prepare;;
  unit) unit;;
  network) network;;
  start) start;;
  verify) verify;;
  help|-h|--help)
    cat <<EOF
Usage: sudo SOURCE_DIR=/opt/rust-vpn-poc-updated SERVER_IP=139.162.156.48 WAN=eth0 PHONE_IP=<iphone_public_ipv4> $0 PHASE
Phases: preflight (read-only), prepare (build/stage/config/keys), unit (create new unit only), network (scoped firewall/NAT), start, verify.
Set PHONE_IP only for network. Do not run 'unit' on an existing service: it will refuse to overwrite.
Never run 'prepare' on a running VPN daemon. See ikev2-vps-recovery-README.md.
EOF
    ;;
  *) die "Unknown phase: $PHASE. Run '$0 help'.";;
esac
