# HyperVault IKEv2 — Ubuntu VPS recovery runbook

**Recorded from the successful iPhone PoC deployment on 24 October 2026.** Companion: `ikev2-vps-recovery.sh`. This is a **recovery script**, not a turnkey unattended installer. Its phases are intentionally separate to protect the live Linode VPS (SSH, mail, nginx, SSTP, UFW, Docker). Review before execution. The original repository's `docs/iphone-poc.md` remains authoritative for provisioning details.

## Established working deployment

| Setting | Value |
| --- | --- |
| Host | Ubuntu 24.04.3 on Linode |
| VPN domain / public IPv4 | `vpn.hypervault.biz` / `139.162.156.48` |
| External interface | `eth0` |
| IKEv2 listener | UDP `500` |
| NAT-T listener | UDP `4500` |
| Dedicated account | `ikev2lab` (non-root) |
| Unit | `ikev2-iphone-poc.service` |
| Executable | `/usr/local/libexec/ikev2d` |
| Public config | `/etc/ikev2/iphone-poc.toml` (root:root `0644`) |
| Secrets | `/etc/ikev2lab/` (root:root `0700`; individual files `0600`) |
| Certificate | Let's Encrypt RSA-3072 for `vpn.hypervault.biz` |
| Virtual IP allocation | `10.77.0.10`–`10.77.0.20` |
| DNS | `1.1.1.1`, `1.0.0.1` |
| Lifetime | `1800` seconds |
| XFRM reqid baseline | `65536` |
| XFRM policy priority | `10000` |
| Previously tested iPhone source IP | `188.119.23.106` — dynamic; **verify before applying firewall** |
| Other live services | SSH TCP `7890`, nginx TCP `80/443`, SSTP TCP `8443`, mail, Docker, UFW |

Last test: service started, both UDP listeners bound, and native iPhone VPN connected; daemon reported `authenticated_ike=1`, `authentication_failed=0`, `active_children=1`. These metrics do not independently verify sustained traffic or DNS.

## What to back up before rebuilding the VPS

Back up securely and **encrypted/off-server**:

- `/etc/ikev2lab/master.key` — 32 bytes (necessary to decrypt existing verifiers).
- `/etc/ikev2lab/verifiers.v1` — encrypted verifier database; must match `master.key`.
- `/etc/ikev2/iphone-poc.toml` and `/etc/systemd/system/ikev2-iphone-poc.service`.
- The current Rust source repository, especially the **fixed** `src/crates/vpn-auth/src/credentials.rs`. The recovery source archive on the VPS was `/root/rust-vpn-poc-updated.tar.gz` and extracted to `/opt/rust-vpn-poc-updated/` (note: the workspace root directly contains `Cargo.lock` and `crates/`).
- Any operational notes on DNS TXT validation, firewall exceptions, certificate renewal and client configuration.

**Never** publish or commit `master.key`, `verifiers.v1`, private keys, user passwords or credential dumps. Keep certificate private keys managed by certbot or separately in secured backup. Preserve original master-key/verifier pairing if restoring users. Passwords cannot be recovered from encrypted verifiers.

## First-time recovery sequence

### 1. Restore the source and base tools

Log in to the VPS over SSH port `7890` using your normal secured access. Ensure Rust/cargo, compiler, OpenSSL development tools, Python 3, OpenSSL, certbot and iptables are available. The original installation involved building the workspace on the VPS, not transferring an Arch Linux executable. Do **not** blindly rerun any old SSH/UFW/network commands.

If the source archive is transferred to `/root/rust-vpn-poc-updated.tar.gz`, extract it with:

```bash
sudo mkdir -p /opt/rust-vpn-poc-updated && sudo tar -xzf /root/rust-vpn-poc-updated.tar.gz -C /opt/rust-vpn-poc-updated
```

Verify `/opt/rust-vpn-poc-updated/Cargo.lock` and `/opt/rust-vpn-poc-updated/crates/vpn-auth/src/credentials.rs` exist. If the archive nests the project an extra level, set `SOURCE_DIR` accordingly.

Check Rust and OpenSSL toolchain readiness and configure a source package manager as you ordinarily would. The script does **not** install packages or alter system repositories.

### 2. Obtain or restore the trusted server certificate

The successful deployment used certbot with **manual DNS TXT validation** and a valid Let's Encrypt **RSA-3072**, SHA-256 certificate. DNS verification is interactive and not unattended. For a new certificate, use your approved certbot manual DNS workflow for `vpn.hypervault.biz`, set the requested `_acme-challenge` TXT value, confirm DNS propagation, and finish validation. A representative manual command is:

```bash
sudo certbot certonly --manual --preferred-challenges dns --key-type rsa --rsa-key-size 3072 -d vpn.hypervault.biz
```

Only run this on a fresh host or where renewal/issuance is actually necessary. The previously issued certificate expired **22 January 2027**. **Manual DNS issuance does not automatically renew.** The script expects:

- `/etc/letsencrypt/live/vpn.hypervault.biz/fullchain.pem`
- `/etc/letsencrypt/live/vpn.hypervault.biz/privkey.pem`
- `/etc/letsencrypt/live/vpn.hypervault.biz/chain.pem`
- `/etc/letsencrypt/live/vpn.hypervault.biz/cert.pem`

It verifies CA trust and hostname, then copies the full chain and key to root-only credential inputs.

### 3. Install script, inspect its assumptions, run read-only checks

Transfer both recovery files to the server, e.g. `/root/ikev2-vps-recovery.sh` and `/root/ikev2-vps-recovery-README.md`.

```bash
sudo bash /root/ikev2-vps-recovery.sh preflight
```

`SERVER_IP=139.162.156.48`, `WAN=eth0`, `SOURCE_DIR=/opt/rust-vpn-poc-updated` are recorded defaults. Override with environment variables for a different VPS.

### 4. Build and prepare credentials/configuration

```bash
sudo bash /root/ikev2-vps-recovery.sh prepare
```

This builds the updated `ikev2d` and the provisioning example against Ubuntu's libraries; creates the non-login account; stages the executable, cleanup script and certificate files; creates a new 32-byte master key **only if missing**; creates nonsecret public config only if missing; and leaves existing encrypted verifiers unchanged. It does not overwrite a running daemon.

If `verifiers.v1` does not exist, provision the disposable test user using the exact syntax in **`docs/iphone-poc.md`** from the matching source version, using the newly installed `/usr/local/libexec/ikev2-provision` and `systemd-ask-password` to avoid displaying passwords. Restore `master.key` and `verifiers.v1` **together** to retain an existing test account. After provisioning, ensure:

```bash
sudo stat -c '%a %U:%G %n' /etc/ikev2lab /etc/ikev2lab/master.key /etc/ikev2lab/server-key.pem /etc/ikev2lab/server-chain.pem /etc/ikev2lab/verifiers.v1
```

Expected directory `700 root:root`, each file `600 root:root`.

### 5. Install the systemd service

```bash
sudo bash /root/ikev2-vps-recovery.sh unit
```

This installs the known working unit and validates it, **only if no unit currently exists**. It uses `User=ikev2lab`, four `LoadCredential=` directives and restrictive process settings. The key fix was to move the **nonsecret** TOML config from `/etc/ikev2lab/` (unreadable by `ikev2lab`) to `/etc/ikev2/iphone-poc.toml` (readable), while secrets stay root-only.

The matching Rust `vpn-auth` credential loader **must contain the October 2026 systemd 255 fix**, accepting `0550` systemd credential directories and `0440` credential copies **only when ACL/security validation restricts access appropriately**. Do not weaken or remove those checks.

### 6. Configure scoped firewall/NAT

Confirm the **current** public IPv4 of the iPhone. The original `188.119.23.106` may change or differ between Wi-Fi and cellular. Ensure this client IP is intended to be authorized.

```bash
sudo PHONE_IP=188.119.23.106 bash /root/ikev2-vps-recovery.sh network
```

**Replace that sample IP** with the actual current iPhone source address. This delegates to repository script `tools/poc/network.py` using the tested flags `setup --wan eth0 --server-ip 139.162.156.48 --phone-ip ... --subnet 10.77.0.0/24 --apply`. The script installed dedicated `HVPOC_IN`, `HVPOC_FWD` and `HVPOC_NAT` chains, scoped INPUT/FORWARD/POSTROUTING jumps, and a MASQUERADE policy; it did not reset UFW, SSH or Docker. IPv4 forwarding was already enabled in the working host. **Review network.py and its idempotence before rerunning the network phase on a partially configured host.** This recovery script does not blindly flush or reset any firewall chains.

### 7. Start and verify

```bash
sudo bash /root/ikev2-vps-recovery.sh start
```

```bash
sudo bash /root/ikev2-vps-recovery.sh verify
```

Expected: systemd `active`, UDP bindings on `SERVER_IP:500` and `SERVER_IP:4500`, and logs indicating successful IKE authentication/CHILD_SA after a test connection. On iPhone, use native **IKEv2**: Server `vpn.hypervault.biz`, Remote ID `vpn.hypervault.biz`, username `m3-disposable` (if provisioned), local ID blank, username/password authentication, client certificate toggle off, proxy off. iOS still verifies the server certificate.

For live logs:

```bash
sudo journalctl -fu ikev2-iphone-poc.service -o cat
```

For read-only traffic diagnostics:

```bash
sudo ip xfrm state count; sudo ip xfrm policy count
```

Do not post traffic/key dumps publicly. A visible `Connected` indicator plus successful traffic tests is stronger evidence than the handshake statistics alone.

## Special cases / things NOT to automate blindly

1. **Do not reissue or overwrite a working Let's Encrypt certificate** unless necessary; manually issued DNS certificates need explicit renewal planning and updated copies into `/etc/ikev2lab` followed by a controlled service restart.
2. **Do not regenerate `master.key` when restoring `verifiers.v1`** — the verifier database depends on that key.
3. **Do not overwrite an existing service unit automatically**, or enable the experimental daemon at boot without deciding that explicitly (`systemctl enable` was **not** performed in the working deployment).
4. **Do not run generic `iptables -F`, `ufw reset`, `ip xfrm state flush` or `ip xfrm policy flush`.** Existing SSH, mail, Docker and unrelated XFRM records must be preserved.
5. **Do not copy an Arch-built ELF executable onto Ubuntu.** Rebuild from the updated Rust source there.
6. **Do not put the TOML config back under `/etc/ikev2lab`** unless your service can read it via an approved mechanism.
7. **Do not confuse periodic `initial_exchange_metrics` logging with handshake failures.** In the successful run, `authenticated_ike=1`, `authentication_failed=0`, `active_children=1`.
8. The source restriction `PHONE_IP` is a lab policy. If the iPhone switches networks, revisit the rule intentionally rather than exposing UDP 500/4500 from all sources.

## Changes not captured precisely from the original history

The exact original apt install command, certbot command-line flags as executed, provisioning utility command-line flags, and custom local SSH/firewall preconditions are not fully available in the chat record. The runbook therefore marks these as interactive/manual, rather than fabricating a supposedly verified one-shot command. The certificate command above is a representative issuance method, not a verbatim record of the original invocation.
