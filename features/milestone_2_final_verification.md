# Milestone 2 final verification

Update: M2 automated verification was accepted by the maintainer. M2-R1/R2/R3 have since been remediated; see [the remediation report](milestone_2_remediation_report.md) for changed-source checks, residual risks and operator gates. The 30-minute evidence below applies to the pre-remediation baseline.

Date: 2026-10-18. Scope: accepted ADR-002 / Milestone 2 IKE_SA_INIT only. **Final acceptance remains pending operator iPhone and Ubuntu evidence and disposition of review findings.** No Milestone 3 implementation, commit, push, firewall modification, certificate installation, or server deployment was performed.

## Tests actually executed

Host: Arch Linux, x86_64; this is not Ubuntu deployment evidence. Commands below run from `src/`. Full retained local output and exit codes are in `features/milestone_2_evidence/local_checks.json` and adjacent logs.

| Command | Exit | Result |
|---|---:|---|
| `cargo fmt --all -- --check` | 0 | Pass |
| `cargo clippy --workspace --all-targets -- -D warnings` | 0 | Pass |
| `cargo test --workspace` | 0 | 48 tests passed; includes real-provider ECDH, crypto vectors, malformed packets, state/cookie/expiry, both loopback UDP framing paths and CLI opt-in |

The initial direct test command passed. A second run captured through a sandboxed Python subprocess exited 101 because the OS denied the loopback socket (`test.log`); the separately captured outside-sandbox rerun exited 0 with all 48 tests passing (`test-unrestricted.log`). The protocol probe initially exited 1 when the sandbox denied socket creation, then exited 0 outside the sandbox; the daemon was deliberately terminated afterward (signal exit -15). The profile example was parsed as well-formed XML; native installation was not tested. `git diff --check` also passed. The final staged source/document check (`git diff --cached --check -- . ":(exclude)**/*.log"`) passed. The unfiltered staged check reports whitespace only in raw tool logs; those bytes are preserved deliberately to keep evidence hashes intact.

### Sanitizer campaigns

| Target | Fuzz seconds | Executions | Exit | Sanitizer diagnostics |
|---|---:|---:|---:|---|
| `sa_init` | 1801 | 15,814,991 | 0 | None reported |
| `crypto_peer` | 1801 | 15,377,630 | 0 | None reported |

Both full-duration campaigns passed with ASan and leak detection enabled. Runner exit: **0**. Both preflights exited 0. Source hashes before/after match. Evidence directory: `src/fuzz/results/milestone-2-acceptance-unrestricted-20261018/`. The exact starting corpus is archived in `initial-corpus.tar.gz`; restore its two target directories under `src/fuzz/corpus/` in a separate clean checkout to repeat from those bytes. Archive SHA-256 and all final evidence hashes are in `SHA256SUMS`. The archive contains only synthetic fuzz inputs, not live traffic or credentials.

Reproduce from `src/` in an environment permitting LeakSanitizer tracing:

```sh
python3 fuzz/run_campaign.py --seconds 1800 --seed 20261018 \
  --targets sa_init crypto_peer --results fuzz/results/NEW-UNIQUE-DIRECTORY
```

The runner uses nightly cargo-fuzz with `--sanitizer address`, `ASAN_OPTIONS=detect_leaks=1:abort_on_error=1`, `LSAN_OPTIONS=exitcode=23`, libFuzzer `-detect_leaks=1`, max input 65536, timeout 10 seconds and RSS limit 512 MiB. Each target receives its own 1800-second campaign; they run concurrently. `environment.json` retains exact versions, commands, initial corpus hashes, binary hashes and source hashes before/after; `campaign.json` retains durations, diagnostics, exit codes, final statistics and log SHA-256. Raw preflight and campaign logs are retained. Time-limited scheduling means execution counts need not reproduce exactly.

The first attempt, `src/fuzz/results/milestone-2-acceptance-20261018/`, stopped at `sa_init` sanitizer preflight: runner exit 1, cargo preflight exit 1, underlying target reported exit 77 with LeakSanitizer fatal tracing diagnostics. No 30-minute campaign ran in that attempt. The empty-input artifact is not evidence of a malformed-packet defect. This failed evidence is preserved separately from the unrestricted rerun; no sanitizer was disabled and no ptrace/sysctl configuration was changed.

The Rust fuzz targets call the host's dynamically linked OpenSSL. That library was not rebuilt with ASan: successful runs cover the instrumented Rust/FFI boundary and leak checks, not complete instrumentation of OpenSSL internals. Fuzzing is not RFC conformance or native iOS evidence.

## Protocol review findings (historical baseline)

The entries below preserve the original findings and evidence. Their current disposition is recorded in `milestone_2_remediation_report.md`; native interoperability remains pending.

Review scope: current core, crypto provider, UDP transport, daemon, existing unit/integration fixtures and sanitizer evidence. This is a bounded review, not a complete security audit. Findings are reported without changing responder code.

| ID / severity | Evidence and impact | Disposition |
|---|---|---|
| M2-R1 / Low | `src/crates/ikev2-core/src/responder.rs:265` ignores CERTREQ only when its critical bit is clear; setting the bit changes the outcome to INVALID_SYNTAX. Recognized payload types must ignore that bit (RFC 7296 §§2.5, 3.2). CERTREQ contents remain outside M2 processing, but its critical bit should not alone change the ignore decision. A conforming sender sets this bit to zero, so this mainly affects robustness. | Reproducer and outcomes retained in `features/milestone_2_evidence/protocol_probe.json`. Resolve or explicitly waive before final acceptance; no certificate handling is proposed. |
| M2-R2 / Medium, deployment risk | `src/crates/ikev2-core/src/responder.rs:285` negotiates before cookie gating; lines 305–327 gate DH by pending occupancy, not a packet/work rate. `src/crates/ikev2-transport/src/lib.rs:162` synchronously processes packets, and lines 175–180 send replies without a network rate limit. Source-spoofed requests can consume parser/crypto/reply work; repeated expiry permits fresh DH work. Table bounds and 64 packets/socket/tick do not constitute a CPU or reflection rate limit. | Isolated source-restricted lab only. Measure CPU/RSS and packet rates on Ubuntu; review host ingress controls before any broader exposure. No production DDoS claim. |
| M2-R3 / Low, observability | `src/crates/ikev2-transport/src/lib.rs:167` discards `Outcome.offers` and `Outcome.nat`; the CLI exposes aggregate counters only. Unsupported iOS proposal IDs and NAT decisions cannot be recovered from daemon logs alone despite being available in the core. | Capture packets and retain offer/NAT worksheets for acceptance. Any future logging change must remain bounded and omit keys/credentials. |
| M2-V1 / Medium, validation gap | Shared OpenSSL is not sanitizer-instrumented; native iOS and Ubuntu/privilege tests have not run here. | Keep those gates pending; do not infer them from local green tests. |

RFC basis: [RFC 7296 §§2.5 and 3.2](https://www.rfc-editor.org/rfc/inline-errata/rfc7296.html). No high/critical defect was identified in this review; that is not a guarantee of absence. Existing tests demonstrate approved-suite-only selection, point validation, independent key schedule, bounded state and exact cached duplicate replies. The test-only GCM operations do not implement a protected IKE exchange.

## Native iOS procedure — operator required, NOT EXECUTED

### Safe lab and exact profile

Use a spare/test iPhone on controlled Wi-Fi, an operator-owned IPv4 server on the same LAN first, and a dedicated dummy account `m2-lab-only`. Do not enter real credentials, install a CA, disable certificate validation, configure a shared secret, or select client-certificate authentication. Keep on-demand/always-on VPN off. This service cannot protect application traffic. An eventual VPN connection error is expected.

Record iPhone model, exact iOS version and build (Settings > General > About), server build/checkpoint, profile SHA-256, local/remote IPs and ports, NAT topology, UTC start/end, interface name and capture tool version. Substitute the real server LAN IPv4 and an operator-owned test DNS identity for the two placeholders below. `RemoteIdentifier` is only a future server-identity expectation; M2 never verifies or authenticates it.

The standalone template is `features/milestone_2_evidence/ios-init-only.mobileconfig`; XML and plist parsing passed (`profile_validation.json`). Save a local copy as `m2-init-only.mobileconfig`. Replace `SERVER_IPV4` and `vpn-lab.example.invalid`; preserve XML escaping. Install manually through an operator-controlled channel, review the unsigned lab profile in Settings > General > VPN & Device Management and remove it after testing. Do not distribute this as a production profile.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>PayloadType</key><string>Configuration</string>
  <key>PayloadVersion</key><integer>1</integer>
  <key>PayloadIdentifier</key><string>org.example.m2.init-only</string>
  <key>PayloadUUID</key><string>A5382208-19DC-4C38-9196-4C6E4C753201</string>
  <key>PayloadDisplayName</key><string>M2 INIT-only lab — no VPN service</string>
  <key>PayloadContent</key><array><dict>
    <key>PayloadType</key><string>com.apple.vpn.managed</string>
    <key>PayloadVersion</key><integer>1</integer>
    <key>PayloadIdentifier</key><string>org.example.m2.init-only.vpn</string>
    <key>PayloadUUID</key><string>F83F2DB0-8153-44AA-BF19-DF915BB32202</string>
    <key>PayloadDisplayName</key><string>M2 INIT-only lab</string>
    <key>UserDefinedName</key><string>M2 INIT-only lab</string>
    <key>VPNType</key><string>IKEv2</string>
    <key>OnDemandEnabled</key><integer>0</integer>
    <key>IKEv2</key><dict>
      <key>RemoteAddress</key><string>SERVER_IPV4</string>
      <key>RemoteIdentifier</key><string>vpn-lab.example.invalid</string>
      <key>LocalIdentifier</key><string>m2-lab-only</string>
      <key>AuthenticationMethod</key><string>None</string>
      <key>ExtendedAuthEnabled</key><integer>1</integer>
      <key>AuthName</key><string>m2-lab-only</string>
      <key>IKESecurityAssociationParameters</key><dict>
        <key>EncryptionAlgorithm</key><string>AES-256-GCM</string>
        <key>IntegrityAlgorithm</key><string>SHA2-256</string>
        <key>DiffieHellmanGroup</key><integer>19</integer>
        <key>LifeTimeInMinutes</key><integer>60</integer>
      </dict>
      <key>ChildSecurityAssociationParameters</key><dict>
        <key>EncryptionAlgorithm</key><string>AES-256-GCM</string>
        <key>IntegrityAlgorithm</key><string>SHA2-256</string>
        <key>DiffieHellmanGroup</key><integer>19</integer>
        <key>LifeTimeInMinutes</key><integer>60</integer>
      </dict>
    </dict>
  </dict></array>
</dict></plist>
```

`AuthenticationMethod=None` plus extended authentication is Apple's username/password configuration; it does not request client certificates or authorize bypassing server authentication. Omit `AuthPassword`: if iOS requires a password before transmitting, enter an arbitrary disposable lab string only. The CHILD dictionary is client configuration only; the server does not process CHILD_SA. Apple's profile uses the `IntegrityAlgorithm` field alongside GCM; it must not be assumed to produce a separate INTEG transform on the wire. Confirm actual PRF and transforms from the capture. This exact profile is a test candidate, not a verified iOS compatibility claim. If installation fails, retain the error and build number and mark profile compatibility blocked rather than weakening authentication settings.

Profile key references: [Apple IKEv2](https://developer.apple.com/documentation/devicemanagement/vpn/ikev2-data.dictionary), [IKE SA parameters](https://developer.apple.com/documentation/devicemanagement/vpn/ikev2-data.dictionary/ikesecurityassociationparameters-data.dictionary), [CHILD SA parameters](https://developer.apple.com/documentation/devicemanagement/vpn/ikev2-data.dictionary/childsecurityassociationparameters-data.dictionary).

### Server setup, capture and execution

Complete the Ubuntu preparation below first. Copy `src/config/milestone-2-lab.toml` outside Git, replacing its `[udp]` values with the server's actual local unicast IPv4 and ports **500** and **4500**. Native iOS cannot be directed to the high loopback lab ports by this profile. Keep all handshake limits unchanged initially. Do not bind `0.0.0.0` or a public NAT address that is not assigned locally. Ensure another service is not already using either port.

In a private operator evidence directory (`umask 077`), start a bounded capture before toggling VPN. Replace `enp1s0` with the actual ingress interface and `PHONE_OR_NAT_IP` with the source as observed at the server:

```sh
sudo tcpdump -i enp1s0 -nn -s 0 -U -c 2000 \
  -w ios-m2-direct.pcap \
  'host PHONE_OR_NAT_IP and (udp port 500 or udp port 4500)'
```

Run the responder using the restricted service setup below and save its journal. In Settings > VPN select the lab profile and enable it once. Capture 30–60 seconds; disable VPN and stop tcpdump with Ctrl-C if the packet cap has not ended it. Stop the daemon after at least `lifetime_secs + 2` idle seconds. Retain the last metrics proving `pending=0` and `expired` increased. Record all process exit codes; an operator stop via SIGTERM is not a sanitizer finding or normal protocol completion. Use `tshark -r ios-m2-direct.pcap -Y isakmp -V > ios-m2-direct.decoded.txt` or Wireshark's IKEv2 dissector. Capture full packet bytes, not only screenshots. Hash artifacts with `sha256sum`; keep captures outside Git because they contain network/identity metadata.

Repeat with a real NAT between phone and server only in an arranged source-restricted test network. Capture on the server and, if available, both sides of the NAT; record translations. Cellular requires a separately arranged reachable endpoint and narrowly scoped temporary access policy; do not expose an unrestricted M2 responder to obtain this result. A phone's carrier NAT address can change. Remove temporary lab access and profile afterward.

### Expected packets and verdict

For every attempt record offered proposal number and all transform IDs/attributes, selected proposal, SPIi/SPIr, nonce and KE lengths, both NAT hashes, UDP tuple, timestamp and retransmission relationship. Compute NAT hashes as SHA1(SPIi || SPIr || IPv4 || port), network byte order; request SPIr is zero, response SPIr is the newly chosen nonzero value. In the response the source hash describes the server's local bound endpoint and the destination hash the observed peer. A NAT-mapped public endpoint can legitimately differ from the server's bound local endpoint.

1. Request: IKEv2 IKE_SA_INIT (exchange 34), I flag, message ID 0, nonzero SPIi, zero SPIr; SA/KE/Ni. Approved IKE suite is ENCR_AES_GCM_16=20 with key length attribute 14=256, PRF_HMAC_SHA2_256=5, DH=19, and **no separate INTEG transform**. Capture what iOS actually offers.
2. Supported request: response has R flag, exchange 34, message ID 0, matching SPIi, fresh nonzero SPIr, selected approved SA, group-19 64-byte KE, 32-byte Nr and two 20-byte NAT detection notifications (16388/16389). No certificate, AUTH, EAP or CHILD_SA is returned.
3. Identical request retransmitted on the same tuple before the default 10-second expiry: byte-identical cached IKE response and no new pending entry. Fresh attempts use fresh SPIs/nonces. Do not infer exact duplicate behavior if iOS changes bytes or the tuple. After expiry, recomputation is expected. If iOS supplies no duplicate, this gate is covered locally but remains unobserved on iOS.
4. Valid request with unsupported proposals: NO_PROPOSAL_CHOSEN (14). A selected suite with a wrong KE group: INVALID_KE_PAYLOAD (17), data `00 13`. Structurally malformed input may be silently dropped. These negative cases are locally tested; native negative coverage requires a separately saved modified profile and observed request. Do not weaken the server suite to make a profile pass.
5. Under configured load, COOKIE (16390) response allocates no pending state. A retry places the echoed COOKIE first. For an optional controlled iOS cookie test, use a separate config with `cookie_threshold=1`, seed exactly one valid synthetic pending handshake from an operator harness, then initiate from the phone within its lifetime. Retain that seed request and timestamps; absence of induced load is not native COOKIE coverage. Hard capacity must still hold after valid cookies.
6. After successful INIT, an encrypted IKE_AUTH request (exchange 35, normally message ID 1) from the iPhone is the strongest packet evidence that it accepted the initial response. It may move to UDP 4500 on detecting NAT; those packets have the four-zero-byte non-ESP marker. The responder drops IKE_AUTH and eventually expires pending state. The iPhone times out/fails to connect. This is expected for M2. A successful VPN connection would require investigation of a wrong endpoint or another service.

**Pass:** valid approved offer, correct response fields/crypto sizes/NAT hashes, iOS advances to IKE_AUTH, daemon stays alive and bounded, pending state expires; save separate direct and NAT results. **Fail:** wrong suite/flags/SPI/message ID/NAT hashes, nonidentical pre-expiry exact duplicate replies, crash, secret-bearing logs, state beyond caps or no cleanup. **Blocked/inconclusive:** no captured request (routing/firewall/profile), unsupported client offer, or response captured but no subsequent IKE_AUTH; retain evidence rather than declaring interoperability. An iOS error popup alone establishes neither pass nor fail of INIT. Routing, server-certificate trust, EAP, ESP and full VPN connectivity cannot be accepted in M2.

## Ubuntu LTS procedure — operator required, NOT EXECUTED

Use a disposable, fully security-updated Ubuntu **24.04 LTS** lab VM/server as the initial validation target, with exact point release, architecture and kernel recorded. Other LTS releases require their own results. This is a validation candidate, not an approved production baseline. Preserve `cat /etc/os-release`, `uname -a`, `rustc -Vv`, `cargo -V`, `openssl version -a`, `pkg-config --modversion openssl`, relevant `dpkg-query` output, executable SHA-256 and source checkpoint.

Operator-run build prerequisites and tools:

```sh
sudo apt-get update
sudo apt-get install build-essential pkg-config libssl-dev openssl \
  ca-certificates git python3 tcpdump tshark iproute2 libcap2-bin
```

`tshark` may ask whether unprivileged users can capture: leave that disabled; use narrowly scoped sudo tcpdump for this lab. Install a trusted Rust toolchain **1.97 or newer** separately; do not assume the distribution Cargo meets this workspace's declared MSRV/edition. Nightly and cargo-fuzz are only needed if repeating sanitizer campaigns on Ubuntu. No VPN-server package is required. [Ubuntu package listings](https://packages.ubuntu.com/libssl-dev) establish availability; record installed security revision instead of pinning an old OpenSSL patch release.

Build and verify on the target (from `src/`):

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo build --release --locked -p ikev2d
ldd target/release/ikev2d
openssl version -a
pkg-config --modversion openssl
openssl list -providers
openssl list -cipher-algorithms
openssl list -public-key-algorithms
```

The provider explicitly accepts OpenSSL `>=3.0,<4.0` (`src/crates/ikev2-crypto/src/lib.rs:78`). `libssl-dev` provides build headers; runtime shared libraries must match the executable's ABI (24.04 uses `libssl3t64`; 22.04 uses `libssl3`). Build on the target to avoid Arch glibc/ABI assumptions. `ldd` must resolve every dependency and the daemon startup log must report OpenSSL 3.x; the CLI `openssl` version alone does not prove which library the process loads. Run crypto tests under the service's actual environment: provider policy/FIPS settings can alter algorithm availability, including SHA-1 NAT hashing. No FIPS compatibility is claimed. Do not enable legacy algorithms or downgrade OpenSSL to bypass failures.

Check the selected address exists and both ports are free:

```sh
ip -4 addr show
ss -lunp 'sport = :500 or sport = :4500'
sysctl net.ipv4.ip_unprivileged_port_start
```

Use an external lab TOML with explicit local unicast address, UDP 500/4500, and default bounded handshake settings. Run `target/release/ikev2d /absolute/path/lab.toml` first: it validates then exits without binding. Full provider/bind checks require `--serve`. Verify invalid/wildcard config fails before serving. Do not change `ip_unprivileged_port_start`, enable forwarding, install XFRM policies, open ESP or grant `CAP_NET_ADMIN`/`CAP_NET_RAW`. Port 500 requires `CAP_NET_BIND_SERVICE` where the host's privileged-port threshold covers it; 4500 normally does not. A bind failure from occupied ports or a nonlocal IP must be investigated, not bypassed with root.

For an operator-approved restricted lab service, install the binary root-owned and non-writable by its dedicated unprivileged account `ikev2lab`, and a root-owned read-only config at `/etc/ikev2lab/m2.toml`. Account/directory creation and service installation are operator actions, not performed here. Example candidate systemd unit:

```ini
[Unit]
Description=Milestone 2 unauthenticated IKE_SA_INIT lab
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=ikev2lab
Group=ikev2lab
ExecStart=/opt/ikev2lab/ikev2d --serve /etc/ikev2lab/m2.toml
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
RestrictAddressFamilies=AF_INET AF_UNIX
RestrictSUIDSGID=yes
LockPersonality=yes
UMask=0077
LimitCORE=0
Restart=no

[Install]
WantedBy=multi-user.target
```

Do not enable at boot during validation. Do not use `PrivateNetwork=yes` (it hides the lab interface), or socket activation (the current binary does not accept inherited sockets). Prefer service-scoped capabilities to globally applying `setcap` to a development binary. If the host already allows unprivileged port 500, test removing both capability directives; record the result. Capture permission belongs to the operator's capture tool, not the daemon. Confinement reference: [Ubuntu security features](https://documentation.ubuntu.com/security/security-features/security-features-overview/).

Validate with `systemd-analyze verify /etc/systemd/system/ikev2lab.service`, start the unit, retain `systemctl status`, `journalctl -u ikev2lab`, `ss -lunp`, and `/proc/PID/status` UID/GID/CapEff/CapBnd/NoNewPrivs fields. Expect a nonroot UID, only necessary bind capability and no net-admin capability. Confirm both sockets bind only the intended address; confirm no control-plane/TCP listeners. Review actual service sandboxing with `systemd-analyze security ikev2lab.service`; its score alone is not acceptance. `NoNewPrivileges` must be 1. Record provider/startup failures and exit status. Never send signals to an unverified reused PID.

Restrict host/cloud ingress to the arranged phone or lab NAT source and UDP 500/4500, preserving administrative access. Review existing rules before making changes; no blanket firewall replacement or public ingress is prescribed. Complete the direct/NAT packet procedure above. Monitor service RSS/CPU under a bounded operator-generated workload, record limits and duration; do not infer whole-process memory bounds from pending-entry limits. Stop the service, confirm sockets close and no additional XFRM states/policies were installed (compare `ip xfrm state` / `ip xfrm policy` snapshots locally, protecting any preexisting production secrets). Remove only the lab's temporary access rules/profile and optional unit/account after evidence collection. Do not flush existing XFRM state or firewall rules.

**Ubuntu pass:** target-native build/tests succeed, supported shared OpenSSL loads, restricted nonroot process binds intended ports, positive/negative lab packets behave as specified, idle pending cleanup occurs and service stops cleanly. **Fail:** missing/unsupported libraries, panic, permission workaround requiring broad root, incorrect binding, secret logs, failed cleanup or unexpected kernel/network changes. Keep release-specific results and actual commands/exit codes in a separate operator report; none are asserted here.

## Git checkpoint

The checkpoint is prepared in the Git staging area for review, with the exact file list in `features/milestone_2_checkpoint_files.txt` and scope/preservation metadata in `features/milestone_2_git_scope.json`. It includes Milestone 2 implementation, authorization/design records, fixtures, smoke evidence, final campaign logs/metadata/starting corpus, this report and local validation evidence. Build outputs, mutable corpus, crash artifacts and full working-tree backup patches are excluded. The preexisting README branding change (`Harbor VPN`) is left unstaged; the checkpoint retains the original project name while updating its milestone number. All preexisting source contents and other tracked worktree bytes are preserved; only `src/fuzz/.gitignore` gained explicit final-evidence exceptions. The initial index was empty. Final verification confirmed exactly 97 manifest-listed files staged, no untracked nonignored files, only the unrelated README branding unstaged, unchanged HEAD and matching evidence hashes. Review with `git diff --cached --stat`, `git diff --cached` and `git diff -- README.md`. No commit or push is authorized by this report. Unrelated working-tree content must remain intact. ADR-001's pending certificate, verifier, IPv6, future XFRM privilege and control-plane decisions remain unresolved; the procedures above do not accept them.
