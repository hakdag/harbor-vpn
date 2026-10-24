# iPhone VPN PoC implementation report

Status: **ready for operator interoperability testing; no iPhone/VPS acceptance claimed**. This assignment supersedes the prior M3-only scope for initial CHILD_SA, XFRM and IPv4 networking. No control plane, device restrictions, Arch client, MOBIKE or advanced rekey was added. Nothing was deployed, staged, committed or pushed.

## Completed

- Preserved the existing certificate-authenticated RFC7296/EAP-MSCHAPv2 responder, encrypted disposable-user provisioning and systemd credential custody. IKE remains AES-256-GCM-16 / PRF-HMAC-SHA256 / ECP19, RSA3072/SHA256 with RFC7427; no trust or authentication fallback.
- Added `ikev2-core::child`: initial ESP AES256-GCM proposal selection, peer/responder SPIs, no-ESN negotiation, bounded configurable private IPv4 leases, full IPv4 selectors, CP address/DNS replies and final-AUTH-gated installation. Failed AUTH/install never advertises a working CHILD. Authentication-only mode retains its prior no-CHILD behavior.
- Added `ikev2-crypto::initial_child_keymat`: RFC7296 prf+(SK_d, Ni||Nr), 36-byte AES256 key/salt per direction, tested against independent Python HMAC output.
- Added `xfrm-linux`: direct NETLINK_XFRM exclusive creates with ACK/source/sequence checks, RFC4106 key/salt/tag framing, replay window, NAT-T endpoints, three tunnel policies, lease-bound SAD/SPD selectors, hard lifetimes and owned reverse-order rollback/cleanup. No shell or key-bearing command arguments in the runtime adapter. A narrowly isolated libc call enables UDP_ENCAP; protocol crates keep unsafe forbidden.
- Added encrypted INFORMATIONAL empty liveness replies and IKE/ESP deletes, strict IDs/tuple/cache handling, resource release on disconnect/expiry, fixed bounded session lifetime and SIGINT/SIGTERM cleanup. Reconnect obtains a free lease; kernel failure rollback releases it. Active CHILD count is exposed without secrets.
- Added operator-only scoped firewall/NAT setup/rollback, reserved-reqid crash reconciliation, example config/service/profile and short deployment/iPhone steps in [docs/iphone-poc.md](../docs/iphone-poc.md).

Exact source inventory and baseline/final hashes: [iphone_poc_scope.json](iphone_poc_scope.json). The baseline is the post-M3 working tree, not HEAD or the older staged M2 checkpoint. HEAD, index binary diff and unrelated README branding were verified unchanged; prior fuzz evidence was retained.

## Tests actually executed

| Check | Result |
|---|---|
| `cargo build --workspace --offline` | exit0 |
| `cargo fmt --all -- --check` | exit0 |
| `cargo clippy --workspace --all-targets --offline -- -D warnings` | exit0 |
| `cargo test --workspace --offline` | exit0, **90 passed**, one namespace-only test ignored in ordinary workspace run |
| Namespace-only kernel integration test, explicitly enabled | exit0: SAs/policies accepted; conflicting install rolled back; existing resource preserved; teardown and exact crash reconciliation removed owned objects; idempotent subsequent Drop |
| Rust XFRM adapter ↔ independent iproute2 peer, two temporary network namespaces | exit0: virtual-IP UDP round trip over RFC4106 ESP-in-UDP; encrypted forged inner source rejected |
| Scoped networking setup/cleanup in fresh namespace | exit0: NAT/filter rules accepted; unrelated sentinel chain and previous forwarding restored |
| Python syntax, password-free profile parse, Git whitespace check | passed |

New unit/integration coverage includes weak/incompatible ESP proposals and SPI/key-size/truncation rejection, selector narrowing, pool exhaustion/release, failed installation, no installation before final AUTH, multi-round CHILD/CP success, liveness/deletes/retransmits/expiry, config constraints, independent KEYMAT and graceful SIGTERM. All prior authentication tests remain passing.

[Evidence](poc_evidence/checks.json) retains commands, exit codes, source hashes and logs. Kernel/network tests ran in fresh user/network namespaces, never the host/VPS namespace. The first sandbox XFRM probe was denied; namespace tests were run with sandbox restrictions lifted. Initial namespace guarding via `/proc/1` was incompatible with proc permissions and was corrected to compare the parent namespace. Crash-cleanup testing also exposed iproute2's lack of XFRM JSON, annotated SPIs and statistics-only policy indexes; those issues were fixed and the exact cleanup path passed. Failed development attempts are labeled in retained logs. **No fuzz campaigns or comprehensive security audit were run during this PoC cycle.**

## Remaining gates and limits

1. **Native iOS/public certificate — unverified.** Need exact iOS build, suitable public chain/usage, actual SHA256/RFC7427 offers, certificate acceptance, EAP mutual completion and final AUTH. No public certificate was provisioned or trust bypass introduced.
2. **Ubuntu VPS/Internet — unverified.** Need actual systemd credential-copy ownership, OpenSSL/kernel crypto support, CAP_NET_ADMIN/bind behavior, configured pool/DNS, firewall ordering, IPv4 forwarding/MASQUERADE, TCP/MTU and public IPv4 egress. Local encrypted UDP proves the kernel path, not Internet routing or iPhone interoperability.
3. **Lifecycle — PoC scope.** Fixed hard lifetime defaults1800s; reconnect before expiry. Empty peer liveness requests are answered; no active responder probes, automatic rekey, MOBIKE or negotiated IKE fragmentation. Missing delete eventually expires. SIGKILL/lost ACK can leave objects until hard expiry or reviewed reserved-reqid reconciliation; do not flush unrelated state.
4. **IPv4 only.** No IPv6 address/route/leak protection claim. Use an IPv4-only test network first. No IncludeAllNetworks workaround or host IPv6 disablement.
5. **Privilege/ownership.** Nonroot service has broad CAP_NET_ADMIN within the host namespace. Adapter is a crate, not a separate privileged daemon. Reserve one conflict-free pool, reqid range and chain namespace; do not run concurrent owners. Runtime cleanup errors require operator reconciliation. Validate cleanup parsing on the target iproute2 release; unsupported formats fail instead of broad deletion.

Next operator step: review [the procedure](../docs/iphone-poc.md), provision the disposable identity/user, approve a source-restricted test window, then test connect → IPv4/DNS → HTTPS/public IPv4 egress → disconnect/reconnect. Record those results separately before calling the VPN working on the actual iPhone/VPS.
