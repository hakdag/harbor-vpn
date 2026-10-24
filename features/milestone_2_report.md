# Milestone 2 implementation and verification report

Date: 2026-10-17. Scope authority: accepted ADR-002 and `docs/Milestone_2_Codex_Implementation_Prompt.md`. Implementation is ready for review; native-client/deployment acceptance remains incomplete. **IKE_SA_INIT success is unauthenticated and does not create a usable VPN. Milestone 3 has not been started.**

## Delivered

- Added `ikev2-crypto`, `ikev2-core` and `ikev2-transport` crates under the existing `src/` workspace. The existing wire codec remains unchanged and independent of exchange/negotiation policy.
- Implemented only AES-256-GCM-16 (20, key-length 256), PRF-HMAC-SHA-256 (5), P-256/group 19 and no separate integrity transform. Unknown offers remain numeric diagnostics; there is no weaker-suite fallback or configuration switch enabling one.
- Added OpenSSL 3.x CSPRNG, fresh ephemeral P-256 ECDH, point validation before responder key generation, SKEYSEED/prf+ with nonce/SPI ordering, and AES-GCM provider operations with authenticated AAD, salt/IV composition, unique per-key IV counters and checked exhaustion. This does not build encrypted IKE exchanges.
- Implemented initial header/payload validation, suite selection, responder SPI/nonce, INVALID_KE_PAYLOAD, NO_PROPOSAL_CHOSEN, INVALID_SYNTAX, UNSUPPORTED_CRITICAL_PAYLOAD and INVALID_MAJOR_VERSION responses where safe. Malformed wire input is dropped independently of valid-but-unsupported proposals/features.
- Implemented bounded pending state, exact duplicate response caching without repeated DH or deadline renewal, conflict drops and monotonic expiration during traffic and idle ticks. Configurable defaults: global 1024, per-source IP 32, lifetime 10 seconds, COOKIE threshold 512, secret rotation 60 seconds; hard ceilings are documented in the protocol document.
- Added stateless context-bound HMAC COOKIE challenge/verification with current/previous secret epochs, placement/length checks, and load/capacity behavior. A validated cookie never bypasses the pending caps. These caps concern unauthenticated handshakes, not users, devices or authenticated session counts.
- Added bounded nonblocking IPv4 UDP adapter for logical UDP 500/4500, non-ESP marker, keepalive/ESP ignoring, oversize rejection, endpoint-correct NAT detection and response hashing. Explicit unicast local IPv4 addresses are required; wildcard binding is rejected.
- Added explicit `ikev2d --serve config.toml` opt-in. Default invocation still validates configuration and exits. High-port loopback lab config requires no low-port capability. Startup and once-per-second metrics log only metadata, rejection categories, counters and maximum processing time.
- Added independent Python stdlib golden request/response/cookie fixtures, key-schedule/NAT reference bytes, published crypto vectors, negative/state/loopback/CLI tests and two new fuzz targets. Application-owned secrets use zeroizing buffers and redacted Debug output; no claim is made about complete FFI/allocator/process-memory erasure.

Details: [initial-exchange design and safe operation](../docs/protocol/ike-sa-init.md), [decision register](../docs/decision-register.md).

## Verification

Commands were run from `src/` on the final implementation:

| Command | Result |
|---|---|
| `cargo fmt --all -- --check` | Exit 0 |
| `cargo clippy --workspace --all-targets -- -D warnings` | Exit 0, no warnings |
| `cargo test --workspace` | Exit 0: **48 tests passed**, none failed/ignored; doc tests passed |
| `cargo fmt --manifest-path fuzz/Cargo.toml --all -- --check` | Exit 0 |
| `cargo clippy --manifest-path fuzz/Cargo.toml --all-targets -- -D warnings` | Exit 0 |
| `cargo +nightly fuzz build` | Exit 0; all five targets built |
| Final five-target smoke command below | Runner exit 0; all preflights/runs exit 0; no reported sanitizer diagnostics |

The 48 tests comprise 21 existing codec tests, 14 core tests (13 integration + one stored-key agreement test), five crypto tests, three transport tests, three configuration tests and two CLI tests. The tests cover:

- Independent canonical request/response/cookie bytes; P-256 RFC 5903 §8.1, HMAC RFC 4231 case 1, AES-256-GCM known ciphertext/tag and independently generated Python HMAC key schedule/NAT hashes. Deterministic private scalars/providers are confined to tests; synthetic fixed shared material is confined to the fuzz harness.
- Actual random OpenSSL ECDH, initiator/responder derived-key agreement and test-only AES-GCM agreement; invalid/off-curve/noncanonical shares, wrong share lengths/groups, authentication failures on modified AAD/tag/ciphertext/IV, IV uniqueness/exhaustion, nonce/SPI/derivation bounds and redacted diagnostics.
- Required/duplicate payloads, every truncation of the golden request, unknown critical/noncritical payloads, valid payload reordering, invalid flags/SPIs/message IDs/exchange/version, higher minor versions and proposal number/alternative selection. Unsupported offers never cause fallback.
- Exact retransmissions without additional DH or deadline extension; conflicting retransmits; timeout/clock reversal; stateless context-bound cookies, rotation/previous-key expiry, misplaced/invalid cookie; 1000-request spoofed-SPI burst without extra DH after reaching capacity, source/global caps even with a valid cookie, entropy failure without pending insertion, and limits that cannot encode the mandatory response.
- Real unprivileged IPv4 loopback sockets through both transport channels, correct response NAT hashes, fresh ECDH, duplicate responses, marker/keepalive/ESP behavior, oversized UDP datagrams, idle expiry, wildcard rejection, and launching the actual CLI on ephemeral loopback ports. These are project test harnesses, not an independently developed IKE client.

### Final fuzz campaign

```sh
python3 fuzz/run_campaign.py --seconds 60 --targets message sa structured sa_init crypto_peer --results fuzz/results/milestone-2-final-smoke-20261017
```

Run outside the restricted sandbox with `ASAN_OPTIONS=detect_leaks=1:abort_on_error=1`, `LSAN_OPTIONS=exitcode=23`, explicit `--sanitizer address`, seed 20261017, maximum input 65,536 bytes, per-input timeout 10 seconds and RSS limit 512 MiB. Each target has a successful sanitizer preflight. The final campaign ran concurrently from 20:27:31 to 20:28:33 UTC; libFuzzer reported 61 seconds per target for the requested 60-second limit.

| Target | Executions | Average executions/s | Peak reported RSS MiB | Exit / sanitizer findings |
|---|---:|---:|---:|---|
| `message` | 8,307,369 | 136,186 | 420 | 0 / none reported |
| `sa` | 19,875,807 | 325,832 | 341 | 0 / none reported |
| `structured` | 5,518,312 | 90,464 | 440 | 0 / none reported |
| `sa_init` | 1,457,448 | 23,892 | 440 | 0 / none reported |
| `crypto_peer` | 474,971 | 7,786 | 478 | 0 / none reported |

Total: **35,633,907 executions**. No crash reproducer, timeout, OOM or sanitizer finding was produced. Source hashes were identical before/after and still match the delivered source. The `sa_init` target includes threshold-triggered COOKIE echo/retry and bounded second-state allocation; `crypto_peer` exercises real provider calls, authenticated round trips and malformed ciphertext/public shares. System OpenSSL is dynamically linked, not rebuilt with sanitizer instrumentation; this is not exhaustive coverage of its internals.

Evidence: [campaign statistics, commands, exit codes and log hashes](../src/fuzz/results/milestone-2-final-smoke-20261017/campaign.json), [environment, source/binary/corpus hashes and preflights](../src/fuzz/results/milestone-2-final-smoke-20261017/environment.json), and adjacent raw logs. The earlier five-target smoke also passed (36,356,511 executions), preserved separately in `milestone-2-smoke-20261017/`; the final campaign followed added metrics, constructor-limit coverage and stateful COOKIE fuzz checks. These are smoke campaigns, **not 30-minute campaigns for the new targets**. The historical M1 30-minute acceptance evidence is unchanged.

### Toolchain, dependencies and linkage

| Component | Observed version / status |
|---|---|
| Host | Arch Linux, x86_64; Ubuntu LTS not tested |
| Stable rustc | 1.97.1 (`8bab26f4f`, 2026-07-14) |
| Stable cargo | 1.97.1 (`c980f4866`, 2026-06-30) |
| Nightly rustc | 1.101.0-nightly (`5d8fec066`, 2026-10-16), fuzz tooling only |
| Nightly cargo | 1.101.0-nightly (`3960fa69b`, 2026-10-12) |
| cargo-fuzz | 0.13.2 |
| OpenSSL CLI/library/pkg-config | 3.6.5, 29 Sep 2026 |
| `openssl` crate | 0.10.81, Apache-2.0 |
| `openssl-sys` crate | 0.9.117, MIT |
| `zeroize` crate | 1.9.1, Apache-2.0 OR MIT |

`ldd target/debug/ikev2d` resolves `/usr/lib/libssl.so.3` and `/usr/lib/libcrypto.so.3`; no vendored OpenSSL build is enabled. Provider startup rejects a runtime outside OpenSSL major version 3. Applications still require an operator-maintained/supported library release. Brief deployment/license review: OpenSSL 3 uses Apache-2.0; Rust dependency license declarations were inspected locally. Preserve applicable notices and complete the full transitive dependency/security review before production packaging. Ubuntu needs a C toolchain, pkg-config and OpenSSL 3 development headers/libraries; exact supported Ubuntu LTS/library baseline remains A-08, not inferred from this Arch build.

### Environmental failures and limits

Initial sandboxed socket tests failed with `Operation not permitted`; rerunning the full suite outside the sandbox passed using only unprivileged loopback ports. Initial dependency/fuzz compilation encountered sandbox network restrictions and succeeded after the approved outside-sandbox retry. No sanitizer was disabled and no host tracing setting changed. Optional `cargo metadata --offline` could not enumerate every target-specific cached package (`valuable` was uncached); the actual builds, Clippy, tests and fuzz campaigns succeeded. Crypto dependency licenses were read from their installed manifests instead.

No genuine implementation defect or sanitizer finding remained after verification. Passing local tests/fuzzing does not establish protocol completeness, native-client interoperability or production readiness.

## Safe lab operation

```sh
cd src
# Validate and exit; no sockets.
cargo run -p ikev2d -- config/milestone-2-lab.toml
# Explicit opt-in, loopback high ports 15000 and 14500; Ctrl-C stops it.
cargo run -p ikev2d -- --serve config/milestone-2-lab.toml
```

The listener neither elevates privileges nor changes the host. For a separately configured native-client lab, use explicit local IPv4 addresses and UDP 500/4500. Where low-port policy restricts UDP 500, arrange narrowly scoped bind privileges and confinement through an operator review; do not default to unrestricted root. UDP 4500 normally needs no low-port capability. No firewall, network namespace, systemd unit, capability or sysctl has been modified. See the protocol document for binding limitations and proposed service confinement checks.

## Incomplete acceptance items and remaining decisions

1. **Native iOS and real NAT:** no device was available. Record exact iOS build, explicit profile settings, actual proposal capture, direct and real-NAT IKE_SA_INIT/retry behavior. No iOS or usable-VPN success is claimed.
2. **Target-host lab:** actual privileged UDP 500/4500 and Ubuntu LTS deployment/permissions were not tested. Both logical framing paths were tested over ephemeral loopback ports. No external-network packet capture or independently developed standards-client verification was performed. These ADR-002 acceptance gates remain open.
3. **Security depth:** longer scheduled campaigns for the new targets, broader load/latency measurement, independent protocol/security review and target OpenSSL patch/packaging/confinement review remain follow-up. Current threshold-based COOKIE defense is not a network rate limiter or comprehensive DDoS protection.
4. **Decisions:** INIT-01/02/03 are accepted only as narrowed by ADR-002; iOS interoperability evidence remains open. C-01–C-05 and C-07 are unchanged; C-06/A-01 remain open for native-client/ESP choices. Certificate trust/signature/lifecycle and isolation (A-02/A-05), authentication challenge-response API (C-02/C-07), compatible verifier format/custody (C-03/A-03), network/IPv6 choices (A-04), XFRM recovery/privilege design (A-05/A-06), later extension scope (A-07), Ubuntu baseline (A-08) and Phase 2 IPC (A-09) require their respective later review. No independent changes were made to PRD/TDD/ADR-001/ADR-002.

Intentionally excluded: IKE_AUTH, EAP-MSCHAPv2, credentials/users, certificate authentication, CHILD_SA/ESP, XFRM, forwarding/IP/DNS assignment, control-plane APIs, device registration/restrictions, established-session caps, fragmentation, MOBIKE and production DPD/rekey. Proposed next work is to close the outstanding Milestone 2 validation gates and review this change. Any Milestone 3 implementation requires separate approval.

## File inventory and Git scope

Starting checkpoint: `190dc5f` (`docs updated`), following M1 checkpoint `64b51dd`. At inspection the pre-existing untracked `docs/ADR-002.md` and `docs/Milestone_2_Codex_Implementation_Prompt.md` were present; both were read and left unmodified. No unrelated tracked changes were present initially. No commit, push, delete or overwrite of unrelated content was performed. Build outputs/mutable corpus remain ignored. Final changes are confined to the following approved project files:

Modified:

```text
README.md
docs/decision-register.md
src/Cargo.toml
src/Cargo.lock
src/bins/ikev2d/Cargo.toml
src/bins/ikev2d/src/main.rs
src/crates/vpn-config/Cargo.toml
src/crates/vpn-config/src/lib.rs
src/fuzz/.gitignore
src/fuzz/Cargo.toml
src/fuzz/Cargo.lock
src/fuzz/README.md
src/fuzz/run_campaign.py
```

Created:

```text
features/milestone_2_report.md
docs/protocol/ike-sa-init.md
src/bins/ikev2d/tests/cli.rs
src/config/milestone-2-lab.toml
src/crates/ikev2-core/Cargo.toml
src/crates/ikev2-core/src/lib.rs
src/crates/ikev2-core/src/policy.rs
src/crates/ikev2-core/src/cookie.rs
src/crates/ikev2-core/src/responder.rs
src/crates/ikev2-core/tests/handshake.rs
src/crates/ikev2-core/tests/fixtures/generate_reference.py
src/crates/ikev2-core/tests/fixtures/request.hex
src/crates/ikev2-core/tests/fixtures/response.hex
src/crates/ikev2-core/tests/fixtures/cookie.hex
src/crates/ikev2-crypto/Cargo.toml
src/crates/ikev2-crypto/src/lib.rs
src/crates/ikev2-crypto/src/tests.rs
src/crates/ikev2-crypto/tests/fixtures/generate_reference.py
src/crates/ikev2-crypto/tests/fixtures/schedule.json
src/crates/ikev2-transport/Cargo.toml
src/crates/ikev2-transport/src/lib.rs
src/crates/ikev2-transport/tests/loopback.rs
src/fuzz/fuzz_targets/sa_init.rs
src/fuzz/fuzz_targets/crypto_peer.rs
src/fuzz/seeds/sa_init/request
src/fuzz/seeds/sa_init/marker-request
src/fuzz/seeds/sa_init/truncated
src/fuzz/seeds/crypto_peer/valid-point
src/fuzz/seeds/crypto_peer/invalid-point
src/fuzz/seeds/crypto_peer/short
```

Created evidence directories `src/fuzz/results/milestone-2-smoke-20261017/` and `src/fuzz/results/milestone-2-final-smoke-20261017/` each contain these twelve retained files (24 evidence files total):

```text
campaign.json
environment.json
message-preflight.log
message.log
sa-preflight.log
sa.log
structured-preflight.log
structured.log
sa_init-preflight.log
sa_init.log
crypto_peer-preflight.log
crypto_peer.log
```
