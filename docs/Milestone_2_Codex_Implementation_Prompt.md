# Codex — Milestone 2 implementation authorization

Read `AGENTS.md`, `docs/PRD.md`, `docs/TDD.md`, `docs/ADR-001.md`, the accepted `docs/ADR-002.md`, `docs/decision-register.md`, and the Milestone 1 report. Treat accepted ADR-002 as binding; if files have different names, locate the matching project documentation before proceeding.

## Objective
Implement a secure and testable **IKE_SA_INIT responder** in Rust using the existing Milestone 1 wire codec. Scope is restricted to the initial IKE security-association exchange. Do **not** implement IKE_AUTH, EAP-MSCHAPv2, user management, certificates for authentication, CHILD_SA/ESP, kernel XFRM, VPN traffic forwarding, or the control plane. An IKE_SA_INIT response is not a usable or authenticated VPN connection.

## Approved decisions
1. **Crypto suite:** AES-256-GCM-16 (ENCR_AES_GCM_16, key length 256), PRF-HMAC-SHA-256 (PRF_HMAC_SHA2_256), ECP group 19 (P-256). No separate integrity transform with AEAD. Do not silently negotiate alternative suites. Preserve unsupported proposal identifiers for diagnostics.
2. **Provider:** `openssl` crate with supported OpenSSL 3.x behind a project-owned `ikev2-crypto` interface. Reuse established cryptographic primitives only; never implement AES, P-256 or HMAC primitives yourself.
3. **Transport/state:** IPv4 UDP 500 and NAT-aware UDP 4500 (including non-ESP marker), correct NAT detection, bounded pending states, initiator retransmission/idempotence, controlled timeout/cleanup, and RFC 7296 COOKIE defense under load. Never introduce device concepts or caps on established user sessions.

## Sequence
1. Inspect the repo and the final Git checkpoint; do not modify unrelated tracked/untracked content. Review the source codec API and ADR-002. Report any blockers or conflicts before modifying the architecture.
2. Present a short implementation plan: crate boundaries, state transitions, error handling, crypto provider API, request/response fixtures, UDP behavior, DoS strategy and acceptance criteria. Then implement within this agreed scope; do not start Milestone 3.
3. Extend wire payload support only where necessary for the IKE_SA_INIT exchange and NAT detection. Keep parsing independent of negotiation semantics; ensure checked lengths, state-specific validation and safe error paths.
4. Implement ephemeral ECDH with validated P-256 public points, OS-backed CSPRNG, IKEv2 SKEYSEED/prf+ key schedule and nonce/SPI ordering per RFC 7296; ensure AES-GCM key/IV handling is ready for encrypted later exchanges without implementing IKE_AUTH. Use independent reference vectors where available.
5. Implement responder SA proposal selection, error notifications (`INVALID_KE_PAYLOAD`, `NO_PROPOSAL_CHOSEN`), responder SPI, nonce, NAT detection notifications, cookie challenge and validation, duplicate packet handling, and bounded pending state. Make operational caps configurable under safe ceilings.
6. Implement UDP 500 and 4500 transport with explicit packet size restrictions and the correct four-byte non-ESP marker on UDP 4500; expose non-privileged offline/integration test harnesses before live socket testing. Document permissions for privileged UDP 500 binding; do not change firewall, network namespace or systemd privileges without explicit approval.
7. Add golden wire tests, crypto vector tests, invalid group/point/proposal tests, retransmission/cookie/burst/timeout tests, error paths and relevant fuzzing. Document limitations and metrics without logging secrets.
8. Run `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`, and applicable fuzz smoke tests. Record test commands, pass/fail results, toolchain versions and environmental blockers. Do not claim iOS interoperability unless tested with native iOS, exact build/profile, real proposals and NAT environment.

## Deliverable
Write `features/milestone_2_report.md` including: files changed; implemented and intentionally excluded features; security and interoperability tests; failures or incomplete work; pending ADR decisions; how to run the responder in a safe test setup; and proposed follow-up. Do not implement IKE_AUTH, ESP or Milestone 3. Do not commit unrelated changes.
