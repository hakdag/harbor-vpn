# Codex Implementation Authorization — Milestone 3: IKE_AUTH and EAP-MSCHAPv2

**Project:** Custom Rust VPN server  
**Decision authority:** PRD v0.3, TDD v0.2, ADR-001, ADR-002, **ADR-003 v1.0 (Accepted)**  
**Status:** Approved to implement Milestone 3 only; no deployment or later milestone authorized.

## 1. First inspect, then plan

Read `AGENTS.md`, `docs/PRD.md`, `docs/TDD.md`, `docs/ADR-001.md`, `docs/ADR-002.md`, and **`docs/ADR-003.md`**, together with existing core/crypto/wire/transport, tests, and Milestone 2 remediation evidence. If names or paths differ, locate their actual counterparts; do not assume absent files. Confirm which Milestone 2 source revision is the starting point and inspect `git status`. Preserve unstaged branding, unrelated changes, and prior fuzz artifacts.

Before writing code, produce a short in-session implementation plan with crate responsibilities, RFC 7296 message sequencing, test checkpoints, and any detected source/document conflicts. When an architecture/security decision is genuinely missing, **stop that subtask and ask**, rather than inventing a protocol variation. Work incrementally in small testable steps.

## 2. Non-negotiable architecture

- Keep the accepted **AES-256-GCM-16 / PRF-HMAC-SHA-256 / ECP group 19** IKE SA suite and OpenSSL 3 provider boundary from ADR-002. Never silently add a weaker fallback.
- Use **standard certificate-authenticated IKEv2 responder with EAP-MSCHAPv2 user authentication** (RFC 7296); **not** RFC 5998 EAP-only mode.
- No client certificates, device registration/identifiers/limits, PSK client authentication or external VPN server implementation.
- Public CA strategy for `vpn.hypervault.biz`, initially RSA-3072/SHA-256 subject to proper protocol signing format and verified iOS acceptance. A public HTTPS certificate is **not automatically** suitable for IKEv2. **Do not weaken trust validation or silently substitute a private CA**; report an interoperability blocker with evidence if necessary.
- No Phase 2 control plane, REST endpoints, IP pool, DNS, routing, first CHILD_SA installation, ESP or XFRM in this milestone.
- No production credentials, private keys or plaintext secret material in the repository. No insecure lab fallback to bypass failed authentication.

## 3. Implementation work packages

### M3-A — Protected IKE_AUTH wire/crypto

Implement checked parsing and serialization for the IKE_AUTH-relevant IDi/IDr, CERT, CERTREQ, AUTH, EAP, configuration/SA/traffic-selector *envelopes* needed to parse IKE_AUTH without promising CHILD_SA installation, and protected SK payload framing. Follow RFC 7296 payload chaining inside decrypted SK; enforce authenticated decryption **before interpreting inner payloads**. Validate AEAD AAD, direction-dependent keys, nonce/IV uniqueness, tag validation, message IDs and bounded lengths. Keep unknown/critical payload behavior standards-conforming. Add independent goldens and tamper tests (AAD, nonce, ciphertext, tag, truncated payloads, wrong direction).

### M3-B — Server identity and RSA signature AUTH

Introduce a bounded server-certificate loader/signing provider using OpenSSL 3. Validate key/certificate match, SAN hostname, time validity, trust-chain/provisioning expectations, signing permissions and relevant key-usage/EKU compatibility. Implement RFC-conforming signed-octets/AUTH calculations and correct signature authentication payload encoding, including RFC 7427 negotiation if required by observed client behavior. Test offline with independent signed transcripts and negative cases (wrong identity, wrong key, expired cert, invalid chain/usage, malformed signature). Certificate **verification by iOS**, not merely local loading, is an acceptance gate. Avoid logging keys, decrypted protected payloads or transcript secrets.

### M3-C — EAP-MSCHAPv2 verifier and key custody

Implement the multi-round, mutually authenticated EAP-MSCHAPv2 exchange, including challenge generation, username binding, NT response verification, authenticator response, EAP success/failure, EAP-derived keying material and **final IKE AUTH confirmation**. Do not mark the SA authenticated based on EAP Success alone. Use well-vetted crypto providers (do **not** implement MD4/DES primitives from scratch); validate against independent RFC 2759 and relevant IKEv2 key-derivation vectors. Identify weak/unsupported provider algorithms early rather than globally enabling OpenSSL legacy mode or silently changing the password protocol.

For Phase 1 use encrypted per-user NT-hash-equivalent verifiers and a **separate root-owned `0600` lab master-key file outside source control**; use reviewed AEAD with random nonces, versioned records and error handling. Never store plaintext VPN passwords or assume Argon2/bcrypt-alone works for MSCHAPv2. Document secure provisioning, file/service-account access, fail-closed behavior, revocation and rotation implications. No `POST /auth/verify {password}` API.

### M3-D — Stateful exchanges and error paths

Extend the post-INIT state machine with strict SPI/session binding, expected request/response message IDs, EAP sequencing, encrypted response caching and retransmission handling, duplicate/replay rejection, bounded memory/work, timeouts and secret cleanup. Maintain the Milestone 2 admission controls and diagnostics safeguards. On any authentication failure never install CHILD_SA, grant IP configuration or claim an operational VPN. Explicitly preserve future state distinctions such as `AWAIT_AUTH_REQUEST`, `SERVER_AUTH_SENT`, `EAP_IN_PROGRESS`, `AWAIT_FINAL_AUTH`, `AUTHENTICATED`, `FAILED` (precise identifiers may vary).

### M3-E — Tests, fuzzing, and observability

Add deterministic independent wire/signature/EAP test vectors, unit and negative tests, multi-round integration tests, fuzz targets at encrypted-payload/EAP boundaries, and bounded structured state-transition diagnostics that omit secret values and plaintext credentials. Verify error responses do not leak username existence when feasible. Run:

```bash
cd src
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo fmt --manifest-path fuzz/Cargo.toml --all -- --check
cargo clippy --manifest-path fuzz/Cargo.toml --all-targets -- -D warnings
```

Run sanitizer-enabled fuzz smoke for changed targets and retain source hashes, commands, durations, exit codes and diagnostics; propose final longer campaigns before production acceptance. Preserve earlier campaign evidence. Re-test Ubuntu/OpenSSL 3 compatibility when operator access is provided; **do not change the VPS or firewall** autonomously.

## 4. Manual native iOS acceptance plan — not automatic authorization

Prepare a step-by-step source-restricted test plan using a disposable user, safely provisioned publicly trusted server certificate and matching RemoteIdentifier. Verify iOS version, certificate issuance/chain/usage, actual packet offers and progression through IKE_AUTH. Avoid transmitting actual passwords in report files, verbose logs or pcaps (EAP payloads are encrypted, but captures are still sensitive). Separate observed server identity acceptance, EAP completion, final AUTH validation and CHILD_SA absence. VPN **connection failure may still be expected** without CHILD_SA. Do not publicly expose the incomplete responder or install real certs on the existing Linode automatically.

## 5. Deliverables and stop rule

Deliver:

1. Milestone 3 implementation in the existing Rust workspace and focused tests.
2. Updated `docs/protocol/ike-auth.md` with RFC state/message sequence, approved crypto/auth assumptions, certificate provisioning and limitations.
3. Test/fuzz evidence with reproducible commands and any remaining issues ranked by severity.
4. `features/milestone_3_report.md` with detailed change inventory, validated vs unvalidated claims, and future acceptance gates.
5. Git diff/commit-scope proposal preserving unrelated work. **Do not commit or push without approval.**

**Stop at Milestone 3.** Do not implement CHILD_SA, ESP/XFRM, IP configuration, forwarding, Phase 2 control plane, Windows support, or production deployment. If public-CA certificate suitability or standard EAP-MSCHAPv2 provider support is blocked, report the exact blocker and do not compromise protocol security to make the test pass.
