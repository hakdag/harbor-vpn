# Milestone 2 review remediation

Date: 2026-10-18. Scope: M2-R1, M2-R2 and M2-R3 only. ADR-002's AES-256-GCM-16 / PRF-HMAC-SHA-256 / group-19 suite and offline-core/crypto/UDP/daemon boundaries are preserved. Native iOS/direct-and-NAT and Ubuntu acceptance remain pending. No commit or push.

## Changes and finding disposition

| Finding | Remediation | Evidence |
|---|---|---|
| M2-R1 (Low) | `ikev2-core/src/responder.rs` ignores CERTREQ's critical bit; the payload remains opaque. No certificate processing. | Regression compares deterministic responses with the bit clear/set, including opaque contents; independent loopback probe now receives successful INIT for both variants. [RFC 7296 §§2.5/3.2](https://www.rfc-editor.org/rfc/inline-errata/rfc7296.html). |
| M2-R2 (Medium deployment risk) | New `ikev2-core/src/work.rs`: global/per-source token buckets before decoding or crypto, bounded source tracking, silent over-limit drops, monotonic refill and safe expiry. `policy.rs`, `vpn-config/src/lib.rs` and the lab TOML expose validated settings. `responder.rs` preserves COOKIE/pending caps and schedules pending scans by earliest deadline; expiry continues during denied traffic/idle ticks. | Fractional refill, burst cap, clock reversal, fixed source capacity/reclamation, no expiry token reset, port/source/socket sharing, no DH/reply on denial, cached reply admission, COOKIE retry and hard pending caps. |
| M2-R3 (Low) | `ikev2-core/src/responder.rs` exports numeric allowlisted proposal metadata and actual selected proposal. `ikev2-transport/src/lib.rs` passes bounded samples to `ikev2d/src/main.rs`, which emits structured scalar JSON records for offers, selection and NAT comparisons; counters expose suppressed samples and admission drops. | Tests check truncation, selection beyond truncation, both NAT-match/change outcomes, absent NAT, queue ceiling, shared sampling rate, JSON field types and exclusion of synthetic payload/attribute sentinels. |

Additional files: core public exports; focused core/transport/CLI/config tests; `ikev2d/Cargo.toml` plus workspace lockfile (wire crate is a **test-only** dependency); `fuzz_targets/sa_init.rs` and two synthetic CERTREQ seeds; protocol documentation, report/evidence and log-ignore exceptions. Crypto provider, wire codec and accepted ADR-002 are unchanged.

## Executed checks

| Executed check | Result / exit |
|---|---|
| Workspace and fuzz-manifest stable rustfmt checks | Pass / 0 each |
| `cargo clippy --workspace --all-targets -- -D warnings` | Pass / 0 |
| `cargo test --workspace` outside sandbox | **61 passed** / 0 |
| Saved CERTREQ loopback probe | Both variants accepted / 0 |
| `sa_init` ASan/LSan smoke | 61 seconds; 1,718,942 executions; no diagnostics / **0** |
| `crypto_peer` ASan/LSan smoke | 61 seconds; 615,776 executions; no diagnostics / **0** |

Runner exit 0; both sanitizer preflights exit 0; source hashes before/after match. Starting corpora are archived for reproduction; SHA256SUMS verify retained artifacts. Exact commands and statuses are in `milestone_2_remediation_evidence/checks.json`. Raw check logs, a protocol probe, structured diagnostic examples, host/toolchain metadata, source/binary/corpus hashes and checksums are retained under `features/milestone_2_remediation_evidence/` and `src/fuzz/results/milestone-2-remediation-smoke-20261018/`.

The initial development run caught a test-fixture borrow-check error, corrected before validation. A sandbox run then failed the UDP integration tests because socket creation was denied; the outside-sandbox rerun permits only the existing loopback test behavior and is the validation result. Nightly lacks rustfmt; formatting uses installed stable rustfmt for both manifests. Sanitizer smoke uses nightly cargo-fuzz with ASan and integrated LeakSanitizer enabled; no sanitizer/tracing setting is weakened.

The accepted 1801-second-per-target campaigns remain preserved as **baseline evidence**. This remediation changes source and is covered by the new smoke run, not a claim that those earlier full-duration runs tested these changes. Shared system OpenSSL is not rebuilt with sanitizer instrumentation.

## Remaining risks and operator validation

The three findings are remediated in code/tests; M2-R2's broader DDoS/reflection deployment risk remains. Defaults are global 200 work permits/s with burst 400, per-source 20/s with burst 40; limits are shared across both UDP sockets and include retransmission/error/COOKIE work. Source tracking caps at 1024; diagnostic storage caps at eight samples, at most one new sample/s, four proposals × eight transforms/sample. Details, accepted ranges, byte/work bounds and retention rules are in `docs/protocol/ike-sa-init.md`.

Distributed/spoofed traffic can starve the shared budget, fill the source table and exhaust kernel/NIC resources. Admitted unauthenticated traffic can still cause replies before address proof; response opportunities are bounded, reflection is not eliminated. NATed clients share an IP quota; overload can suppress retransmissions and useful diagnostics. This is not measured whole-host CPU/memory/bandwidth or production DDoS protection. Keep source-restricted labs, assess upstream/host filtering and log retention, and tune only after Ubuntu load measurements.

Operator steps (not executed here): follow the iOS and Ubuntu procedures in `milestone_2_final_verification.md`; record exact iOS build/profile/packet capture, successful progression to the deliberately unsupported IKE_AUTH, direct and real-NAT hashes, target OpenSSL linkage, low-port least privilege and cleanup. Also induce a bounded lab burst with low admission settings: verify `rate_limited` rises, reply count is capped, COOKIE/pending limits hold, pending expiry continues and normal negotiation resumes after refill. Confirm sample/truncation/suppression fields against a capture at a low traffic rate; absence of a sample is not proof of absence of a packet. No native interop, Ubuntu deployment, certificate trust or VPN routing claim is made.

## Git preservation

The previously prepared staging area and unrelated README branding are preserved. Remediation changes remain separately reviewable with `git diff`; baseline HEAD, index patch hash and worktree hashes are retained in `milestone_2_remediation_evidence/baseline.json`. No reset, commit, push, privilege configuration or external deployment was performed.
