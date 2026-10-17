# Milestone 1 implementation report

Acceptance follow-up: the full-duration clean sanitizer gate subsequently passed for all three targets. See [final verification](milestone_1_verification.md); the earlier failed-run details below are retained as history.

Status: offline implementation and ordinary checks complete. All three full-duration fuzz loops completed; sandboxed LeakSanitizer exit checks failed. Separate outside-sandbox sanitizer verification passed. A fully clean full-duration sanitizer exit gate remains unverified. No Milestone 2 work is authorized or implemented.

## Implemented behavior

- Four-member stable Rust workspace: wire codec, typed resource configuration, structured metadata logging, offline `ikev2d` entry point.
- Separate raw envelope decoding, typed structural decoding and explicit support checking. Malformed, Unsupported, Limit and InvalidLimits are separate error categories.
- Borrowed, bounded parser and serializer for headers, outer payload chains, SA/proposal/transform/TV/TLV attributes, KE, Nonce, Notify and Vendor ID. Unknown numeric identifiers are retained without negotiating algorithms.
- Correct opaque SK/SKF outer-chain termination; encrypted contents and later payload bodies remain unimplemented and explicit in support checking.
- Configurable limits with safe hard ceilings. Checked reads/writes, complete envelope consumption, nested length/count/termination checks, reserved-field receive/send handling and no unsafe Rust.
- Independent hand-authored golden fixtures, malformed/truncation/boundary tests, 512 cases per property test and three instrumented fuzz targets.
- Dedicated specification conflict/decision register; PRD, TDD and ADR source documents unchanged.

## Validation

Layout update: all workspace code, configuration, tests, fuzz tooling and generated build artifacts have moved under `src/`. Cargo commands run from `src/`. Historical campaign JSON/log paths and source-hash keys remain unchanged as provenance; resolve their workspace-relative paths against `src/` after relocation. The original approved plan is preserved unchanged.

Environment: Arch Linux x86_64, stable Rust 1.97.1, nightly 1.101.0-nightly (2026-10-16), cargo-fuzz 0.13.2. Declared workspace MSRV 1.97; no earlier compiler tested. Exact tool versions and codec/harness source hashes are recorded in `src/fuzz/results/final/environment.json`.

| Check | Result |
|---|---|
| `cargo fmt --all -- --check` | Passed |
| `cargo fmt --manifest-path fuzz/Cargo.toml --all -- --check` | Passed |
| `cargo clippy --workspace --all-targets -- -D warnings` | Passed |
| `cargo clippy --manifest-path fuzz/Cargo.toml --all-targets -- -D warnings` | Passed |
| `cargo test --workspace` | Passed: 23 tests (17 codec, 4 resource-policy/serializer, 2 configuration); 0 failures |
| `cargo run -p ikev2d -- config/milestone-1.toml` | Passed; metadata event then exit, no listener |
| Final 30-minute campaign per target | Each completed 1,801 seconds; no codec findings; exit 1 from sandboxed LeakSanitizer tracing restriction |
| Outside-sandbox sanitizer verification | All three targets passed, 61 seconds each, exit 0; all three empty artifacts replayed with exit 0 |

The first negative-test run exposed an incorrect test mutation: changing the numeric key-length value is not a structural error without negotiation context. That expectation was corrected. No parser defect was involved.

## Fuzz evidence

Three independent targets run concurrently with AddressSanitizer, seed 20261017, 65,536-byte input cap, 10-second per-input timeout and 512 MiB RSS limit. Synthetic checked-in seeds are supplemented by a mutable corpus from preparatory runs. Preparatory results are separate from the final-source campaign.

The complete final commands, timestamps and original exit statuses are in `src/fuzz/results/final/campaign.json`; extracted statistics and classification are in `src/fuzz/results/final/summary.json`. Local ignored logs are `src/fuzz/results/final/message.log`, `sa.log`, `structured.log`.

| Target | Executions | Completed seconds | Peak RSS MiB | Exit |
|---|---:|---:|---:|---:|
| message | 239,197,438 | 1,801 | 389 | 1 |
| sa | 499,733,745 | 1,801 | 295 | 1 |
| structured | 155,345,206 | 1,801 | 400 | 1 |

Total: 894,276,389 executions. All three logs show DONE and full statistics before LeakSanitizer reports that tracing is unavailable. This is not a clean sanitizer pass. Each generated artifact is the zero-byte input (SHA-1 `da39a3ee5e6b4b0d3255bfef95601890afd80709`); all replay successfully outside the sandbox with leak detection enabled. No parser assertion, timeout, OOM or memory-safety finding was reported during the loops. No codec repair or codec regression fixture was needed for this tooling failure.

Outside-sandbox follow-up retained both sanitizers and passed with exit 0: message 8,188,646 executions, SA 24,871,369, structured 6,275,077; each ran 61 seconds. Exact commands and evidence are in `src/fuzz/results/verification.json` and local `verification-*.log`. No sanitizer was disabled and no host tracing setting was changed. Preparatory-run evidence is retained separately in `src/fuzz/results/campaign.json`; it also encountered the same exit-time restriction and is not counted in final-source statistics.

## Incomplete and intentionally deferred items

- Full-duration clean sanitizer exit remains unverified: the 30-minute loops finished but their LeakSanitizer exit checks were sandbox-blocked. The outside-sandbox follow-up covers 61 seconds per target, not a replacement 30-minute clean-exit campaign.
- Ubuntu LTS/kernel validation has not run: the available host is Arch Linux. No deployment or native iOS interoperability is claimed.
- No CI provider workflow was configured; bounded smoke and scheduled-campaign commands are documented for later CI integration.
- No live native-client captures are available. Golden fixtures are synthetic structural examples, including a deliberately short group-19 KE value, not usable cryptographic handshake vectors.
- Opaque payload bodies are not validated beyond their envelopes. No encrypted-content validation/decryption, SKF reassembly, identity/certificate/AUTH/EAP/configuration/traffic-selector/delete body implementation is claimed.
- Exchange-context checks remain outside this milestone: offer/response proposal binding, initial/rekey SPI requirements, required payload sets, transform combinations, group-specific KE validation, notification semantics, message windows, peer state and authentication.
- No sockets, credentials, cryptographic operations, algorithm selection, XFRM, routes, DNS provisioning or control plane.

Remaining architecture decisions are listed in `docs/decision-register.md`: exact client/suite matrix, CA/signature lifecycle, verifier protection/key custody, pool/DNS/IPv6, privilege isolation, XFRM lifecycle/recovery, fragmentation/DPD/rekey/MOBIKE, Ubuntu baseline and Phase 2 IPC/revocation semantics. No pending ADR decision was approved by implementation.

## Created files

The inventory below covers project source, fixtures, seeds, lockfiles, documentation and retained campaign summaries. Build products, mutable coverage corpus and local runtime logs are generated artifacts, listed separately by directory. Existing working-tree deletions and previously untracked specification/plan files were left untouched.

- `src/Cargo.lock`
- `src/Cargo.toml`
- `README.md`
- `src/bins/ikev2d/Cargo.toml`
- `src/bins/ikev2d/src/main.rs`
- `src/config/milestone-1.toml`
- `src/crates/ikev2-wire/Cargo.toml`
- `src/crates/ikev2-wire/src/decode.rs`
- `src/crates/ikev2-wire/src/encode.rs`
- `src/crates/ikev2-wire/src/lib.rs`
- `src/crates/ikev2-wire/src/limits.rs`
- `src/crates/ikev2-wire/src/raw.rs`
- `src/crates/ikev2-wire/src/types.rs`
- `src/crates/ikev2-wire/tests/codec.rs`
- `src/crates/ikev2-wire/tests/fixtures/encrypted.hex`
- `src/crates/ikev2-wire/tests/fixtures/multiple-proposals.hex`
- `src/crates/ikev2-wire/tests/fixtures/notify-vendor.hex`
- `src/crates/ikev2-wire/tests/fixtures/sa-init.hex`
- `src/crates/ikev2-wire/tests/limits.rs`
- `src/crates/vpn-config/Cargo.toml`
- `src/crates/vpn-config/src/lib.rs`
- `src/crates/vpn-observability/Cargo.toml`
- `src/crates/vpn-observability/src/lib.rs`
- `docs/decision-register.md`
- `docs/protocol/wire-codec.md`
- `features/milestone_1_report.md`
- `src/fuzz/.gitignore`
- `src/fuzz/Cargo.lock`
- `src/fuzz/Cargo.toml`
- `src/fuzz/README.md`
- `src/fuzz/fuzz_targets/message.rs`
- `src/fuzz/fuzz_targets/sa.rs`
- `src/fuzz/fuzz_targets/structured.rs`
- `src/fuzz/results/campaign.json`
- `src/fuzz/results/final/campaign.json`
- `src/fuzz/results/final/environment.json`
- `src/fuzz/results/final/summary.json`
- `src/fuzz/results/verification.json`
- `src/fuzz/run_campaign.py`
- `src/fuzz/seeds/message/encrypted`
- `src/fuzz/seeds/message/notify-vendor`
- `src/fuzz/seeds/message/sa-init`
- `src/fuzz/seeds/message/truncated`
- `src/fuzz/seeds/sa/multiple-proposals`
- `src/fuzz/seeds/sa/proposal`
- `src/fuzz/seeds/sa/truncated`
- `src/fuzz/seeds/structured/basic`

Generated local artifacts: `src/target/`, `src/fuzz/target/`, `src/fuzz/corpus/`, `src/fuzz/results/*.log`, `src/fuzz/results/final/*.log`, and the three empty LeakSanitizer exit artifacts under `src/fuzz/artifacts/`. No existing project files were modified during the original implementation; relocation documentation updates are listed below.

## Source layout relocation

Moved `Cargo.toml`, `Cargo.lock`, `crates/`, `bins/`, `config/`, `fuzz/` and generated `target/` into `src/`. Updated the root README, this report, codec documentation and fuzz README for the new layout. Protocol source, fixtures, seeds, manifests, lockfiles and historical fuzz evidence were preserved byte-for-byte. No protocol behavior changed.

Relocation verification from `src/`: workspace and fuzz formatting checks passed; workspace and fuzz Clippy checks passed with warnings denied; all 23 tests passed; the offline binary accepted `config/milestone-1.toml` and exited successfully; the campaign runner help command resolved correctly. The long fuzz campaign was not repeated for this path-only change.
