# Milestone 1 final verification

Status: sanitizer and workspace verification passed. Milestone 2 is not implemented. The 64-file Git checkpoint is prepared in the staging area; a commit requires the missing Git author identity.

## Full-duration sanitizer results

All targets ran outside the restricted sandbox with AddressSanitizer and LeakSanitizer enabled (`--sanitizer address`, `-detect_leaks=1`, `ASAN_OPTIONS=detect_leaks=1:abort_on_error=1`, `LSAN_OPTIONS=exitcode=23`). All three preflights and full runs exited 0. No host tracing setting changed.

| Target | Completed seconds | Executions | Peak RSS MiB | Exit | Sanitizer findings |
|---|---:|---:|---:|---:|---|
| message | 1,801 | 239,955,056 | 460 | 0 | None reported |
| sa | 1,801 | 754,893,731 | 356 | 0 | None reported |
| structured | 1,801 | 171,518,122 | 370 | 0 | None reported |

Total: **1,166,366,909 executions**. All 36 recorded source/fixture hashes were unchanged before/after and verified against current files. No new crash artifacts were produced. No genuine defects were found; no protocol or fuzz-target implementation fixes were needed. The runner was improved only to protect and capture verification evidence.

Evidence directory: `src/fuzz/results/milestone-1-acceptance-20261017/`. `campaign.json` records commands, timestamps, exit codes, statistics, sanitizer diagnostics and log SHA-256; `environment.json` records source/binary/corpus hashes and sanitizer settings; `tools.json` records exact compiler/Cargo/LLVM/cargo-fuzz/Python versions. Six raw preflight/campaign logs are included in the allowlist. Earlier sandbox-failed evidence remains intact.

Toolchains: stable Rust **1.97.1**, nightly Rust **1.101.0-nightly (2026-10-16)**, cargo-fuzz **0.13.2**. Host: Arch Linux x86_64; this is not Ubuntu deployment or iOS interoperability validation.

## Workspace checks

After the campaigns, run from `src/`: `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`, and `cargo test --workspace` all passed. **23 tests passed**, zero failed. Fuzz-workspace formatting and Clippy also passed.

## Git checkpoint and preservation

The index was empty initially. The approved 64-file allowlist is `features/milestone_1_checkpoint_files.txt`; `features/milestone_1_git_scope.json` lists its scope and the **75 excluded pre-existing tracked changes**. These include `.cursor/` and `.taskmaster/` deletions, older PRD and Rust-scaffolding deletions, edits to `.env`, `.env.example`, `.gitignore`, and five supporting architecture documents. Their tracked file contents/deletions remain identical to the start-of-task baseline. Environment contents were neither printed nor staged.

Checkpoint scope includes only the approved workspace, fixtures/seeds, verification evidence, Milestone 1 plans/reports, wire/decision documentation, README and unchanged authoritative architecture inputs (`AGENTS.md`, PRD, TDD, ADR-001). Build outputs, mutable corpus, crash artifacts and unrelated changes are excluded. The original approved plan is unchanged.

Git has no configured author name/email. Those were requested asynchronously; no identity was invented. The staged snapshot was verified to match exactly the 64-file allowlist, with byte-for-byte staged-file checks, zero overlap with the 75 exclusions, and unchanged pre-existing tracked contents/deletions. No commit was created because Git author identity is unset.

## Required decisions before IKE_SA_INIT

Recorded as INIT-01 through INIT-03 in `docs/decision-register.md`; no pending choice is approved here:

1. Exact **IKE-only proposal policy**: algorithms/IDs/key lengths, PRF/DH, AEAD integrity handling, selection order and native-iOS test builds/offers.
2. Reviewed **crypto provider boundary** for the chosen DH/PRF, OS randomness, share checks, IKE key derivation and ephemeral-key protection.
3. Bounded **initial-handshake state/transport policy**: pending limits/timeouts, cookies/DoS, duplicates/retransmissions, NAT/4500 scope, and bind privileges before live UDP tests. Advertise only implemented extensions.

CA lifecycle, password-verifier storage, pool/DNS/IPv6, ESP/XFRM, full DPD/rekey/MOBIKE and Phase 2 IPC/revocation are later-work decisions. Ubuntu host selection gates live integration testing, not writing the offline exchange core. No Milestone 2 code was added.
