# Milestone 3 implementation and verification

Date: 2026-10-18. Scope: M3 only under accepted ADR-003 v1.0 and explicit implementation authorization. Local implementation is complete; native interoperability and target-host acceptance remain pending. No commit, push, deployment, real certificate issuance or VPS/firewall change was performed.

## Starting revision and preserved work

HEAD was `190dc5f07f345df36cf68a5de24a108fd6fc83b9`. The actual source baseline was the **remediated M2 working tree**, not HEAD or the older staged M2 checkpoint. Its source hashes matched the retained M2 remediation smoke environment. [baseline.json](milestone_3_evidence/baseline.json) records those hashes, starting status, index-patch hash and unrelated README branding hash. ADR-003 and the operator's M3 authorization document were already present and are not rewritten. The older staged checkpoint, M2 remediation, historical fuzz artifacts and unrelated README changes are preserved.

ADR-003 describes native INIT-to-AUTH progress; the earlier M2 evidence still says native acceptance pending and no corresponding native capture is available here. That claim is not upgraded into observed M3 evidence. PRD/TDD older certificate/storage questions are resolved only to the extent explicitly accepted by ADR-003 and this session. One missing custody detail was resolved by the operator: root-owned 0600 master source handed to the nonroot service through **systemd LoadCredential**, validating the protected copy. No alternative trust or password protocol was invented.

## Change inventory

| Area | Files | Implemented behavior |
|---|---|---|
| Inner wire | `src/crates/ikev2-wire/src/auth.rs`, `src/lib.rs`, `tests/auth.rs` | Bounded IDi/IDr, CERT/CERTREQ, AUTH, EAP, CP/SA/TS envelopes; payload chains; known/unknown critical handling; truncation/size tests |
| Protected messages | `src/crates/ikev2-crypto/src/protected.rs`, `src/tests.rs` | AES-GCM SK AAD/framing, direction keys/IVs, tag-first parsing, tamper/truncation tests; reserved header bits ignored while I/R enforced |
| Server identity | `src/crates/ikev2-crypto/src/identity.rs` | OpenSSL RSA3072/SHA256 signer, RFC7427 AUTH, exact signed octets/final MSK AUTH, bounded leaf/chain/key checks, lifetime checks, fixed system trust and fail-closed policy |
| Password crypto | `src/crates/ikev2-crypto/src/mschap.rs` | Private OpenSSL legacy-provider context for MD4/DES, RFC2759/3079 verification/authenticator response/MSK, no global algorithm changes |
| Independent vectors | `src/crates/ikev2-crypto/tests/fixtures/{auth-reference.json,generate_auth_reference.py}`, crypto test module | Python/PyCA-generated SK/RSA/signature/transcript/HMAC goldens plus published MSCHAP/MPPE vectors; only synthetic data/public keys retained |
| Authentication custody | NEW `src/crates/vpn-auth/{Cargo.toml,src/*,examples/provision.rs}` | Encrypted versioned verifier records, random AEAD nonces/bound AAD, dummy unknown-user work, revocation-enabled bit, bounded cooldown, strict EAP sequencing, protected systemd-copy loader, offline single-user provisioning example |
| Stateful responder | `src/crates/ikev2-core/src/{auth_exchange.rs,responder.rs,lib.rs}`, `tests/handshake.rs` | Explicit AUTH/EAP/final-AUTH states, both SPIs/tuple/message binding, encrypted duplicate cache, fixed deadlines, immediate failed-secret cleanup; final no-CHILD notification; M2 work/COOKIE/table protections preserved |
| Daemon/config/diagnostics | `src/bins/ikev2d/{Cargo.toml,src/main.rs,tests/cli.rs}`, `src/crates/vpn-config/src/lib.rs`, `src/crates/ikev2-transport/src/lib.rs`, `src/config/milestone-3-lab.toml` | Explicit auth opt-in; credential validation before bind; nonroot service boundary; bounded static state events/aggregate counters; NAT evaluation diagnostic now follows actual NAT presence; loopback-only lab example |
| Build/fuzz | Workspace/core/crypto manifests and lockfiles; `src/fuzz/{Cargo.toml,Cargo.lock,run_campaign.py,.gitignore,fuzz_targets/{protected_auth,eap}.rs,seeds/{protected_auth,eap}/*}` | New crate/dependencies, x509-parser extension checks, protected/EAP fuzz targets, retained sanitizer evidence. Existing target semantics preserved |
| Documentation | `docs/protocol/ike-auth.md`, this report, M3 evidence/scope manifests | RFC sequence, certificate/custody/provisioning procedure, exact operator iOS settings/capture/outcome criteria, Ubuntu/service validation and limitations |

The wire row's `src/lib.rs` and crypto row's `src/tests.rs` are relative to their listed crate. The scope JSON contains exact paths and baseline/final hashes, distinguishing M3 changes from existing M2 work.

## Executed checks

Final commands, run from `src`, all exited **0**:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo fmt --manifest-path fuzz/Cargo.toml --all -- --check
cargo clippy --manifest-path fuzz/Cargo.toml --all-targets -- -D warnings
```

**79 tests passed**, including all existing M2 tests. [Raw logs and check metadata](milestone_3_evidence/checks.json) are retained. Workspace tests ran outside the sandbox to permit real local UDP socket tests; no external server was accessed.

Focused evidence includes independent frozen AES-GCM SK bytes, signed-octets and RSA/HMAC checks; all SK truncations and AAD/IV/ciphertext/tag/direction mutations; certificate SAN/key/chain/KU/EKU/expiry and malformed-signature rejection; RFC2759 response/authenticator and RFC3079 receive/send/MSK; encrypted-store corruption/wrong-master/truncation; copy ownership/mode/no-symlink checks; generic unknown/disabled/wrong-name/cooldown outcomes; and explicit failure before bind without credentials.

Six added core integration tests exercise the complete multi-round exchange plus wrong NT response, wrong final AUTH, unsupported critical inner payload, missing RFC7427 capability and fixed timeout. The full exchange checks real cryptography, authenticated 500-to-4500 port movement, wrong SPI/tag/ID/altered duplicate rejection, exact ciphertext retransmissions, mutual method response, EAP Success remaining unauthenticated, both final MSK AUTH values and no CHILD/CP success payload. This harness uses an in-memory synthetic signer/certificate envelope for state testing; separate identity unit tests validate ephemeral test certificates. It is **not** evidence that a real public certificate or iPhone accepted the server. Existing transport integration exercises actual unprivileged loopback UDP; no fully provisioned M3 systemd daemon/iOS UDP exchange was run.

Sanitizer smoke uses ASan with integrated LSan, `detect_leaks=1`, seed20261018, 65536 maximum input, timeout10, RSS512MiB per target. The initial sandbox preflight failed: instrumented exit77 / cargo-fuzz exit1 / runner exit1 because LSan could not inspect threads under ptrace restrictions. No campaign began in that attempt. Its diagnostics are preserved at `src/fuzz/results/milestone-3-smoke-20261018`. Unrestricted rerun and final revised-source run are separately retained, without disabling leak checks. See final [campaign.json](../src/fuzz/results/milestone-3-final-smoke-20261018/campaign.json) and [environment.json](../src/fuzz/results/milestone-3-final-smoke-20261018/environment.json) for per-target exact commands, durations, exit codes, diagnostics, source and binary hashes. Initial corpora are archived for reproducibility. Historic M2 campaigns were not replaced.

Final revised-source results (each completed **61 seconds**, each exit **0**, no ASan/LSan diagnostics):

| Target | Executions |
|---|---:|
| sa_init | 1,299,121 |
| crypto_peer | 491,111 |
| protected_auth | 461,100 |
| eap | 37,824 |

Source hashes were unchanged throughout the campaign and match the final checked source. Archive/log/metadata hashes are in each campaign's `SHA256SUMS`.

Fuzz smoke is a regression check, not exhaustive assurance. Before production acceptance propose at least 30 minutes each for protected_auth, eap, sa_init and crypto_peer on a fixed reviewed source revision, then additional full-exchange state fuzzing and sustained bounded-load testing. Longer M3 campaigns were not run here.

## Findings and remaining risks

| ID / severity | Evidence and effect | Required action / gate |
|---|---|---|
| M3-01 **High acceptance blocker** | `identity.rs` public-CA candidate uses serverAuth/SSL_SERVER local checks; no real issuance/chain/iOS IKE evidence. An HTTPS certificate is not proof of IKE suitability; local OS trust may include admin roots. | Audit public issuance/usage/trust, test actual RSA3072/RFC7427/SHA256 acceptance on target iOS; reject any need for trust bypass/private CA substitution. |
| M3-02 **High acceptance blocker** | Core full-round evidence is offline; no native packet/log evidence of certificate acceptance, EAP mutual authentication or final AUTH. | Execute source-restricted iPhone procedure; distinguish each phase and expected no-CHILD connection failure. |
| M3-03 **Medium operational gate** | `vpn-auth/credentials.rs` protected-copy tests do not exercise actual systemd mount/ownership. Local OpenSSL3 private-provider tests pass, but Ubuntu LTS/FIPS restrictions were not exercised. | Operator target-host validation of LoadCredential and private MD4/DES availability; fail closed, no global legacy activation. |
| M3-04 **Medium inherent risk** | MSCHAPv2 NT-hash-equivalent compromise/offline dictionary attacks; per-user cooldown does not prevent all distributed attempts or deliberate known-user lockout. | Disposable random strong passwords, protected custody/backups, reviewed revocation/rotation, source restrictions; no Internet exposure approval. |
| M3-05 **Medium lab limitation** | `auth_exchange.rs` bounds sessions and rejects CHILD creation; no IKE fragmentation, MOBIKE, INFORMATIONAL/DPD/rekey/later lifecycle. Large public chains may fragment IP datagrams or exceed response cap. | Measure actual chain/datagram sizes/native behavior. Do not label an authenticated IKE SA as a working VPN or expand into later milestones. |
| M3-06 **Medium availability limitation** | Existing admission/COOKIE/pending caps protect bounded local work, not distributed bandwidth or reflection. CERT replies can be larger than requests; no universal anti-reflection guarantee. | Keep source-restricted test window; require separate deployment/availability review. |
| M3-07 **Low verification limit** | Same generic failure API/message and dummy crypto for unknown users; no end-to-end timing analysis, mlock or proof that all FFI/OS copies are wiped. | No claim of constant-time remote behavior or comprehensive memory-forensics resistance. Restrict process/core/capture access. |
| M3-08 **Low fixed** | Final review found protected header validation rejected reserved/informational bits (`protected.rs`). | Ignore those bits while enforcing direction; regression added, final checks/fuzz rerun. |

No unresolved architecture decision was bypassed. A missing/unsupported algorithm or failed certificate trust gate remains an explicit blocker rather than a fallback. The trusted signer trait is dependency injection for core tests; the shipped daemon exclusively constructs the validated production loader.

## Unexecuted operator validation

Follow [ike-auth.md](../docs/protocol/ike-auth.md) for exact provisioning, reviewed service directives, Ubuntu packages/ABI, UDP binding/capabilities and native settings/capture steps. These were **prepared, not executed**: publicly trusted certificate provisioning, real root0600-to-systemd0400 handoff, target Ubuntu tests, privileged UDP500/4500, native iOS profile/connect/wrong-password/Remote-ID cases, iOS certificate/final AUTH acceptance, target XFRM before/after observation. No real password/key/capture belongs in these reports.

Closure requires those observations plus review of this implementation and longer proposed campaigns. M3 does not authorize any CHILD_SA, ESP, XFRM, IP configuration, forwarding, control plane, Windows support or production deployment.

## Git checkpoint proposal

[Scope manifest](milestone_3_git_scope.json) lists exact M3 source changes against the recorded remediated M2 baseline and verifies HEAD/index/README preservation. Nothing was staged, committed or pushed. The current index predates M2 remediation, so an unqualified `git add src` or commit of all working-tree changes would mix milestones. Review/checkpoint the already accepted M2 remediation separately first; then stage only the listed M3 paths/hunks and M3 documents/evidence after approval. Keep README branding and operator-supplied ADR/authorization document decisions separate. No automatic commit is proposed from the existing mixed index.
