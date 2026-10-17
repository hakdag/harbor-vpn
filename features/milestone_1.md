I read `AGENTS.md` and all eight documents under `docs/`. No files were changed.

The proposed scope is an **offline Rust workspace and bounded IKEv2 wire codec**, with tests and fuzzing. It will not open sockets, establish connections, authenticate users, perform cryptography, or modify XFRM.

**Milestone alignment**

[TDD §8](/mnt/data/projects/personal%20vpn/docs/TDD.md) labels architectural decision review as Step 1 and “workspace + typed config + tracing + parser” as Step 2. Your requested Milestone 1 combines decision review with planning that foundation work. Approval should explicitly record this mapping; it should not imply approval for the later IKE_SA_INIT responder.

**Unresolved decisions and specification conflicts**

| Decision or conflict | Effect on this milestone | Proposed treatment |
|---|---|---|
| Exact IKE/ESP transforms and supported iOS versions remain pending under ADR D4 | Affects identifiers and proposal representation | Preserve numeric IDs and attributes; implement no negotiation policy or suite defaults |
| Parser coverage and resource limits are unspecified | Direct implementation decision | Approve the bounded scope and limits below |
| Stable Rust baseline and Ubuntu LTS version are unpinned | Affects reproducible builds | Record the tested stable compiler and Ubuntu release when implementation starts; declare an MSRV |
| Certificate trust/signature scheme, verifier encryption and key custody remain pending | Block later authentication work | Keep unresolved; introduce no crypto or credential dependencies |
| Pool, DNS, full-tunnel behavior and IPv6 policy conflict across documents | Block later network acceptance | Treat addresses as examples; do not encode deployment defaults |
| XFRM privilege isolation and crash recovery remain pending | Block later kernel integration | Keep wire parsing independent of Linux privileges and netlink |
| Fragmentation, MOBIKE and lifecycle feature scope remain unresolved | Affects future interoperability | Recognize unsupported payloads safely; implement no reassembly or lifecycle behavior |

The supporting documents also require reconciliation:

- `process_separation_spec.md` and `architecture_diagrams_and_config.md` place the control plane in Phase 1, conflicting with the explicit Phase 2 boundary.
- Several documents prescribe Argon2/bcrypt-only storage and plaintext-password verification. TDD/ADR identify why these cannot implement the EAP-MSCHAPv2 verification flow.
- `threat_model_spec.md` proposes per-user concurrent-session caps, conflicting with the accepted unlimited concurrent-session model.
- `network_model_spec.md` describes IPv4 full tunnel while deferring IPv6; this does not resolve the IPv6 leak policy.
- The simplified authentication diagrams omit required EAP/IKE authentication sequencing.

These conflicts should be recorded for review. None requires choosing a production default to build an offline codec. ADR-001 explicitly permits early parser work while interoperability decisions remain pending.

**Proposed workspace**

Follow TDD §7, creating only crates needed for the approved foundation:

| Path | Responsibility |
|---|---|
| `crates/ikev2-wire` | Wire types, checked parsing, serialization, limits and structured errors; no I/O |
| `crates/vpn-config` | Minimal validated foundation settings, principally codec limits; no credential format or deployment policy |
| `crates/vpn-observability` | Minimal structured diagnostic setup; metadata and errors only |
| `bins/ikev2d` | Non-listening entry point that validates configuration and initializes diagnostics |
| `crates/ikev2-wire/tests/` | Independent byte fixtures, malformed packets and property tests |
| `fuzz/` | Separate fuzz workspace, corpus and reproducible instructions |
| `docs/protocol/` | Codec coverage, invariants, fixture provenance and limitations |

Reserve the TDD responsibilities for `ikev2-crypto`, `ikev2-core`, `vpn-auth`, and `xfrm-linux` without creating empty implementations. `controld`, `vpnctl`, and `vpn-profiles` remain Phase 2 work.

Dependency direction stays simple: the binary wires components together; `ikev2-wire` depends on neither configuration nor observability.

**Parser and serializer implementation plan**

1. **Define the codec contract.** Accept exactly one IKE message, excluding UDP headers and the UDP 4500 non-ESP marker. Separate structural decoding from future negotiation and exchange-state validation.
2. **Implement the fixed header.** Decode the 28-byte header using checked reads and network byte order. Preserve SPIs, flags, exchange type and message ID; validate lengths and handle versions according to the RFC.
3. **Implement payload-chain traversal.** Bound each payload to its enclosing message, require forward progress, reject truncated or inconsistent chains, and require complete consumption.
4. **Implement initial typed bodies.** Cover SA proposals/transforms/attributes, KE, Nonce, Notify and Vendor ID. Preserve unknown numeric algorithm values without treating them as supported.
5. **Handle extension and encryption boundaries.** Retain or skip unknown noncritical payloads; return a structured unsupported-critical error for unknown critical payloads. Treat encrypted content as opaque. An SK payload terminates outer traversal; its Next Payload field describes encrypted inner content.
6. **Implement serialization.** Derive all lengths and chain links from typed values, check integer conversions and output limits, and emit reserved fields correctly. Provide no unchecked caller-supplied length fields.
7. **Document coverage.** Later payload bodies—identity, certificates, AUTH, EAP, configuration, selectors and deletes—remain explicitly opaque or unsupported until approved.

The wire layout and extension rules will follow [RFC 7296 §3](https://www.rfc-editor.org/rfc/rfc7296.html#section-3).

Proposed engineering limits, subject to review:

- Maximum IKE message: **65,535 bytes**, independently enforced before allocation.
- Maximum payloads: **128**.
- Maximum proposals: **64**; transforms per proposal: **64**; attributes per transform: **64**.
- Borrow input slices where practical; never allocate directly from an unchecked declared length.
- Use iterative traversal, checked arithmetic and safe Rust; errors contain offsets and categories, not packet dumps.

These are resource limits, not protocol-mandated maxima or user/device restrictions. Tests will cover each limit and one value beyond it.

**Dependencies**

| Area | Proposal |
|---|---|
| Wire codec | Standard library initially; checked slice operations and explicit endian conversions |
| Configuration | `serde` and `toml`, if file-based foundation configuration is included |
| Diagnostics | `tracing` and `tracing-subscriber` |
| Property tests | `proptest`, development-only |
| Fuzzing | `cargo-fuzz` / `libfuzzer-sys`, isolated from normal workspace builds |

Select compatible versions during implementation and commit the workspace lockfile. No crypto, async runtime, netlink, database, HTTP or third-party VPN server dependency is needed.

Production code and ordinary tests target Rust stable. `cargo-fuzz` uses a separate nightly tooling environment; it does not change the application’s compiler requirement. See the [Rust Fuzz Book](https://rust-fuzz.github.io/book/cargo-fuzz.html).

**Initial tests**

| Test group | Required cases |
|---|---|
| Header | Independently specified bytes; endian correctness; SPI/flag/message-ID preservation; version handling |
| Payload chains | Single/multiple payloads; valid termination; unknown noncritical continuation; unknown critical error; SK outer-chain termination |
| SA structure | Multiple proposals/transforms; correct last-substructure markers; SPI sizes; declared counts; TV/TLV attributes; unknown IDs |
| Typed bodies | Valid KE, nonce boundaries, Notify SPI/data boundaries and Vendor ID |
| Serialization | Golden byte output; computed lengths/links; overflow and capacity errors; reserved-field output |
| Properties | Typed encode/decode equivalence; deterministic encoding; bounded output; documented normalization behavior |

Malformed-packet coverage will include:

- Every truncation point of representative valid messages.
- Declared lengths below minimum, beyond input, and inconsistent with enclosing structures.
- Zero/undersized payloads, dangling Next Payload links and unexpected trailing bytes.
- Proposal/transform count and termination mismatches.
- Truncated attributes, impossible SPI lengths and excessive element counts.
- Unsupported critical payloads and version/flag edge cases.
- Serializer inputs that exceed representable lengths or configured limits.

Tests must distinguish structurally malformed data from structurally valid but unsupported algorithms. Protocol SA state-transition tests begin with the later state-machine milestone; codec traversal transitions are tested here.

**Fuzz strategy**

- Targets: complete-message parser, SA-body parser, and structured serialize/reparse.
- Seed with small valid fixtures and targeted malformed cases; include sanitized native-client captures when available.
- Assert no panics, hangs, unchecked allocation growth or limit bypasses.
- Run bounded pull-request smoke tests and longer scheduled runs.
- Minimize every finding and add it as a deterministic regression fixture.
- Proposed acceptance run: **30 minutes per target**, recording toolchain, command, duration and corpus. This provides evidence, not proof of correctness.

**Deliverables and acceptance criteria**

The approved implementation would deliver:

- A compiling workspace with the boundaries above.
- A documented, bounded parser and serializer with explicit coverage limits.
- Independent golden fixtures, negative tests and property tests.
- Runnable fuzz targets and a recorded initial campaign.
- A decision register distinguishing accepted architecture, proposed codec choices and deferred deployment decisions.

Acceptance requires:

- `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`, and `cargo test --workspace` pass on the recorded stable toolchain.
- Malformed inputs return structured errors without panics; limits are enforced before allocation.
- Golden fixtures pass independently of round-trip tests.
- Fuzz findings are fixed and retained as regression tests.
- No listeners, connection establishment, authentication, cryptographic operations, XFRM changes or control-plane implementation.
- Pending ADR decisions remain visibly pending.

This plan is ready for review; implementation has not started.
