# Codex Instructions — Rust VPN

## Project

Implement a custom VPN server in Rust, following the specifications in:

- `docs/PRD.md`
- `docs/TDD.md`
- `docs/ADR-001.md`

Read these documents before making architectural decisions.

## Architecture Rules

- Implement the IKEv2/IPsec responder in Rust.
- Use Linux kernel XFRM for ESP processing.
- Target Ubuntu LTS for server deployment.
- Keep protocol implementations in separate daemons.
- Introduce the internal control plane in Phase 2, not Phase 1.
- Do not introduce a device-registration or device-restriction model.
- Use username/password authentication via EAP-MSCHAPv2.
- Do not implement client-certificate authentication.
- Do not introduce third-party VPN server implementations.

## Development Rules

- Follow the milestones defined in the TDD.
- Do not implement functionality from future milestones without approval.
- Use established cryptographic libraries; never implement cryptographic primitives from scratch.
- Validate all untrusted network inputs.
- Avoid panics on malformed packets.
- Write unit tests for parsers, serializers, and state transitions.
- Run `cargo fmt`, `cargo clippy`, and `cargo test` when applicable.
- Explain architectural deviations before implementing them.
- Treat decisions marked pending in ADR-001 as unresolved, not approved defaults.
- Never store secrets, private keys, or production credentials in Git.

## Workflow

1. Inspect relevant specifications and existing code.
2. Present a short implementation plan.
3. Implement only the approved milestone.
4. Run applicable tests.
5. Summarize changes, test results, and unresolved issues.

Do not begin the next milestone automatically.