# Custom Rust VPN — Milestone 1

Offline IKEv2 wire foundations for the architecture in `docs/`. No VPN connections can be established. The `ikev2d` entry point validates configuration, emits one metadata event and exits; it opens no listeners.

## Workspace

All application code, configuration, tests and fuzz tooling live under `src/`, including the Cargo workspace manifests and lockfiles.

- `src/crates/ikev2-wire`: dependency-free checked wire decoding and encoding.
- `src/crates/vpn-config`: typed TOML codec limits with safe hard ceilings.
- `src/crates/vpn-observability`: structured metadata logging.
- `src/bins/ikev2d`: offline composition only.
- `src/fuzz`: isolated nightly libFuzzer workspace, targets, seeds and campaign runner.

Stable Rust 1.97 or later is declared; tested with 1.97.1. Rust edition 2024. Deployment target remains Ubuntu LTS; the current validation host is Arch Linux, so Ubuntu validation is still outstanding.

```sh
cd src
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo run -p ikev2d -- config/milestone-1.toml
```

See [codec behavior and coverage](docs/protocol/wire-codec.md), [decision register](docs/decision-register.md), [fuzz instructions](src/fuzz/README.md) and [implementation report](features/milestone_1_report.md).

Future crates from TDD §7 are intentionally not scaffolded. PRD/TDD/ADR source documents are unchanged. Milestone 2 requires separate approval.

Milestone 1 acceptance verification: all three 30-minute sanitizer runs exited 0 and all 23 tests passed. See the [final verification report](features/milestone_1_verification.md) for evidence, checkpoint scope and remaining IKE_SA_INIT decisions.
