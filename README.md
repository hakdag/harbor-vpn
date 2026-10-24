# Harbor VPN — Milestone 2

Custom Rust IKEv2 foundations following the architecture in `docs/`. Milestone 2 adds an opt-in, unauthenticated IKE_SA_INIT responder. No usable VPN connection can be established: IKE_AUTH, EAP, ESP, XFRM and the control plane are not implemented. By default `ikev2d` validates configuration and exits without listening.

## Workspace

All application code, configuration, tests and fuzz tooling live under `src/`, including the Cargo workspace manifests and lockfiles.

- `src/crates/ikev2-wire`: dependency-free checked wire decoding and encoding.
- `src/crates/ikev2-crypto`: OpenSSL 3.x P-256, randomness, PRF/key derivation and AES-GCM provider boundary.
- `src/crates/ikev2-core`: offline initial-exchange validation, approved suite selection, cookies and bounded pending state.
- `src/crates/ikev2-transport`: bounded IPv4 UDP and NAT-T framing adapter.
- `src/crates/vpn-config`: typed TOML limits and explicit IPv4 bind addresses with safe hard ceilings.
- `src/crates/vpn-observability`: structured metadata logging.
- `src/bins/ikev2d`: configuration check or explicit `--serve` lab listener.
- `src/fuzz`: isolated nightly libFuzzer workspace, targets, seeds and campaign runner.

Stable Rust 1.97 or later is declared; tested with 1.97.1. Rust edition 2024. Deployment target remains Ubuntu LTS; the current validation host is Arch Linux, so Ubuntu validation is still outstanding.

```sh
cd src
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo run -p ikev2d -- config/milestone-1.toml
# Optional unprivileged loopback lab; stop with Ctrl-C.
cargo run -p ikev2d -- --serve config/milestone-2-lab.toml
```

Build prerequisites include a C compiler, pkg-config and OpenSSL 3.x development headers/libraries (Ubuntu packages: `build-essential`, `pkg-config`, `libssl-dev`). The tested build links the host's shared `libcrypto.so.3` and `libssl.so.3`; OpenSSL is not vendored. Only the ADR-002 suite is selectable: AES-256-GCM-16 / PRF-HMAC-SHA-256 / P-256, without a separate integrity transform.

See [initial-exchange behavior and safe lab operation](docs/protocol/ike-sa-init.md), [Milestone 2 report](features/milestone_2_report.md), [codec behavior](docs/protocol/wire-codec.md), [decision register](docs/decision-register.md) and [fuzz instructions](src/fuzz/README.md). Native iOS, real NAT and Ubuntu deployment validation remain outstanding. Milestone 3 requires separate approval.

Milestone 1 acceptance verification: all three 30-minute sanitizer runs exited 0 and all 23 tests passed. See the [final verification report](features/milestone_1_verification.md) for evidence, checkpoint scope and remaining IKE_SA_INIT decisions.
