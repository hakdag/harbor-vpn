# Architecture decision register

Status: the Milestone 1 entries below preserve the decisions and conflicts recorded at that checkpoint. The Milestone 2 update records the subsequent accepted ADR-002 and implementation authorization. This register does not amend the PRD, TDD or ADR-001, or independently accept their remaining pending decisions.

## Approved implementation boundaries

| ID | Decision | Basis / effect |
|---|---|---|
| M1-01 | Offline workspace and wire codec only | Maintainer approval. No listeners, exchange state machine, authentication, negotiation, cryptography, XFRM, or control plane. |
| M1-02 | Raw envelopes, typed structural decoding, and support checking are separate | Maintainer adjustment. Successful structural decoding never authorizes an exchange or selects an algorithm. |
| M1-03 | Configurable positive resource limits with fixed ceilings | Message bytes 28–65,535; payloads 1–128; proposals, transforms per proposal, attributes per transform 1–64. Every public codec entry point validates limits. |
| M1-04 | Preserve unknown IDs and opaque noncritical payloads | Unknown algorithm IDs are data, not enabled suites. Unknown critical and recognized unimplemented features produce Unsupported in explicit support checking. |
| M1-05 | Follow RFC reserved-field receive/send rules | Ignore reserved bits on receipt; emit zero in modeled reserved fields. Do not reject an understood payload solely because Critical is set. Opaque body fields cannot be normalized. |
| M1-06 | Stable workspace, separate nightly fuzz tooling | Edition 2024, declared MSRV 1.97, tested stable 1.97.1. No claim of testing an earlier compiler. Nightly is tooling only. |
| M1-07 | Milestone naming maps to TDD steps 1–2 foundations | The approved feature plan spans decision review plus the offline workspace/parser foundation. TDD step 3 / a working IKE_SA_INIT responder remains unapproved. |

## Specification conflicts (unresolved; no source specification changed)

| ID | Sources | Conflict / current implementation boundary | Closure owner / gate |
|---|---|---|---|
| C-01 | PRD Phase 1; TDD §§1–2; ADR D9 versus process_separation_spec and architecture_diagrams_and_config §§1,6 | Supporting documents place the control plane in Phase 1 and prohibit local credential access without a phase exception. Binding scope puts control plane in Phase 2, local file configuration in Phase 1. No credential handling in M1. | Maintainer: reconcile phase-specific ownership before authentication work. |
| C-02 | PRD authentication API; process_separation_spec §7; architecture_diagrams_and_config §2 versus TDD §§4,9 and ADR D6 | Plaintext `{username,password}` verification cannot represent received MSCHAPv2 proof inputs. Session/IP assignment is also shown as an immediate proof-check side effect. | Maintainer / authentication implementer: approve challenge-response contract and later session lifecycle events. |
| C-03 | PRD Phase 4; threat_model_spec §3.1; architecture_diagrams_and_config §5.4 versus TDD §4 and ADR D6 | Argon2/bcrypt alone cannot verify MSCHAPv2 NT-Response; encryption described as optional conflicts with protected verifier requirements. | Security/operations: approve compatible verifier storage, encryption, custody, backup and restoration. |
| C-04 | threat_model_spec §3.4 versus PRD Phase 2, TDD §1 and ADR D10 | Per-user concurrent-session caps conflict with unlimited user concurrency. Parser/node resource protection does not create a user/device restriction. | Maintainer: reconcile threat mitigations without a device or user concurrency cap. |
| C-05 | network_model_spec §§2–4,8 versus TDD §5 and ADR D7 | Pool/DNS are described as defaults and full tunnel as all traffic while IPv6 is deferred. ADR leaves deployment values and IPv6 leak policy unresolved. | Network implementer: deployment overlap, DNS and Wi-Fi/cellular IPv6 tests. |
| C-06 | protocol_crypto_spec §§1,4–5 versus ADR D4 | “Locks”/“canonical” language conflicts with an unverified proposal matrix. Algorithms, IDs, priority and supported client versions are still pending. | Protocol implementer: native iOS offers, exact transform matrix and Ubuntu kernel capability evidence. |
| C-07 | PRD TLS wording; supporting authentication diagrams versus TDD §§1,3–4 and ADR D3 | IKE certificate authentication is not TLS; diagrams omit full EAP mutual confirmation and final IKE AUTH sequencing. | Protocol implementer / maintainer: reviewed message flow before authentication work. |

## Remaining architecture decisions (not resolved by codec implementation)

| ID | Decision | Required evidence / owner |
|---|---|---|
| A-01 | Supported iOS builds and exact IKE/ESP suite matrix | Protocol implementer; captures, IANA mappings, native-client and kernel tests. |
| A-02 | Public/private CA, signature scheme and certificate lifecycle | Maintainer; trust, SAN, wrong-hostname and renewal tests. |
| A-03 | Verifier secret format and key custody | Security/operations; threat review and recovery/permission tests. |
| A-04 | IPv4 pool, DNS, routing and IPv6 policy | Network implementer; actual deployment and leak testing. |
| A-05 | XFRM helper/capabilities/systemd boundary; certificate-key isolation | Systems implementer; privilege review and confinement tests. |
| A-06 | Partial XFRM failure, crash reconciliation, rekey concurrency | Systems/protocol implementer; idempotency and fault-injection tests. |
| A-07 | Fragmentation, DPD, rekey and MOBIKE scope | Protocol implementer; feature and reconnection matrix. SKF is opaque and explicitly unsupported in M1. |
| A-08 | Ubuntu LTS/kernel baseline and deployment prerequisites | Operations; choose supported LTS, kernel, DNS ownership, public IP/firewall. Current validation host is Arch Linux, not Ubuntu. |
| A-09 | Phase 2 transport, authorization, revoke latency and daemon-down recovery | Control-plane implementer / maintainer; authenticated IPC and multi-session revoke tests. No M1 implementation. |

At the Milestone 1 checkpoint, Milestone 2 required separate maintainer approval. The subsequent authorization is recorded below; no other pending ADR entry is promoted to Accepted here.

## Decisions required before implementing IKE_SA_INIT

This is a review of prerequisite scope, not approval of proposed settings and not implementation of Milestone 2.

| ID | Required decision | Source / closure |
|---|---|---|
| INIT-01 | Exact **IKE SA** proposal policy and supported native iOS test builds: encryption/key lengths, PRF, DH groups, AEAD integrity-transform treatment, selection order and unsupported-proposal behavior. | A-01 / C-06 / ADR D4. Record IANA IDs and client-offer evidence; obtain maintainer approval. The ESP/CHILD_SA matrix is not a prerequisite to implementing this initial exchange. |
| INIT-02 | Reviewed stable-Rust crypto provider boundary for the chosen DH/PRF operations, OS randomness, public-share checks, IKE key derivation and ephemeral-secret lifetime/zeroization. | TDD §3.3 and ADR D1 / §6. Select established libraries and document provider interfaces before calling them; no custom primitives. This concerns ephemeral handshake keys, not the later password-verifier store. |
| INIT-03 | Initial-exchange state and network-exposure boundary: offline core versus isolated UDP integration, unprivileged parser and low-port binding, pending-handshake budgets/timeouts, cookie/DoS policy, duplicate/retransmission behavior, and NAT-detection/4500 framing coverage. Advertise only extensions actually implemented. | TDD §§2–3 and ADR D8; narrow initial-exchange portions of A-05/A-07. Review the bounded initial state model and test seam before implementation; resolve host/bind privileges before live UDP tests. No XFRM privileges or public deployment are implied. |

These are the prerequisites for the initial exchange only. CA/signature lifecycle, password-verifier storage, address pool/DNS/IPv6, ESP installation, XFRM helper/recovery, full DPD/rekey/MOBIKE and Phase 2 IPC/revocation remain decisions for their later work. Pinning an Ubuntu LTS integration-test host is a live-test prerequisite (A-08), not a blocker to writing the offline exchange core. None of these pending choices is selected here.

## Milestone 2 update — 2026-10-17

Authority: accepted [ADR-002](ADR-002.md) and the maintainer's [implementation prompt](Milestone_2_Codex_Implementation_Prompt.md). The prerequisite table above is historical; the following supersedes its unapproved status only for the specified initial-exchange scope.

| ID | Status / implementation | Remaining evidence or gate |
|---|---|---|
| INIT-01 | Accepted for IKE SA: ENCR_AES_GCM_16 (20), key-length 256, PRF_HMAC_SHA2_256 (5), ECP group 19, no INTEG transform and no fallback. Unknown offers remain numeric data. | Actual iOS build, explicit profile and captured proposals remain unvalidated. A-01/C-06 remain open for client interoperability and ESP. |
| INIT-02 | Accepted OpenSSL 3.x through `ikev2-crypto`; checked peer points, ephemeral ECDH, CSPRNG, PRF/key schedule and bounded AES-GCM API. | Ubuntu packaging, maintained library baseline, full transitive license/security review and deployment evidence remain outstanding. No FIPS or comprehensive FFI-memory-erasure claim. |
| INIT-03 | Accepted initial IPv4 UDP/NAT-T boundary. Offline core, explicit nonblocking sockets, exact-response cache, deadlines, pending budgets and rotating stateless cookies implemented. | Real NAT/iOS and target-host low-port permissions/confinement tests remain outstanding; XFRM privileges, fragmentation, MOBIKE, DPD/rekey and established-session policy are not selected. |
| M2-01 | Tunable implementation defaults: 1,024 pending globally, 32/source IP, 10 s lifetime, COOKIE at 512 pending, 60 s secret rotation; current and preceding cookie epoch accepted. | These protect unauthenticated pending exchanges only. Tune with deployment load evidence; no user/device/session cap. See protocol document for hard ceilings. |
| M2-02 | Explicit unicast local IPv4 bind required; wildcard binding rejected so std UDP sockets provide the correct local address for NAT hashes. High-port loopback lab supplied; no privilege changes. | Multihomed wildcard support would need reviewed destination-address ancillary-data handling. Public/privileged deployment is not implied. |
| M2-03 | RFC 7296 §2.6 cookie MAC binds epoch, nonce, SPIi and source/destination IP+port. No pending state or ECDH before cookie validation under load. KE is not MAC-bound, permitting invalid-group retry. | No native-client retry capture yet. Threshold defense is not a production DDoS guarantee or network rate limiter. |

C-01 through C-05 and C-07 remain unresolved. C-06 is narrowed by ADR-002 only for the implemented IKE SA suite; no supporting specification is silently rewritten. A-02 through A-09 retain the later-work gates listed above. Before any separately approved authentication work, resolve the authentication flow/API, compatible verifier storage and custody, certificate trust/signature/lifecycle and key isolation. Do not begin Milestone 3 automatically.
