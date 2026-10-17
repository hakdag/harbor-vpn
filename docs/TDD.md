# Custom VPN Platform — Phase 0 Technical Design (TDD)

**Status:** Draft v0.2 — reconciled with latest uploaded PRD v0.3; not implementation approval  
**Basis:** Custom VPN PRD v0.3 (latest user-uploaded version, including expanded Phase 2 API)  
**Primary platform:** Ubuntu LTS server; native iOS IKEv2 client  
**Language:** Rust  
**Scope:** Phase 0 design and Phase 1 implementation blueprint

## 1. Purpose and decisions carried forward

Build a self-owned Rust IKEv2/IPsec VPN service that interoperates with iOS's built-in client, without requiring third-party VPN client software or running a third-party VPN server. The Linux kernel's XFRM/ESP implementation is an intended platform dependency. Later, reuse the IKEv2 daemon for Windows and add separate protocol daemons only when justified.

**Fixed product constraints:**
- Native iOS client first; Windows next.
- One protocol per daemon; shared internal control plane introduced in Phase 2.
- Username/password via EAP-MSCHAPv2 is the permanent *client* authentication method.
- A trusted server certificate authenticates the IKEv2 server. No client certificate requirement.
- **No device entity, registration, cap, fingerprint, or device-scoped policy.** One user may have multiple concurrent sessions.
- Phase 1: single Ubuntu node, configuration files, no API or user-management service.
- Phase 2: internal-only user management, authentication verification, session orchestration and profile generation.

**Important security distinction:** “No client certificates” does not mean “no certificates”: IKEv2 requires the client to authenticate the server using a certificate in this design. Certificates are used for IKE peer authentication, not merely generic TLS transport (IKEv2 is not TLS).

## 2. Architecture and trust boundaries

```text
  iOS native IKEv2 client
         | UDP 500 / UDP 4500 (NAT-T)
         v
  +-----------------------------------+
  | ikev2d (Rust, untrusted network)   |
  | parse/validate IKE messages        |
  | negotiate algorithms and keys      |
  | server certificate + signature     |
  | EAP-MSCHAPv2 protocol              |
  | IKE_SA / CHILD_SA lifecycle         |
  | session table, timers, cleanup     |
  +------------------+----------------+
                     | netlink (least privilege)
                     v
  +-----------------------------------+
  | Linux kernel XFRM: ESP SAs/policy  |
  | kernel encrypts/decrypts data      |
  +-----------------------------------+
                     |
             forwarding + NAT/routing
                     |
                  Internet

  Phase 1: local config/credential file -> ikev2d
  Phase 2: ikev2d <-> private authenticated Unix socket <-> controld
                                              | users, auth, policy, audit
                                              | profile generation, sessions
```

**Ownership boundaries:**
- `ikev2d`: protocol responder, UDP sockets, IKE state, EAP challenge-response exchange, live session state; never queries the Phase 2 database directly.
- `controld` (Phase 2): user status, password verifier material, audit records, config/profile generation, disconnect commands; does not process VPN data packets.
- XFRM: ESP encryption/decryption, selectors and packet security associations.
- Host network: forwarding, filtering and NAT as required by routing mode.
- Privilege design: network-facing parser should not keep unrestricted root privileges; restrict XFRM configuration to a small privileged boundary, with service isolation designed before production.

## 3. IKEv2 protocol design

### 3.1 Required exchanges and phases

1. **IKE_SA_INIT:** parse initiator proposals, negotiate transforms, Diffie-Hellman and nonces, detect NAT, derive IKE keys; enforce anti-DoS limits and valid packet lengths.
2. **IKE_AUTH with EAP:** present server identity/certificate and authenticated responder response; negotiate EAP method; run EAP-MSCHAPv2 challenge and response inside protected IKE exchanges; complete EAP-dependent authentication and required IKE AUTH confirmation per RFC 7296; create first CHILD_SA only after successful authentication.
3. **Configuration payloads:** assign virtual IPv4 address, DNS servers and negotiated traffic selectors; test expected iOS full-tunnel behavior.
4. **CHILD_SA management:** install both directions' inbound/outbound XFRM states and policies, SPIs, keys, traffic selectors, lifetimes and correct cleanup.
5. **INFORMATIONAL:** encrypted liveness checks, deletes, errors and teardown. Support retransmission, message IDs and duplicate handling.
6. **Rekey/lifetimes:** implement IKE_SA and CHILD_SA replacement and collision handling before calling the server reliably usable; document deliberately deferred features and limitations.

### 3.2 State machines

```text
NEW -> SA_INIT_IN_PROGRESS -> IKE_AUTH_EAP -> AUTHENTICATED
                                         |             |
                                         v             v
                                       FAILED     CHILD_SA_ACTIVE
                                                        |
                                             REKEY / DPD / DELETE
                                                        |
                                                      CLOSED
```

Specify separately:
- IKE SA identity: initiator/responder SPI pair, endpoint tuple, negotiated suite, keys, message windows, EAP state.
- CHILD SA identity: directional ESP SPIs, policy selectors, assigned internal address, expiration, kernel handles.
- Retransmission, timeout, replay, duplicate-message and sequence-number behavior.
- Resource caps: pending handshakes, packet sizes, fragment reassembly, sessions and per-peer rate limits. **Resource caps are not device restrictions.**

### 3.3 Cryptography and interoperability

- Use established, reviewed Rust crypto primitives; **implement the IKEv2 protocol ourselves, not new cryptographic primitives**.
- Negotiate AEAD (e.g. AES-GCM) with correct IKE and ESP transform attributes, key lengths, nonces, integrity/PRF semantics and DH groups. Do not assume one suite works on all supported iOS versions.
- Select proposal matrix only after inspecting currently supported iOS native configurations and testing real client offers; document exact IANA transform IDs and kernel capabilities in an ADR.
- Obtain randomness from the OS CSPRNG. Protect key material and clear where practical.
- Support NAT detection and UDP encapsulation on 4500, including the non-ESP marker and keepalives where required.
- Include IKE fragmentation (RFC 7383) in the interoperability plan; support is negotiated, not unconditional.
- Distinguish **IKE fragmentation** from IPv4 packet fragmentation and ESP/MTU handling.
- Validate malformed payloads, out-of-order exchanges, cookies, unknown critical payloads and unsupported transforms without panics.

**Standards basis:** RFC 7296 (IKEv2), RFC 5998 (EAP-only authentication behavior), RFC 2759 (MS-CHAPv2), RFC 7383 (IKE fragmentation), RFC 8247 as updated by RFC 9395 (IKE crypto guidance), and applicable ESP/XFRM specifications.

## 4. Authentication and credential storage — mandatory design correction

**Chosen client UX:** one account username and password, with unlimited simultaneous connections. The server proves its identity with its certificate; client password authentication uses EAP-MSCHAPv2.

**EAP-MSCHAPv2 is a challenge-response protocol.** The responder normally receives username, authenticator challenge, peer challenge and response; it does **not** receive the user's plaintext password. Therefore the Phase 2 API must **not** be specified as `POST /auth/verify {username, password}`.

Likewise, **Argon2id/bcrypt password hashes alone cannot be used to verify the MSCHAPv2 response**. Verification needs password-equivalent material suitable for MSCHAPv2 (typically the NT hash) or a compatible backend. NT hashes are sensitive password-equivalent secrets. The verifier service should:
- Keep them in a restricted credential store; encrypt at rest with a separately controlled key, restrict process access, protect backups and never log secrets.
- Enforce strong random or long unique passwords, throttling and user disable.
- Use constant-time comparisons and avoid error messages that reveal account existence.
- Document the inherent MSCHAPv2/offline-dictionary-attack risks and the importance of correctly verifying the server certificate on iOS.
- Password updates recompute verifier material inside the trusted control plane; no device-scoped credentials.

**Phase 1:** encrypted/restricted local credential material in a config file (prototype only), with explicit ownership/permissions; do not publish production credential format until threat model reviewed.

**Phase 2 minimal daemon-to-control-plane operation (illustrative semantic contract):**

```http
POST /internal/auth/mschapv2/verify
Content-Type: application/json

{
  "username": "alice",
  "authenticator_challenge": "<hex>",
  "peer_challenge": "<hex>",
  "nt_response": "<hex>",
  "protocol": "ikev2"
}
```

Response contains `allowed`, canonical `user_id` if authorized, and the **MSCHAPv2 authenticator response needed for mutual method confirmation** on success; no plaintext password or verifier material is returned. Confirm all required EAP attributes, input binding and RFC 2759 calculations in unit tests. The daemon remains responsible for full EAP/IKE state sequencing. Only the server-local privileged Unix socket can invoke this operation.

**Authorization boundary:** verification also checks that the account is enabled; successful EAP verification does not itself authorize an already-revoked account. Sessions are registered *only after* the IKE exchange reaches the established state.

## 5. Network and Linux XFRM

**Initial reference config (not fixed until Phase 0 validation):**

| Setting | Proposed Phase 1 value | Validation |
|---|---|---|
| VPN address pool | `10.10.10.0/24` | Must not overlap deployed LAN or client networks |
| VPN server DNS name | `vpn.hypervault.biz` | Confirm domain control and certificate SAN |
| IKE UDP | `500`, `4500` | Confirm firewall and public reachability |
| Routing | IPv4 full tunnel first | Decide IPv6 leak policy explicitly |
| DNS | Configurable resolver addresses | Confirm pushed settings on iOS |
| Ubuntu | Supported LTS | Pin kernel, packages and test matrix |

**XFRM implementation plan:**
1. Create small privileged adapter to configure kernel SA and policy via netlink; keep a mocked equivalent for tests.
2. Track both inbound/outbound ESP state: SPI, source/destination, tunnel endpoints, mode, AEAD key/salt, replay-window settings, lifetime, `reqid`/marks if used.
3. Program SPD policy selectors for the negotiated client virtual IP / traffic selectors; verify forwarding behavior using packet captures and kernel counters.
4. Make install atomic enough to roll back on partial errors; delete states and policies on disconnect, timeout, rekey and crash recovery.
5. Configure host `net.ipv4.ip_forward`, firewall forward rules and SNAT/MASQUERADE only when needed. Never assume XFRM alone routes Internet packets.
6. Validate NAT-T encapsulated ESP and plain ESP, MTU, MSS, PMTU handling and reconnect from different access networks.
7. Decide whether first release disables IPv6 or supports it properly; prevent accidental IPv6 bypass under claimed full tunnel.

**Privilege note:** XFRM management generally requires `CAP_NET_ADMIN` in the relevant network namespace. Do not grant it indiscriminately to future public-facing components.

## 6. Server identity and iOS provisioning

- Issue or obtain a valid X.509 server certificate with SAN matching the VPN hostname, valid server-identity usage and trusted chain. Document private key rotation, storage and process permissions.
- Sign the IKE_AUTH responder authentication data correctly. This is IKE authentication with a certificate, **not a TLS listener**.
- Produce a minimal `.mobileconfig` using the appropriate Apple IKEv2 payload keys. Avoid embedding user passwords unless unavoidable and explicitly approved.
- Verify iOS trust behavior experimentally (hostname, CA trust, algorithm proposal, prompt behavior).
- Phase 1 profile is manual; Phase 2 generates profiles. A profile is configuration, **not** a device identity or account authorization token.

## 7. Rust workspace and module boundaries

```text
vpn/
  Cargo.toml                 # workspace
  crates/
    ikev2-wire/             # strict parser, serialization, bounded buffers
    ikev2-crypto/           # wrappers around reviewed crypto libraries
    ikev2-core/             # IKE SA state, exchanges, EAP, timers
    vpn-auth/               # MSCHAPv2 verifier interface + phase-1 backend
    xfrm-linux/             # netlink adapter, SA/SPD lifecycle
    vpn-config/             # validated typed configuration
    vpn-observability/      # structured events, metrics interfaces
    vpn-profiles/           # Apple profile generation (phase 2)
  bins/
    ikev2d/                 # UDP server + wiring
    controld/               # phase 2 local service
    vpnctl/                 # phase 2 admin CLI
  tests/
    interop/                # integration harness/test vectors
  docs/
    adr/                    # recorded architecture decisions
    protocol/               # message flow and compatibility matrix
```

Use dependency injection through Rust traits for crypto, clock, network I/O, auth backend and XFRM; avoid a central monolith. Put secrets behind types with redacted `Debug`. Avoid speculative general-purpose frameworks in Phase 1.

## 8. Phase 1 implementation milestones and acceptance tests

| Step | Deliverable | Acceptance gate |
|---|---|---|
| 1 | ADRs for suites, secrets, network model and privilege boundary | Decisions reviewed, no blocking ambiguity |
| 2 | Rust workspace + typed config + tracing + parser | Fuzz/negative parsing tests; no panics |
| 3 | IKE_SA_INIT responder | Deterministic test vectors and packet capture conform to RFC |
| 4 | Protected IKE_AUTH + server certificate | Native iOS validates server identity |
| 5 | EAP-MSCHAPv2 | RFC test vectors + valid/invalid credentials |
| 6 | XFRM installation + configuration payloads | Bidirectional ping / TCP via assigned virtual IP |
| 7 | NAT-T, routing, DNS, full tunnel | Internet traffic and DNS work from iPhone |
| 8 | INFORMATIONAL / DPD / rekey / cleanup | Repeated connect/disconnect, timeout, reconnect, no leaked SAs |
| 9 | Interop and robustness | Mobile data/Wi-Fi, malformed packets, loss, restarts |

**Definition of done for iOS MVP:** the native iOS client connects without a third-party app; it validates the server certificate and authenticates by username/password; assigned IP, DNS and route work; packet confidentiality comes from kernel ESP; repeat connections, NAT-T, teardown and recovery pass reproducible tests. Do not declare MVP complete on the basis of a successful IKE_SA_INIT response alone.

## 9. Phase 2 internal API — reconciled with PRD v0.3 (not in Phase 1)

The latest PRD contains a **broad endpoint catalog** under “Minimal Internal API (User-based).” This TDD preserves that catalog as the **product-requested interface inventory**, but distinguishes the subset necessary for the Phase 2 exit criteria from additional administrative capabilities. Endpoints are not implemented in Phase 1. There is **no device resource, registration, limit, or device-scoped credential**. Concurrent sessions belonging to one user are allowed.

### 9.1 Transport and trust

- Bind the control API to a Unix domain socket (preferred) or explicitly restricted loopback; **never publish an administrative listener to the Internet**.
- Separate **daemon operations** from **admin CLI operations** using peer identity and authorization; a local socket alone is not an authorization mechanism.
- All responses exclude password verifier material, secret keys, and profile-embedded passwords. Use auditable mutations and redact credentials from logs.
- Internal HTTP-style endpoints are provisional interface names, not a promise to deploy REST externally. The PRD allows REST/gRPC; choose one transport in an ADR.

### 9.2 Endpoint alignment with the PRD

| Area | PRD v0.3 requested routes | Phase 2 sequencing / technical interpretation |
|---|---|---|
| Health | `GET /health`, `GET /ready`, `GET /version` | `/health` first; readiness verifies config and credential backend; version optional |
| Authentication | `POST /auth/verify`, `POST /auth/logout` | **Correct `/auth/verify` payload**, see §9.3; logout closes session records |
| Sessions | `GET /sessions`, `GET /sessions/{session_id}`, `DELETE /sessions/{session_id}` | List and forced teardown are essential; details optional |
| Users | `POST /users`, `GET /users`, `GET /users/{user_id}`, `PATCH /users/{user_id}`, `POST /users/{user_id}/password`, `POST /users/{user_id}/enable`, `POST /users/{user_id}/disable`, `DELETE /users/{user_id}` | Create/list/disable/password reset first; rest administrative expansions; disable terminates **all** user's sessions |
| Policy | `GET /policy/default`, `PUT /policy/default` | Keep system-wide default DNS/routes/tunnel settings; validate updates against active SAs |
| IP pool | `GET /ip-pool`, `PUT /ip-pool` | Guard against collisions and changes incompatible with live leases |
| iOS profiles | `POST /profiles/ios`, `GET /profiles/{profile_id}`, `DELETE /profiles/{profile_id}` | Generation required; retrieval/deletion only if persisting artifacts; deleting profile file does **not** revoke VPN credentials |
| Audit | `GET /audit/auth`, `GET /audit/users` | Structured logs required; query endpoints can follow log persistence |
| Maintenance | `POST /reload`, `POST /backup`, `POST /restore` | PRD-listed, **not minimum for initial Phase 2 exit**; backup/restore require tight privilege controls and secret protection |

**Route naming reconciliation:** preserve `/auth/verify` from the PRD, but correct its **request/response contract** below; an internal alias `/internal/auth/mschapv2/verify` may be used if agreed in the API ADR. Do not implement both merely for aesthetics. The PRD's `{username,password}` sample is *not executable as written* for EAP-MSCHAPv2.

### 9.3 Authentication wire contract (correction required before coding)

In IKEv2/EAP-MSCHAPv2 the server receives a challenge/response, **not plaintext client password**. The daemon calls an authorized local verifier with RFC 2759 inputs, for example:

```http
POST /auth/verify
Content-Type: application/json

{
  "username": "alice",
  "authenticator_challenge": "<hex>",
  "peer_challenge": "<hex>",
  "nt_response": "<hex>",
  "protocol": "ikev2"
}
```

Verification must bind the identity, challenge, response, and account enabled state. On success, return a boolean authorization result, canonical `user_id`, and required MSCHAPv2 mutual-authentication response. **Do not allocate a definitive `session_id`, VPN IP, routes, or DNS as a side effect of merely checking a password proof.** Those belong to later authorization/session establishment once IKE authentication succeeds. For Phase 2, define a daemon-initiated session-created/session-ended notification mechanism, either via internal operations or a daemon-owned event channel (an engineering addition to the PRD catalog); verify source identity and deduplicate events.

Argon2id/bcrypt may be appropriate for unrelated plaintext-password interfaces but **cannot alone verify MSCHAPv2**. Store the MSCHAPv2-compatible verifier as protected password-equivalent secret material; document and approve key management and offline-dictionary attack risk before production. Never downgrade server-certificate validation to accommodate a misconfigured iPhone.

### 9.4 Session revocation and concurrency

- A disable operation first prevents new successful authentications and sends termination requests for **every active session** associated with the user; retain the enabled/disabled state durably.
- `ikev2d` tears down the IKE SA and relevant CHILD SAs, deletes kernel XFRM state/policy and acknowledges cleanup. Handle retries, crashes, lost acknowledgments and daemon restart reconciliation.
- `DELETE /sessions/{session_id}` terminates only the named session; **it does not imply device identification or impose per-user concurrency limits**.
- The PRD's phrase “instant revocation” is an operational requirement, not a guarantee achievable by one DB write; define a measurable latency SLO and failure behavior in the Phase 2 implementation ADR.

### 9.5 Minimum implementation order for Phase 2

1. Internal transport, peer authorization, `GET /health` and `GET /ready`.
2. `POST /auth/verify` with challenge-response verification and tests; user create/list/password reset/disable.
3. Session event bookkeeping; `GET /sessions`, `DELETE /sessions/{session_id}`; fan-out disconnect on user disable.
4. `POST /profiles/ios` to emit a valid `.mobileconfig` without device registration.
5. Add remaining PRD endpoints as separately tested administrative capabilities. They belong to the PRD inventory but need not block the first demonstrable user-management milestone unless the PRD owner explicitly makes them mandatory.

**Exit tests derived from PRD:** add/remove users without daemon restart; generate a usable iOS profile; one user sustains parallel connections; disabling that user blocks new authentication and closes all active tunnels; control plane has no packet-processing responsibility; IKE daemon never reads the user DB.

## 10. Test plan and operational checks

- **Protocol:** published RFC vectors, packet captures, interop with native iOS; cross-check expected handshake behavior against independent standards-conforming implementations in a test lab (not deployed as product server).
- **Security:** invalid cert/trust, wrong password, replay, tampered payload, invalid lengths, repeated EAP failures, amplification/DoS protections, privilege separation.
- **Networking:** Wi-Fi, cellular, home NAT, double NAT, outbound filtering, DNS, split/full-tunnel behavior, IPv6, large packets.
- **Correctness:** one user/parallel sessions; disconnect one vs disable all; no leaked kernel state; collisions, packet retransmits, rekey.
- **Operations:** clean start/stop, systemd least-privilege service, secret file permissions, log redaction, metrics, controlled crash recovery.

## 11. Risks and explicit open decisions to close before code

1. **EAP-MSCHAPv2 verifier storage:** decide encrypted NT-hash storage and encryption-key management, or a different MSCHAPv2-compatible backend. Argon2-only is incompatible. Document risk acceptance.
2. **Server certificate and iOS trust:** choose public CA vs privately managed CA; confirm profile enrollment and SAN requirements.
3. **Cipher suite compatibility:** capture iOS proposals and commit exact IKE/ESP transform matrix; validate against Ubuntu kernel.
4. **IP model and IPv6:** choose full tunnel, address pool and an explicit no-leak IPv6 strategy.
5. **Kernel resource lifecycle:** decide handling of failed SA install, rekey concurrency and daemon crash/recovery.
6. **Privilege separation:** identify whether a small helper is needed to isolate CAP_NET_ADMIN and certificate key access.
7. **Scope of initial RFC features:** prioritize IKE fragmentation, rekey and DPD for reliability; specify MOBIKE support or an explicit short-term limitation and test reconnections accordingly.
8. **PRD/API reconciliation:** the PRD authentication request example must be corrected from plaintext password to EAP-MSCHAPv2 proof inputs; agree on session lifecycle notifications and which catalog routes constitute the Phase 2 acceptance gate.
9. **Deployment prerequisites:** confirm Ubuntu version, firewall, public IP/NAT, current DNS ownership and clean server state. Previous SSTP deployment settings should not be blindly reused.

## 12. Proposed immediate next action

**Complete ADR-001 (Baseline Interoperability & Security):** in one short design pass, record the chosen host/network environment, certificate trust strategy, exact IKE/ESP proposals, EAP verifier key management, IPv6 policy and expected connection behavior. Then create the Rust workspace and write the bounded IKE header/payload parser with unit tests. No cloud rollout or root-required XFRM mutation until packet-level tests pass.

## 13. Reconciliation notes for v0.2

- **Preserved:** iOS-first IKEv2/IPsec, separate Rust protocol daemons, XFRM kernel ESP, permanent EAP-MSCHAPv2 username/password, no client certificates, no device model or restrictions, manual Phase 1 / internal-only Phase 2.
- **Updated from latest PRD:** Phase 2 endpoint inventory now includes health, authentication, sessions, users, policy, IP pool, profiles, audit and maintenance. Each is mapped to an implementation priority.
- **Technical deviation requiring PRD correction:** `/auth/verify` cannot accept plaintext `password` in this IKEv2 flow; session/IP parameters must not be claimed as the immediate result of an MSCHAPv2 proof check.
- **Technical deviation requiring PRD correction:** “bcrypt/argon2” alone is incompatible with EAP-MSCHAPv2; use a protected, compatible verifier and accept its risks.
- **Wording correction recommended to PRD:** replace “Strict TLS config” with “strict IKEv2/IPsec and server-certificate verification” because IKEv2 is not TLS.
- **Scope clarification:** Phase 2 catalog is broader than the smallest milestone. The user-owned PRD is unchanged; this TDD distinguishes catalog coverage from implementation gating.

### References

- RFC 7296 — IKEv2: https://www.rfc-editor.org/rfc/rfc7296
- RFC 5998 — EAP-Only Authentication in IKEv2: https://www.rfc-editor.org/rfc/rfc5998
- RFC 2759 — MS-CHAPv2: https://www.rfc-editor.org/rfc/rfc2759
- RFC 7383 — IKEv2 Fragmentation: https://www.rfc-editor.org/rfc/rfc7383
- RFC 8247 — IKEv2 Algorithm Guidance: https://www.rfc-editor.org/rfc/rfc8247
- RFC 9395 — IKEv2 Algorithm Update: https://www.rfc-editor.org/rfc/rfc9395
- Linux kernel XFRM documentation: https://docs.kernel.org/networking/xfrm.html
- Apple Device Management VPN payload reference: https://support.apple.com/guide/deployment/vpn-settings-dep2d2adb35d/web

---

*This document expands the supplied PRD into technical proposals. Any proposal not already committed in the PRD is explicitly marked for validation or decision; it is not treated as an existing product requirement.*
