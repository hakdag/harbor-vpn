# Product Requirements Document (PRD)

## Project: Custom VPN Platform (iOS-first, Separate Daemons)
### 1. Purpose & Vision

Build a self-owned VPN system where:

Clients use built-in OS VPN support (no third-party VPN apps).

The server stack is fully under our control, written primarily in Rust.

Multiple VPN protocols are supported via separate daemons, sharing a common control plane.

iPhone (iOS) is the first-class client.

### 2. Non-Goals (Explicit)

❌ No third-party VPN client apps (WireGuard/OpenVPN apps not allowed)

❌ No “auto-detect protocol” single daemon

❌ No reliance on opaque commercial VPN software

❌ SSTP is not in scope for iOS (Windows-only)

### 3. Target Platforms
| Platform         | Support Type                             |
| ---------------- | ---------------------------------------- |
| **iPhone / iOS** | Built-in VPN (primary target)            |
| Windows          | Built-in VPN (later phase)               |
| Linux            | Optional custom client or later protocol |

### 4. Chosen Architecture (Key Decision)

Separate Daemons + Shared Control Plane
                 ┌────────────────────┐
                 │   Control Plane     │
                 │  (Rust, custom)     │
                 │ - users             │
                 │ - auth              │
                 │ - server certs      │
                 │ - policy            │
                 └─────────┬──────────┘
                           │
        ┌──────────────────┼──────────────────┐
        │                  │                  │
┌─────────────┐    ┌──────────────┐    ┌─────────────┐
│ IKEv2 Daemon│    │ SSTP Daemon  │    │ Future Proto│
│ (iOS first) │    │ (Windows)   │    │ (optional)  │
└─────────────┘    └──────────────┘    └─────────────┘

Each protocol:
- Own binary
- Own ports
- Own state machine
- No protocol multiplexing

### 5. Protocol Choice (Phase 1)
Primary Protocol: IKEv2/IPsec
Why
- Native to iOS
- Native to Windows
- Enterprise-grade
- No app installation required

Transport
- UDP 500 / UDP 4500
- ESP via Linux kernel (XFRM)

Crypto
- AES-GCM
- SHA-256+
- Diffie-Hellman (PFS)

### 6. Authentication Model

Phase 1 (MVP)
- Username / password using EAP-MSCHAPv2
- Server-issued certificates for IKE handshake

Phase 2
- Password-based auth remains (EAP-MSCHAPv2)
- Centralized user management and revocation
- Profile generation automation

### 7. Client Experience (iOS)
Provisioning
- User installs a .mobileconfig profile
- Profile contains:
    - IKEv2 settings
    - Server hostname
    - Auth method (EAP)
    - Trust anchor (CA)

Connection Flow
- User toggles VPN in iOS settings
- iOS initiates IKEv2
- Server authenticates
- Kernel XFRM handles packet encryption
- Traffic is routed

### 8. Functional Requirements
#### Core
FR-1: Accept IKEv2 connections from iOS
FR-2: Authenticate users against internal auth store
FR-3: Assign virtual IPs
FR-4: Route traffic through server
FR-5: DNS push to clients

#### Control Plane
FR-6: User CRUD
FR-7: Credential lifecycle
FR-8: Profile generation (.mobileconfig)
FR-9: Revoke access instantly

#### Observability
FR-10: Connection logs
FR-11: Auth failures visibility
FR-12: Per-session metrics

### 9. Non-Functional Requirements
| Category        | Requirement                  |
| --------------- | ---------------------------- |
| Security        | No plaintext secrets at rest |
| Reliability     | Daemon restart safe          |
| Performance     | Kernel-level crypto only     |
| Portability     | Ubuntu LTS first             |
| Maintainability | Clear daemon boundaries      |

### 10. System Components (Detailed)
#### 10.1 IKEv2 Daemon (Rust)
- Implements IKEv2 responder (RFC 7296)
- Handles:
    - IKE_SA_INIT
    - IKE_AUTH
    - CHILD_SA
Delegates ESP to kernel via netlink/XFRM

#### 10.2 Control Plane (Rust)
- REST/gRPC internal API
- User store
- Credential issuance
- Server certificate management (transport only)
- Profile generation

#### 10.3 Kernel Integration
- NETLINK_XFRM
- ip xfrm equivalent logic
- NAT traversal support

### 11. Security Considerations
- Rate-limit auth
- Dead peer detection
- Replay protection
- Minimal exposed ports
- Strict TLS config
- Separate privileges per daemon

### 12. Phased Roadmap

This roadmap is designed to be **execution-oriented**. Each phase produces a
working, testable system and unlocks the next phase without major rewrites.

---

#### Phase 0 – Design & Foundations

**Objective:** Eliminate ambiguity before writing protocol code.

**Tasks:**
- Select and lock the **initial protocol**: IKEv2/IPsec
- Choose **authentication method for MVP**:
  - EAP-MSCHAPv2 (username/password)
- Define **network model**:
  - VPN address pool (e.g. 10.10.10.0/24)
  - Full-tunnel vs split-tunnel behavior
- Define **threat model**:
  - Credential theft
  - Replay attacks
  - Brute-force attempts
- Decide **process separation**:
  - IKEv2 daemon (no database access)
  - Control plane (no packet handling)
- Produce:
  - High-level architecture diagram
  - IKEv2 message flow diagram
  - Initial configuration conventions

**Exit criteria:**
- Clear protocol, auth, and architecture decisions
- No open “we’ll decide later” items

---

#### Phase 1 – iOS MVP (Single-Server, Manual)

**Objective:** Prove that an iPhone can connect using built-in VPN and route traffic.

**Tasks:**
- Implement **IKEv2 responder daemon** in Rust:
  - IKE_SA_INIT
  - IKE_AUTH
  - CHILD_SA establishment
- Integrate with **Linux kernel IPsec (XFRM)**:
  - Program ESP SAs via netlink
  - No user-space packet encryption
- Implement **EAP-MSCHAPv2 authentication**
- Hardcode or file-configure:
  - User credentials
  - IP assignment
  - DNS servers
- Generate **manual iOS .mobileconfig**:
  - Server hostname
  - CA trust anchor
  - IKEv2 + EAP settings
- Validate:
  - iOS connects successfully
  - Client receives IP
  - Traffic routes through VPN
  - Disconnect/reconnect stability

**Explicit non-goals in this phase:**
- No API
- No automation
- No multi-user management

**Exit criteria:**
- iPhone connects reliably using built-in VPN
- Traffic flows end-to-end
- Logs clearly show connection lifecycle

---

#### Phase 2 – Control Plane (Minimal, Internal)

**Objective:** Centralize user identity, credentials, and policy without overengineering.

**Design note:**  
There is **no device concept**. Access control, revocation, and auditing are
**strictly user-based**. A single user may connect from multiple devices
simultaneously.

---

**Tasks:**

- Implement **Control Plane service** in Rust:
  - Runs locally on the server
  - Communicates over **Unix domain socket** or **localhost-only** interface
  - Not exposed to the public internet
- Define **minimal internal API** (used only by VPN daemons and admin CLI)
- Move from static config to:
  - User store (file-based or embedded DB)
  - Secure password hashing
- Generate **iOS `.mobileconfig` automatically**
- Implement **instant revocation**:
  - Disable user
  - All active sessions dropped immediately
- Ensure:
  - IKEv2 daemon never touches user storage directly
  - Control plane never processes VPN traffic

---

### Minimal Internal API (User-based)

> Scope: Internal only. No public authentication.  
> Transport: Unix socket or loopback HTTP.

#### Health & Introspection
- `GET /health`
  - Liveness check
- `GET /ready`
  - Readiness check (storage loaded, config valid)
- `GET /version`
  - Build/version metadata

---

#### Authentication (called by VPN daemons)
- `POST /auth/verify`
  - Input:
    ```json
    {
      "username": "string",
      "password": "string",
      "protocol": "ikev2",
      "source_ip": "string"
    }
    ```
  - Output (allowed):
    ```json
    {
      "allowed": true,
      "user_id": "string",
      "session_id": "string",
      "assigned_ip": "string",
      "dns": ["string"],
      "routes": ["string"]
    }
    ```
  - Output (denied):
    ```json
    {
      "allowed": false,
      "reason": "string"
    }
    ```

- `POST /auth/logout`
  - Called by daemon on disconnect
  - Marks session closed

---

#### Sessions (user-level runtime control)
- `GET /sessions`
  - List active sessions
- `GET /sessions/{session_id}`
  - Session details
- `DELETE /sessions/{session_id}`
  - Force-disconnect session

---

#### Users
- `POST /users`
  - Create user
- `GET /users`
  - List users
- `GET /users/{user_id}`
  - User details/status
- `PATCH /users/{user_id}`
  - Update metadata or status
- `POST /users/{user_id}/password`
  - Set or reset password
- `POST /users/{user_id}/enable`
- `POST /users/{user_id}/disable`
  - Disables user and disconnects all sessions
- `DELETE /users/{user_id}`
  - Optional hard delete

---

#### Policy & Network Parameters
- `GET /policy/default`
  - Current default policy
- `PUT /policy/default`
  - Update default DNS, routes, tunnel mode
- `GET /ip-pool`
  - Current VPN IP pool
- `PUT /ip-pool`
  - Update pool definition

---

#### Provisioning (Client Profiles)
- `POST /profiles/ios`
  - Generate iOS `.mobileconfig`
  - Output: downloadable profile blob
- `GET /profiles/{profile_id}`
  - Retrieve previously generated profile
- `DELETE /profiles/{profile_id}`
  - Invalidate profile artifact

---

#### Audit & Logs
- `GET /audit/auth`
  - Authentication success/failure events
- `GET /audit/users`
  - User lifecycle events (create, disable, delete)

---

#### Maintenance
- `POST /reload`
  - Reload configuration without restart
- `POST /backup`
  - Export user + policy state
- `POST /restore`
  - Restore from backup (restricted)

---

**Exit criteria:**
- Adding/removing users requires no daemon restart
- Profiles are generated automatically
- Revocation takes effect immediately
- VPN daemons depend only on the internal API

---

#### Phase 3 – Windows Support

**Objective:** Extend support without modifying the core architecture.

**Tasks:**
- Reuse existing IKEv2 daemon (no protocol rewrite)
- Generate **Windows IKEv2 VPN profiles**:
  - PowerShell or XML-based provisioning
- Validate:
  - Windows native VPN client connects
  - Auth works identically to iOS
  - Routing and DNS behave as expected
- Add Windows-specific documentation
- Handle Windows-specific quirks:
  - NAT-T behavior
  - Fragmentation / MTU tuning

**Exit criteria:**
- Windows connects using built-in VPN
- Same control plane supports both platforms
- No protocol-specific logic leaks into control plane

---

#### Phase 4 – Hardening & Production Readiness

**Objective:** Make the system safe, observable, and maintainable for long-term use,
while keeping **password-based authentication as the permanent model**.

**Authentication policy (explicit decision):**
- Authentication remains **username/password–based** (EAP-MSCHAPv2)
- No client certificates
- No per-device certificates
- Server certificates are used **only** for transport security (IKEv2)

---

**Tasks:**

- Harden password authentication:
  - Enforce strong password policy (length, complexity)
  - Store passwords using a secure password hash (e.g. bcrypt/argon2)
  - Implement account lockout / cooldown after repeated failures
- Improve runtime security:
  - Rate-limit authentication attempts per IP/user
  - Enable Dead Peer Detection (DPD)
  - Enable replay protection and strict timeouts
- Operational hardening:
  - Structured logging (auth success/failure, session lifecycle)
  - Metrics: active sessions, failed auths, reconnect rates
  - Graceful daemon restarts without crashing active services
- Session management:
  - Reliable session cleanup on disconnect
  - Force-disconnect support on user disable
- Network hardening:
  - Firewall rules limited to required ports
  - NAT-T validation
  - MTU/fragmentation tuning
- Documentation & ops readiness:
  - Clear runbooks for:
    - Adding users
    - Removing users
    - Rotating server certificates
    - Recovering from daemon crashes

**Explicit non-goals in this phase:**
- No client certificate issuance
- No certificate revocation lists (CRL/OCSP)
- No device-bound credentials
- No PKI management for clients

---

**Exit criteria:**
- Password compromise can be mitigated by immediate user disable
- Brute-force attempts are effectively limited
- System remains stable under reconnect storms
- Operators can diagnose issues from logs and metrics alone


---


### 13. Success Criteria (MVP)
- iPhone connects using built-in VPN
- Traffic securely routed
- No third-party VPN client installed
- Full server control via own code

