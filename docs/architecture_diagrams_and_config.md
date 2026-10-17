## Architecture Diagrams, Message Flows & Configuration Conventions

This document describes the core diagrams and configuration conventions for the Custom VPN Platform. Textual diagram descriptions are provided so they can be implemented in tools like draw.io, PlantUML, or Mermaid.

---

### 1. High-Level System Architecture

**Diagram description**

Elements:
- Client (iOS device)
- Public internet
- VPN server (single node for Phase 1) with:
  - IKEv2 daemon
  - Control plane service
  - Credential store (file/embedded DB)
  - Logging/metrics sink
- Linux kernel (XFRM/IPsec stack)

Relationships:
- iOS client connects over the internet to the VPN server’s public IP on UDP 500/4500.
- IKEv2 daemon:
  - Listens on UDP 500/4500.
  - Talks to kernel via netlink/XFRM.
  - Talks to control plane via Unix domain socket or loopback HTTP.
- Control plane:
  - Talks to credential store and configuration storage.
  - Exposes internal API (auth verify/logout, policy, ip-pool).
- Kernel:
  - Encrypts/decrypts IPsec ESP traffic and routes packets according to policies.

Suggested layout:
- Left: iOS client.
- Center: “Internet / NAT”.
- Right: VPN server box, containing IKEv2 daemon, control plane, credential store, and kernel boundary.

---

### 2. IKEv2 Message Flow (Responder, MVP)

**Diagram description**

Actors:
- iOS client
- IKEv2 daemon
- Control plane
- Kernel (XFRM/IPsec)

Main sequence (simplified):
1. **IKE_SA_INIT**
   - Client → IKEv2 daemon: IKE_SA_INIT request (SA proposals, key exchange, nonces).
   - IKEv2 daemon:
     - Chooses acceptable proposal.
     - Generates responder nonce and DH share.
   - IKEv2 daemon → Client: IKE_SA_INIT response.

2. **IKE_AUTH + EAP-MSCHAPv2**
   - Client → IKEv2 daemon: IKE_AUTH request (IDi, EAP-Start/EAP-Response with username).
   - IKEv2 daemon → Control plane: `/auth/verify` with username/password or EAP-derived info.
   - Control plane:
     - Verifies credentials.
     - Returns allowed/denied plus session metadata (user_id, session_id, assigned_ip, DNS, routes).
   - If allowed:
     - IKEv2 daemon → Client: IKE_AUTH response with AUTH, EAP-Success, configuration payloads (virtual IP, DNS).

3. **CHILD_SA Establishment**
   - IKEv2 daemon programs ESP SAs via XFRM.
   - Client and server exchange ESP-protected traffic.

4. **Rekey / Delete**
   - Optional exchanges for rekeying or deleting SAs.

The diagram should clearly show that:
- Credentials are checked by the control plane.
- Keying material and IPsec SAs live between IKEv2 daemon and kernel.

---

### 3. Authentication Flow (EAP-MSCHAPv2)

**Diagram description**

Actors:
- iOS client
- IKEv2 daemon
- Control plane
- Credential store

Flow:
1. Client initiates VPN and sends EAP identity (username).
2. IKEv2 daemon issues MSCHAPv2 challenge to client.
3. Client responds with challenge response derived from password.
4. IKEv2 daemon:
   - Forwards username, challenge, and response to control plane `/auth/verify`.
5. Control plane:
   - Fetches stored password hash for user from credential store.
   - Performs MSCHAPv2 verification.
   - Returns allowed/denied and metadata.
6. IKEv2 daemon continues IKE_AUTH based on decision.

Emphasis:
- IKEv2 daemon never reads raw password storage directly.
- Credential verification is encapsulated in the control plane.

---

### 4. Network Topology & Routing

**Diagram description**

Elements:
- iOS client:
  - Physical IP (e.g., behind NAT).
  - Virtual VPN IP from pool `10.10.10.0/24` (e.g., `10.10.10.101`).
- Internet / NAT device.
- VPN server:
  - Public IP.
  - Internal VPN gateway IP (e.g., `10.10.10.1`).
- Downstream networks (internet or private networks) behind VPN server.

Key points:
- ESP traffic between client and server flows over UDP 4500 (with NAT-T) or ESP directly where applicable.
- Client default route points to VPN interface (full-tunnel).
- DNS queries go to VPN-provided DNS (e.g., `10.10.10.1`).
- Server routes packets from `10.10.10.0/24` out to the internet and back.

---

### 5. Configuration Conventions

#### 5.1 File & Directory Layout

Baseline (can be adjusted per distro, but should remain consistent):
- Config:
  - `/etc/custom-vpn/ikev2/` – IKEv2 daemon configuration (listener, crypto, basic settings).
  - `/etc/custom-vpn/control-plane/` – control plane configuration (DB path, API settings, policies).
- Runtime state:
  - `/var/run/custom-vpn/` – PID files, Unix domain sockets (e.g., `control-plane.sock`).
- Logs:
  - `/var/log/custom-vpn/ikev2/` – IKEv2 daemon logs.
  - `/var/log/custom-vpn/control-plane/` – control plane logs.
- Data:
  - `/var/lib/custom-vpn/` – credential store, policy DB, and IP lease data (when persisted).

#### 5.2 Ports & Protocols

- IKEv2 daemon:
  - UDP 500: IKE_SA_INIT and initial exchanges.
  - UDP 4500: NAT-Traversal (IKE + ESP-in-UDP).
- Control plane:
  - Unix domain socket: `/var/run/custom-vpn/control-plane.sock`.
  - Optional loopback HTTP/gRPC: `127.0.0.1:<port>` (exact port TBD, but reserved in configuration).

#### 5.3 Logging Standards

- Format:
  - Structured logs (e.g., JSON) with fields such as:
    - timestamp
    - level (`DEBUG`, `INFO`, `WARN`, `ERROR`)
    - component (`ikev2-daemon`, `control-plane`)
    - event type (`auth_attempt`, `session_start`, `session_end`, `config_reload`, etc.)
    - correlation IDs (session_id, user_id where safe)
- Policy:
  - No secrets or passwords in logs.
  - Minimal PII; usernames only where necessary and at appropriate log levels.
  - Configurable log level with secure defaults (e.g., INFO in production).

#### 5.4 Secret Storage

- Passwords:
  - Stored only as strong password hashes (Argon2 or bcrypt) with per-user salts.
  - Located in control-plane data store under `/var/lib/custom-vpn/`.
- Server certificates and keys:
  - Stored under `/etc/custom-vpn/ikev2/certs/` or similar.
  - File permissions restricted to `vpn-ikev2` and root.
- Encryption at rest (optional for later phase):
  - Underlying storage for user DB and secrets can be encrypted using OS-level facilities where required.

---

### 6. Deployment Topologies (Textual)

#### 6.1 Single-Server Deployment (Phase 1)

- One Linux VM/host:
  - Runs both IKEv2 daemon and control plane.
  - Uses local credential store.
  - Suitable for initial MVP and small-scale setups.

#### 6.2 Future HA/Scale-Out Sketch

- Multiple VPN nodes running IKEv2 daemon instances.
- Shared or replicated control plane and state store.
- Load balancer or anycast IP in front of VPN nodes.
- Consistent configuration conventions across nodes to minimize operational complexity.

