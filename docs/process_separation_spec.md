## Process Separation Architecture & Communication Boundaries

### 1. Overview

This document defines the process separation model for the Custom VPN Platform, focusing on:
- Roles and responsibilities of the IKEv2 daemon vs. control plane
- Inter-process communication (IPC) mechanisms and boundaries
- Privilege separation and isolation
- Failure isolation and restart behavior
- Secret handling and data flow
- API contract considerations

The design follows the principle of least privilege and assumes:
- IKEv2 daemon handles protocol and packet-level concerns only.
- Control plane handles all user, credential, and policy management.

### 2. Process Roles

#### 2.1 IKEv2 Daemon

**Responsibilities**
- Implement IKEv2 responder (RFC 7296):
  - IKE_SA_INIT
  - IKE_AUTH
  - CHILD_SA establishment and rekeying
- Interface with Linux XFRM/netlink to program ESP SAs.
- Perform NAT-T handling on UDP 500/4500.
- Call into the control plane for:
  - Authentication decisions (username/password via EAP-MSCHAPv2).
  - Session metadata (assigned IP, DNS, routes).

**Explicit non-responsibilities**
- No direct database or credential store access.
- No user or policy management.
- No long-term storage of secrets.

#### 2.2 Control Plane

**Responsibilities**
- User and credential management (create, update, disable, delete).
- Secure password hashing and storage.
- Policy management:
  - Default DNS and routes.
  - IP pool configuration.
- Session lifecycle tracking (create, list, revoke).
- Profile generation (e.g., iOS `.mobileconfig`).
- Internal API for VPN daemons:
  - `/auth/verify`
  - `/auth/logout`
  - Session and policy queries.

**Explicit non-responsibilities**
- No direct packet handling.
- No direct manipulation of IPsec SAs.

### 3. Inter-Process Communication (IPC)

#### 3.1 Transport Choices

- **Primary option**: Unix domain socket
  - Path: e.g., `/var/run/custom-vpn/control-plane.sock`
  - Permissions:
    - Restricted to VPN-related system users/groups.
    - Mode `0660` or stricter.
- **Alternative option**: Loopback-only HTTP/gRPC
  - Bind to `127.0.0.1` with firewall rules preventing external access.

Unix domain sockets are preferred for:
- Simpler access-control via filesystem permissions.
- Avoiding network stack exposure.

#### 3.2 Authentication & Authorization

- Only processes running under approved users/groups may connect.
- The control plane validates client identity via:
  - Socket ownership/group checks.
  - Optional shared secret or token if loopback HTTP is used.
- No unauthenticated IPC endpoints.

### 4. Privilege Separation

#### 4.1 Users & Groups

- **IKEv2 daemon**:
  - Runs under a dedicated system user, e.g., `vpn-ikev2`.
  - Minimal group memberships.
  - Granted only capabilities needed for:
    - Binding to UDP 500/4500.
    - Interacting with XFRM (e.g., via `CAP_NET_ADMIN`).
- **Control plane**:
  - Runs under a separate system user, e.g., `vpn-control`.
  - Owns the credential store and configuration files.
  - No raw network packet privileges.

#### 4.2 Filesystem & Namespace Isolation

- Consider:
  - `chroot`/namespaces to further isolate processes.
  - Separate configuration and log directories:
    - IKEv2 daemon: e.g., `/etc/custom-vpn/ikev2/`, `/var/log/custom-vpn/ikev2/`.
    - Control plane: e.g., `/etc/custom-vpn/control-plane/`, `/var/log/custom-vpn/control-plane/`.
- Ensure that compromise of one process does not grant easy access to the other’s files.

### 5. Failure Isolation & Restart Behavior

- IKEv2 daemon and control plane are separate binaries/services.
- Requirements:
  - A crash in the IKEv2 daemon must not take down the control plane.
  - A control-plane failure should not immediately crash the daemon; instead:
    - Auth attempts fail closed (deny) with clear logs.
    - Existing sessions may continue until rekey or explicit teardown.
- Systemd or equivalent service manager:
  - Independent unit files for each process.
  - Restart policies tuned per component (e.g., on-failure with backoff).

### 6. Secret Handling

- **Control plane**:
  - Sole owner of password hashes and sensitive user data.
  - Responsible for secure storage (hashed passwords, encrypted backing store if applicable).
  - Only returns minimal necessary data to the daemon:
    - `allowed` / `denied` decision.
    - User/session identifiers.
    - Assigned IP, DNS, routes.
- **IKEv2 daemon**:
  - Never stores or logs raw credentials.
  - Does not cache long-term secrets beyond what is strictly required for SA lifetimes.
  - Keys derived for IKE/ESP:
    - Kept in-memory only.
    - Zeroized when SAs are torn down.

### 7. API Contract (High-Level)

- The internal API between daemon and control plane mirrors the PRD’s minimal API:
  - `POST /auth/verify`:
    - Input: username, password, protocol, source IP.
    - Output: allowed/denied plus session metadata.
  - `POST /auth/logout`:
    - Input: session identifier.
  - Read-only endpoints for:
    - Default policy (DNS, routes, tunnel mode).
    - IP pool configuration.
- Versioning:
  - Include a simple version field in requests or headers.
  - Control plane may support multiple versions; daemon should log mismatch.

### 8. Summary

- IKEv2 daemon: packet handling, protocol state, minimal privileges; no direct user DB access.
- Control plane: users, credentials, policy, sessions; no packet handling or raw network powers.
- IPC: primarily Unix domain socket with strict permissions; optional loopback HTTP.
- Privilege separation: distinct users, limited capabilities, possible namespace isolation.
- Failure isolation: independent processes with deny-by-default behavior on IPC failure.
- Secret handling: centralized in control plane; daemon receives only decisions and metadata.

