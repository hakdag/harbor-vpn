## Protocol & Cryptographic Suite Specification

### 1. Overview

This document locks the protocol and cryptographic suite decisions for the Custom VPN Platform. It serves as the canonical reference for implementation and security review.

### 2. Protocol Selection

- **Primary VPN protocol**: IKEv2/IPsec
- **Reasoning**:
  - Native support on iOS and Windows (no custom client required)
  - Enterprise-grade and widely deployed
  - Supports strong modern cryptography
  - Well-documented standard (RFC 7296 and related RFCs)

#### 2.1 Alternatives Considered (High-Level)

The following alternatives are out of scope for Phase 1 but listed for completeness:

- **WireGuard**: Excellent modern protocol, but would require a custom app on iOS which violates the PRD “no third-party VPN apps” constraint.
- **OpenVPN**: Similarly requires a third-party client on iOS.
- **SSTP**: In scope only for Windows in a later phase, not for iOS.

### 3. Authentication Model

- **User authentication method (MVP and beyond)**: EAP-MSCHAPv2
- **Credential type**: Username + password
- **Server authentication**: Server certificate used for IKEv2 handshake (transport security only)

#### 3.1 EAP-MSCHAPv2 Flow (High-Level)

1. Client initiates IKEv2 negotiation with the server.
2. During IKE_AUTH, the server requests EAP-based authentication.
3. Client presents username and responds to MSCHAPv2 challenge using the password-derived response.
4. Server verifies the MSCHAPv2 response against securely stored password hashes via the control plane.
5. On success, the control plane returns an “allowed” decision along with user/session metadata (IP, DNS, routes).
6. IKEv2 daemon completes IKE_AUTH and establishes CHILD_SA.

> Note: Detailed EAP-MSCHAPv2 message diagrams will live in the authentication-flow documentation; this section defines the choice and high-level flow only.

### 4. Cryptographic Suite

- **Encryption**: AES-GCM
- **Integrity / PRF**: SHA-256 or stronger
- **Key exchange**: Diffie-Hellman with Perfect Forward Secrecy (PFS)

#### 4.1 IKEv2 Proposal Defaults (Initial Target)

The exact suite will be tuned during implementation, but the target characteristics are:

- IKE SA:
  - Encryption: AES-GCM (128-bit or 256-bit)
  - Integrity: Implicit in AES-GCM, plus SHA-256 for PRF
  - DH group: Modern group with PFS (e.g., 14+ or elliptic-curve group)
- CHILD SA:
  - Encryption: AES-GCM
  - Integrity: AES-GCM authenticated encryption

The implementation MUST:

- Prefer modern, secure algorithms (no legacy ciphers).
- Reject weak proposals (e.g., 3DES, MD5, null encryption).

### 5. Cipher Suite Negotiation Priorities

The responder (our IKEv2 daemon) will:

- Prefer proposals that:
  - Use AES-GCM with SHA-256+ PRF
  - Use strong DH groups with PFS
- Accept only a curated allowlist of suites that meet our security bar.
- Treat any non-allowlisted or legacy proposal as unsupported.

Exact numeric identifiers and ordering will be documented alongside the IKEv2 daemon implementation once the specific Rust IKEv2/IPsec stack choices are finalized.

### 6. Key Derivation

Key derivation will follow RFC 7296 IKEv2 requirements:

- Use the PRF (SHA-256 or stronger) defined for the SA.
- Derive keys for:
  - IKE SA integrity and encryption
  - CHILD SA (ESP) integrity and encryption
- Enforce PFS by rekeying CHILD SAs using fresh DH exchanges where appropriate.

Implementation notes:

- All key material must be kept strictly in memory and never logged.
- Zeroize keys when SAs are torn down.

### 7. Security Constraints & Non-Goals

- **No client certificates** for user authentication (password-only auth is an explicit, permanent design choice).
- **No device-bound credentials**: Authentication is purely user-based.
- **Server certificates** are used only for transport security within IKEv2.
- **No legacy algorithms**: Do not enable older cipher suites “for compatibility”.

### 8. References

- RFC 7296: Internet Key Exchange Protocol Version 2 (IKEv2)
- Project PRD: Custom VPN Platform (sections on protocol choice, authentication model, and security considerations)

