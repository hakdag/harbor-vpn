## Threat Model & Security Mitigation Strategies

### 1. Scope & Objectives

This document defines the initial threat model and concrete mitigation strategies for the Custom VPN Platform, focusing on:
- Credential theft
- Replay attacks
- Brute-force attacks
- Rate limiting and abuse prevention
- DDoS and resource exhaustion
- Man-in-the-middle (MITM)
- Side-channel and information leakage

The scope is aligned with Phase 0/1 of the PRD and assumes:
- Primary protocol: IKEv2/IPsec
- Authentication: username/password via EAP-MSCHAPv2
- Server-managed certificates for IKEv2 transport security only

### 2. Assets

Key assets that must be protected:
- User credentials (passwords)
- Authentication decisions and session tokens/IDs
- VPN session keys and IPsec SAs
- Control plane configuration (users, policies, IP pools, DNS)
- Logs and audit data

### 3. Threats and Mitigations

#### 3.1 Credential Theft

**Threats**
- Theft of stored passwords or password hashes on the server.
- Interception of credentials in transit (e.g., on auth path).
- Accidental exposure via logs or crash dumps.

**Mitigations**
- Storage:
  - Store passwords only as strong password hashes (e.g., Argon2 or bcrypt) with per-user salts.
  - No plaintext password storage anywhere.
- Transmission:
  - All control-plane communication (e.g., `/auth/verify`) must be protected with TLS on loopback or Unix domain sockets with strict permissions.
  - IKEv2 already protects EAP-MSCHAPv2 exchanges within the encrypted IKE_SA.
- Logging:
  - Never log raw credentials or full EAP payloads.
  - Redact usernames where appropriate in logs, or at minimum avoid logging them at debug levels by default.
- Access control:
  - Restrict access to credential store files/DB to the control-plane process only.

#### 3.2 Replay Attacks

**Threats**
- An attacker replays captured IKEv2 or EAP-MSCHAPv2 messages to gain unauthorized access or disrupt sessions.

**Mitigations**
- IKEv2-level:
  - Follow RFC 7296 for anti-replay:
    - Use nonces and sequence numbers.
    - Reject messages outside expected windows.
  - Ensure the implementation validates SPIs and message IDs strictly.
- Control plane:
  - Track session IDs and ensure that duplicate or stale session establishment attempts are rejected.
- Logging and detection:
  - Log repeated failed attempts with same parameters to support operational detection.

#### 3.3 Brute-Force Attacks on Passwords

**Threats**
- Automated guessing of usernames/passwords via repeated EAP-MSCHAPv2 attempts.

**Mitigations**
- Account-level protections:
  - Implement configurable account lockout or cooldown after a threshold of failed attempts.
  - Expose lockout status via control plane (e.g., user disabled/locked).
- IP-level protections:
  - Track failed attempts per source IP and apply backoff or temporary bans.
- Feedback control:
  - Avoid revealing whether a username exists; use generic error messages.
- Observability:
  - Emit structured logs for failed authentication attempts (with counts and source IP) to support alerting.

#### 3.4 Rate Limiting & Abuse Prevention

**Threats**
- Malicious or misconfigured clients causing resource exhaustion via rapid connect/disconnect or authentication attempts.

**Mitigations**
- Per-IP and per-user rate limiting:
  - Limit new IKE_SA attempts per IP over a time window.
  - Limit auth attempts per user over a time window.
- Session caps:
  - Cap concurrent sessions per user and per IP.
- Backpressure:
  - When limits are hit, respond with minimal processing and clear log entries.

#### 3.5 DDoS & Resource Exhaustion

**Threats**
- Floods of IKEv2 packets aimed at exhausting CPU, memory, or bandwidth.

**Mitigations**
- Network edge:
  - Use basic firewall rules to drop obvious garbage traffic.
  - Optionally use upstream protection (e.g., provider-level DDoS protections) in production.
- Daemon behavior:
  - Implement inexpensive early rejection for malformed or unauthenticated packets.
  - Set caps on:
    - Pending half-open IKE_SAs.
    - Total concurrent sessions per node.
- Operational:
  - Instrument metrics for:
    - IKE_SA creation rate.
    - Failed/denied connections.
    - Resource usage under load.

#### 3.6 Man-in-the-Middle (MITM)

**Threats**
- Attacker between client and server attempting to intercept or tamper with IKEv2 traffic.

**Mitigations**
- Certificates:
  - Use properly issued server certificates with strong TLS/IKEv2 parameters.
  - Ensure iOS profiles pin the correct CA or certificate.
- Configuration:
  - Require strict certificate validation on clients (no “trust on first use”, no weak ciphers).
  - Disable fallback or legacy algorithms that could weaken the handshake.

#### 3.7 Side-Channel & Information Leakage

**Threats**
- Leaking sensitive information via logs, error messages, or timing differences.

**Mitigations**
- Logging:
  - Structured logs with minimal PII, no secrets.
  - Configurable log levels with safe defaults (no verbose crypto internals in production).
- Errors:
  - Generic error messages for auth failures and internal errors.
  - Avoid revealing exact reason (e.g., “user not found” vs “wrong password”).
- Timing:
  - Where feasible, avoid large timing differences between valid and invalid credentials.

### 4. Mapping Threats to Implementation

Each of the above mitigations should be reflected in:
- IKEv2 daemon:
  - Protocol-level anti-replay and DOS protections.
  - Strict parsing and early rejection of invalid messages.
- Control plane:
  - Password hashing, lockout/rate limiting, user disable.
  - APIs for listing and managing sessions, users, policies.
- Operational tooling:
  - Dashboards/alerts on auth failures, connection rates, and resource usage.

### 5. References

- Project PRD sections:
  - Security considerations (rate-limiting, replay protection, minimal exposed ports).
  - Hardening & production readiness phase.
- Standards and best practices:
  - RFC 7296 (IKEv2)
  - OWASP guidance for authentication and session management

