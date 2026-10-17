## Network Model & VPN Configuration Parameters

### 1. Overview

This document defines the network model for the Custom VPN Platform, including:
- VPN address pool and allocation strategy
- Default tunneling behavior
- DNS push configuration
- NAT traversal settings
- Client routing behavior
- IP lease management basics
- IPv6 considerations (initial stance)

### 2. VPN Address Pool

- **Primary VPN address pool**: `10.10.10.0/24`
  - Reserved ranges:
    - `10.10.10.1`: VPN gateway/server internal address
    - `10.10.10.2–10.10.10.10`: Reserved for future infrastructure or special roles
  - Dynamic client range:
    - `10.10.10.11–10.10.10.250`: Assignable to VPN clients

#### 2.1 Allocation Strategy

- Allocation model: **DHCP-like**, managed by the control plane or simple in-daemon allocator in Phase 1.
- Requirements:
  - Each active session must have **one stable virtual IP** for the lifetime of the session.
  - Avoid reusing addresses of active sessions.
  - On session termination, addresses are returned to the free pool.
- Conflict avoidance:
  - This private range should be chosen to minimize overlap with common home/office networks (e.g., 192.168.0.0/16, 10.0.0.0/8 variants). Final choice should be validated against deployment environment, but `10.10.10.0/24` is our **default**.

### 3. Tunneling Behavior

- **Default mode (Phase 1)**: **Full-tunnel**
  - All client traffic (0.0.0.0/0) is routed through the VPN.
  - Justification:
    - Simplifies initial routing logic.
    - Matches typical “personal VPN” expectations.
    - Avoids subtle leaks from incorrect split-tunnel configuration.

- **Future option**: Split-tunnel
  - Not enabled by default.
  - Would be controlled by policy in the control plane via route lists (e.g., only corporate subnets).

### 4. DNS Configuration

- DNS servers pushed to clients (default):
  - Primary: `10.10.10.1` (can be a DNS forwarder on the VPN server)
  - Secondary: Optional public DNS (e.g., `1.1.1.1` or `9.9.9.9`) depending on deployment choices.

- Requirements:
  - When connected, the client should **prefer VPN-provided DNS** for all domains.
  - iOS must be configured via `.mobileconfig` to use these DNS servers with the IKEv2 profile.

### 5. NAT Traversal

- Transport ports:
  - **UDP 500**: IKEv2 initial exchange
  - **UDP 4500**: NAT-Traversal (UDP encapsulation of ESP)

- Requirements:
  - IKEv2 daemon must:
    - Detect NAT on the path and switch to UDP 4500 as per RFC 7296.
    - Use Linux XFRM to handle ESP encapsulation/decapsulation.
  - Deployment firewalls must allow:
    - Inbound UDP 500 and 4500 from the internet.

### 6. Client Routing Behavior

- When VPN is connected:
  - Default route `0.0.0.0/0` is set to the VPN interface.
  - VPN-assigned IP (e.g., `10.10.10.x`) is used as the client’s source address for routed traffic.
  - DNS queries are sent to VPN-provided DNS servers.

- iOS specifics:
  - Routing behavior is configured via the IKEv2 profile in `.mobileconfig`.
  - For Phase 1, configuration should request:
    - Full-tunnel routing.
    - Use of VPN DNS for all lookups.

### 7. IP Address Lease Management (Initial)

- Phase 1:
  - Simple in-memory or file-based allocator.
  - On daemon restart, it is acceptable to reassign IPs (no persistence guarantees) as long as:
    - There are no overlapping active sessions after restart.

- Later phases:
  - Move lease state into the control plane (embedded DB or file store).
  - Track:
    - Session ID → assigned IP
    - Lease start time
    - Optional lease expiry for cleanup.

### 8. IPv6 Considerations

- Initial stance:
  - IPv6 **out of scope** for Phase 1.
  - All configuration assumes IPv4-only VPN address pool and routing.

- Future work:
  - Define a separate IPv6 pool (e.g., ULA prefix).
  - Extend control plane and daemon to support dual-stack tunnels.

### 9. Summary

- Default pool: `10.10.10.0/24` with DHCP-like allocation.
- Default mode: **Full-tunnel**, all traffic through VPN.
- DNS: VPN-provided DNS (default `10.10.10.1`) pushed to clients.
- NAT-T: Use UDP 500/4500 with XFRM for ESP, open on the server firewall.
- Routing: Default route via VPN when connected; iOS configured accordingly.
- Lease management: Simple allocator in Phase 1, later centralized in control plane.
- IPv6: Explicitly deferred to a later phase.

