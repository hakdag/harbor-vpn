# IKE_SA_INIT responder — Milestone 2

The binding policy is [ADR-002](../ADR-002.md). This exchange derives **unauthenticated** keys; it does not authenticate either party, assign a user/address, install ESP or create a usable VPN.

## Boundaries and exchange behavior

`ikev2-wire` retains structural decoding/serialization independently of exchange policy. `ikev2-core` takes bounded IKE bytes, observed IPv4 source/destination endpoints and elapsed monotonic time; it performs no I/O. `ikev2-transport` strips/adds NAT-T framing and drives the core. `ikev2-crypto` owns the OpenSSL interface; no cryptographic primitives are implemented locally. `ikev2d` composes these only when explicitly started with `--serve config.toml`.

The initial request must have IKEv2 major version 2, exchange 34, initiator flag set, response flag clear, message ID 0, nonzero SPIi and zero SPIr. Reserved receive bits and higher minor versions follow the existing codec/RFC rules. Higher major versions receive INVALID_MAJOR_VERSION; lower ones are dropped. Require exactly one SA, KE and nonce. The first proposal number is 1; nonce bounds are 16–256 bytes. Unrecognized noncritical extensions are ignored; unknown critical payloads receive UNSUPPORTED_CRITICAL_PAYLOAD. Duplicate mandatory payloads and invalid initial-exchange payloads receive INVALID_SYNTAX when structural decoding permits a safe reply. Structurally malformed/oversized packets and inadmissible outer headers are dropped.

Select only IKE proposals with the exact approved encryption/key-length, PRF and DH combination and no separate integrity transform. Multiple alternatives of an allowed transform type may be offered; select the approved combination and preserve the selected proposal number. Unsupported IDs are retained in bounded numeric offer summaries on NO_PROPOSAL_CHOSEN, never enabled as fallback. Wrong KE group receives INVALID_KE_PAYLOAD with group 19. A group-19 share must be exactly the 64-byte uncompressed X||Y coordinates and a valid non-infinite on-curve point before responder key generation.

For a fresh accepted request: generate ephemeral P-256 key, derive the 32-byte common value, generate a nonzero collision-checked responder SPI and a 32-byte nonce, derive keys and encode SA/KE/nonce/two NAT notifications. Cache the exact request/response and unauthenticated keys only after successful processing. The private ECDH handle and common value are released promptly. No transition to authenticated state exists. Exact request duplicates on the same endpoint/SPI tuple receive byte-identical cached responses without new DH or deadline extension; conflicting requests with that tuple are dropped. Deadline expiry drops the cache and keys, including during idle transport ticks. Clock reversal fails closed.

## Crypto construction and limits

OpenSSL supplies P-256, random generation, HMAC-SHA256, AES-256-GCM and constant-time comparisons. RFC 7296 key ordering is `SKEYSEED = prf(Ni || Nr, shared)` and `prf+(SKEYSEED, Ni || Nr || SPIi || SPIr)`. The 168 derived bytes comprise SK_d(32), SK_ai/SK_ar(0 each), SK_ei/SK_er(36 each: key32+salt4), SK_pi/SK_pr(32 each). SHA-1 is used solely for RFC-mandated NAT detection, never negotiated as a PRF/integrity fallback.

Each noncloneable GCM key has a random initial 64-bit explicit IV, checked monotonically increasing counter and exhaustion error; the 96-bit GCM nonce is salt4||IV8. An IV is consumed even on an encryption failure. AAD is authenticated by the library; decryption returns plaintext only after successful tag verification. The API caps plaintext/ciphertext/AAD at 65,535 bytes. This is provider readiness only: encrypted IKE payload construction, replay/message-ID validation and IKE_AUTH are not implemented. Later exchange code must supply the exact RFC header/SK AAD and enforce protocol/state rules.

Application-owned secret buffers use `Zeroizing`; secret Debug output is redacted, packet/outcome dumps are avoided, and logs contain aggregate metadata only. This does not guarantee erasure of every OpenSSL/allocator/internal copy or memory after abrupt process termination.

| Setting | Default | Accepted range / relationship |
|---|---|---|
| `max_pending` | 1024 | 1–4096 |
| `per_source` | 32 | 1–128 and no greater than global cap |
| `cookie_threshold` | 512 | 1–global cap |
| `lifetime_secs` | 10 | 1–60 |
| `cookie_rotation_secs` | 60 | 10–300 |
| `max_request_bytes` | 4096 | 256–16384 IKE bytes, excluding NAT-T marker |
| `max_response_bytes` | 2048 | 256–16384 IKE bytes, excluding marker |

The codec byte limit must cover both handshake byte limits, and its payload/transform limits must allow the mandatory five-payload/three-transform response. These are checked before serving. Pending transcript storage is bounded by the caps (at the absolute configured ceilings, at most 128 MiB of cached request+response bytes, plus bounded keys/entries/decoder overhead). This is not a measured whole-process RSS guarantee. Per-source counting/expiry scan at most the bounded pending table; each transport tick handles at most 64 datagrams per socket, with no application send queue. Metrics include event/rejection categories, pending count, expiration, I/O errors and maximum observed processing time; no per-packet logging flood.

COOKIE challenges activate at the pending threshold or exhausted per-source budget. They allocate no pending entry and perform no ECDH. Cookie40 = epoch8 || HMAC-SHA256(secret, domain-label || epoch8 || nonce-length2 || Ni || SPIi8 || source-IP4 || source-port2 || destination-IP4 || destination-port2), all integers network order. The domain label is `harbor-ikev2-cookie-v1`. Current and immediately previous rotation epochs are accepted; skipping epochs discards the old key. A supplied invalid cookie is rechallenged even below the threshold. A valid cookie never bypasses hard capacity. The COOKIE notify must be first in a retry; source/destination changes require a fresh cookie. This is bounded handshake defense, not comprehensive production DDoS protection.

## UDP, NAT and safe lab use

The same adapter handles IPv4 UDP 500 and 4500, with configurable ports for tests. UDP 4500 IKE packets require the four zero-byte non-ESP marker. Single-byte `ff` NAT keepalives and nonzero-SPI ESP datagrams are ignored; ESP is never processed. An oversize-sentinel receive buffer prevents accepting a truncated oversized datagram as valid. Responses use the receiving channel and observed peer endpoint.

NAT hashes are SHA1(SPIi8||SPIr8||IPv4||port2). Initial requests use SPIr=0; responses use the actual responder SPI. Source notifications compare to the observed remote endpoint and destination to the bound local endpoint. Multiple source hashes are accepted with any-match semantics; exactly one destination hash is allowed, and source/destination notifications must occur together. The response source/destination hashes describe local/peer respectively. Changed hashes are metadata; they do not authenticate a peer or start ESP. A later authenticated exchange/port migration is outside this milestone.

Run from the repository:

```sh
cd src
cargo run -p ikev2d -- config/milestone-2-lab.toml
cargo run -p ikev2d -- --serve config/milestone-2-lab.toml
```

The first command only checks configuration; the second binds loopback `127.0.0.1:15000` and `127.0.0.1:14500`. Stop with Ctrl-C. Tests use independently generated golden packets and ephemeral loopback ports; no native-client compatibility is claimed.

For a separately arranged native-client lab, configure an actual local unicast IPv4 address and ports 500/4500. Wildcard binding is rejected because std UDP sockets do not expose the per-packet destination needed for correct NAT hashes. Do not run this lab service as unrestricted root. On Linux hosts restricting low ports, binding 500 needs narrowly scoped `CAP_NET_BIND_SERVICE` or an operator-reviewed socket-activation design; UDP 4500 normally does not. No capabilities, sysctls, firewall, network namespace or systemd settings are changed by this project. Before target-host deployment review a dedicated service identity, only the necessary bind capability, filesystem protections, `NoNewPrivileges`, address-family restrictions and systemd confinement against the actual Ubuntu release. No service unit or socket-activation implementation is supplied here.

## Evidence and remaining work

See [Milestone 2 report](../../features/milestone_2_report.md) for reproducible commands and results. Independent Python stdlib fixtures cover canonical request/response/cookie and HMAC key schedule/NAT hashes; published vectors cover P-256, HMAC and GCM. Actual loopback tests use fresh OpenSSL ECDH and both framing paths.

Outstanding: native iOS version/build and explicit profile/captured offers, direct and real-NAT tests on 500/4500, Ubuntu LTS/library/privilege verification, packet-capture evidence and longer new-target fuzz campaigns. Host OpenSSL is dynamically linked and is not itself rebuilt with sanitizer instrumentation. IKE_AUTH/EAP/certificates, CHILD_SA/ESP/XFRM, routing/DNS, fragmentation/MOBIKE/DPD/rekey and the control plane remain excluded.

Protocol references: [RFC 7296](https://www.rfc-editor.org/rfc/rfc7296.html), [RFC 5282](https://www.rfc-editor.org/rfc/rfc5282.html), [RFC 5903 §8.1](https://www.rfc-editor.org/rfc/rfc5903.html#section-8.1), [RFC 4231](https://www.rfc-editor.org/rfc/rfc4231.html).

## Milestone 2 finding remediation (2026-10-18)

CERTREQ (type 38) remains opaque and ignored regardless of its critical bit, as required for recognized payload types by RFC 7296 §§2.5/3.2. No certificate contents are parsed, trusted, loaded or returned.

Pre-cryptography admission now runs in the offline core before wire decoding, proposal negotiation, COOKIE HMAC/rotation, point validation, DH, and cached/error replies. Two integer token buckets limit work: one global and one per observed source IPv4, shared across ports and both sockets. Each attempt charges the global bucket even when its source quota or source-table capacity denies admission. Denials produce `RateLimited`, no reply and no packet diagnostic; aggregate `rate_limited` counts them. Invalid framing/oversize rejected by transport performs only existing bounded framing work. Idle ticks continue to expire pending keys. Pending-table scans occur only when the next pending deadline is reached, rather than on every packet.

| `[handshake]` setting | Default | Accepted range |
|---|---:|---:|
| `work_per_second` | 200 | 1–2000 |
| `work_burst` | 400 | 1–8192 |
| `source_work_per_second` | 20 | 1–2000 |
| `source_work_burst` | 40 | 1–4096 |

Buckets start full, refill continuously using elapsed monotonic nanoseconds, and never exceed their configured burst. A source is its observed IPv4, not a device/user identity. The source table has a fixed ceiling of 1024 entries and fails closed for new addresses when full. At most once per monotonic second, it removes entries idle for `max(60, ceil(source_work_burst / source_work_per_second))` seconds (up to 4096 seconds at the allowed extremes). This avoids resetting partially refilled buckets through expiry. Denied attempts do not renew source retention. No packet-by-packet eviction or unbounded per-source allocation exists. Existing pending caps, COOKIE threshold, verification, rotation and expiry remain in force; a valid COOKIE cannot bypass admission or pending caps. Cached responses are byte-identical only when admitted; overloaded clients may need to retransmit later.

Over any interval of `t` seconds the global bucket bounds admitted packet work/replies by `work_burst + work_per_second*t`; every admitted request can generate at most one response and at most one fresh DH operation. At defaults, a conservative IKE-response-byte bound is `2048*(400 + 200*t)` (plus UDP/NAT-T/IP framing). This bounds application work and response opportunities, not CPU utilization, actual throughput or host bandwidth. Spoofed/distributed sources can consume the global budget or fill the source table and deny legitimate access. Hosts behind one NAT share a source quota. COOKIE address proof remains occupancy-triggered, so some pre-threshold replies/DH work are still unauthenticated. Floods can exhaust NIC/kernel queues, receive-loop time, outbound bandwidth and logging/storage resources; neither DDoS protection nor elimination of reflection is claimed. Use controlled source-restricted labs; target-host capacity measurement, upstream anti-spoofing/filtering, ingress/egress policy and log retention remain operator work. High allowed configuration ceilings are not recommended operating values.

Transport now retains at most eight safe diagnostic samples, admitting at most one sample per second globally across both sockets, with a suppression counter. The daemon drains this bounded buffer and emits scalar JSON tracing events: `ike_sa_init_diagnostic` (sample ID, channel/outcome, actual selected proposal and fixed ADR-002 IDs, NAT comparison flags), `ike_proposal_offer` (proposal number/protocol), and `ike_proposal_transform` (numeric kind/algorithm/key-length). Each sample contains at most four offered proposals and eight transforms per proposal (at most 37 events/sample); `offers_truncated`, `transforms_truncated` and `attributes_omitted` identify omissions. Selection examines the complete bounded offer, even if the chosen proposal lies beyond the diagnostic cap. No attribute bytes, packet bytes, identities, key shares, nonces, COOKIE values, hashes, credentials or keys enter these diagnostic types. `selected=false` means suite fields are zero placeholders, not a negotiated algorithm. `nat_evaluated=true` means actual NAT hashes were compared; only then interpret NAT change flags. `nat_present=false` with `nat_evaluated=false` does not establish a no-NAT path. Malformed/rate-limited traffic has aggregate counters only. Sampling may omit an important client under contention; captures remain required for native acceptance.

See [remediation report](../../features/milestone_2_remediation_report.md). The accepted 30-minute campaigns describe the earlier implementation; the changed source has separate sanitizer smoke evidence and must not inherit that source hash.
