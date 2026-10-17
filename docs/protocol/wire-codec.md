# Offline IKEv2 wire codec

## Scope and entry points

The Cargo workspace is in `src/`; codec source and tests are in `src/crates/ikev2-wire/`.

`ikev2-wire` has no runtime dependencies, unsafe code, I/O, cryptography, algorithm negotiation or protocol state. Wire models borrow payload bytes; bounded vectors hold payload/proposal/transform/attribute metadata. Packet-bearing types intentionally do not implement Debug. Errors carry only category, byte offset and static reason.

1. `raw::decode(bytes, limits)` reads a complete header and outer payload envelopes, including termination at SK/SKF. It retains version, exchange type, critical flags and opaque bytes. It does not claim body validity.
2. `decode(bytes, limits)` adds structural decoding for SA, KE, Nonce, Notify and Vendor ID. Other bodies remain explicitly opaque, including protected bytes. A decoded packet is untrusted.
3. `decode_sa(body, limits)` exercises a standalone SA body; error offsets start at zero. Message decoding reports absolute message offsets.
4. `check_support(&message)` checks implementation coverage: unsupported major version, exchange types outside RFC 7296's four base exchanges, unknown critical payloads, unimplemented base payload bodies, SK and SKF report Unsupported. Unknown noncritical extension payloads can be skipped/preserved. Newer minor versions are accepted. This is not full RFC conformance checking or an algorithm allowlist.
5. `encode(&message, limits)` derives lengths and links, bounds output and validates modeled structural invariants. It can encode unsupported identifiers; this does not enable them. Payload offsets are diagnostic and ignored on serialization.

No function checks peer state, required exchange payload sets/order, message-ID windows, retransmissions, response binding, identities or authentication. No received data may trigger protocol actions in this milestone.

## Structural invariants

- Exactly one 28-byte-header IKE message; declared total length equals input length. Exclude UDP headers, port 4500's four-byte non-ESP marker, keepalives and ESP from the input.
- Generic payload lengths include the four-byte header and stay within the enclosing message. Next Payload traverses forward with no leftovers or dangling links. Unaligned bodies are accepted.
- SK and SKF terminate the outer chain; their Next Payload describes inner content. No ciphertext, padding, IV, tag or fragment body is validated without its future protocol/crypto context.
- SA is nonempty. Proposal/transform lengths agree with enclosing bytes, terminal markers agree with actual substructure position, and declared transform counts agree with decoded counts. Each proposal has at least one transform.
- Proposal numbers are nonzero and consecutive within the body. Whether the first number must be 1 (offer) or match a previous offer (response) requires exchange context and remains outside the wire decoder.
- Known proposal SPI sizes are IKE 0 or 8, AH/ESP 4; deciding initial IKE versus rekey requires exchange context. Unknown protocol IDs retain their declared SPI bytes.
- Transform TV/TLV attributes have bounded complete values, no duplicate types, and Key Length uses TV. Unknown transform/attribute identifiers are retained. Algorithm-specific attribute validity, key sizes, transform combinations and DH share validation remain future negotiation/crypto responsibilities.
- KE has its four-byte fixed body header; group-specific data sizes and public-value checks are deferred. Nonce body length is 16–256 bytes; PRF-specific entropy/size requirements cannot be checked yet.
- Notify's fixed fields and SPI length fit its body. Individual notification data semantics and context-dependent protocol/SPI requirements are deferred. Vendor ID bytes are opaque.
- RFC reserved fields are ignored on receipt and zeroed on output where modeled. Header I/V/R bits are retained. Critical is ignored for understood payloads; output clears it for base RFC payloads. Opaque body bytes are preserved without interpretation.

Malformed errors mean a modeled structural invariant failed. Unsupported errors mean implementation coverage is insufficient, not that the input is malformed. Limit errors are local resource policy, not a protocol validity judgment. Opaque bodies cannot be certified well-formed beyond their generic envelope. Unknown algorithm IDs are neither malformed nor approved algorithms.

## Limits and serialization

Defaults and hard ceilings: 65,535 message bytes, 128 payloads, 64 proposals, 64 transforms per proposal, 64 attributes per transform. Operators can lower them through typed TOML configuration; message bytes must be at least 28 and element caps at least 1. All public parsing/encoding entry points revalidate ceilings before allocations. The standalone SA body has the same byte ceiling; adding an envelope may exceed it.

Checked cursors borrow input, iterative loops always advance, and the writer checks available capacity before copying. Vector sizes are bounded before insertion. Duplicate attribute checks are bounded by the attribute ceiling. Serialization never trusts caller length fields, rejects invalid typed models and normalizes modeled reserved fields; therefore byte-for-byte round trips are promised only for canonical inputs. Encode/decode/encode is deterministic for valid decoded models.

## Fixtures and verification

Hex fixtures are hand-authored from field layouts, not generated by this serializer or captured from live users:

| Fixture | Independent assertions / limits |
|---|---|
| `sa-init.hex` | 100-byte structural example: fixed SPIs, one proposal, three transforms including TV Key Length, KE and 16-byte nonce. Four-byte KE data is deliberately synthetic, not a valid group-19 public key or a usable handshake. |
| `notify-vendor.hex` | 48-byte message with nonzero responder SPI/message ID, private notification 65000, Vendor ID. No notification behavior is implemented. |
| `encrypted.hex` | 40-byte message with SK, Next Payload 35 and opaque synthetic bytes. No cryptographic validity claim. |
| `multiple-proposals.hex` | Standalone 32-byte SA body: consecutive proposal numbers and unknown transform IDs 65000/65001. No accepted suite implied. |

Tests assert independently constructed typed models against expected bytes in both directions, nested malformed lengths/counts/markers, truncation with original and adjusted outer lengths, critical/unknown behavior, receive/send normalization, SPI and nonce boundaries, custom limits and every hard ceiling. Property tests cover arbitrary bytes and generated typed messages. Fuzzing instructions and retained evidence are in `../../src/fuzz/README.md` and `../../src/fuzz/results/`.

## Standards and deferred work

Wire behavior is based on RFC 7296 §§2.5, 2.10 and 3.1–3.4, 3.9–3.10, 3.12, 3.14: https://www.rfc-editor.org/rfc/rfc7296.html. SKF is recognized only as an unsupported encrypted boundary from RFC 7383, with no fragment decoder or reassembly.

Future milestones must add exchange/state validation, supported-suite policy, authenticated decryption before parsing inner bodies, EAP/IKE AUTH, transport framing, timers, lifecycle and kernel integration. None is implemented here. See `../decision-register.md` for unresolved architectural choices.
