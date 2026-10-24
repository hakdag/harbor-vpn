# Milestone 3: protected IKE_AUTH and EAP-MSCHAPv2

Status: implemented and locally exercised; native iOS and Ubuntu service acceptance pending. This is a lab authentication responder, not an operational VPN. ADR-002 and accepted ADR-003 govern this milestone. No CHILD_SA, ESP, XFRM, address/DNS allocation, forwarding, control plane or deployment is included.

## Responsibilities and cryptographic boundary

`ikev2-wire::auth` checks inner payload chains, identities, certificate/AUTH/EAP envelopes, CP/SA/traffic-selector envelopes and bounded lengths. CERTREQ is recognized; its critical bit is ignored as required for known payloads, without certificate-request processing. Unknown noncritical payloads can be skipped; unknown critical payloads cause an encrypted UNSUPPORTED_CRITICAL_PAYLOAD response. Nested SK/SKF is rejected.

`ikev2-crypto::protected` authenticates AES-256-GCM before interpreting inner payloads. AAD is the exact IKE header plus SK header; the UDP/4500 non-ESP marker is outside AAD. Keys and four-byte salts are direction dependent. Eight-byte outgoing IV counters never repeat within a key; retransmissions reuse cached ciphertext rather than invoking encryption again. Padding is checked only after tag verification. The IKE suite remains AES-256-GCM-16 / PRF-HMAC-SHA-256 / ECP19 with no fallback.

`ikev2-crypto::identity` loads and validates the responder identity and signs exact RFC 7296 octets. `mschap` uses OpenSSL MD4 and DES-ECB fetched in a **private** library context with a private legacy provider for the approved password method. No global legacy activation or replacement of IKE algorithms occurs. Unsupported providers fail closed. SHA-1 inside the standardized MSCHAPv2 method does not negotiate SHA-1 IKE AUTH.

`vpn-auth` owns encrypted verifier records, cooldowns and the EAP method. `ikev2-core` owns the SPI/message/state binding and final AUTH confirmation. Transport keeps the existing bounded shared admission and sampled diagnostic path. `ikev2d` explicitly opts into authentication and loads all protected credentials before opening listeners.

## RFC sequence

The following are message IDs, not EAP identifiers. Each request has one corresponding response and requests advance by one. Optional notifications/envelopes are omitted below.

| ID | Initiator request | Responder response | Resulting state |
|---|---|---|---|
| 0 | SAi1, KEi, Ni, SIGNATURE_HASH_ALGORITHMS(SHA256) | SAr1, KEr, Nr, hash capability, NAT detection | AWAIT_AUTH_REQUEST |
| 1 | SK{IDi, [IDr/CERTREQ/CP_REQUEST], SAi2, TSi, TSr}; no AUTH | SK{IDr, CERT chain, AUTH(signature), EAP Request/Identity} | SERVER_AUTH_SENT |
| 2 | SK{EAP Response/Identity} | SK{EAP Request/MSCHAPv2 Challenge} | EAP_IN_PROGRESS |
| 3 | SK{EAP Response/MSCHAPv2 Response} | SK{EAP Request/MSCHAPv2 Success, authenticator response} | EAP_IN_PROGRESS |
| 4 | SK{EAP Response/MSCHAPv2 Success acknowledgement} | SK{EAP Success} | AWAIT_FINAL_AUTH |
| 5 | SK{AUTH derived from EAP MSK} | SK{AUTH derived from EAP MSK, NO_PROPOSAL_CHOSEN} | AUTHENTICATED (IKE only) |

A bad NT response follows generic method Failure then EAP Failure and terminal FAILED. Malformed authenticated requests return encrypted INVALID_SYNTAX; authentication/signature capability failures return AUTHENTICATION_FAILED. Invalid tags, unrelated SPIs, stale/gapped IDs and tuple mismatches are dropped. No username-existence detail is returned or logged. Uniform error contents do not constitute a proven constant-time network service.

The server proves certificate possession before requesting user authentication. This is standard RFC 7296 section 2.16, **not RFC 5998**. The initiator's initial AUTH omission requests EAP; it does not remove responder signature AUTH. EAP Success alone never authenticates the IKE SA. Both final AUTH computations use `prf(prf(MSK, "Key Pad for IKEv2"), signed_octets)` with the negotiated PRF. Signed octets contain the exact corresponding initial IKE packet (without UDP marker), opposite nonce and PRF of the exact ID body, including received reserved bytes. MSK is server-receive key || server-send key || 32 zero bytes, per RFC 3079/EAP-MSCHAPv2 key export.

Signature AUTH method 14 uses RFC 7427: one-byte AlgorithmIdentifier length 15, DER sha256WithRSAEncryption (including NULL), then RSA-3072 PKCS#1 v1.5 signature. SHA-256 capability must be offered in INIT. Absence fails closed; neither SHA-1 RSA method 1 nor EAP-only is substituted. Native iOS offers and acceptance still need measurement.

NO_PROPOSAL_CHOSEN is the RFC 7296 generic first CHILD_SA failure. Authentication and CHILD creation have separate outcomes (sections 1.2, 2.21.2, 3.10.1). No successful SA/TS/CP response or IP assignment is produced. A client may delete this IKE SA or show connection failure. Post-authentication INFORMATIONAL/DPD/rekey and long-lived SA management are not implemented in this milestone.

## State, bounds and diagnostics

Existing global/source token buckets run before decode, lookup and cryptography, on both UDP ports including cached replies. COOKIE and pending quotas remain. Sessions bind both SPIs and source/local IPs. The first valid protected request may move ports (normal 500 to 4500); its exact tuple is then pinned. This is not MOBIKE. Only the most recent exact encrypted request/response pair is cached. Duplicates do not repeat signing/EAP/encryption, change states or extend deadlines. Changed duplicates/replays never advance state.

INIT retains its existing expiry; the first valid AUTH request starts a fixed 60-second authentication deadline, never renewed by later rounds or retransmissions. Terminal failures release IKE/EAP secrets immediately after sealing the response, retaining encrypted cache for five seconds. Successful exchanges clear EAP/MSK/ID secrets and retain IKE keys only until bounded pending expiry. Pending/table/payload/packet limits remain configuration bounded; auth-enabled configuration checks that the certificate response fits before listening. User file: at most 1024 records / 200000 bytes, usernames printable ASCII 1..128, no normalization or silent realm mapping. EAP Identity and MSCHAP Name must match exactly. Five failures trigger a 30-second per-known-user cooldown; unknown users use a dummy encrypted record without allocating attacker-selected state.

Diagnostics contain bounded numeric INIT offer/selection/NAT fields, static state names and aggregate counters. They do not include usernames, certificates, credentials, key material, decrypted payloads, signed octets or raw packets. Existing queue size eight and shared one-per-second sampling apply to state events; events can be omitted. Test evidence uses direct state/counter assertions, not the assumption that every event will be logged.

These controls limit one responder's CPU/state, not distributed denial-of-service or link saturation. Spoofed requests may consume global allowance; COOKIE is not a distributed attack defense. Certificate responses and UDP reflection remain risks; authentication is not permission to expose this lab service publicly. MSCHAPv2's historical offline password attack limitations remain: use a strong random disposable password and source restrictions. Secret buffers zeroize on drop where owned by Rust secret types; compiler/FFI/OS copies and crash dumps are not proven absent. Disable core dumps and restrict operator access.

## Certificate provisioning gate

Production loading accepts RSA-3072 keys only, matching the leaf; leaf must be non-CA, have SAN hostname `vpn.hypervault.biz`, digitalSignature KU, serverAuth EKU, valid time and a verified chain. Local trust is the fixed Ubuntu `/etc/ssl/certs/ca-certificates.crt`; environment trust overrides and application private-CA fallback are absent. Leaf validity is checked again at signing. Chains are at most four supplied certificates, 12000 total DER bytes; provision leaf then intermediates, omit the root. The current loader uses OpenSSL SSL_SERVER purpose as an initial public-CA compatibility filter. It does not establish that a web certificate is IKE-suitable or publicly trusted on iOS. Locally installed OS roots must be audited; a system trust store can include administrator roots.

Before operator testing, verify domain ownership/issuance authorization, public CA policy for this use, SAN, RSA key size, signature algorithm, KU/EKU, full intermediate path and current iOS root trust. Record public certificate fingerprints, serial, expiry and issuance policy, never the key. Verify local certificate/key public-key digests match without printing private material. Run `openssl verify -purpose sslserver -verify_hostname vpn.hypervault.biz -CAfile /etc/ssl/certs/ca-certificates.crt -untrusted intermediates.pem leaf.pem` and inspect `openssl x509 -in leaf.pem -noout -text`. This is a preflight, not iOS IKE acceptance. ipsecIKE-only EKU, missing required usages, unsupported signature negotiation, revocation or native trust rejection must be reported as blockers, not bypassed. There is no OCSP/CRL fetcher or automatic certificate renewal/reload; audit/revoke/replace and restart the lab service under operator control. Real certificate issuance and native verification were not performed here.

## Master-key custody and offline provisioning

The authorized handoff is systemd `LoadCredential`. Originals live outside source control in a root-owned 0700 directory; master key is an independently generated 32-byte root-owned **0600** file. The nonroot daemon does not read that file directly. systemd provides protected read-only credential copies: owner-only 0400 files/0500 directories, or systemd 255 root-owned 0440 files/0550 directories whose POSIX ACL grants access only to the service UID and owner. The loader validates the ACL rather than interpreting its mask as group access. It requires a nonroot euid, `$CREDENTIALS_DIRECTORY` immediately under `/run/credentials`, trusted root-owned parent directories, fixed names, descriptor-relative no-symlink traversal, regular files, restricted permissions/owners and bounded actual reads. Missing/malformed credentials fail startup before binding. Root-owned `/run/credentials` must not be group/world writable. Actual mount/ownership behavior must be validated on the target systemd release; failures must not be worked around by relaxing checks.

Version-1 encrypted records bind username and enabled bit as AES-256-GCM AAD with a random 96-bit nonce; ciphertext holds exactly one 16-byte NT-hash-equivalent verifier. No plaintext password file, password API or Argon2/bcrypt-only substitution exists. Verifier compromise is password-equivalent; protect encrypted bundles and master independently in backups. Wrong key, record tampering, duplicates/truncation or unsupported format fail closed.

Operator-only provisioning example (not executed; review/install the built binary into a root-controlled directory first):

```sh
cd src
cargo build --release -p vpn-auth --example provision
# As root in a separate administrative session, outside the repository:
install -d -o root -g root -m 0700 /etc/ikev2lab
# Only for a NEW lab key; do not overwrite an existing key:
(umask 077; set -C; openssl rand 32 > /etc/ikev2lab/master.key)
# Install the reviewed binary as /usr/local/libexec/ikev2-provision, root-owned 0755.
# Run with pipefail; password is entered at the prompt, never in argv/env/history:
set -o pipefail
systemd-ask-password 'Disposable VPN password (20+ random characters):' | /usr/local/libexec/ikev2-provision /etc/ikev2lab/master.key m3-disposable /etc/ikev2lab/verifiers.v1
```

The example creates one encrypted disposable user, uses create-new 0600 output, validates root master ownership/mode and refuses output in source repositories. Do not run Cargo as root. Do not use sample/vector passwords. The store API supports bounded multi-user bundles, but no user-management daemon/API or in-place administrative editor is introduced. Changes/revocation require replacing a reviewed bundle and restarting; the running store has no file watcher. Restart removes all pending SAs. Password rotation requires new challenge-compatible verifier provisioning. Master rotation requires decrypt/re-encrypt under an audited offline administrative workflow or re-provisioning users; no unreviewed migration tool is supplied. Protect and securely retire prior copies; rotating only the master does not revoke a compromised NT hash.

Example service directives for operator review only, **not an installed unit**:

```ini
[Service]
User=ikev2lab
Group=ikev2lab
LoadCredential=master-key:/etc/ikev2lab/master.key
LoadCredential=server-key:/etc/ikev2lab/server-key.pem
LoadCredential=server-chain:/etc/ikev2lab/server-chain.pem
LoadCredential=verifiers:/etc/ikev2lab/verifiers.v1
ExecStart=/usr/local/libexec/ikev2d --serve --config /etc/ikev2lab/lab.toml
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
RestrictAddressFamilies=AF_INET AF_UNIX
LimitCORE=0
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE
```

All source files above must be root-owned 0600. No `CAP_NET_ADMIN`, root daemon or XFRM access is required. For unprivileged loopback ports drop both capability directives. Restrict sources before authorizing a reachable test, then bind a specific local unicast address; default M3 example remains loopback 15000/14500. No firewall/unit/server changes were made automatically.

## Ubuntu/OpenSSL validation — operator access required

On an operator-approved disposable Ubuntu LTS host record release, kernel, systemd, `openssl version -a`, Rust/compiler and locked source hashes. Required build packages: `build-essential pkg-config libssl-dev ca-certificates`; runtime OpenSSL 3 `libssl3` or the release's `libssl3t64`, `openssl`, `ca-certificates`, systemd; capture uses `tcpdump` and optional Wireshark off-server. Use distribution package names for that LTS, not an older ABI shim. Run the exact workspace/fuzz checks in the report against the lockfiles. MSCHAP tests must prove private MD4/DES availability and unchanged global provider availability. FIPS-only/provider-restricted environments may fail and are not currently validated; never globally enable legacy or weaken IKE to compensate.

Validate `systemd-analyze verify` on the reviewed unit, service uid, root source modes, actual copy directory/file owner/modes and no symlink traversal. Do not print credential contents or `/proc/.../environ` into reports. Startup without each credential, with corrupt encrypted data, wrong master, wrong certificate/key/hostname/time/usage must fail before listeners. With approved credentials, check `ss -lunp` for only intended UDP ports. Privileged 500/4500 need only CAP_NET_BIND_SERVICE; loopback high ports need none. Check that XFRM state/policy and routing remain unchanged using operator-owned before/after observations. Do not install credentials on the existing Linode or change VPS/firewall without separate authorization.

## Native iOS acceptance — operator iPhone required

1. Record iPhone model, exact iOS build, source-restricted test topology, public source IP/NAT and reviewed server build/source hashes. Use a disposable strong user/password and suitable publicly trusted certificate. Audit root trust on both ends. No private root profile or trust bypass.
2. Review exposure separately; use the iPhone's known egress address only, short test window and specific server address UDP500/4500. No automatic public exposure is authorized. High loopback ports cannot be used directly by native iOS; prepare a separate approved test host/topology.
3. On iPhone Settings > General > VPN & Device Management > VPN > Add VPN Configuration: Type **IKEv2**; Description **M3 disposable**; Server **vpn.hypervault.biz**; Remote ID **vpn.hypervault.biz**; Local ID **m3-disposable**; User Authentication **Username**; Username **m3-disposable**; Password **Ask Every Time** (enter disposable password interactively); Proxy **Off**. Do not select client certificate or shared secret. No Always On/On Demand or device registration. A managed profile equivalent uses VPNType=IKEv2, RemoteAddress/RemoteIdentifier=vpn.hypervault.biz, LocalIdentifier/AuthName=m3-disposable, AuthenticationMethod=None, ExtendedAuthEnabled=1, no AuthPassword, no PayloadCertificateUUID/SharedSecret. Apple calls this client EAP-only in profile UI documentation; responder certificate/signature AUTH is still mandatory here and RFC5998 is not implemented. Inspect actual negotiation to verify this assumption. Offer AES256GCM/256, PRFSHA256, DH19 in IKE parameters if a profile is used; no weaker suite is accepted by the server. Leave CHILD parameters to native offers since none will be installed.
4. On the approved server, in a root-only capture directory with umask077, run `sudo timeout 90 tcpdump -i INTERFACE -nn -s 0 -U -w m3-ios.pcap 'host IPHONE_EGRESS_IP and (udp port 500 or udp port 4500)'`. Replace both placeholders with reviewed values. Do not upload captures to the repository or enable decrypted packet/key dumps. Record capture hash, start/end/timezone, tcpdump exit (timeout124 is normal timed stop) and packet loss. Capture contains sensitive metadata even though EAP is encrypted.
5. Connect once. Verify decoded INIT offers approved IKE suite and RFC7427 SHA256 hash capability; validate responder selection, NAT notifications and port movement. Observe protected IKE_AUTH rounds/message IDs without exporting SK keys. Record server aggregate transitions and iOS diagnostics available through approved tooling; sampled logs alone may omit transitions. Separate **server identity accepted**, **EAP method/mutual response complete**, **final initiator AUTH validated**, **final responder AUTH accepted**, and **no CHILD_SA** in the evidence. Later encrypted requests plus validated server transitions support progression; encrypted packet counts alone do not prove password or certificate acceptance. If native logs cannot substantiate acceptance, mark that claim unverified.
6. A VPN connection failure is expected/allowed after final no-CHILD notification. Success for M3 requires independently evidenced native certificate/signature trust, correct EAP/mutual/final AUTH progression, no IP/SA assignment, no secret diagnostics, no kernel data-plane change. Fail for trust prompts/bypasses, SHA1 downgrade, unexpected RFC5998, EAP success alone treated as authenticated, wrong-password/identity accepted, crashes or any CHILD/IP/ESP installation. Missing evidence is pending, not a pass.
7. Run wrong-password and Remote ID mismatch tests separately; both must fail without bypassing trust or reporting username existence. Stop after bounded attempts to avoid cooldown confusion. Stop service, revoke/retire disposable user and remove profile/capture according to operator retention policy. Do not use production credentials.

## References

- [RFC 7296 sections 2.15–2.16, 2.21 and payload formats](https://www.rfc-editor.org/rfc/rfc7296.html)
- [RFC 5282 AES-GCM framing](https://www.rfc-editor.org/rfc/rfc5282.html)
- [RFC 7427 signature negotiation and AUTH encoding](https://www.rfc-editor.org/rfc/rfc7427.html)
- [RFC 2759 MSCHAPv2 vectors](https://www.rfc-editor.org/rfc/rfc2759.html), [RFC 3079 key derivation](https://www.rfc-editor.org/rfc/rfc3079.html)
- [Apple IKEv2 deployment settings](https://support.apple.com/en-au/guide/deployment/dep4ce9487d/web), [Apple IKEv2 profile schema](https://developer.apple.com/documentation/devicemanagement/vpn/ikev2-data.dictionary)
- [systemd credentials](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html#Credentials)
