use crate::{cookie::CookieKeys, *};
use ikev2_crypto::{
    CryptoProvider, EphemeralDh, IkeKeys, constant_time_eq, derive_keys, nat_detection,
};
use ikev2_wire::{Attribute, Body, Header, Limits, Message, Payload, Proposal};
use std::{collections::HashMap, net::SocketAddrV4, time::Duration};

#[derive(Default, Clone, Copy, Debug)]
pub struct Stats {
    pub requests: u64,
    pub accepted: u64,
    pub retransmits: u64,
    pub cookies: u64,
    pub rejected: u64,
    pub no_proposal: u64,
    pub invalid_ke: u64,
    pub invalid_syntax: u64,
    pub unsupported_critical: u64,
    pub invalid_version: u64,
    pub dropped: u64,
    pub busy: u64,
    pub expired: u64,
    pub crypto_errors: u64,
    pub rate_limited: u64,
    pub auth_messages: u64,
    pub authenticated: u64,
    pub authentication_failed: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event {
    PendingCreated,
    Retransmit,
    CookieChallenge,
    Rejected(u16),
    Dropped,
    Busy,
    RateLimited,
    Auth { from: AuthState, to: AuthState },
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NatStatus {
    pub source_changed: bool,
    pub destination_changed: bool,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransformSummary {
    pub kind: u8,
    pub id: u16,
    pub key_bits: Option<u16>,
    pub attributes_omitted: bool,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OfferSummary {
    pub number: u8,
    pub protocol: u8,
    pub transforms: Vec<TransformSummary>,
    pub transforms_truncated: bool,
}
/// Does not implement Debug, avoiding accidental packet/transcript dumps.
pub struct Outcome {
    pub response: Option<Vec<u8>>,
    pub event: Event,
    pub nat: Option<NatStatus>,
    pub offers: Vec<OfferSummary>,
    pub offers_truncated: bool,
    /// Present only for an accepted exchange or its exact cached duplicate.
    pub selected_proposal: Option<u8>,
}
impl Outcome {
    fn dropped(event: Event) -> Self {
        Self {
            response: None,
            event,
            nat: None,
            offers: Vec::new(),
            offers_truncated: false,
            selected_proposal: None,
        }
    }
}
#[derive(Clone, Hash, PartialEq, Eq)]
struct CacheKey {
    peer: SocketAddrV4,
    local: SocketAddrV4,
    spii: u64,
}
struct Pending {
    request: Vec<u8>,
    response: Vec<u8>,
    _keys: Option<IkeKeys>,
    auth: Option<crate::auth_exchange::Exchange>,
    expires: Duration,
    nat: Option<NatStatus>,
    spir: u64,
    selected_proposal: u8,
}
pub struct Responder<P: CryptoProvider> {
    provider: P,
    policy: Policy,
    wire: Limits,
    pending: HashMap<CacheKey, Pending>,
    cookies: CookieKeys,
    last_time: Duration,
    next_expiry: Option<Duration>,
    stats: Stats,
    work: crate::work::WorkLimiter,
    auth: Option<AuthContext>,
}
impl<P: CryptoProvider> Responder<P> {
    pub fn new(mut provider: P, policy: Policy, wire: Limits) -> Result<Self, Error> {
        let policy = policy.validate()?;
        wire.validate().map_err(|_| Error::InvalidPolicy)?;
        if wire.payloads < 5 || wire.transforms < 3 {
            return Err(Error::InvalidPolicy);
        }
        if wire.message_bytes < policy.max_request_bytes
            || wire.message_bytes < policy.max_response_bytes
        {
            return Err(Error::InvalidPolicy);
        }
        let cookies = CookieKeys::new(&mut provider)?;
        Ok(Self {
            provider,
            policy,
            wire,
            pending: HashMap::new(),
            cookies,
            last_time: Duration::ZERO,
            next_expiry: None,
            stats: Stats::default(),
            work: crate::work::WorkLimiter::new(policy),
            auth: None,
        })
    }
    pub fn with_auth(mut self, context: AuthContext) -> Result<Self, Error> {
        if self.wire.payloads < 6 || self.policy.max_response_bytes < context.response_bound() {
            return Err(Error::InvalidPolicy);
        }
        self.auth = Some(context);
        Ok(self)
    }
    pub fn policy(&self) -> Policy {
        self.policy
    }
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }
    pub fn active_child_count(&self) -> usize {
        self.pending
            .values()
            .filter(|p| p.auth.as_ref().is_some_and(|a| a.has_child()))
            .count()
    }
    pub fn stats(&self) -> Stats {
        self.stats
    }
    pub fn expire(&mut self, now: Duration) -> Result<(), Error> {
        self.work.expire(now)?;
        if now < self.last_time {
            return Err(Error::ClockWentBackwards);
        }
        if now == self.last_time {
            return Ok(());
        }
        self.last_time = now;
        if self.next_expiry.is_some_and(|deadline| deadline <= now) {
            let before = self.pending.len();
            self.pending.retain(|_, p| p.expires > now);
            self.next_expiry = self.pending.values().map(|p| p.expires).min();
            self.stats.expired = self
                .stats
                .expired
                .saturating_add((before - self.pending.len()) as u64);
        }
        Ok(())
    }
    pub fn handle(
        &mut self,
        input: &[u8],
        peer: SocketAddrV4,
        local: SocketAddrV4,
        now: Duration,
    ) -> Result<Outcome, Error> {
        self.stats.requests = self.stats.requests.saturating_add(1);
        if now < self.last_time {
            return Err(Error::ClockWentBackwards);
        }
        let admitted = self.work.admit(*peer.ip(), now, self.policy)?;
        self.expire(now)?;
        if !admitted {
            self.stats.rate_limited = self.stats.rate_limited.saturating_add(1);
            return Ok(Outcome::dropped(Event::RateLimited));
        }
        let result = self.process(input, peer, local, now);
        if let Ok(out) = &result {
            let n = match out.event {
                Event::PendingCreated => &mut self.stats.accepted,
                Event::Retransmit => &mut self.stats.retransmits,
                Event::CookieChallenge => &mut self.stats.cookies,
                Event::Rejected(_) => &mut self.stats.rejected,
                Event::Dropped => &mut self.stats.dropped,
                Event::Busy => &mut self.stats.busy,
                Event::RateLimited => &mut self.stats.rate_limited,
                Event::Auth { .. } => &mut self.stats.auth_messages,
            };
            *n = n.saturating_add(1);
            if let Event::Auth { from, to } = out.event
                && from != to
            {
                match to {
                    AuthState::Authenticated => {
                        self.stats.authenticated = self.stats.authenticated.saturating_add(1)
                    }
                    AuthState::Failed => {
                        self.stats.authentication_failed =
                            self.stats.authentication_failed.saturating_add(1)
                    }
                    _ => {}
                }
            }
            let category = match out.event {
                Event::Rejected(NO_PROPOSAL) => Some(&mut self.stats.no_proposal),
                Event::Rejected(INVALID_KE) => Some(&mut self.stats.invalid_ke),
                Event::Rejected(INVALID_SYNTAX) => Some(&mut self.stats.invalid_syntax),
                Event::Rejected(UNSUPPORTED_CRITICAL) => Some(&mut self.stats.unsupported_critical),
                Event::Rejected(5) => Some(&mut self.stats.invalid_version),
                _ => None,
            };
            if let Some(count) = category {
                *count = count.saturating_add(1);
            }
        } else {
            self.stats.crypto_errors = self.stats.crypto_errors.saturating_add(1);
        }
        result
    }
    fn process(
        &mut self,
        input: &[u8],
        peer: SocketAddrV4,
        local: SocketAddrV4,
        now: Duration,
    ) -> Result<Outcome, Error> {
        if input.len() > self.policy.max_request_bytes {
            return Ok(Outcome::dropped(Event::Dropped));
        }
        if matches!(input.get(18), Some(35 | 37)) && self.auth.is_some() {
            return self.process_auth(input, peer, local, now);
        }
        let message = match ikev2_wire::decode(input, self.wire) {
            Ok(m) => m,
            Err(_) => return Ok(Outcome::dropped(Event::Dropped)),
        };
        let h = &message.header;
        // The V flag and higher minor versions do not invalidate a version-2 request.
        if h.exchange != 34
            || h.flags & 0x28 != 8
            || h.message_id != 0
            || h.initiator_spi == 0
            || h.responder_spi != 0
        {
            return Ok(Outcome::dropped(Event::Dropped));
        }
        if h.version >> 4 != 2 {
            return if h.version >> 4 > 2 {
                self.reject(h, 5, &[])
            } else {
                Ok(Outcome::dropped(Event::Dropped))
            };
        }
        let key = CacheKey {
            peer,
            local,
            spii: h.initiator_spi,
        };
        if let Some(cached) = self.pending.get(&key) {
            if cached.request != input {
                return Ok(Outcome::dropped(Event::Dropped));
            }
            let (offers, offers_truncated) = summarize(
                message
                    .payloads
                    .iter()
                    .find_map(|p| match &p.body {
                        Body::Sa(p) => Some(p.as_slice()),
                        _ => None,
                    })
                    .unwrap_or(&[]),
            );
            return Ok(Outcome {
                response: Some(cached.response.clone()),
                event: Event::Retransmit,
                nat: cached.nat,
                offers,
                offers_truncated,
                selected_proposal: Some(cached.selected_proposal),
            });
        }
        let mut proposals = None;
        let mut ke = None;
        let mut nonce = None;
        let mut cookie = None;
        let mut sources = Vec::new();
        let mut destination = None;
        let mut signature_hashes = None;
        for (i, payload) in message.payloads.iter().enumerate() {
            match &payload.body {
                Body::Sa(p) if proposals.is_none() => proposals = Some(p.as_slice()),
                Body::KeyExchange { group, data } if ke.is_none() => ke = Some((*group, *data)),
                Body::Nonce(n) if nonce.is_none() => nonce = Some(*n),
                Body::Notify {
                    protocol,
                    spi,
                    kind,
                    data,
                } => match *kind {
                    16431
                        if signature_hashes.is_none()
                            && *protocol == 0
                            && spi.is_empty()
                            && !data.is_empty()
                            && data.len() % 2 == 0 =>
                    {
                        signature_hashes = Some(data.chunks_exact(2).any(|v| v == [0, 2]));
                    }
                    16431 => return self.reject(h, INVALID_SYNTAX, &[]),
                    COOKIE
                        if i == 0
                            && cookie.is_none()
                            && *protocol == 0
                            && spi.is_empty()
                            && (1..=64).contains(&data.len()) =>
                    {
                        cookie = Some(*data)
                    }
                    NAT_SOURCE if *protocol == 0 && spi.is_empty() && data.len() == 20 => {
                        sources.push(*data)
                    }
                    NAT_DESTINATION
                        if destination.is_none()
                            && *protocol == 0
                            && spi.is_empty()
                            && data.len() == 20 =>
                    {
                        destination = Some(*data)
                    }
                    COOKIE | NAT_SOURCE | NAT_DESTINATION => {
                        return self.reject(h, INVALID_SYNTAX, &[]);
                    }
                    _ => {}
                },
                Body::VendorId(_) => {}
                Body::Opaque { kind, .. } if !(33..=49).contains(kind) => {
                    if payload.critical {
                        return self.reject(h, UNSUPPORTED_CRITICAL, &[*kind]);
                    }
                }
                // A certificate request is not acted on in this milestone.
                Body::Opaque { kind: 38, .. } => {}
                _ => return self.reject(h, INVALID_SYNTAX, &[]),
            }
        }
        let (Some(proposals), Some((group, public)), Some(ni)) = (proposals, ke, nonce) else {
            return self.reject(h, INVALID_SYNTAX, &[]);
        };
        if proposals.first().is_none_or(|p| p.number != 1)
            || sources.is_empty() != destination.is_none()
        {
            return self.reject(h, INVALID_SYNTAX, &[]);
        }
        let (offers, offers_truncated) = summarize(proposals);
        let selected = select(proposals);
        if selected.is_none() {
            let mut out = self.reject(h, NO_PROPOSAL, &[])?;
            out.offers = offers;
            out.offers_truncated = offers_truncated;
            return Ok(out);
        }
        let number = selected.ok_or(Error::Encoding)?;
        let source_count = self
            .pending
            .keys()
            .filter(|k| k.peer.ip() == peer.ip())
            .count();
        self.cookies.rotate(
            &mut self.provider,
            now.as_secs() / self.policy.cookie_rotation_secs,
        )?;
        let valid_cookie = match cookie {
            Some(c) => self.cookies.verify(c, ni, h.initiator_spi, peer, local)?,
            None => false,
        };
        let loaded = self.pending.len() >= self.policy.cookie_threshold
            || source_count >= self.policy.per_source;
        if (loaded && !valid_cookie) || (cookie.is_some() && !valid_cookie) {
            let data = self.cookies.make(ni, h.initiator_spi, peer, local)?;
            let mut out = self.reject(h, COOKIE, &data)?;
            out.event = Event::CookieChallenge;
            out.offers = offers;
            out.offers_truncated = offers_truncated;
            return Ok(out);
        }
        if self.pending.len() >= self.policy.max_pending || source_count >= self.policy.per_source {
            return Ok(Outcome::dropped(Event::Busy));
        }
        if group != 19 {
            let mut out = self.reject(h, INVALID_KE, &19u16.to_be_bytes())?;
            out.offers = offers;
            out.offers_truncated = offers_truncated;
            return Ok(out);
        }
        if public.len() != 64 {
            return self.reject(h, INVALID_SYNTAX, &[]);
        }
        match ikev2_crypto::validate_p256(public) {
            Ok(()) => {}
            Err(ikev2_crypto::Error::InvalidPeer) => return self.reject(h, INVALID_SYNTAX, &[]),
            Err(e) => return Err(e.into()),
        }
        let dh = self.provider.generate_p256()?;
        let shared = match dh.shared_secret(public) {
            Ok(secret) => secret,
            Err(ikev2_crypto::Error::InvalidPeer) => return self.reject(h, INVALID_SYNTAX, &[]),
            Err(e) => return Err(e.into()),
        };
        let responder_public = dh.public_value()?;
        drop(dh); // Private ECDH key lifetime ends after deriving the common value.
        let mut spi = None;
        for _ in 0..8 {
            let mut random = [0; 8];
            self.provider.random(&mut random)?;
            let candidate = u64::from_be_bytes(random);
            if candidate != 0 && self.pending.values().all(|p| p.spir != candidate) {
                spi = Some(candidate);
                break;
            }
        }
        let spir = spi.ok_or(Error::Crypto)?;
        let mut nr = [0; 32];
        self.provider.random(&mut nr)?;
        let keys = derive_keys(
            &mut self.provider,
            shared.expose(),
            ni,
            &nr,
            h.initiator_spi,
            spir,
        )?;
        drop(shared);
        let nat = if let Some(expected_destination) = destination {
            let expected_source = nat_detection(h.initiator_spi, 0, peer);
            Some(NatStatus {
                source_changed: !sources
                    .iter()
                    .any(|s| constant_time_eq(s, &expected_source)),
                destination_changed: !constant_time_eq(
                    expected_destination,
                    &nat_detection(h.initiator_spi, 0, local),
                ),
            })
        } else {
            None
        };
        let source_hash = nat_detection(h.initiator_spi, spir, local);
        let destination_hash = nat_detection(h.initiator_spi, spir, peer);
        let mut response = Message {
            header: response_header(h, spir),
            payloads: vec![
                payload(Body::Sa(vec![selected_proposal(number)])),
                payload(Body::KeyExchange {
                    group: 19,
                    data: &responder_public,
                }),
                payload(Body::Nonce(&nr)),
                payload(Body::Notify {
                    protocol: 0,
                    spi: &[],
                    kind: NAT_SOURCE,
                    data: &source_hash,
                }),
                payload(Body::Notify {
                    protocol: 0,
                    spi: &[],
                    kind: NAT_DESTINATION,
                    data: &destination_hash,
                }),
            ],
        };
        if self.auth.is_some() {
            response.payloads.push(payload(Body::Notify {
                protocol: 0,
                spi: &[],
                kind: 16431,
                data: &[0, 2],
            }));
        }
        let response = self.encode(&response)?;
        let expires = now
            .checked_add(Duration::from_secs(self.policy.lifetime_secs))
            .ok_or(Error::ClockWentBackwards)?;
        self.next_expiry = Some(
            self.next_expiry
                .map_or(expires, |deadline| deadline.min(expires)),
        );
        self.pending.insert(
            key,
            Pending {
                request: input.to_vec(),
                response: response.clone(),
                _keys: Some(keys),
                auth: self.auth.as_ref().map(|_| {
                    crate::auth_exchange::Exchange::new(ni, &nr, signature_hashes.unwrap_or(false))
                }),
                expires,
                nat,
                spir,
                selected_proposal: number,
            },
        );
        Ok(Outcome {
            response: Some(response),
            event: Event::PendingCreated,
            nat,
            offers,
            offers_truncated,
            selected_proposal: Some(number),
        })
    }
    fn process_auth(
        &mut self,
        input: &[u8],
        peer: SocketAddrV4,
        local: SocketAddrV4,
        now: Duration,
    ) -> Result<Outcome, Error> {
        let raw = match ikev2_wire::raw::decode(input, self.wire) {
            Ok(v) => v,
            Err(_) => return Ok(Outcome::dropped(Event::Dropped)),
        };
        let key = self
            .pending
            .iter()
            .find(|(k, p)| {
                k.peer.ip() == peer.ip()
                    && k.local.ip() == local.ip()
                    && k.spii == raw.header.initiator_spi
                    && p.spir == raw.header.responder_spi
            })
            .map(|(k, _)| k.clone());
        let Some(key) = key else {
            return Ok(Outcome::dropped(Event::Dropped));
        };
        let pending = self.pending.get_mut(&key).ok_or(Error::Encoding)?;
        let Some(exchange) = pending.auth.as_mut() else {
            return Ok(Outcome::dropped(Event::Dropped));
        };
        let context = self.auth.as_mut().ok_or(Error::Encoding)?;
        let limits = Limits {
            message_bytes: self.policy.max_request_bytes,
            ..self.wire
        };
        let result = exchange.handle(
            context,
            &mut pending._keys,
            crate::auth_exchange::Transcript {
                request: &pending.request,
                response: &pending.response,
            },
            crate::auth_exchange::Request {
                wire: input,
                peer,
                local,
                now,
                limits,
                response_limit: self.policy.max_response_bytes,
            },
        );
        let reply = match result {
            Ok(v) => v,
            Err(e) => {
                self.pending.remove(&key);
                self.next_expiry = self.pending.values().map(|p| p.expires).min();
                return Err(e);
            }
        };
        if reply.first {
            pending.expires = now.saturating_add(Duration::from_secs(60));
        }
        if reply.to == AuthState::Authenticated
            && reply.from != AuthState::Authenticated
            && exchange.has_child()
        {
            pending.expires = now.saturating_add(Duration::from_secs(
                context
                    .child
                    .as_ref()
                    .ok_or(Error::InvalidPolicy)?
                    .lifetime_secs(),
            ));
        }
        if reply.terminal {
            pending.expires = now.saturating_add(Duration::from_secs(5));
        }
        self.next_expiry = self.pending.values().map(|p| p.expires).min();
        let mut out = Outcome::dropped(if reply.response.is_some() {
            Event::Auth {
                from: reply.from,
                to: reply.to,
            }
        } else {
            Event::Dropped
        });
        out.response = reply.response;
        Ok(out)
    }
    fn encode(&self, message: &Message<'_>) -> Result<Vec<u8>, Error> {
        let limits = Limits {
            message_bytes: self.policy.max_response_bytes,
            ..self.wire
        };
        ikev2_wire::encode(message, limits).map_err(|_| Error::Encoding)
    }
    fn reject(&self, header: &Header, kind: u16, data: &[u8]) -> Result<Outcome, Error> {
        let response = Message {
            header: response_header(header, 0),
            payloads: vec![payload(Body::Notify {
                protocol: 0,
                spi: &[],
                kind,
                data,
            })],
        };
        Ok(Outcome {
            response: Some(self.encode(&response)?),
            event: Event::Rejected(kind),
            nat: None,
            offers: Vec::new(),
            offers_truncated: false,
            selected_proposal: None,
        })
    }
}
// Only numeric allowlisted fields escape the protocol boundary. No attribute bytes.
fn summarize(proposals: &[Proposal<'_>]) -> (Vec<OfferSummary>, bool) {
    let offers = proposals
        .iter()
        .take(4)
        .map(|p| OfferSummary {
            number: p.number,
            protocol: p.protocol,
            transforms: p
                .transforms
                .iter()
                .take(8)
                .map(|t| TransformSummary {
                    kind: t.kind,
                    id: t.id,
                    key_bits: t.attributes.iter().find_map(|a| match a {
                        Attribute::Tv { kind: 14, value } => Some(*value),
                        _ => None,
                    }),
                    attributes_omitted: t
                        .attributes
                        .iter()
                        .any(|a| !matches!(a, Attribute::Tv { kind: 14, .. })),
                })
                .collect(),
            transforms_truncated: p.transforms.len() > 8,
        })
        .collect();
    (offers, proposals.len() > 4)
}
fn payload(body: Body<'_>) -> Payload<'_> {
    Payload {
        offset: 0,
        critical: false,
        body,
    }
}
fn response_header(request: &Header, spir: u64) -> Header {
    Header {
        initiator_spi: request.initiator_spi,
        responder_spi: spir,
        version: 0x20,
        exchange: 34,
        flags: 0x20,
        message_id: 0,
    }
}
fn select(proposals: &[Proposal<'_>]) -> Option<u8> {
    for p in proposals {
        if p.protocol != 1
            || !p.spi.is_empty()
            || p.transforms.iter().any(|t| !matches!(t.kind, 1 | 2 | 4))
        {
            continue;
        }
        let encr = p.transforms.iter().any(|t| {
            t.kind == 1
                && t.id == 20
                && t.attributes.as_slice()
                    == [Attribute::Tv {
                        kind: 14,
                        value: 256,
                    }]
        });
        let prf = p
            .transforms
            .iter()
            .any(|t| t.kind == 2 && t.id == 5 && t.attributes.is_empty());
        let dh = p
            .transforms
            .iter()
            .any(|t| t.kind == 4 && t.id == 19 && t.attributes.is_empty());
        if encr && prf && dh {
            return Some(p.number);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use ikev2_crypto::OpenSslProvider;
    #[test]
    fn stored_responder_keys_match_independent_initiator_exchange() {
        let mut provider = OpenSslProvider::new().unwrap();
        let initiator = provider.generate_p256().unwrap();
        let public = initiator.public_value().unwrap();
        let ni = [42; 32];
        let spii = 0x12345678;
        let request = Message {
            header: Header {
                initiator_spi: spii,
                responder_spi: 0,
                version: 0x20,
                exchange: 34,
                flags: 8,
                message_id: 0,
            },
            payloads: vec![
                payload(Body::Sa(vec![selected_proposal(1)])),
                payload(Body::KeyExchange {
                    group: 19,
                    data: &public,
                }),
                payload(Body::Nonce(&ni)),
            ],
        };
        let request = ikev2_wire::encode(&request, Limits::default()).unwrap();
        let mut responder = Responder::new(
            OpenSslProvider::new().unwrap(),
            Policy::default(),
            Limits::default(),
        )
        .unwrap();
        let peer = "192.0.2.1:500".parse().unwrap();
        let local = "192.0.2.2:500".parse().unwrap();
        let response = responder
            .handle(&request, peer, local, Duration::ZERO)
            .unwrap()
            .response
            .unwrap();
        let response = ikev2_wire::decode(&response, Limits::default()).unwrap();
        let (Body::KeyExchange { data: public_r, .. }, Body::Nonce(nr)) =
            (&response.payloads[1].body, &response.payloads[2].body)
        else {
            panic!("KE and nonce required")
        };
        let shared = initiator.shared_secret(public_r).unwrap();
        let initiator_keys = derive_keys(
            &mut provider,
            shared.expose(),
            &ni,
            nr,
            spii,
            response.header.responder_spi,
        )
        .unwrap();
        let pending = responder.pending.values_mut().next().unwrap();
        assert!(constant_time_eq(
            initiator_keys.sk_d.expose(),
            pending._keys.as_ref().unwrap().sk_d.expose()
        ));
        let sealed = pending
            ._keys
            .as_mut()
            .unwrap()
            .responder
            .seal(b"future header AAD", b"test-only plaintext")
            .unwrap();
        assert!(constant_time_eq(
            initiator_keys
                .responder
                .open(b"future header AAD", &sealed)
                .unwrap()
                .expose(),
            b"test-only plaintext"
        ));
        assert_eq!(
            format!("{:?}", pending._keys.as_ref().unwrap()),
            "IkeKeys([REDACTED])"
        );
    }
}
