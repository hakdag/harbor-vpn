//! Post-INIT RFC 7296 EAP sequence. No CHILD_SA/IP configuration side effects.
use crate::Error;
use ikev2_crypto::{
    IkeKeys, SecretBytes, constant_time_eq,
    identity::{ServerSigner, eap_auth, signed_octets},
    protected::{self, Direction},
};
use ikev2_wire::{
    Header, Limits,
    auth::{self, Body, Eap, Identity, Payload},
};
use std::{net::SocketAddrV4, time::Duration};
use vpn_auth::{AuthStore, EapSession, EapState};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthState {
    AwaitAuthRequest,
    ServerAuthSent,
    EapInProgress,
    AwaitFinalAuth,
    Authenticated,
    Failed,
    Closed,
}
impl AuthState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AwaitAuthRequest => "AWAIT_AUTH_REQUEST",
            Self::ServerAuthSent => "SERVER_AUTH_SENT",
            Self::EapInProgress => "EAP_IN_PROGRESS",
            Self::AwaitFinalAuth => "AWAIT_FINAL_AUTH",
            Self::Authenticated => "AUTHENTICATED",
            Self::Failed => "FAILED",
            Self::Closed => "CLOSED",
        }
    }
}
pub struct AuthContext {
    pub(crate) signer: Box<dyn ServerSigner>,
    pub(crate) store: AuthStore,
    pub(crate) child: Option<crate::child::ChildService>,
}
impl AuthContext {
    pub fn new(signer: Box<dyn ServerSigner>, store: AuthStore) -> Result<Self, Error> {
        if signer.hostname() != ikev2_crypto::identity::HOSTNAME
            || signer.certificates().is_empty()
            || signer.certificates().len() > 4
            || signer.certificates().iter().map(Vec::len).sum::<usize>() > 12000
        {
            return Err(Error::InvalidPolicy);
        }
        Ok(Self {
            signer,
            store,
            child: None,
        })
    }
    pub fn with_child(mut self, child: crate::child::ChildService) -> Self {
        self.child = Some(child);
        self
    }
    pub(crate) fn response_bound(&self) -> usize {
        self.signer
            .certificates()
            .iter()
            .map(|c| c.len() + 5)
            .sum::<usize>()
            + 1024
    }
}
pub(crate) struct Exchange {
    pub state: AuthState,
    expected: u32,
    offer: Option<crate::child::Offer>,
    active: Option<crate::child::ActiveChild>,
    tuple: Option<(SocketAddrV4, SocketAddrV4)>,
    ni: Vec<u8>,
    nr: Vec<u8>,
    signature_sha256: bool,
    idi: Option<SecretBytes>,
    eap: Option<EapSession>,
    msk: Option<SecretBytes>,
    cached: Option<(Vec<u8>, Vec<u8>)>,
}
pub(crate) struct Transcript<'a> {
    pub request: &'a [u8],
    pub response: &'a [u8],
}
pub(crate) struct Request<'a> {
    pub wire: &'a [u8],
    pub peer: SocketAddrV4,
    pub local: SocketAddrV4,
    pub now: Duration,
    pub limits: Limits,
    pub response_limit: usize,
}
pub(crate) struct Reply {
    pub response: Option<Vec<u8>>,
    pub from: AuthState,
    pub to: AuthState,
    pub first: bool,
    pub terminal: bool,
}
impl Exchange {
    pub fn new(ni: &[u8], nr: &[u8], signature_sha256: bool) -> Self {
        Self {
            state: AuthState::AwaitAuthRequest,
            expected: 1,
            offer: None,
            active: None,
            tuple: None,
            ni: ni.to_vec(),
            nr: nr.to_vec(),
            signature_sha256,
            idi: None,
            eap: None,
            msk: None,
            cached: None,
        }
    }
    pub fn handle(
        &mut self,
        context: &mut AuthContext,
        keys: &mut Option<IkeKeys>,
        transcript: Transcript<'_>,
        request: Request<'_>,
    ) -> Result<Reply, Error> {
        let Request {
            wire,
            peer,
            local,
            now,
            limits,
            response_limit,
        } = request;
        let from = self.state;
        let dropped = || Reply {
            response: None,
            from,
            to: from,
            first: false,
            terminal: false,
        };
        if self.tuple.is_some_and(|t| t != (peer, local)) {
            return Ok(dropped());
        }
        if let Some((request, response)) = &self.cached
            && request == wire
        {
            return Ok(Reply {
                response: Some(response.clone()),
                ..dropped()
            });
        }
        if matches!(self.state, AuthState::Failed | AuthState::Closed) {
            return Ok(dropped());
        }
        let Some(session_keys) = keys.as_mut() else {
            return Ok(dropped());
        };
        let opened = match protected::open(session_keys, Direction::Initiator, wire, limits) {
            Ok(v) => v,
            Err(_) => return Ok(dropped()),
        };
        if opened.header.message_id != self.expected {
            return Ok(dropped());
        }
        self.tuple = Some((peer, local));
        let first = self.state == AuthState::AwaitAuthRequest;
        let inner = auth::decode_chain(opened.plaintext.expose(), opened.first_inner, limits);
        let response_limits = Limits {
            message_bytes: response_limit,
            ..limits
        };
        let unknown = inner.as_ref().ok().and_then(|p| {
            p.iter().find_map(|p| match p.body {
                Body::Unknown { kind, .. } if p.critical && !(33..=48).contains(&kind) => {
                    Some(kind)
                }
                _ => None,
            })
        });
        let result = match inner {
            Ok(ref p) if unknown.is_none() => {
                if opened.header.exchange == 37 {
                    self.informational(p, response_limits)
                } else if self.state == AuthState::Authenticated {
                    return Ok(dropped());
                } else {
                    self.process(context, session_keys, &transcript, p, now, response_limits)
                }
            }
            _ => Err(Error::Encoding),
        };
        let (first_inner, bytes) = match result {
            Ok(v) => v,
            Err(error) => {
                self.state = AuthState::Failed;
                let kind = if unknown.is_some() {
                    1
                } else if error == Error::Encoding {
                    7
                } else {
                    24
                };
                let detail = unknown.map(|k| [k]);
                encode(
                    &[payload(Body::Notify {
                        protocol: 0,
                        spi: &[],
                        kind,
                        data: detail.as_ref().map_or(&[][..], |v| &v[..]),
                    })],
                    response_limits,
                )?
            }
        };
        let h = Header {
            flags: 32,
            ..opened.header
        };
        let response = protected::seal(
            session_keys,
            Direction::Responder,
            h,
            first_inner,
            &bytes,
            response_limits,
        )
        .map_err(|_| Error::Crypto)?;
        self.expected = self.expected.checked_add(1).ok_or(Error::Encoding)?;
        self.cached = Some((wire.to_vec(), response.clone()));
        let terminal = matches!(self.state, AuthState::Failed | AuthState::Closed);
        if terminal {
            self.active = None;
            self.clear();
            *keys = None;
        }
        Ok(Reply {
            response: Some(response),
            from,
            to: self.state,
            first,
            terminal,
        })
    }
    pub fn has_child(&self) -> bool {
        self.active.is_some()
    }
    fn informational(&mut self, p: &[Payload<'_>], limits: Limits) -> Result<(u8, Vec<u8>), Error> {
        if self.state != AuthState::Authenticated {
            return Err(Error::Encoding);
        }
        if p.is_empty() {
            return encode(&[], limits);
        }
        if p.len() != 1 {
            return Err(Error::Encoding);
        }
        let Body::Unknown { kind: 42, data } = p[0].body else {
            return Err(Error::Encoding);
        };
        if data.len() < 4 {
            return Err(Error::Encoding);
        }
        let count = usize::from(u16::from_be_bytes([data[2], data[3]]));
        if data[0] == 1 && data[1] == 0 && count == 0 && data.len() == 4 {
            self.active = None;
            self.state = AuthState::Closed;
            return encode(&[], limits);
        }
        if data[0] == 3 && data[1] == 4 && count > 0 && count <= 16 && data.len() == 4 + 4 * count {
            let Some(child) = self.active.as_ref() else {
                return Err(Error::Encoding);
            };
            let matched = data[4..]
                .chunks_exact(4)
                .any(|spi| spi == child.outbound_spi.to_be_bytes());
            if matched {
                let mut answer = vec![3, 4, 0, 1];
                answer.extend_from_slice(&child.inbound_spi.to_be_bytes());
                self.active = None;
                return encode(
                    &[payload(Body::Unknown {
                        kind: 42,
                        data: &answer,
                    })],
                    limits,
                );
            }
            return encode(&[], limits);
        }
        Err(Error::Encoding)
    }
    fn clear(&mut self) {
        self.idi = None;
        self.eap = None;
        self.msk = None;
        self.offer = None;
    }
    fn process(
        &mut self,
        context: &mut AuthContext,
        keys: &IkeKeys,
        transcript: &Transcript<'_>,
        p: &[Payload<'_>],
        now: Duration,
        limits: Limits,
    ) -> Result<(u8, Vec<u8>), Error> {
        match self.state {
            AuthState::AwaitAuthRequest => {
                if !self.signature_sha256 {
                    return Err(Error::Crypto);
                }
                let mut idi = None;
                let mut sa = false;
                let mut tsi = false;
                let mut tsr = false;
                let mut cp = false;
                let mut idr_seen = false;
                for value in p {
                    match &value.body {
                        Body::Idi(id) if idi.is_none() => idi = Some(*id),
                        Body::Idr(id)
                            if !idr_seen
                                && id.kind == 2
                                && id
                                    .data
                                    .eq_ignore_ascii_case(context.signer.hostname().as_bytes()) =>
                        {
                            idr_seen = true;
                        }
                        Body::CertReq { .. } | Body::Notify { .. } => {}
                        Body::Unknown { kind, .. } if !(33..=48).contains(kind) || *kind == 43 => {}
                        Body::Sa(_) if !sa => sa = true,
                        Body::Ts {
                            responder: false, ..
                        } if !tsi => tsi = true,
                        Body::Ts {
                            responder: true, ..
                        } if !tsr => tsr = true,
                        Body::Config(data) if !cp && data[0] == 1 => cp = true,
                        _ => return Err(Error::Encoding),
                    }
                }
                if !sa || !tsi || !tsr {
                    return Err(Error::Encoding);
                }
                if context.child.is_some() {
                    self.offer = Some(crate::child::Offer::parse(p, limits)?);
                }
                self.idi = Some(id_bytes(idi.ok_or(Error::Encoding)?));
                let idr = Identity {
                    kind: 2,
                    reserved: [0; 3],
                    data: context.signer.hostname().as_bytes(),
                };
                let idr_body = id_bytes(idr);
                let signed = signed_octets(
                    transcript.response,
                    &self.ni,
                    keys.sk_pr.expose(),
                    idr_body.expose(),
                )
                .map_err(|_| Error::Crypto)?;
                let signature = context
                    .signer
                    .sign(signed.expose())
                    .map_err(|_| Error::Crypto)?;
                let eap = EapSession::new().map_err(|_| Error::Crypto)?;
                let request = eap.start().map_err(|_| Error::Crypto)?;
                let mut out = vec![payload(Body::Idr(idr))];
                for cert in context.signer.certificates() {
                    out.push(payload(Body::Cert {
                        encoding: 4,
                        data: cert,
                    }));
                }
                out.push(payload(Body::Auth {
                    method: 14,
                    data: &signature,
                }));
                out.push(payload(Body::Eap(
                    Eap::decode(&request).map_err(|_| Error::Encoding)?,
                )));
                let encoded = encode(&out, limits)?;
                self.eap = Some(eap);
                self.state = AuthState::ServerAuthSent;
                Ok(encoded)
            }
            AuthState::ServerAuthSent | AuthState::EapInProgress => {
                if p.len() != 1 {
                    return Err(Error::Encoding);
                }
                let Body::Eap(e) = &p[0].body else {
                    return Err(Error::Encoding);
                };
                let session = self.eap.as_mut().ok_or(Error::Crypto)?;
                let response = session
                    .step(
                        &e.encode().map_err(|_| Error::Encoding)?,
                        &mut context.store,
                        now,
                    )
                    .map_err(|_| Error::Crypto)?;
                self.state = match session.state() {
                    EapState::Complete => {
                        self.msk = Some(session.take_msk().map_err(|_| Error::Crypto)?);
                        AuthState::AwaitFinalAuth
                    }
                    EapState::Failed => AuthState::Failed,
                    _ => AuthState::EapInProgress,
                };
                encode(
                    &[payload(Body::Eap(
                        Eap::decode(&response).map_err(|_| Error::Encoding)?,
                    ))],
                    limits,
                )
            }
            AuthState::AwaitFinalAuth => {
                if p.len() != 1 {
                    return Err(Error::Encoding);
                }
                let Body::Auth { method: 2, data } = &p[0].body else {
                    return Err(Error::Encoding);
                };
                let name = self
                    .eap
                    .as_ref()
                    .and_then(EapSession::username)
                    .ok_or(Error::Crypto)?;
                if !context.store.enabled(name) {
                    return Err(Error::Crypto);
                }
                let msk = self.msk.as_ref().ok_or(Error::Crypto)?;
                let signed_i = signed_octets(
                    transcript.request,
                    &self.nr,
                    keys.sk_pi.expose(),
                    self.idi.as_ref().ok_or(Error::Crypto)?.expose(),
                )
                .map_err(|_| Error::Crypto)?;
                let expected =
                    eap_auth(msk.expose(), signed_i.expose()).map_err(|_| Error::Crypto)?;
                if !constant_time_eq(expected.expose(), data) {
                    return Err(Error::Crypto);
                }
                let idr = Identity {
                    kind: 2,
                    reserved: [0; 3],
                    data: context.signer.hostname().as_bytes(),
                };
                let body = id_bytes(idr);
                let signed_r = signed_octets(
                    transcript.response,
                    &self.ni,
                    keys.sk_pr.expose(),
                    body.expose(),
                )
                .map_err(|_| Error::Crypto)?;
                let answer =
                    eap_auth(msk.expose(), signed_r.expose()).map_err(|_| Error::Crypto)?;
                if let Some(service) = context.child.as_mut() {
                    let (peer, local) = self.tuple.ok_or(Error::Encoding)?;
                    self.active = Some(service.establish(
                        keys,
                        (&self.ni, &self.nr),
                        self.offer.as_ref().ok_or(Error::Encoding)?,
                        peer,
                        local,
                    )?);
                }
                let mut response = vec![payload(Body::Auth {
                    method: 2,
                    data: answer.expose(),
                })];
                if let Some(child) = &self.active {
                    response.extend([
                        payload(Body::Config(&child.cp)),
                        payload(Body::Sa(&child.sa)),
                        payload(Body::Ts {
                            responder: false,
                            data: &child.tsi,
                        }),
                        payload(Body::Ts {
                            responder: true,
                            data: &child.tsr,
                        }),
                    ]);
                } else {
                    response.push(payload(Body::Notify {
                        protocol: 0,
                        spi: &[],
                        kind: 14,
                        data: &[],
                    }));
                }
                let encoded = encode(&response, limits)?;
                self.state = AuthState::Authenticated;
                self.clear();
                Ok(encoded)
            }
            AuthState::Authenticated | AuthState::Failed | AuthState::Closed => {
                Err(Error::Encoding)
            }
        }
    }
}
fn payload(body: Body<'_>) -> Payload<'_> {
    Payload {
        critical: false,
        body,
    }
}
fn encode(p: &[Payload<'_>], limits: Limits) -> Result<(u8, Vec<u8>), Error> {
    auth::encode_chain(p, limits).map_err(|_| Error::Encoding)
}
fn id_bytes(id: Identity<'_>) -> SecretBytes {
    let mut out = vec![id.kind];
    out.extend_from_slice(&id.reserved);
    out.extend_from_slice(id.data);
    SecretBytes::new(out)
}
