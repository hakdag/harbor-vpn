//! Bounded inner IKE_AUTH envelopes. Call only after SK authentication.
//! No certificate verification, EAP method processing or CHILD_SA installation.
use crate::{Error, ErrorKind, Limits, decode_sa, raw::Cursor};

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Identity<'a> {
    pub kind: u8,
    pub reserved: [u8; 3],
    pub data: &'a [u8],
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Eap<'a> {
    pub code: u8,
    pub identifier: u8,
    pub method: Option<u8>,
    pub data: &'a [u8],
}
impl<'a> Eap<'a> {
    pub fn decode(bytes: &'a [u8]) -> Result<Self, Error> {
        if bytes.len() < 4 || usize::from(u16::from_be_bytes([bytes[2], bytes[3]])) != bytes.len() {
            return Err(bad("EAP length"));
        }
        match bytes[0] {
            1 | 2 if bytes.len() >= 5 => Ok(Self {
                code: bytes[0],
                identifier: bytes[1],
                method: Some(bytes[4]),
                data: &bytes[5..],
            }),
            3 | 4 if bytes.len() == 4 => Ok(Self {
                code: bytes[0],
                identifier: bytes[1],
                method: None,
                data: &[],
            }),
            _ => Err(bad("EAP code or type")),
        }
    }
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        let n = 4 + usize::from(self.method.is_some()) + self.data.len();
        let n = u16::try_from(n).map_err(|_| bad("EAP length"))?;
        let mut out = vec![self.code, self.identifier];
        out.extend_from_slice(&n.to_be_bytes());
        if let Some(m) = self.method {
            out.push(m);
        }
        out.extend_from_slice(self.data);
        Eap::decode(&out)?;
        Ok(out)
    }
}
#[derive(Clone, PartialEq, Eq)]
pub enum Body<'a> {
    Idi(Identity<'a>),
    Idr(Identity<'a>),
    Cert {
        encoding: u8,
        data: &'a [u8],
    },
    CertReq {
        encoding: u8,
        data: &'a [u8],
    },
    Auth {
        method: u8,
        data: &'a [u8],
    },
    Eap(Eap<'a>),
    Sa(&'a [u8]),
    Ts {
        responder: bool,
        data: &'a [u8],
    },
    Config(&'a [u8]),
    Notify {
        protocol: u8,
        spi: &'a [u8],
        kind: u16,
        data: &'a [u8],
    },
    Unknown {
        kind: u8,
        data: &'a [u8],
    },
}
#[derive(Clone, PartialEq, Eq)]
pub struct Payload<'a> {
    pub critical: bool,
    pub body: Body<'a>,
}
impl Body<'_> {
    pub fn kind(&self) -> u8 {
        match self {
            Self::Idi(_) => 35,
            Self::Idr(_) => 36,
            Self::Cert { .. } => 37,
            Self::CertReq { .. } => 38,
            Self::Auth { .. } => 39,
            Self::Eap(_) => 48,
            Self::Sa(_) => 33,
            Self::Ts {
                responder: false, ..
            } => 44,
            Self::Ts {
                responder: true, ..
            } => 45,
            Self::Config(_) => 47,
            Self::Notify { .. } => 41,
            Self::Unknown { kind, .. } => *kind,
        }
    }
}
fn bad(reason: &'static str) -> Error {
    Error::malformed(0, reason)
}
fn identity(input: &[u8]) -> Result<Identity<'_>, Error> {
    if input.len() < 5 {
        return Err(bad("identity length"));
    }
    let id = Identity {
        kind: input[0],
        reserved: input[1..4].try_into().map_err(|_| bad("identity header"))?,
        data: &input[4..],
    };
    match id.kind {
        1 if id.data.len() == 4 => {}
        5 if id.data.len() == 16 => {}
        2 | 3 | 11 if id.data.len() <= 253 => {}
        _ => return Err(bad("identity type/length")),
    };
    Ok(id)
}
fn ts(data: &[u8]) -> Result<(), Error> {
    if data.len() < 4 || data[0] == 0 || data[0] > 16 {
        return Err(bad("traffic selector count"));
    }
    let mut c = Cursor::new(&data[4..], 4);
    for _ in 0..data[0] {
        let kind = c.u8()?;
        c.u8()?;
        let n = usize::from(c.u16()?);
        let size = match kind {
            7 => 16,
            8 => 40,
            _ => return Err(bad("traffic selector type")),
        };
        if n != size {
            return Err(bad("traffic selector length"));
        }
        let value = c.take(n - 4)?;
        if value[..2] > value[2..4] {
            return Err(bad("traffic selector ports"));
        }
        let address = (n - 8) / 2;
        if value[4..4 + address] > value[4 + address..] {
            return Err(bad("traffic selector range"));
        }
    }
    if c.left() != 0 {
        return Err(bad("traffic selector trailing bytes"));
    }
    Ok(())
}
fn config(data: &[u8]) -> Result<(), Error> {
    if data.len() < 4 || !(1..=4).contains(&data[0]) {
        return Err(bad("configuration header"));
    }
    let mut c = Cursor::new(&data[4..], 4);
    let mut count = 0;
    while c.left() > 0 {
        count += 1;
        if count > 32 {
            return Err(bad("configuration attributes"));
        }
        c.u16()?;
        let n = usize::from(c.u16()?);
        c.take(n)?;
    }
    Ok(())
}
pub fn decode_chain(input: &[u8], mut kind: u8, limits: Limits) -> Result<Vec<Payload<'_>>, Error> {
    let limits = limits.validate()?;
    Limits::count(input.len(), limits.message_bytes, 0, "inner bytes")?;
    let mut c = Cursor::new(input, 0);
    let mut out = Vec::new();
    while kind != 0 {
        Limits::count(out.len() + 1, limits.payloads, c.at(), "inner payloads")?;
        let next = c.u8()?;
        let critical = c.u8()? & 128 != 0;
        let n = usize::from(c.u16()?);
        if n < 4 {
            return Err(bad("inner length"));
        }
        let bytes = c.take(n - 4)?;
        let body = match kind {
            35 => Body::Idi(identity(bytes)?),
            36 => Body::Idr(identity(bytes)?),
            37 | 38 => {
                if bytes.is_empty() {
                    return Err(bad("certificate envelope"));
                }
                if kind == 37 {
                    Body::Cert {
                        encoding: bytes[0],
                        data: &bytes[1..],
                    }
                } else {
                    Body::CertReq {
                        encoding: bytes[0],
                        data: &bytes[1..],
                    }
                }
            }
            39 => {
                if bytes.len() < 5 {
                    return Err(bad("AUTH envelope"));
                }
                Body::Auth {
                    method: bytes[0],
                    data: &bytes[4..],
                }
            }
            48 => Body::Eap(Eap::decode(bytes)?),
            33 => {
                decode_sa(bytes, limits)?;
                Body::Sa(bytes)
            }
            44 | 45 => {
                ts(bytes)?;
                Body::Ts {
                    responder: kind == 45,
                    data: bytes,
                }
            }
            47 => {
                config(bytes)?;
                Body::Config(bytes)
            }
            41 => {
                let mut v = Cursor::new(bytes, 0);
                let protocol = v.u8()?;
                let n = usize::from(v.u8()?);
                let kind = v.u16()?;
                let spi = v.take(n)?;
                Body::Notify {
                    protocol,
                    spi,
                    kind,
                    data: v.take(v.left())?,
                }
            }
            46 | 49 => return Err(bad("nested encrypted payload")),
            _ => Body::Unknown { kind, data: bytes },
        };
        out.push(Payload { critical, body });
        kind = next;
    }
    if c.left() != 0 {
        return Err(bad("inner trailing bytes"));
    }
    Ok(out)
}
pub fn encode_chain(payloads: &[Payload<'_>], limits: Limits) -> Result<(u8, Vec<u8>), Error> {
    let limits = limits.validate()?;
    Limits::count(payloads.len(), limits.payloads, 0, "inner payloads")?;
    let first = payloads.first().map_or(0, |p| p.body.kind());
    let mut out = Vec::new();
    for (i, p) in payloads.iter().enumerate() {
        let kind = p.body.kind();
        if kind == 0 {
            return Err(bad("zero inner kind"));
        }
        let data_len = match &p.body {
            Body::Idi(id) | Body::Idr(id) => id.data.len(),
            Body::Cert { data, .. }
            | Body::CertReq { data, .. }
            | Body::Auth { data, .. }
            | Body::Sa(data)
            | Body::Ts { data, .. }
            | Body::Config(data)
            | Body::Unknown { data, .. } => data.len(),
            Body::Eap(e) => e.data.len(),
            Body::Notify { spi, data, .. } => {
                Limits::count(spi.len(), 255, 0, "notify SPI")?;
                data.len()
            }
        };
        Limits::count(data_len, limits.message_bytes, 0, "payload body")?;
        let mut bytes = Vec::new();
        match &p.body {
            Body::Idi(id) | Body::Idr(id) => {
                bytes.extend_from_slice(&[id.kind, 0, 0, 0]);
                bytes.extend_from_slice(id.data);
            }
            Body::Cert { encoding, data } | Body::CertReq { encoding, data } => {
                bytes.push(*encoding);
                bytes.extend_from_slice(data);
            }
            Body::Auth { method, data } => {
                bytes.extend_from_slice(&[*method, 0, 0, 0]);
                bytes.extend_from_slice(data);
            }
            Body::Eap(e) => bytes = e.encode()?,
            Body::Sa(data) | Body::Ts { data, .. } | Body::Config(data) => {
                bytes.extend_from_slice(data)
            }
            Body::Notify {
                protocol,
                spi,
                kind,
                data,
            } => {
                let n = u8::try_from(spi.len()).map_err(|_| bad("notify SPI"))?;
                bytes.extend_from_slice(&[*protocol, n]);
                bytes.extend_from_slice(&kind.to_be_bytes());
                bytes.extend_from_slice(spi);
                bytes.extend_from_slice(data);
            }
            Body::Unknown { kind, data } => {
                if matches!(kind,33|35..=39|41|44..=49) {
                    return Err(bad("unknown conflicts with typed kind"));
                }
                bytes.extend_from_slice(data);
            }
        }
        let n = u16::try_from(bytes.len() + 4).map_err(|_| bad("inner payload size"))?;
        Limits::count(
            out.len() + usize::from(n),
            limits.message_bytes,
            0,
            "inner bytes",
        )?;
        out.extend_from_slice(&[
            payloads.get(i + 1).map_or(0, |p| p.body.kind()),
            if p.critical && !(33..=48).contains(&kind) {
                128
            } else {
                0
            },
        ]);
        out.extend_from_slice(&n.to_be_bytes());
        out.extend_from_slice(&bytes);
    }
    decode_chain(&out, first, limits)?;
    Ok((first, out))
}
/// Context calls this after authenticated decode. Known Critical bits are ignored.
pub fn check_critical(payloads: &[Payload<'_>]) -> Result<(), Error> {
    if payloads.iter().any(|p| {
        p.critical && matches!(p.body, Body::Unknown {kind,..} if !(33..=48).contains(&kind))
    }) {
        return Err(Error::new(
            0,
            ErrorKind::Unsupported("critical inner payload"),
        ));
    }
    Ok(())
}
