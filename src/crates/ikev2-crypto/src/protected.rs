//! RFC 5282 AES-GCM SK framing. NAT-T marker is outside this API/AAD.
use crate::{Error, GcmKey, IkeKeys, Sealed, SecretBytes};
use ikev2_wire::{Body, Header, Limits, Message, Payload};
use zeroize::Zeroizing;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Initiator,
    Responder,
}
impl Direction {
    fn flags(self) -> u8 {
        match self {
            Self::Initiator => 8,
            Self::Responder => 32,
        }
    }
}
pub struct Opened {
    pub header: Header,
    pub first_inner: u8,
    pub plaintext: SecretBytes,
}
fn validate(h: &Header, d: Direction) -> Result<(), Error> {
    if h.version >> 4 != 2
        || !matches!(h.exchange, 35 | 37)
        // Only I/R identify the sender and response direction. RFC 7296 requires
        // ignoring reserved bits; the higher-version-capable bit is informational.
        || h.flags & 0x28 != d.flags()
        || h.message_id == 0
        || h.initiator_spi == 0
        || h.responder_spi == 0
    {
        return Err(Error::Authentication);
    }
    Ok(())
}
fn key(keys: &IkeKeys, d: Direction) -> &GcmKey {
    match d {
        Direction::Initiator => &keys.initiator,
        Direction::Responder => &keys.responder,
    }
}
fn key_mut(keys: &mut IkeKeys, d: Direction) -> &mut GcmKey {
    match d {
        Direction::Initiator => &mut keys.initiator,
        Direction::Responder => &mut keys.responder,
    }
}
pub fn seal(
    keys: &mut IkeKeys,
    d: Direction,
    h: Header,
    first_inner: u8,
    inner: &[u8],
    limits: Limits,
) -> Result<Vec<u8>, Error> {
    validate(&h, d)?;
    limits.validate().map_err(|_| Error::InvalidLength)?;
    if inner.len() > limits.message_bytes.saturating_sub(57) {
        return Err(Error::InvalidLength);
    }
    let mut padded = Zeroizing::new(Vec::with_capacity(inner.len() + 1));
    padded.extend_from_slice(inner);
    padded.push(0);
    let placeholder = vec![0; 8 + padded.len() + 16];
    let mut wire = ikev2_wire::encode(
        &Message {
            header: h,
            payloads: vec![Payload {
                offset: 0,
                critical: false,
                body: Body::Encrypted {
                    first_inner,
                    data: &placeholder,
                },
            }],
        },
        limits,
    )
    .map_err(|_| Error::InvalidLength)?;
    let sealed = key_mut(keys, d).seal(&wire[..32], &padded)?;
    wire[32..40].copy_from_slice(&sealed.iv);
    let end = 40 + sealed.ciphertext.len();
    wire[40..end].copy_from_slice(&sealed.ciphertext);
    wire[end..].copy_from_slice(&sealed.tag);
    Ok(wire)
}
pub fn open(keys: &IkeKeys, d: Direction, wire: &[u8], limits: Limits) -> Result<Opened, Error> {
    let raw = ikev2_wire::raw::decode(wire, limits).map_err(|_| Error::Authentication)?;
    validate(&raw.header, d)?;
    if raw.payloads.len() != 1 || raw.payloads[0].kind != 46 || raw.payloads[0].offset != 28 {
        return Err(Error::Authentication);
    }
    let payload = &raw.payloads[0];
    let data = payload.body;
    if data.len() < 25 {
        return Err(Error::Authentication);
    }
    let tag_start = data.len() - 16;
    let sealed = Sealed {
        iv: data[..8].try_into().map_err(|_| Error::Authentication)?,
        ciphertext: data[8..tag_start].to_vec(),
        tag: data[tag_start..]
            .try_into()
            .map_err(|_| Error::Authentication)?,
    };
    let padded = key(keys, d).open(&wire[..32], &sealed)?;
    let bytes = padded.expose();
    let padding = usize::from(*bytes.last().ok_or(Error::Authentication)?);
    let end = bytes
        .len()
        .checked_sub(padding + 1)
        .ok_or(Error::Authentication)?;
    Ok(Opened {
        header: raw.header,
        first_inner: payload.next,
        plaintext: SecretBytes::new(bytes[..end].to_vec()),
    })
}
