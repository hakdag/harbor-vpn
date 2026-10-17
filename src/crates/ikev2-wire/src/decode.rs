use crate::{raw::Cursor, *};

pub fn decode(input: &[u8], limits: Limits) -> Result<Message<'_>, Error> {
    let raw = raw::decode(input, limits)?;
    let mut payloads = Vec::new();
    for p in raw.payloads {
        let mut c = Cursor::new(p.body, p.offset + 4);
        let body = match p.kind {
            33 => Body::Sa(sa(p.body, limits, p.offset + 4)?),
            34 => {
                let group = c.u16()?;
                c.take(2)?; // Reserved: ignore on receipt.
                Body::KeyExchange {
                    group,
                    data: c.take(c.left())?,
                }
            }
            40 => {
                if !(16..=256).contains(&p.body.len()) {
                    return Err(Error::malformed(
                        p.offset + 4,
                        "nonce length must be 16..256",
                    ));
                }
                Body::Nonce(p.body)
            }
            41 => {
                let protocol = c.u8()?;
                let spi_len = c.u8()? as usize;
                let kind = c.u16()?;
                let spi = c.take(spi_len)?;
                Body::Notify {
                    protocol,
                    spi,
                    kind,
                    data: c.take(c.left())?,
                }
            }
            43 => Body::VendorId(p.body),
            46 => Body::Encrypted {
                first_inner: p.next,
                data: p.body,
            },
            kind => Body::Opaque {
                kind,
                next_inner: if kind == 49 { p.next } else { 0 },
                data: p.body,
            },
        };
        payloads.push(Payload {
            offset: p.offset,
            critical: p.critical,
            body,
        });
    }
    Ok(Message {
        header: raw.header,
        payloads,
    })
}

/// Decode a standalone SA body. Proposal numbering relative to a request and
/// initial-vs-rekey SPI requirements need exchange context and are not checked.
pub fn decode_sa(input: &[u8], limits: Limits) -> Result<Vec<Proposal<'_>>, Error> {
    let limits = limits.validate()?;
    Limits::count(input.len(), limits.message_bytes, 0, "SA bytes")?;
    sa(input, limits, 0)
}

fn sa(input: &[u8], limits: Limits, base: usize) -> Result<Vec<Proposal<'_>>, Error> {
    let mut c = Cursor::new(input, base);
    let mut proposals: Vec<Proposal<'_>> = Vec::new();
    while c.left() != 0 {
        Limits::count(
            proposals.len() + 1,
            limits.proposals,
            c.at(),
            "proposal count",
        )?;
        let at = c.at();
        let last = c.u8()?;
        c.u8()?;
        let len = c.u16()? as usize;
        if len < 8 {
            return Err(Error::malformed(at + 2, "proposal length below header"));
        }
        let mut p = Cursor::new(c.take(len - 4)?, at + 4);
        if last != if c.left() == 0 { 0 } else { 2 } {
            return Err(Error::malformed(at, "proposal termination marker"));
        }
        let number = p.u8()?;
        if number == 0
            || proposals
                .last()
                .is_some_and(|prev| prev.number.checked_add(1) != Some(number))
        {
            return Err(Error::malformed(at + 4, "proposal numbering"));
        }
        let protocol = p.u8()?;
        let spi_len = p.u8()? as usize;
        let count = p.u8()? as usize;
        if count == 0 {
            return Err(Error::malformed(at + 7, "empty transform list"));
        }
        Limits::count(count, limits.transforms, at + 7, "transform count")?;
        if matches!(protocol, 2 | 3) && spi_len != 4 || protocol == 1 && !matches!(spi_len, 0 | 8) {
            return Err(Error::malformed(at + 6, "protocol SPI size"));
        }
        let spi = p.take(spi_len)?;
        let mut transforms = Vec::new();
        while p.left() != 0 {
            Limits::count(
                transforms.len() + 1,
                limits.transforms,
                p.at(),
                "transform count",
            )?;
            let at = p.at();
            let last = p.u8()?;
            p.u8()?;
            let len = p.u16()? as usize;
            if len < 8 {
                return Err(Error::malformed(at + 2, "transform length below header"));
            }
            let mut t = Cursor::new(p.take(len - 4)?, at + 4);
            if last != if p.left() == 0 { 0 } else { 3 } {
                return Err(Error::malformed(at, "transform termination marker"));
            }
            let kind = t.u8()?;
            t.u8()?;
            let id = t.u16()?;
            let mut attributes: Vec<Attribute<'_>> = Vec::new();
            while t.left() != 0 {
                Limits::count(
                    attributes.len() + 1,
                    limits.attributes,
                    t.at(),
                    "attribute count",
                )?;
                let at = t.at();
                let field = t.u16()?;
                let kind = field & 0x7fff;
                if attributes.iter().any(|a| a.kind() == kind) {
                    return Err(Error::malformed(at, "duplicate transform attribute"));
                }
                let value = t.u16()?;
                let attr = if field & 0x8000 != 0 {
                    Attribute::Tv { kind, value }
                } else {
                    Attribute::Tlv {
                        kind,
                        value: t.take(value as usize)?,
                    }
                };
                // RFC 7296 3.3.5: Key Length uses TV format.
                if kind == 14 && field & 0x8000 == 0 {
                    return Err(Error::malformed(at, "key length attribute must use TV"));
                }
                attributes.push(attr);
            }
            transforms.push(Transform {
                kind,
                id,
                attributes,
            });
        }
        if transforms.len() != count {
            return Err(Error::malformed(at + 7, "transform count mismatch"));
        }
        proposals.push(Proposal {
            number,
            protocol,
            spi,
            transforms,
        });
    }
    if proposals.is_empty() {
        return Err(Error::malformed(base, "empty SA"));
    }
    Ok(proposals)
}
