use crate::*;

struct Writer {
    bytes: Vec<u8>,
    max: usize,
}
impl Writer {
    fn put(&mut self, bytes: &[u8]) -> Result<(), Error> {
        if bytes.len() > self.max - self.bytes.len() {
            return Err(Error::new(
                self.bytes.len(),
                ErrorKind::Limit("output bytes"),
            ));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }
    fn u16(&mut self, n: u16) -> Result<(), Error> {
        self.put(&n.to_be_bytes())
    }
    fn length(&mut self, start: usize, field: usize) -> Result<(), Error> {
        let n = u16::try_from(self.bytes.len() - start)
            .map_err(|_| Error::new(start, ErrorKind::Limit("16-bit length")))?;
        self.bytes[field..field + 2].copy_from_slice(&n.to_be_bytes());
        Ok(())
    }
}

/// Serialize with derived lengths/links and zero reserved fields. Validates
/// typed wire invariants but deliberately permits unsupported IDs/features.
pub fn encode(message: &Message<'_>, limits: Limits) -> Result<Vec<u8>, Error> {
    let limits = limits.validate()?;
    Limits::count(message.payloads.len(), limits.payloads, 28, "payload count")?;
    let mut w = Writer {
        bytes: Vec::new(),
        max: limits.message_bytes,
    };
    w.put(&message.header.initiator_spi.to_be_bytes())?;
    w.put(&message.header.responder_spi.to_be_bytes())?;
    w.put(&[
        message.payloads.first().map_or(0, |p| p.body.kind()),
        message.header.version,
        message.header.exchange,
        message.header.flags & 0x38,
    ])?;
    w.put(&message.header.message_id.to_be_bytes())?;
    w.put(&[0; 4])?;
    for (i, p) in message.payloads.iter().enumerate() {
        let at = w.bytes.len();
        let kind = p.body.kind();
        if kind == 0 {
            return Err(Error::malformed(at, "zero payload type"));
        }
        let next = match &p.body {
            Body::Encrypted { first_inner, .. } => *first_inner,
            Body::Opaque {
                kind: 49,
                next_inner,
                ..
            } => *next_inner,
            _ => message.payloads.get(i + 1).map_or(0, |p| p.body.kind()),
        };
        if matches!(kind, 46 | 49) && i + 1 != message.payloads.len() {
            return Err(Error::malformed(
                at,
                "encrypted payload must terminate outer chain",
            ));
        }
        // RFC-defined payloads send Critical=0, even if received with it set.
        let critical = p.critical && !(33..=48).contains(&kind);
        w.put(&[next, if critical { 0x80 } else { 0 }, 0, 0])?;
        match &p.body {
            Body::Sa(proposals) => write_sa(&mut w, proposals, limits)?,
            Body::KeyExchange { group, data } => {
                w.u16(*group)?;
                w.u16(0)?;
                w.put(data)?;
            }
            Body::Nonce(data) | Body::VendorId(data) => w.put(data)?,
            Body::Notify {
                protocol,
                spi,
                kind,
                data,
            } => {
                let size =
                    u8::try_from(spi.len()).map_err(|_| Error::malformed(at, "SPI too long"))?;
                w.put(&[*protocol, size])?;
                w.u16(*kind)?;
                w.put(spi)?;
                w.put(data)?;
            }
            Body::Encrypted { data, .. } => w.put(data)?,
            Body::Opaque {
                kind,
                next_inner,
                data,
            } => {
                if matches!(kind, 33 | 34 | 40 | 41 | 43 | 46) || *kind != 49 && *next_inner != 0 {
                    return Err(Error::malformed(
                        at,
                        "opaque body conflicts with typed representation",
                    ));
                }
                w.put(data)?;
            }
        }
        w.length(at, at + 2)?;
    }
    let length = u32::try_from(w.bytes.len())
        .map_err(|_| Error::new(24, ErrorKind::Limit("message length")))?;
    w.bytes[24..28].copy_from_slice(&length.to_be_bytes());
    // Reuse the structural validator, preventing serializer/parser drift.
    // Allocations stay bounded by the same limits and output ceiling.
    decode(&w.bytes, limits)?;
    Ok(w.bytes)
}

fn write_sa(w: &mut Writer, proposals: &[Proposal<'_>], limits: Limits) -> Result<(), Error> {
    Limits::count(
        proposals.len(),
        limits.proposals,
        w.bytes.len(),
        "proposal count",
    )?;
    for (i, p) in proposals.iter().enumerate() {
        Limits::count(
            p.transforms.len(),
            limits.transforms,
            w.bytes.len(),
            "transform count",
        )?;
        let at = w.bytes.len();
        let spi_len =
            u8::try_from(p.spi.len()).map_err(|_| Error::malformed(at, "SPI too long"))?;
        let count = u8::try_from(p.transforms.len())
            .map_err(|_| Error::malformed(at, "too many transforms"))?;
        w.put(&[
            if i + 1 == proposals.len() { 0 } else { 2 },
            0,
            0,
            0,
            p.number,
            p.protocol,
            spi_len,
            count,
        ])?;
        w.put(p.spi)?;
        for (j, t) in p.transforms.iter().enumerate() {
            Limits::count(
                t.attributes.len(),
                limits.attributes,
                w.bytes.len(),
                "attribute count",
            )?;
            let at = w.bytes.len();
            w.put(&[
                if j + 1 == p.transforms.len() { 0 } else { 3 },
                0,
                0,
                0,
                t.kind,
                0,
            ])?;
            w.u16(t.id)?;
            for a in &t.attributes {
                if a.kind() > 0x7fff {
                    return Err(Error::malformed(
                        w.bytes.len(),
                        "attribute type exceeds 15 bits",
                    ));
                }
                match a {
                    Attribute::Tv { kind, value } => {
                        w.u16(*kind | 0x8000)?;
                        w.u16(*value)?;
                    }
                    Attribute::Tlv { kind, value } => {
                        let len = u16::try_from(value.len()).map_err(|_| {
                            Error::new(w.bytes.len(), ErrorKind::Limit("attribute bytes"))
                        })?;
                        w.u16(*kind)?;
                        w.u16(len)?;
                        w.put(value)?;
                    }
                }
            }
            w.length(at, at + 2)?;
        }
        w.length(at, at + 2)?;
    }
    Ok(())
}
