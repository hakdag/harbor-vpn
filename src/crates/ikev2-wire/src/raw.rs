//! Envelope decoding only. Retains unknown identifiers and critical flags;
//! callers must use typed decoding and support checks before interpretation.
use crate::{Error, Header, Limits};

pub struct RawMessage<'a> {
    pub header: Header,
    pub payloads: Vec<RawPayload<'a>>,
}
pub struct RawPayload<'a> {
    pub offset: usize,
    pub kind: u8,
    pub critical: bool,
    pub next: u8,
    pub body: &'a [u8],
}

/// Checked cursor, with offsets relative to the original containing input.
pub(crate) struct Cursor<'a> {
    pub data: &'a [u8],
    pub pos: usize,
    pub base: usize,
}
impl<'a> Cursor<'a> {
    pub fn new(data: &'a [u8], base: usize) -> Self {
        Self { data, pos: 0, base }
    }
    pub fn at(&self) -> usize {
        self.base + self.pos
    }
    pub fn left(&self) -> usize {
        self.data.len() - self.pos
    }
    pub fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        if n > self.left() {
            return Err(Error::malformed(self.at(), "truncated field"));
        }
        let start = self.pos;
        self.pos += n;
        Ok(&self.data[start..self.pos])
    }
    pub fn u8(&mut self) -> Result<u8, Error> {
        Ok(self.take(1)?[0])
    }
    pub fn u16(&mut self) -> Result<u16, Error> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }
    pub fn u32(&mut self) -> Result<u32, Error> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }
    pub fn u64(&mut self) -> Result<u64, Error> {
        let b = self.take(8)?;
        Ok(u64::from_be_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }
}

pub fn decode(input: &[u8], limits: Limits) -> Result<RawMessage<'_>, Error> {
    let limits = limits.validate()?;
    Limits::count(input.len(), limits.message_bytes, 0, "message bytes")?;
    let mut c = Cursor::new(input, 0);
    let initiator_spi = c.u64()?;
    let responder_spi = c.u64()?;
    let mut kind = c.u8()?;
    let version = c.u8()?;
    let exchange = c.u8()?;
    let flags = c.u8()? & 0x38;
    let message_id = c.u32()?;
    let length = c.u32()? as usize;
    if length != input.len() {
        return Err(Error::malformed(24, "message length mismatch"));
    }
    let header = Header {
        initiator_spi,
        responder_spi,
        version,
        exchange,
        flags,
        message_id,
    };
    let mut payloads = Vec::new();
    while kind != 0 {
        Limits::count(payloads.len() + 1, limits.payloads, c.at(), "payload count")?;
        let offset = c.at();
        let next = c.u8()?;
        let critical = c.u8()? & 0x80 != 0;
        let len = c.u16()? as usize;
        if len < 4 {
            return Err(Error::malformed(offset + 2, "payload length below header"));
        }
        let body = c.take(len - 4)?;
        payloads.push(RawPayload {
            offset,
            kind,
            critical,
            next,
            body,
        });
        if kind == 46 || kind == 49 {
            // SK / SKF: Next Payload names inner content.
            kind = 0;
        } else {
            kind = next;
        }
    }
    if c.left() != 0 {
        return Err(Error::malformed(c.at(), "trailing message bytes"));
    }
    Ok(RawMessage { header, payloads })
}
