use std::fmt;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ErrorKind {
    Malformed(&'static str),
    Unsupported(&'static str),
    Limit(&'static str),
    InvalidLimits,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Error {
    /// Byte offset in the message, or in the SA body for `decode_sa`.
    pub offset: usize,
    pub kind: ErrorKind,
}
impl Error {
    pub(crate) fn new(offset: usize, kind: ErrorKind) -> Self {
        Self { offset, kind }
    }
    pub(crate) fn malformed(offset: usize, reason: &'static str) -> Self {
        Self::new(offset, ErrorKind::Malformed(reason))
    }
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "wire error at {}: {:?}", self.offset, self.kind)
    }
}
impl std::error::Error for Error {}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Header {
    pub initiator_spi: u64,
    pub responder_spi: u64,
    pub version: u8,
    pub exchange: u8,
    /// Only I, V, R bits are retained. Reserved bits are ignored on receipt.
    pub flags: u8,
    pub message_id: u32,
}
#[derive(Clone, PartialEq, Eq)]
pub struct Message<'a> {
    pub header: Header,
    pub payloads: Vec<Payload<'a>>,
}
#[derive(Clone, PartialEq, Eq)]
pub struct Payload<'a> {
    /// Diagnostic location; ignored by serialization.
    pub offset: usize,
    pub critical: bool,
    pub body: Body<'a>,
}
#[derive(Clone, PartialEq, Eq)]
pub enum Body<'a> {
    Sa(Vec<Proposal<'a>>),
    KeyExchange {
        group: u16,
        data: &'a [u8],
    },
    Nonce(&'a [u8]),
    Notify {
        protocol: u8,
        spi: &'a [u8],
        kind: u16,
        data: &'a [u8],
    },
    VendorId(&'a [u8]),
    /// `first_inner` is not an outer chain link. Bytes are not decrypted.
    Encrypted {
        first_inner: u8,
        data: &'a [u8],
    },
    /// No body-level validity is claimed for opaque types.
    Opaque {
        kind: u8,
        next_inner: u8,
        data: &'a [u8],
    },
}
impl Body<'_> {
    pub fn kind(&self) -> u8 {
        match self {
            Self::Sa(_) => 33,
            Self::KeyExchange { .. } => 34,
            Self::Nonce(_) => 40,
            Self::Notify { .. } => 41,
            Self::VendorId(_) => 43,
            Self::Encrypted { .. } => 46,
            Self::Opaque { kind, .. } => *kind,
        }
    }
}
#[derive(Clone, PartialEq, Eq)]
pub struct Proposal<'a> {
    pub number: u8,
    pub protocol: u8,
    pub spi: &'a [u8],
    pub transforms: Vec<Transform<'a>>,
}
#[derive(Clone, PartialEq, Eq)]
pub struct Transform<'a> {
    pub kind: u8,
    pub id: u16,
    pub attributes: Vec<Attribute<'a>>,
}
#[derive(Clone, PartialEq, Eq)]
pub enum Attribute<'a> {
    Tv { kind: u16, value: u16 },
    Tlv { kind: u16, value: &'a [u8] },
}
impl Attribute<'_> {
    pub fn kind(&self) -> u16 {
        match self {
            Self::Tv { kind, .. } | Self::Tlv { kind, .. } => *kind,
        }
    }
}
// Intentionally omit payload-bearing Debug implementations: packet bodies can
// contain identity, key shares, certificates, or EAP material.
