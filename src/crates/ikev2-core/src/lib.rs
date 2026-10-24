//! Bounded IKE responder with optional authenticated IPv4 CHILD_SA backend.
mod auth_exchange;
pub mod child;
pub use auth_exchange::{AuthContext, AuthState};
mod cookie;
mod policy;
mod responder;
mod work;
pub use policy::Policy;
pub use responder::{Event, NatStatus, OfferSummary, Outcome, Responder, Stats, TransformSummary};
use std::fmt;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    InvalidPolicy,
    ClockWentBackwards,
    Crypto,
    Encoding,
}
impl From<ikev2_crypto::Error> for Error {
    fn from(_: ikev2_crypto::Error) -> Self {
        Self::Crypto
    }
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "initial exchange error: {self:?}")
    }
}
impl std::error::Error for Error {}
pub const NAT_SOURCE: u16 = 16388;
pub const NAT_DESTINATION: u16 = 16389;
pub const COOKIE: u16 = 16390;
pub const INVALID_KE: u16 = 17;
pub const NO_PROPOSAL: u16 = 14;
pub const INVALID_SYNTAX: u16 = 7;
pub const UNSUPPORTED_CRITICAL: u16 = 1;
/// The sole ADR-002 suite; this is responder selection, not a codec constraint.
pub fn selected_proposal(number: u8) -> ikev2_wire::Proposal<'static> {
    use ikev2_wire::{Attribute, Proposal, Transform};
    Proposal {
        number,
        protocol: 1,
        spi: &[],
        transforms: vec![
            Transform {
                kind: 1,
                id: 20,
                attributes: vec![Attribute::Tv {
                    kind: 14,
                    value: 256,
                }],
            },
            Transform {
                kind: 2,
                id: 5,
                attributes: vec![],
            },
            Transform {
                kind: 4,
                id: 19,
                attributes: vec![],
            },
        ],
    }
}
