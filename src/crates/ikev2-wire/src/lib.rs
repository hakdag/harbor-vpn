//! Offline IKEv2 wire codec. Successful decoding is not exchange validation,
//! authentication, negotiation, or permission to act on packet contents.
#![forbid(unsafe_code)]
pub mod auth;
mod decode;
mod encode;
mod limits;
pub mod raw;
mod types;

pub use decode::{decode, decode_sa};
pub use encode::encode;
pub use limits::Limits;
pub use types::*;

/// Only checks implementation coverage. Does not validate SA/exchange state.
/// Unknown algorithm IDs remain data; no algorithms are selected here.
pub fn check_support(message: &Message<'_>) -> Result<(), Error> {
    if message.header.version >> 4 != 2 {
        return Err(Error::new(17, ErrorKind::Unsupported("major version")));
    }
    // A newer minor version is intentionally accepted (RFC 7296 section 2.5).
    if !(34..=37).contains(&message.header.exchange) {
        return Err(Error::new(18, ErrorKind::Unsupported("exchange type")));
    }
    for payload in &message.payloads {
        match &payload.body {
            Body::Opaque { kind, .. }
                if (35..=39).contains(kind)
                    || matches!(*kind, 42 | 44 | 45 | 47 | 48 | 49)
                    || payload.critical =>
            {
                return Err(Error::new(
                    payload.offset,
                    ErrorKind::Unsupported("payload"),
                ));
            }
            Body::Encrypted { .. } => {
                return Err(Error::new(
                    payload.offset,
                    ErrorKind::Unsupported("encrypted content"),
                ));
            }
            _ => {}
        }
    }
    Ok(())
}
