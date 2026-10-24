//! IPv4 UDP adapter with explicit optional kernel ESP-in-UDP demultiplexing.
use ikev2_core::{Event, NatStatus, OfferSummary, Outcome, Responder};
use ikev2_crypto::CryptoProvider;
use std::{
    io,
    net::{SocketAddr, SocketAddrV4, UdpSocket},
    time::{Duration, Instant},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Channel {
    Ike,
    NatT,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameError {
    Oversize,
    Truncated,
    InvalidLimit,
}
#[derive(PartialEq, Eq)]
pub enum Datagram<'a> {
    Ike(&'a [u8]),
    Keepalive,
    Esp,
}
pub fn decode(channel: Channel, bytes: &[u8], max_ike: usize) -> Result<Datagram<'_>, FrameError> {
    if !(28..=65_503).contains(&max_ike) {
        return Err(FrameError::InvalidLimit);
    }
    let marker = if channel == Channel::NatT { 4 } else { 0 };
    if bytes.len() > max_ike + marker {
        return Err(FrameError::Oversize);
    }
    if channel == Channel::NatT {
        if bytes == [0xff] {
            return Ok(Datagram::Keepalive);
        }
        if bytes.len() < 4 {
            return Err(FrameError::Truncated);
        }
        if bytes[..4] != [0; 4] {
            return Ok(Datagram::Esp);
        }
        if bytes.len() < 32 {
            return Err(FrameError::Truncated);
        }
        Ok(Datagram::Ike(&bytes[4..]))
    } else {
        if bytes.len() < 28 {
            return Err(FrameError::Truncated);
        }
        Ok(Datagram::Ike(bytes))
    }
}
pub fn encode(channel: Channel, ike: &[u8], max_ike: usize) -> Result<Vec<u8>, FrameError> {
    if !(28..=65_503).contains(&max_ike) {
        return Err(FrameError::InvalidLimit);
    }
    if ike.len() > max_ike {
        return Err(FrameError::Oversize);
    }
    if ike.len() < 28 {
        return Err(FrameError::Truncated);
    }
    let mut out = Vec::with_capacity(ike.len() + 4);
    if channel == Channel::NatT {
        out.extend_from_slice(&[0; 4]);
    }
    out.extend_from_slice(ike);
    Ok(out)
}
#[derive(Default, Clone, Copy, Debug)]
pub struct IoStats {
    pub datagrams: u64,
    pub ignored: u64,
    pub processing_errors: u64,
    pub send_errors: u64,
    pub max_processing_micros: u64,
    pub diagnostics_suppressed: u64,
}
/// Safe, bounded numeric metadata only. Never carries packet bytes or secrets.
#[derive(Debug)]
pub struct Diagnostic {
    pub channel: Channel,
    pub event: Event,
    pub nat: Option<NatStatus>,
    pub offers: Vec<OfferSummary>,
    pub offers_truncated: bool,
    pub selected_proposal: Option<u8>,
}
pub struct UdpResponder<P: CryptoProvider> {
    core: Responder<P>,
    sockets: [UdpSocket; 2],
    buffer: Vec<u8>,
    stats: IoStats,
    diagnostics: Vec<Diagnostic>,
    next_diagnostic: Duration,
}
impl<P: CryptoProvider> UdpResponder<P> {
    /// Explicit local addresses are required: wildcard binding hides the actual
    /// destination address required for correct NAT detection with std sockets.
    pub fn bind(core: Responder<P>, ike: SocketAddrV4, natt: SocketAddrV4) -> io::Result<Self> {
        for address in [ike, natt] {
            if address.ip().is_unspecified()
                || address.ip().is_multicast()
                || address.ip().is_broadcast()
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "use an explicit local unicast IPv4 address",
                ));
            }
        }
        let sockets = [UdpSocket::bind(ike)?, UdpSocket::bind(natt)?];
        for socket in &sockets {
            socket.set_nonblocking(true)?;
        }
        let size = core.policy().max_request_bytes + 5; // Marker + one oversize sentinel byte.
        Ok(Self {
            core,
            sockets,
            buffer: vec![0; size],
            stats: IoStats::default(),
            diagnostics: Vec::new(),
            next_diagnostic: Duration::ZERO,
        })
    }
    /// Enable kernel ESP demultiplexing before accepting PoC sessions.
    pub fn enable_kernel_esp(&self) -> io::Result<()> {
        xfrm_linux::socket::enable_esp_in_udp(&self.sockets[1])
    }
    pub fn addresses(&self) -> io::Result<[SocketAddrV4; 2]> {
        let mut addresses = [SocketAddrV4::new(std::net::Ipv4Addr::LOCALHOST, 0); 2];
        for (i, socket) in self.sockets.iter().enumerate() {
            addresses[i] = match socket.local_addr()? {
                SocketAddr::V4(addr) => addr,
                _ => return Err(io::Error::other("IPv4 socket required")),
            };
        }
        Ok(addresses)
    }
    pub fn core(&self) -> &Responder<P> {
        &self.core
    }
    pub fn stats(&self) -> IoStats {
        self.stats
    }
    /// Drain at most eight samples; admission is one sample/second across both sockets.
    pub fn take_diagnostics(&mut self) -> Vec<Diagnostic> {
        std::mem::take(&mut self.diagnostics)
    }
    /// Bound work per tick; callers supply elapsed monotonic time and schedule
    /// periodic ticks even when sockets are idle, ensuring pending-key cleanup.
    pub fn tick(&mut self, now: Duration) -> io::Result<()> {
        self.core
            .expire(now)
            .map_err(|_| io::Error::other("monotonic clock moved backwards"))?;
        let addresses = self.addresses()?;
        for (i, channel) in [Channel::Ike, Channel::NatT].into_iter().enumerate() {
            for _ in 0..64 {
                let (length, peer) = match self.sockets[i].recv_from(&mut self.buffer) {
                    Ok(packet) => packet,
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(e) => return Err(e),
                };
                self.stats.datagrams = self.stats.datagrams.saturating_add(1);
                let SocketAddr::V4(peer) = peer else {
                    self.ignore();
                    continue;
                };
                let bytes = match decode(
                    channel,
                    &self.buffer[..length],
                    self.core.policy().max_request_bytes,
                ) {
                    Ok(Datagram::Ike(bytes)) => bytes,
                    _ => {
                        self.ignore();
                        continue;
                    }
                };
                let start = Instant::now();
                let result = self.core.handle(bytes, peer, addresses[i], now);
                self.stats.max_processing_micros = self
                    .stats
                    .max_processing_micros
                    .max(start.elapsed().as_micros().min(u64::MAX as u128) as u64);
                let outcome = match result {
                    Ok(result) => result,
                    Err(_) => {
                        self.stats.processing_errors =
                            self.stats.processing_errors.saturating_add(1);
                        continue;
                    }
                };
                let Outcome {
                    response,
                    event,
                    nat,
                    offers,
                    offers_truncated,
                    selected_proposal,
                } = outcome;
                if !offers.is_empty()
                    || selected_proposal.is_some()
                    || matches!(event, Event::Auth { .. })
                {
                    if now >= self.next_diagnostic && self.diagnostics.len() < 8 {
                        self.next_diagnostic = now.saturating_add(Duration::from_secs(1));
                        self.diagnostics.push(Diagnostic {
                            channel,
                            event,
                            nat,
                            offers,
                            offers_truncated,
                            selected_proposal,
                        });
                    } else {
                        self.stats.diagnostics_suppressed =
                            self.stats.diagnostics_suppressed.saturating_add(1);
                    }
                }
                if let Some(response) = response {
                    let bytes = encode(channel, &response, self.core.policy().max_response_bytes)
                        .map_err(|_| io::Error::other("bounded response framing failed"))?;
                    match self.sockets[i].send_to(&bytes, peer) {
                        Ok(sent) if sent == bytes.len() => {}
                        _ => self.stats.send_errors = self.stats.send_errors.saturating_add(1),
                    }
                }
            }
        }
        Ok(())
    }
    fn ignore(&mut self) {
        self.stats.ignored = self.stats.ignored.saturating_add(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn framing_marker_keepalive_and_esp() {
        let ike = [1; 28];
        let bytes = encode(Channel::NatT, &ike, 28).unwrap();
        assert_eq!(&bytes[..4], &[0; 4]);
        assert!(matches!(decode(Channel::NatT,&bytes,28),Ok(Datagram::Ike(b)) if b==ike));
        assert!(matches!(
            decode(Channel::NatT, &[0xff], 28),
            Ok(Datagram::Keepalive)
        ));
        assert!(matches!(
            decode(Channel::NatT, &[1, 2, 3, 4], 28),
            Ok(Datagram::Esp)
        ));
        assert_eq!(encode(Channel::Ike, &ike, 28).unwrap(), ike);
        assert!(matches!(decode(Channel::NatT, &ike, 28), Ok(Datagram::Esp)));
        for n in 0..4 {
            assert!(decode(Channel::NatT, &[0; 4][..n], 28).is_err());
        }
        assert!(decode(Channel::Ike, &[0; 29], 28).is_err());
        assert!(decode(Channel::NatT, &[0; 33], 28).is_err());
        assert!(decode(Channel::Ike, &ike, usize::MAX).is_err());
        assert!(encode(Channel::NatT, &ike, 27).is_err());
    }
}
