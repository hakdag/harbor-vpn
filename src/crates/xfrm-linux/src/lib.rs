//! Linux XFRM UAPI encoding, acknowledged exclusive creates and owned teardown.
//! No shell, ip commands, key-bearing argv, flush, update or wildcard deletes.
pub mod socket;
use ikev2_core::{
    Error,
    child::{ChildBackend, ChildResource, ChildSpec},
};
use ikev2_crypto::SecretBytes;
use rustix::{
    fd::OwnedFd,
    net::{
        self, AddressFamily, RecvFlags, SendFlags, SocketFlags, SocketType,
        netlink::SocketAddrNetlink,
        sockopt::{Timeout, set_socket_timeout},
    },
};
use std::{
    io,
    net::Ipv4Addr,
    sync::{Arc, Mutex},
    time::Duration,
};
use zeroize::Zeroizing;
struct Netlink {
    fd: OwnedFd,
    seq: u32,
}
impl Netlink {
    fn open() -> io::Result<Self> {
        let fd = net::socket_with(
            AddressFamily::NETLINK,
            SocketType::RAW,
            SocketFlags::CLOEXEC,
            Some(net::netlink::XFRM),
        )?;
        net::bind(&fd, &SocketAddrNetlink::new(0, 0))?;
        set_socket_timeout(&fd, Timeout::Recv, Some(Duration::from_millis(500)))?;
        Ok(Self { fd, seq: 0 })
    }
    fn request(&mut self, kind: u16, body: &[u8], create: bool) -> io::Result<()> {
        self.seq = self
            .seq
            .checked_add(1)
            .ok_or_else(|| io::Error::other("netlink sequence exhausted"))?;
        let mut wire = Zeroizing::new(Vec::with_capacity(16 + body.len()));
        wire.extend_from_slice(&((16 + body.len()) as u32).to_ne_bytes());
        wire.extend_from_slice(&kind.to_ne_bytes());
        wire.extend_from_slice(&(if create { 0x605u16 } else { 5u16 }).to_ne_bytes()); // REQUEST|ACK|CREATE|EXCL
        wire.extend_from_slice(&self.seq.to_ne_bytes());
        wire.extend_from_slice(&0u32.to_ne_bytes());
        wire.extend_from_slice(body);
        net::sendto(
            &self.fd,
            &wire,
            SendFlags::empty(),
            &SocketAddrNetlink::new(0, 0),
        )?;
        let mut buffer = Zeroizing::new(vec![0u8; 8192]);
        let (_, length, source) =
            net::recvfrom(&self.fd, buffer.as_mut_slice(), RecvFlags::empty())?;
        let source = source
            .and_then(|a| SocketAddrNetlink::try_from(a).ok())
            .ok_or_else(|| io::Error::other("netlink source"))?;
        if source.pid() != 0 {
            return Err(io::Error::other("nonkernel netlink source"));
        }
        parse_ack(&buffer[..length], self.seq)
    }
}
fn parse_ack(b: &[u8], seq: u32) -> io::Result<()> {
    if b.len() < 20 {
        return Err(io::Error::other("short netlink ACK"));
    }
    let len = u32::from_ne_bytes(b[..4].try_into().map_err(|_| io::Error::other("ACK"))?) as usize;
    if len < 20
        || len > b.len()
        || u16::from_ne_bytes([b[4], b[5]]) != 2
        || u32::from_ne_bytes(b[8..12].try_into().map_err(|_| io::Error::other("ACK"))?) != seq
    {
        return Err(io::Error::other("unmatched netlink ACK"));
    }
    let errno = i32::from_ne_bytes(b[16..20].try_into().map_err(|_| io::Error::other("ACK"))?);
    if errno == 0 {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(
            errno.checked_neg().unwrap_or(libc::EIO),
        ))
    }
}
pub struct LinuxXfrm {
    socket: Arc<Mutex<Netlink>>,
    reqid: u32,
    reqid_end: u32,
    priority: u32,
}
impl LinuxXfrm {
    /// Operator reserves a reqid range and policy priority for this instance.
    pub fn new(reqid: u32, priority: u32) -> io::Result<Self> {
        if !(0x10000..=0xffff0000).contains(&reqid) || priority == 0 {
            return Err(io::Error::other("invalid XFRM ownership range"));
        }
        Ok(Self {
            socket: Arc::new(Mutex::new(Netlink::open()?)),
            reqid,
            reqid_end: reqid + 65535,
            priority,
        })
    }
}
struct Owned {
    socket: Arc<Mutex<Netlink>>,
    undo: Vec<(u16, Vec<u8>)>,
}
impl ChildResource for Owned {}
impl Drop for Owned {
    fn drop(&mut self) {
        if let Ok(mut s) = self.socket.lock() {
            for (kind, body) in self.undo.iter().rev() {
                if let Err(e) = s.request(*kind, body, false)
                    && e.raw_os_error() != Some(libc::ESRCH)
                    && e.raw_os_error() != Some(libc::ENOENT)
                {
                    eprintln!(
                        "XFRM owned cleanup failed (errno {:?}); operator reconciliation required",
                        e.raw_os_error()
                    );
                }
            }
        }
    }
}
impl ChildBackend for LinuxXfrm {
    fn install(&mut self, spec: &ChildSpec) -> Result<Box<dyn ChildResource>, Error> {
        if spec.inbound_spi < 256
            || spec.outbound_spi < 256
            || spec.inbound_key.expose().len() != 36
            || spec.outbound_key.expose().len() != 36
        {
            return Err(Error::InvalidPolicy);
        }
        if self.reqid > self.reqid_end {
            return Err(Error::InvalidPolicy);
        }
        let reqid = self.reqid;
        self.reqid = self.reqid.checked_add(1).ok_or(Error::InvalidPolicy)?;
        let operations = operations(spec, reqid, self.priority);
        let mut owned = Owned {
            socket: self.socket.clone(),
            undo: vec![],
        };
        for (kind, body, undo) in operations {
            let result =
                self.socket
                    .lock()
                    .map_err(|_| Error::Crypto)?
                    .request(kind, body.expose(), true);
            if result.is_err() {
                return Err(Error::Crypto);
            }
            owned.undo.push(undo);
        }
        Ok(Box::new(owned))
    }
}
fn put16(b: &mut [u8], p: usize, v: u16) {
    b[p..p + 2].copy_from_slice(&v.to_ne_bytes());
}
fn put32(b: &mut [u8], p: usize, v: u32) {
    b[p..p + 4].copy_from_slice(&v.to_ne_bytes());
}
fn addr(b: &mut [u8], p: usize, ip: Ipv4Addr) {
    b[p..p + 4].copy_from_slice(&ip.octets());
}
fn lifetime(b: &mut [u8], p: usize, seconds: u64) {
    for i in 0..4 {
        b[p + i * 8..p + i * 8 + 8].copy_from_slice(&u64::MAX.to_ne_bytes());
    }
    b[p + 40..p + 48].copy_from_slice(&seconds.to_ne_bytes());
}
fn attr(b: &mut Vec<u8>, kind: u16, value: &[u8]) {
    b.extend_from_slice(&((value.len() + 4) as u16).to_ne_bytes());
    b.extend_from_slice(&kind.to_ne_bytes());
    b.extend_from_slice(value);
    while !b.len().is_multiple_of(4) {
        b.push(0);
    }
}
fn select(address: Ipv4Addr, out: bool) -> Vec<u8> {
    let mut b = vec![0; 56];
    put16(&mut b, 40, libc::AF_INET as u16);
    if out {
        addr(&mut b, 0, address);
        b[42] = 32;
    } else {
        addr(&mut b, 16, address);
        b[43] = 32;
    }
    b
}
type Operation = (u16, SecretBytes, (u16, Vec<u8>));
fn operations(s: &ChildSpec, reqid: u32, priority: u32) -> Vec<Operation> {
    let mut ops = vec![];
    for inbound in [true, false] {
        let (src, dst, spi, key, sport, dport) = if inbound {
            (
                *s.peer.ip(),
                *s.local.ip(),
                s.inbound_spi,
                &s.inbound_key,
                s.peer.port(),
                s.local.port(),
            )
        } else {
            (
                *s.local.ip(),
                *s.peer.ip(),
                s.outbound_spi,
                &s.outbound_key,
                s.local.port(),
                s.peer.port(),
            )
        };
        let mut b = Zeroizing::new(vec![0; 224]);
        // Bind decrypted source / encrypted destination to this lease in both
        // SAD and SPD, including when no other policy matches a forged source.
        b[..56].copy_from_slice(&select(s.address, !inbound));
        addr(&mut b, 56, dst);
        b[72..76].copy_from_slice(&spi.to_be_bytes());
        b[76] = 50;
        addr(&mut b, 80, src);
        lifetime(&mut b, 96, s.lifetime_secs);
        put32(&mut b, 208, reqid);
        put16(&mut b, 212, libc::AF_INET as u16);
        b[214] = 1;
        b[215] = 32;
        let mut aead = Zeroizing::new(vec![0; 72]);
        let name = b"rfc4106(gcm(aes))";
        aead[..name.len()].copy_from_slice(name);
        put32(&mut aead, 64, 288);
        put32(&mut aead, 68, 128);
        aead.extend_from_slice(key.expose());
        attr(&mut b, 18, &aead);
        if s.udp_encap {
            let mut enc = vec![0; 24];
            put16(&mut enc, 0, 2);
            enc[2..4].copy_from_slice(&sport.to_be_bytes());
            enc[4..6].copy_from_slice(&dport.to_be_bytes());
            attr(&mut b, 4, &enc);
        }
        let mut delete = vec![0; 24];
        addr(&mut delete, 0, dst);
        delete[16..20].copy_from_slice(&spi.to_be_bytes());
        put16(&mut delete, 20, libc::AF_INET as u16);
        delete[22] = 50;
        ops.push((16, SecretBytes::new(b.to_vec()), (17, delete)));
    }
    for direction in [1u8, 0, 2] {
        let out = direction == 1;
        let sel = select(s.address, out);
        let mut b = vec![0; 168];
        b[..56].copy_from_slice(&sel);
        lifetime(&mut b, 56, s.lifetime_secs);
        put32(&mut b, 152, priority);
        b[160] = direction;
        let (src, dst) = if out {
            (*s.local.ip(), *s.peer.ip())
        } else {
            (*s.peer.ip(), *s.local.ip())
        };
        let mut tmpl = vec![0; 64];
        addr(&mut tmpl, 0, dst);
        tmpl[20] = 50;
        put16(&mut tmpl, 24, libc::AF_INET as u16);
        addr(&mut tmpl, 28, src);
        put32(&mut tmpl, 44, reqid);
        tmpl[48] = 1;
        for p in [52, 56, 60] {
            put32(&mut tmpl, p, u32::MAX);
        }
        attr(&mut b, 5, &tmpl);
        let mut delete = vec![0; 64];
        delete[..56].copy_from_slice(&sel);
        delete[60] = direction;
        ops.push((19, SecretBytes::new(b), (20, delete)));
    }
    ops
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn uapi_lengths_endianness_and_ack() {
        let s = ChildSpec {
            local: "192.0.2.1:4500".parse().unwrap(),
            peer: "198.51.100.2:12345".parse().unwrap(),
            address: "10.77.0.10".parse().unwrap(),
            inbound_spi: 0x11223344,
            outbound_spi: 0x55667788,
            inbound_key: SecretBytes::new(vec![7; 36]),
            outbound_key: SecretBytes::new(vec![8; 36]),
            lifetime_secs: 1800,
            udp_encap: true,
        };
        let ops = operations(&s, 65536, 10000);
        assert_eq!(ops.len(), 5);
        let sa = ops[0].1.expose();
        assert_eq!(&sa[72..76], &s.inbound_spi.to_be_bytes());
        assert_eq!(sa.len(), 364);
        assert_eq!(&sa[228..245], b"rfc4106(gcm(aes))");
        assert_eq!(&sa[300..336], &[7; 36]);
        assert_eq!(&ops[2].1.expose()[..4], &s.address.octets());
        assert_eq!(ops[4].2.1.len(), 64);
        let mut ack = vec![0; 20];
        put32(&mut ack, 0, 20);
        put16(&mut ack, 4, 2);
        put32(&mut ack, 8, 7);
        assert!(parse_ack(&ack, 7).is_ok());
        assert!(parse_ack(&ack, 8).is_err());
        for n in 0..20 {
            assert!(parse_ack(&ack[..n], 7).is_err());
        }
    }
}
