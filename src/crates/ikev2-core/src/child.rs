//! Initial IPv4 CHILD_SA only. Installation is gated by verified final IKE AUTH.
use crate::Error;
use ikev2_crypto::{IkeKeys, SecretBytes, initial_child_keymat};
use ikev2_wire::{Attribute, Limits, Proposal, Transform, auth::Body};
use std::{
    collections::BTreeSet,
    net::{Ipv4Addr, SocketAddrV4},
    sync::{Arc, Mutex},
};

pub struct ChildSpec {
    pub local: SocketAddrV4,
    pub peer: SocketAddrV4,
    pub address: Ipv4Addr,
    pub inbound_spi: u32,
    pub outbound_spi: u32,
    /// Initiator -> responder, key32 || salt4.
    pub inbound_key: SecretBytes,
    pub outbound_key: SecretBytes,
    pub lifetime_secs: u64,
    pub udp_encap: bool,
}
/// Returned resources must undo only their own successful operations on Drop.
pub trait ChildResource: Send {}
pub trait ChildBackend: Send {
    fn install(&mut self, spec: &ChildSpec) -> Result<Box<dyn ChildResource>, Error>;
}
#[derive(Clone)]
pub struct ChildConfig {
    pub pool_start: Ipv4Addr,
    pub pool_end: Ipv4Addr,
    pub dns: Vec<Ipv4Addr>,
    pub lifetime_secs: u64,
}
impl ChildConfig {
    pub fn validate(&self) -> Result<(), Error> {
        let a = u32::from(self.pool_start);
        let b = u32::from(self.pool_end);
        if !self.pool_start.is_private()
            || !self.pool_end.is_private()
            || a > b
            || b - a > 1023
            || a >> 8 != b >> 8
            || a & 255 == 0
            || b & 255 == 255
            || !(60..=3600).contains(&self.lifetime_secs)
            || self.dns.is_empty()
            || self.dns.len() > 2
            || self
                .dns
                .iter()
                .any(|ip| ip.is_unspecified() || ip.is_multicast() || ip.is_broadcast())
        {
            return Err(Error::InvalidPolicy);
        }
        Ok(())
    }
}
pub struct ChildService {
    config: ChildConfig,
    allocated: Arc<Mutex<BTreeSet<Ipv4Addr>>>,
    backend: Box<dyn ChildBackend>,
}
pub struct ActiveChild {
    // Drop kernel resources before returning address to pool.
    pub(crate) resource: Option<Box<dyn ChildResource>>,
    address: Ipv4Addr,
    allocated: Arc<Mutex<BTreeSet<Ipv4Addr>>>,
    pub inbound_spi: u32,
    pub outbound_spi: u32,
    pub sa: Vec<u8>,
    pub tsi: Vec<u8>,
    pub tsr: Vec<u8>,
    pub cp: Vec<u8>,
}
impl Drop for ActiveChild {
    fn drop(&mut self) {
        self.resource.take();
        if let Ok(mut pool) = self.allocated.lock() {
            pool.remove(&self.address);
        }
    }
}
#[derive(Clone)]
pub(crate) struct Offer {
    number: u8,
    spi: u32,
    esn: bool,
    tsi: Vec<u8>,
    tsr: Vec<u8>,
}
impl Offer {
    pub fn parse(p: &[ikev2_wire::auth::Payload<'_>], limits: Limits) -> Result<Self, Error> {
        let sa = p
            .iter()
            .find_map(|v| {
                if let Body::Sa(b) = v.body {
                    Some(b)
                } else {
                    None
                }
            })
            .ok_or(Error::Encoding)?;
        let proposals = ikev2_wire::decode_sa(sa, limits).map_err(|_| Error::Encoding)?;
        let selected = proposals
            .iter()
            .find(|p| {
                p.protocol == 3
                    && p.spi.len() == 4
                    && p.transforms.iter().any(|t| {
                        t.kind == 1
                            && t.id == 20
                            && t.attributes
                                == [Attribute::Tv {
                                    kind: 14,
                                    value: 256,
                                }]
                    })
                    && p.transforms.iter().all(|t| match t.kind {
                        1 => true,
                        3 => t.id == 0 && t.attributes.is_empty(),
                        5 => t.attributes.is_empty() && t.id <= 1,
                        _ => false,
                    })
                    && (!p.transforms.iter().any(|t| t.kind == 5)
                        || p.transforms.iter().any(|t| t.kind == 5 && t.id == 0))
            })
            .ok_or(Error::Encoding)?;
        let spi = u32::from_be_bytes(selected.spi.try_into().map_err(|_| Error::Encoding)?);
        if spi < 256 {
            return Err(Error::Encoding);
        }
        let ts = |responder| {
            p.iter()
                .find_map(|v| {
                    if let Body::Ts { responder: r, data } = v.body {
                        if r == responder {
                            Some(data.to_vec())
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                })
                .ok_or(Error::Encoding)
        };
        let cp = p
            .iter()
            .find_map(|v| {
                if let Body::Config(b) = v.body {
                    Some(b)
                } else {
                    None
                }
            })
            .ok_or(Error::Encoding)?;
        let mut pos = 4;
        let mut address = false;
        while pos + 4 <= cp.len() {
            let kind = u16::from_be_bytes([cp[pos], cp[pos + 1]]) & 0x7fff;
            let len = usize::from(u16::from_be_bytes([cp[pos + 2], cp[pos + 3]]));
            if kind == 1 {
                if len != 0 && len != 4 {
                    return Err(Error::Encoding);
                }
                address = true;
            }
            pos += 4 + len;
        }
        if !address {
            return Err(Error::Encoding);
        }
        Ok(Self {
            number: selected.number,
            spi,
            esn: selected.transforms.iter().any(|t| t.kind == 5),
            tsi: ts(false)?,
            tsr: ts(true)?,
        })
    }
}
impl ChildService {
    pub fn new(config: ChildConfig, backend: Box<dyn ChildBackend>) -> Result<Self, Error> {
        config.validate()?;
        Ok(Self {
            config,
            backend,
            allocated: Arc::new(Mutex::new(BTreeSet::new())),
        })
    }
    pub fn lifetime_secs(&self) -> u64 {
        self.config.lifetime_secs
    }
    pub(crate) fn establish(
        &mut self,
        keys: &IkeKeys,
        nonces: (&[u8], &[u8]),
        offer: &Offer,
        peer: SocketAddrV4,
        local: SocketAddrV4,
    ) -> Result<ActiveChild, Error> {
        // Only accept full IPv4 Internet selector; never widen the offered set.
        if !covers(&offer.tsr, 0, u32::MAX) {
            return Err(Error::Encoding);
        }
        let address = {
            let mut pool = self.allocated.lock().map_err(|_| Error::Crypto)?;
            let address = (u32::from(self.config.pool_start)..=u32::from(self.config.pool_end))
                .map(Ipv4Addr::from)
                .find(|a| !pool.contains(a) && covers(&offer.tsi, u32::from(*a), u32::from(*a)))
                .ok_or(Error::InvalidPolicy)?;
            pool.insert(address);
            address
        };
        // Guard the allocation immediately so every later error releases it.
        let mut active = ActiveChild {
            resource: None,
            address,
            allocated: self.allocated.clone(),
            inbound_spi: 0,
            outbound_spi: offer.spi,
            sa: vec![],
            tsi: selector(u32::from(address), u32::from(address)),
            tsr: selector(0, u32::MAX),
            cp: vec![2, 0, 0, 0],
        };
        let mut random = [0; 4];
        openssl::rand::rand_bytes(&mut random).map_err(|_| Error::Crypto)?;
        let spi = u32::from_be_bytes(random).max(256);
        active.inbound_spi = spi;
        let km = initial_child_keymat(keys.sk_d.expose(), nonces.0, nonces.1)?;
        let spec = ChildSpec {
            local,
            peer,
            address,
            inbound_spi: spi,
            outbound_spi: offer.spi,
            inbound_key: SecretBytes::new(km.expose()[..36].to_vec()),
            outbound_key: SecretBytes::new(km.expose()[36..].to_vec()),
            lifetime_secs: self.config.lifetime_secs,
            udp_encap: local.port() == 4500,
        };
        let spi_bytes = spi.to_be_bytes();
        let mut transforms = vec![Transform {
            kind: 1,
            id: 20,
            attributes: vec![Attribute::Tv {
                kind: 14,
                value: 256,
            }],
        }];
        if offer.esn {
            transforms.push(Transform {
                kind: 5,
                id: 0,
                attributes: vec![],
            });
        }
        let message = ikev2_wire::Message {
            header: ikev2_wire::Header {
                initiator_spi: 1,
                responder_spi: 2,
                version: 0x20,
                exchange: 35,
                flags: 32,
                message_id: 1,
            },
            payloads: vec![ikev2_wire::Payload {
                offset: 0,
                critical: false,
                body: ikev2_wire::Body::Sa(vec![Proposal {
                    number: offer.number,
                    protocol: 3,
                    spi: &spi_bytes,
                    transforms,
                }]),
            }],
        };
        active.sa = ikev2_wire::encode(&message, Limits::default()).map_err(|_| Error::Encoding)?
            [32..]
            .to_vec();
        for (kind, ip) in
            std::iter::once((1, address)).chain(self.config.dns.iter().map(|ip| (3, *ip)))
        {
            active.cp.extend_from_slice(&u16::to_be_bytes(kind));
            active.cp.extend_from_slice(&4u16.to_be_bytes());
            active.cp.extend_from_slice(&ip.octets());
        }
        active.resource = Some(self.backend.install(&spec)?);
        Ok(active)
    }
}
fn selector(start: u32, end: u32) -> Vec<u8> {
    let mut b = vec![1, 0, 0, 0, 7, 0, 0, 16, 0, 0, 255, 255];
    b.extend_from_slice(&start.to_be_bytes());
    b.extend_from_slice(&end.to_be_bytes());
    b
}
fn covers(ts: &[u8], start: u32, end: u32) -> bool {
    let mut p = 4;
    while p + 8 <= ts.len() {
        let n = usize::from(u16::from_be_bytes([ts[p + 2], ts[p + 3]]));
        if n < 8 || p + n > ts.len() {
            return false;
        }
        if ts[p] == 7 && n == 16 && ts[p + 1] == 0 && ts[p + 4..p + 8] == [0, 0, 255, 255] {
            let a = u32::from_be_bytes(ts[p + 8..p + 12].try_into().unwrap_or([255; 4]));
            let b = u32::from_be_bytes(ts[p + 12..p + 16].try_into().unwrap_or([0; 4]));
            if a <= start && b >= end {
                return true;
            }
        }
        p += n;
    }
    false
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bounds_and_selector_narrowing() {
        let c = ChildConfig {
            pool_start: Ipv4Addr::new(10, 77, 0, 10),
            pool_end: Ipv4Addr::new(10, 77, 0, 20),
            dns: vec![Ipv4Addr::new(1, 1, 1, 1)],
            lifetime_secs: 1800,
        };
        assert!(c.validate().is_ok());
        let mut bad = c.clone();
        bad.pool_end = Ipv4Addr::new(10, 78, 0, 20);
        assert!(bad.validate().is_err());
        assert!(covers(&selector(0, u32::MAX), 1, 1));
        assert!(!covers(&selector(1, 1), 0, u32::MAX));
    }
    struct Backend {
        fail: bool,
        live: Arc<std::sync::atomic::AtomicUsize>,
    }
    struct Resource(Arc<std::sync::atomic::AtomicUsize>);
    impl ChildResource for Resource {}
    impl Drop for Resource {
        fn drop(&mut self) {
            self.0.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
        }
    }
    impl ChildBackend for Backend {
        fn install(&mut self, _: &ChildSpec) -> Result<Box<dyn ChildResource>, Error> {
            if self.fail {
                return Err(Error::Crypto);
            }
            self.live.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(Box::new(Resource(self.live.clone())))
        }
    }
    #[test]
    fn lease_exhaustion_release_and_failed_install() {
        let live = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let cfg = ChildConfig {
            pool_start: Ipv4Addr::new(10, 77, 0, 10),
            pool_end: Ipv4Addr::new(10, 77, 0, 10),
            dns: vec![Ipv4Addr::new(1, 1, 1, 1)],
            lifetime_secs: 60,
        };
        let mut service = ChildService::new(
            cfg,
            Box::new(Backend {
                fail: false,
                live: live.clone(),
            }),
        )
        .unwrap();
        let offer = Offer {
            number: 1,
            spi: 4096,
            esn: false,
            tsi: selector(0, u32::MAX),
            tsr: selector(0, u32::MAX),
        };
        let mut provider = ikev2_crypto::OpenSslProvider::new().unwrap();
        let keys =
            ikev2_crypto::derive_keys(&mut provider, &[1; 32], &[2; 32], &[3; 32], 1, 2).unwrap();
        let peer = "198.51.100.1:4500".parse().unwrap();
        let local = "192.0.2.1:4500".parse().unwrap();
        let first = service
            .establish(&keys, (&[2; 32], &[3; 32]), &offer, peer, local)
            .unwrap();
        assert!(
            service
                .establish(&keys, (&[2; 32], &[3; 32]), &offer, peer, local)
                .is_err()
        );
        drop(first);
        assert_eq!(live.load(std::sync::atomic::Ordering::SeqCst), 0);
        service.backend = Box::new(Backend {
            fail: true,
            live: live.clone(),
        });
        assert!(
            service
                .establish(&keys, (&[2; 32], &[3; 32]), &offer, peer, local)
                .is_err()
        );
        assert!(service.allocated.lock().unwrap().is_empty());
        service.backend = Box::new(Backend {
            fail: false,
            live: live.clone(),
        });
        let next = service
            .establish(&keys, (&[2; 32], &[3; 32]), &offer, peer, local)
            .unwrap();
        drop(next);
        assert_eq!(live.load(std::sync::atomic::Ordering::SeqCst), 0);
    }
    #[test]
    fn reject_child_weak_suite_spi_and_incompatible_selectors() {
        let sa = [
            0, 0, 0, 24, 1, 3, 4, 1, 0, 0, 16, 0, 0, 0, 0, 12, 1, 0, 0, 20, 128, 14, 1, 0,
        ];
        let ts = selector(0, u32::MAX);
        let cp = [1, 0, 0, 0, 0, 1, 0, 0];
        let check = |sa: &[u8]| {
            let p = vec![
                ikev2_wire::auth::Payload {
                    critical: false,
                    body: Body::Sa(sa),
                },
                ikev2_wire::auth::Payload {
                    critical: false,
                    body: Body::Ts {
                        responder: false,
                        data: &ts,
                    },
                },
                ikev2_wire::auth::Payload {
                    critical: false,
                    body: Body::Ts {
                        responder: true,
                        data: &ts,
                    },
                },
                ikev2_wire::auth::Payload {
                    critical: false,
                    body: Body::Config(&cp),
                },
            ];
            Offer::parse(&p, Limits::default())
        };
        assert!(check(&sa).is_ok());
        let mut weak = sa;
        weak[19] = 12;
        assert!(check(&weak).is_err());
        let mut short = sa;
        short[8..12].copy_from_slice(&7u32.to_be_bytes());
        assert!(check(&short).is_err());
        let mut key = sa;
        key[22..24].copy_from_slice(&128u16.to_be_bytes());
        assert!(check(&key).is_err());
        for n in 0..sa.len() {
            assert!(check(&sa[..n]).is_err());
        }
    }
}
