use ikev2_core::{NAT_DESTINATION, NAT_SOURCE, Policy, Responder};
use ikev2_crypto::{
    CryptoProvider, EphemeralDh, OpenSslProvider, constant_time_eq, derive_keys, nat_detection,
};
use ikev2_transport::{Channel, UdpResponder};
use ikev2_wire::{Body, Header, Limits, Message, Payload};
use std::{
    net::{SocketAddr, SocketAddrV4, UdpSocket},
    time::{Duration, Instant},
};
fn payload(body: Body<'_>) -> Payload<'_> {
    Payload {
        offset: 0,
        critical: false,
        body,
    }
}
#[test]
fn unprivileged_ipv4_udp_channels_real_ecdh_and_nat_metadata() {
    let core = Responder::new(
        OpenSslProvider::new().unwrap(),
        Policy::default(),
        Limits::default(),
    )
    .unwrap();
    let mut server = UdpResponder::bind(
        core,
        "127.0.0.1:0".parse().unwrap(),
        "127.0.0.1:0".parse().unwrap(),
    )
    .unwrap();
    let addresses = server.addresses().unwrap();
    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    client.set_nonblocking(true).unwrap();
    let peer: SocketAddrV4 = match client.local_addr().unwrap() {
        SocketAddr::V4(addr) => addr,
        _ => unreachable!(),
    };
    let mut provider = OpenSslProvider::new().unwrap();
    let start = Instant::now();
    for (i, channel) in [Channel::Ike, Channel::NatT].into_iter().enumerate() {
        let dh = provider.generate_p256().unwrap();
        let public = dh.public_value().unwrap();
        let ni = [0x42; 32];
        let spii = (i + 1) as u64;
        let source = nat_detection(spii, 0, peer);
        let destination = nat_detection(spii, 0, addresses[i]);
        let request = Message {
            header: Header {
                initiator_spi: spii,
                responder_spi: 0,
                version: 0x20,
                exchange: 34,
                flags: 8,
                message_id: 0,
            },
            payloads: vec![
                payload(Body::Sa(vec![ikev2_core::selected_proposal(1)])),
                payload(Body::KeyExchange {
                    group: 19,
                    data: &public,
                }),
                payload(Body::Nonce(&ni)),
                payload(Body::Notify {
                    protocol: 0,
                    spi: &[],
                    kind: NAT_SOURCE,
                    data: &source,
                }),
                payload(Body::Notify {
                    protocol: 0,
                    spi: &[],
                    kind: NAT_DESTINATION,
                    data: &destination,
                }),
            ],
        };
        let request = ikev2_wire::encode(&request, Limits::default()).unwrap();
        let packet = ikev2_transport::encode(channel, &request, 4096).unwrap();
        client.send_to(&packet, addresses[i]).unwrap();
        let mut buffer = [0; 4096];
        let response = loop {
            server.tick(start.elapsed()).unwrap();
            match client.recv_from(&mut buffer) {
                Ok((n, from)) => {
                    assert_eq!(from, SocketAddr::V4(addresses[i]));
                    break buffer[..n].to_vec();
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(
                        start.elapsed() < Duration::from_secs(3),
                        "loopback responder timed out"
                    );
                    std::thread::sleep(Duration::from_millis(1));
                }
                Err(e) => panic!("{e}"),
            }
        };
        if channel == Channel::NatT {
            assert_eq!(response[..4], [0; 4]);
        }
        let ike = match ikev2_transport::decode(channel, &response, 4096).unwrap() {
            ikev2_transport::Datagram::Ike(b) => b,
            _ => panic!("IKE response required"),
        };
        let m = ikev2_wire::decode(ike, Limits::default()).unwrap();
        assert_eq!(m.header.initiator_spi, spii);
        assert_ne!(m.header.responder_spi, 0);
        let mut shared = None;
        let mut nr = None;
        for p in &m.payloads {
            match &p.body {
                Body::KeyExchange { group: 19, data } => {
                    shared = Some(dh.shared_secret(data).unwrap())
                }
                Body::Nonce(data) => nr = Some(*data),
                Body::Notify {
                    kind: NAT_SOURCE,
                    data,
                    ..
                } => assert!(constant_time_eq(
                    data,
                    &nat_detection(spii, m.header.responder_spi, addresses[i])
                )),
                Body::Notify {
                    kind: NAT_DESTINATION,
                    data,
                    ..
                } => assert!(constant_time_eq(
                    data,
                    &nat_detection(spii, m.header.responder_spi, peer)
                )),
                _ => {}
            }
        }
        // Independently act as initiator through the provider: derive actual keys
        // without adding any IKE_AUTH logic or accepting authenticated access.
        let keys = derive_keys(
            &mut provider,
            shared.unwrap().expose(),
            &ni,
            nr.unwrap(),
            spii,
            m.header.responder_spi,
        )
        .unwrap();
        assert_eq!(keys.sk_d.expose().len(), 32);
        client.send_to(&packet, addresses[i]).unwrap();
        let duplicate = loop {
            server.tick(start.elapsed()).unwrap();
            match client.recv_from(&mut buffer) {
                Ok((n, _)) => break buffer[..n].to_vec(),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(start.elapsed() < Duration::from_secs(3));
                    std::thread::sleep(Duration::from_millis(1));
                }
                Err(e) => panic!("{e}"),
            }
        };
        assert_eq!(duplicate, response);
    }
    // ESP/keepalives, malformed marker and oversized datagrams are ignored.
    for bytes in [vec![0xff], vec![1, 2, 3, 4], vec![0; 3], vec![0; 7000]] {
        client.send_to(&bytes, addresses[1]).unwrap();
    }
    client.send_to(&[0; 7000], addresses[0]).unwrap();
    std::thread::sleep(Duration::from_millis(5));
    server.tick(start.elapsed()).unwrap();
    assert!(server.stats().ignored >= 5);
    assert_eq!(server.core().pending_count(), 2);
    server.tick(Duration::from_secs(11)).unwrap();
    assert_eq!(server.core().pending_count(), 0);
    assert_eq!(server.core().stats().retransmits, 2);
}
#[test]
fn wildcard_listener_is_rejected_without_binding() {
    let core = Responder::new(
        OpenSslProvider::new().unwrap(),
        Policy::default(),
        Limits::default(),
    )
    .unwrap();
    assert!(
        UdpResponder::bind(
            core,
            "0.0.0.0:0".parse().unwrap(),
            "127.0.0.1:0".parse().unwrap()
        )
        .is_err()
    );
}

#[test]
fn admission_is_shared_between_sockets_and_diagnostics_are_bounded() {
    let policy = Policy {
        work_per_second: 1,
        work_burst: 1,
        source_work_per_second: 1,
        source_work_burst: 1,
        ..Policy::default()
    };
    let mut server = UdpResponder::bind(
        Responder::new(OpenSslProvider::new().unwrap(), policy, Limits::default()).unwrap(),
        "127.0.0.1:0".parse().unwrap(),
        "127.0.0.1:0".parse().unwrap(),
    )
    .unwrap();
    let addresses = server.addresses().unwrap();
    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    client
        .set_read_timeout(Some(Duration::from_millis(100)))
        .unwrap();
    let text = include_str!("../../ikev2-core/tests/fixtures/request.hex");
    let hex: String = text.split_whitespace().collect();
    let bytes: Vec<u8> = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect();
    let mut buffer = [0; 2048];
    // Same source on either socket shares all admission limits.
    client.send_to(&bytes, addresses[0]).unwrap();
    server.tick(Duration::ZERO).unwrap();
    assert!(client.recv_from(&mut buffer).is_ok());
    client
        .send_to(
            &ikev2_transport::encode(Channel::NatT, &bytes, 4096).unwrap(),
            addresses[1],
        )
        .unwrap();
    server.tick(Duration::ZERO).unwrap();
    assert!(client.recv_from(&mut buffer).is_err());
    assert_eq!(server.core().stats().rate_limited, 1);
    assert_eq!(server.core().pending_count(), 1);
    // Do not drain: prove even an embedding caller cannot grow diagnostic storage.
    for second in 1..=10 {
        client.send_to(&bytes, addresses[0]).unwrap();
        server.tick(Duration::from_secs(second)).unwrap();
        assert!(client.recv_from(&mut buffer).is_ok());
    }
    assert_eq!(server.stats().diagnostics_suppressed, 3);
    let samples = server.take_diagnostics();
    assert_eq!(samples.len(), 8);
    assert!(samples[0].selected_proposal.is_some());
    assert_eq!(
        samples[0].nat,
        Some(ikev2_core::NatStatus {
            source_changed: true,
            destination_changed: true
        })
    );
    assert_eq!(samples[0].offers[0].transforms[0].key_bits, Some(256));
    assert!(server.take_diagnostics().is_empty());
}

#[test]
fn diagnostics_sample_rate_is_shared_between_channels() {
    let mut server = UdpResponder::bind(
        Responder::new(
            OpenSslProvider::new().unwrap(),
            Policy::default(),
            Limits::default(),
        )
        .unwrap(),
        "127.0.0.1:0".parse().unwrap(),
        "127.0.0.1:0".parse().unwrap(),
    )
    .unwrap();
    let addresses = server.addresses().unwrap();
    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    let text = include_str!("../../ikev2-core/tests/fixtures/request.hex");
    let hex: String = text.split_whitespace().collect();
    let mut bytes: Vec<u8> = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect();
    let mut buffer = [0; 2048];
    for (i, channel) in [Channel::Ike, Channel::NatT].into_iter().enumerate() {
        bytes[7] = i as u8 + 1;
        client
            .send_to(
                &ikev2_transport::encode(channel, &bytes, 4096).unwrap(),
                addresses[i],
            )
            .unwrap();
        server.tick(Duration::ZERO).unwrap();
        client.recv_from(&mut buffer).unwrap();
    }
    assert_eq!(server.take_diagnostics().len(), 1);
    assert_eq!(server.stats().diagnostics_suppressed, 1);
}
