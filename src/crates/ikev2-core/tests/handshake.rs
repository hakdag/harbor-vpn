use ikev2_core::*;
use ikev2_crypto::{CryptoProvider, EphemeralDh, OpenSslProvider, SecretBytes};
use ikev2_wire::{Body, Limits, Payload};
use std::{
    net::SocketAddrV4,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
fn hex(s: &str) -> Vec<u8> {
    let s: String = s.split_whitespace().collect();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}
fn request() -> Vec<u8> {
    hex(include_str!("fixtures/request.hex"))
}
fn peer() -> SocketAddrV4 {
    "198.51.100.10:500".parse().unwrap()
}
fn local() -> SocketAddrV4 {
    "192.0.2.1:500".parse().unwrap()
}
struct Fake {
    random_calls: u8,
    dh_calls: Arc<AtomicUsize>,
}
struct FakeDh;
impl EphemeralDh for FakeDh {
    fn public_value(&self) -> Result<[u8; 64], ikev2_crypto::Error> {
        Ok(hex("d12dfb5289c8d4f81208b70270398c342296970a0bccb74c736fc7554494bf6356fbf3ca366cc23e8157854c13c58d6aac23f046ada30f8353e74f33039872ab").try_into().unwrap())
    }
    fn shared_secret(&self, peer: &[u8]) -> Result<SecretBytes, ikev2_crypto::Error> {
        if peer
            != hex(
                "dad0b65394221cf9b051e1feca5787d098dfe637fc90b9ef945d0c37725811805271a0461cdb8252d61f1c456fa3e59ab1f45b33accf5f58389e0577b8990bb3",
            )
        {
            return Err(ikev2_crypto::Error::InvalidPeer);
        }
        Ok(SecretBytes::new(hex(
            "d6840f6b42f6edafd13116e0e12565202fef8e9ece7dce03812464d04b9442de",
        )))
    }
}
impl CryptoProvider for Fake {
    type Dh = FakeDh;
    fn random(&mut self, out: &mut [u8]) -> Result<(), ikev2_crypto::Error> {
        self.random_calls = self.random_calls.wrapping_add(1);
        out.fill(self.random_calls);
        Ok(())
    }
    fn generate_p256(&mut self) -> Result<FakeDh, ikev2_crypto::Error> {
        self.dh_calls.fetch_add(1, Ordering::Relaxed);
        Ok(FakeDh)
    }
}
fn responder(policy: Policy) -> (Responder<Fake>, Arc<AtomicUsize>) {
    let calls = Arc::new(AtomicUsize::new(0));
    (
        Responder::new(
            Fake {
                random_calls: 0,
                dh_calls: calls.clone(),
            },
            policy,
            Limits::default(),
        )
        .unwrap(),
        calls,
    )
}
fn handle<P: CryptoProvider>(r: &mut Responder<P>, b: &[u8], seconds: u64) -> Outcome {
    r.handle(b, peer(), local(), Duration::from_secs(seconds))
        .unwrap()
}
fn reencode<'a, F: FnOnce(&mut ikev2_wire::Message<'a>)>(bytes: &'a [u8], f: F) -> Vec<u8> {
    let mut m = ikev2_wire::decode(bytes, Limits::default()).unwrap();
    f(&mut m);
    ikev2_wire::encode(&m, Limits::default()).unwrap()
}
fn cookie_retry(bytes: &[u8], challenge: &[u8]) -> Vec<u8> {
    let challenge = ikev2_wire::decode(challenge, Limits::default()).unwrap();
    reencode(bytes, |m| {
        m.payloads.insert(0, challenge.payloads[0].clone())
    })
}
#[test]
fn codec_limits_must_allow_mandatory_response() {
    for wire in [
        Limits {
            payloads: 4,
            ..Limits::default()
        },
        Limits {
            transforms: 2,
            ..Limits::default()
        },
        Limits {
            message_bytes: 2048,
            ..Limits::default()
        },
    ] {
        assert!(matches!(
            Responder::new(OpenSslProvider::new().unwrap(), Policy::default(), wire),
            Err(Error::InvalidPolicy)
        ));
    }
}
#[test]
fn golden_exchange_duplicate_and_expiry() {
    let (mut r, calls) = responder(Policy::default());
    let bytes = request();
    let first = handle(&mut r, &bytes, 0);
    assert_eq!(first.event, Event::PendingCreated);
    assert_eq!(
        first.nat,
        Some(NatStatus {
            source_changed: false,
            destination_changed: false
        })
    );
    assert_eq!(
        first.response.unwrap(),
        hex(include_str!("fixtures/response.hex"))
    );
    let second = handle(&mut r, &bytes, 9);
    assert_eq!(second.event, Event::Retransmit);
    assert_eq!(
        second.response.unwrap(),
        hex(include_str!("fixtures/response.hex"))
    );
    assert_eq!(calls.load(Ordering::Relaxed), 1);
    r.expire(Duration::from_secs(10)).unwrap();
    assert_eq!(r.pending_count(), 0);
    assert_eq!(r.stats().expired, 1);
    assert_eq!(handle(&mut r, &bytes, 10).event, Event::PendingCreated);
    assert_eq!(calls.load(Ordering::Relaxed), 2);
    assert_eq!(
        r.expire(Duration::from_secs(9)),
        Err(Error::ClockWentBackwards)
    );
}
#[test]
fn cookie_is_stateless_independent_golden_and_context_bound() {
    let policy = Policy {
        cookie_threshold: 1,
        max_pending: 3,
        per_source: 3,
        ..Policy::default()
    };
    let (mut r, calls) = responder(policy);
    let seed = reencode(&request(), |m| m.header.initiator_spi = 1);
    handle(&mut r, &seed, 0);
    // A fresh responder uses byte-1 cookie secret; the extra accepted seed does not rotate it.
    let first = handle(&mut r, &request(), 0);
    assert_eq!(first.event, Event::CookieChallenge);
    assert_eq!(
        first.response.as_ref().unwrap(),
        &hex(include_str!("fixtures/cookie.hex"))
    );
    assert_eq!(r.pending_count(), 1);
    assert_eq!(calls.load(Ordering::Relaxed), 1);
    let retry = cookie_retry(&request(), first.response.as_ref().unwrap());
    let mut modified = retry.clone();
    modified[7] ^= 1;
    assert_eq!(handle(&mut r, &modified, 0).event, Event::CookieChallenge);
    let changed_peer = "198.51.100.11:500".parse().unwrap();
    assert_eq!(
        r.handle(&retry, changed_peer, local(), Duration::ZERO)
            .unwrap()
            .event,
        Event::CookieChallenge
    );
    assert_eq!(handle(&mut r, &retry, 0).event, Event::PendingCreated);
    assert_eq!(handle(&mut r, &retry, 0).event, Event::Retransmit);
    assert_eq!(r.pending_count(), 2);
    assert_eq!(calls.load(Ordering::Relaxed), 2);
}
#[test]
fn cookie_rotation_previous_key_and_expired_key() {
    let policy = Policy {
        max_pending: 4,
        per_source: 4,
        cookie_threshold: 1,
        cookie_rotation_secs: 10,
        lifetime_secs: 60,
        ..Policy::default()
    };
    let (mut r, _) = responder(policy);
    handle(
        &mut r,
        &reencode(&request(), |m| m.header.initiator_spi = 1),
        0,
    );
    let challenge = handle(&mut r, &request(), 0).response.unwrap();
    let retry = cookie_retry(&request(), &challenge);
    assert_eq!(handle(&mut r, &retry, 10).event, Event::PendingCreated);
    let (mut r, _) = responder(policy);
    handle(
        &mut r,
        &reencode(&request(), |m| m.header.initiator_spi = 1),
        0,
    );
    assert_eq!(handle(&mut r, &retry, 20).event, Event::CookieChallenge);
}
#[test]
fn burst_caps_and_verified_cookie_cannot_exceed_capacity() {
    let policy = Policy {
        work_burst: 2048,
        source_work_burst: 2048,
        max_pending: 2,
        per_source: 1,
        cookie_threshold: 1,
        ..Policy::default()
    };
    let (mut r, calls) = responder(policy);
    handle(&mut r, &request(), 0);
    for i in 1..1000u64 {
        let bytes = reencode(&request(), |m| m.header.initiator_spi = i);
        assert_eq!(handle(&mut r, &bytes, 0).event, Event::CookieChallenge);
    }
    let bytes = reencode(&request(), |m| m.header.initiator_spi = 7);
    let challenge = handle(&mut r, &bytes, 0).response.unwrap();
    let retry = cookie_retry(&bytes, &challenge);
    assert_eq!(handle(&mut r, &retry, 0).event, Event::Busy);
    assert_eq!(r.pending_count(), 1);
    assert_eq!(calls.load(Ordering::Relaxed), 1);
    // A second source can pass its address proof and fill the global cap.
    let peer2 = "198.51.100.11:500".parse().unwrap();
    let challenge = r
        .handle(&bytes, peer2, local(), Duration::ZERO)
        .unwrap()
        .response
        .unwrap();
    let retry = cookie_retry(&bytes, &challenge);
    assert_eq!(
        r.handle(&retry, peer2, local(), Duration::ZERO)
            .unwrap()
            .event,
        Event::PendingCreated
    );
    assert_eq!(r.pending_count(), 2);
    assert_eq!(calls.load(Ordering::Relaxed), 2);
    let peer3 = "198.51.100.12:500".parse().unwrap();
    let challenge = r
        .handle(&bytes, peer3, local(), Duration::ZERO)
        .unwrap()
        .response
        .unwrap();
    assert_eq!(
        r.handle(
            &cookie_retry(&bytes, &challenge),
            peer3,
            local(),
            Duration::ZERO
        )
        .unwrap()
        .event,
        Event::Busy
    );
    assert_eq!(r.pending_count(), 2);
}
#[test]
fn proposal_policy_and_invalid_ke_notifications() {
    type ProposalChange = Box<dyn Fn(&mut ikev2_wire::Message<'_>)>;
    let changes: Vec<ProposalChange> = vec![
        Box::new(|m| {
            if let Body::Sa(p) = &mut m.payloads[0].body {
                p[0].transforms[0].id = 12;
            }
        }),
        Box::new(|m| {
            if let Body::Sa(p) = &mut m.payloads[0].body {
                p[0].transforms[1].id = 2;
            }
        }),
        Box::new(|m| {
            if let Body::Sa(p) = &mut m.payloads[0].body {
                p[0].transforms[0].attributes[0] = ikev2_wire::Attribute::Tv {
                    kind: 14,
                    value: 128,
                };
            }
        }),
        Box::new(|m| {
            if let Body::Sa(p) = &mut m.payloads[0].body {
                p[0].transforms.push(ikev2_wire::Transform {
                    kind: 3,
                    id: 0,
                    attributes: vec![],
                });
            }
        }),
    ];
    for change in changes {
        let (mut r, calls) = responder(Policy::default());
        let bytes = reencode(&request(), change);
        let out = handle(&mut r, &bytes, 0);
        assert_eq!(out.event, Event::Rejected(NO_PROPOSAL));
        assert!(!out.offers.is_empty());
        assert_eq!(calls.load(Ordering::Relaxed), 0);
        assert_eq!(r.pending_count(), 0);
    }
    let wrong = reencode(&request(), |m| {
        if let Body::KeyExchange { group, .. } = &mut m.payloads[1].body {
            *group = 14;
        }
    });
    let (mut r, calls) = responder(Policy::default());
    let out = handle(&mut r, &wrong, 0);
    assert_eq!(out.event, Event::Rejected(INVALID_KE));
    assert_eq!(calls.load(Ordering::Relaxed), 0);
    let response = out.response.unwrap();
    let m = ikev2_wire::decode(&response, Limits::default()).unwrap();
    assert_eq!(m.header.responder_spi, 0);
    assert!(matches!(
        m.payloads[0].body,
        Body::Notify {
            kind: INVALID_KE,
            data: &[0, 19],
            ..
        }
    ));
}
#[test]
fn initial_state_validation_unknowns_reordering_and_conflicts() {
    for change in 0..7 {
        let bytes = reencode(&request(), |m| match change {
            0 => m.header.flags = 0,
            1 => m.header.flags = 0x28,
            2 => m.header.message_id = 1,
            3 => m.header.initiator_spi = 0,
            4 => m.header.responder_spi = 1,
            5 => m.header.exchange = 35,
            _ => m.header.version = 0x10,
        });
        let (mut r, calls) = responder(Policy::default());
        assert_eq!(handle(&mut r, &bytes, 0).event, Event::Dropped);
        assert_eq!(calls.load(Ordering::Relaxed), 0);
    }
    let (mut r, _) = responder(Policy::default());
    let first = request();
    handle(&mut r, &first, 0);
    let conflicting = reencode(&first, |m| m.payloads.swap(0, 1));
    assert_eq!(handle(&mut r, &conflicting, 0).event, Event::Dropped);
    let (mut r, _) = responder(Policy::default());
    assert_eq!(handle(&mut r, &conflicting, 0).event, Event::PendingCreated);
    let (mut r, _) = responder(Policy::default());
    let future = reencode(&first, |m| m.header.version = 0x21);
    assert_eq!(handle(&mut r, &future, 0).event, Event::PendingCreated);
    for critical in [false, true] {
        let (mut r, _) = responder(Policy::default());
        let bytes = reencode(&first, |m| {
            m.payloads.push(Payload {
                offset: 0,
                critical,
                body: Body::Opaque {
                    kind: 250,
                    next_inner: 0,
                    data: &[1, 2],
                },
            })
        });
        assert_eq!(
            handle(&mut r, &bytes, 0).event,
            if critical {
                Event::Rejected(UNSUPPORTED_CRITICAL)
            } else {
                Event::PendingCreated
            }
        );
    }
}
#[test]
fn malformed_truncation_notify_missing_and_duplicate_payloads() {
    let bytes = request();
    let (mut r, calls) = responder(Policy {
        work_burst: 512,
        source_work_burst: 512,
        ..Policy::default()
    });
    for end in 0..bytes.len() {
        assert_eq!(handle(&mut r, &bytes[..end], 0).event, Event::Dropped);
    }
    assert_eq!(calls.load(Ordering::Relaxed), 0);
    for which in 0..4 {
        let b = reencode(&bytes, |m| match which {
            0 => {
                m.payloads.remove(1);
            }
            1 => m.payloads.push(m.payloads[0].clone()),
            2 => {
                m.payloads.remove(4);
            }
            _ => {
                if let Body::Notify { protocol, .. } = &mut m.payloads[3].body {
                    *protocol = 1;
                }
            }
        });
        assert_eq!(handle(&mut r, &b, 0).event, Event::Rejected(INVALID_SYNTAX));
    }
    let b = reencode(&bytes, |m| {
        m.payloads[1].body = Body::KeyExchange {
            group: 19,
            data: &[0; 63],
        }
    });
    assert_eq!(handle(&mut r, &b, 0).event, Event::Rejected(INVALID_SYNTAX));
}
#[test]
fn real_provider_rejects_invalid_point_and_detects_nat() {
    let mut r = Responder::new(
        OpenSslProvider::new().unwrap(),
        Policy::default(),
        Limits::default(),
    )
    .unwrap();
    let invalid = reencode(&request(), |m| {
        m.payloads[1].body = Body::KeyExchange {
            group: 19,
            data: &[0; 64],
        }
    });
    assert_eq!(
        handle(&mut r, &invalid, 0).event,
        Event::Rejected(INVALID_SYNTAX)
    );
    assert_eq!(r.pending_count(), 0);
    let b = reencode(&request(), |m| {
        m.payloads[3].body = Body::Notify {
            protocol: 0,
            spi: &[],
            kind: NAT_SOURCE,
            data: &[0; 20],
        };
        m.payloads[4].body = Body::Notify {
            protocol: 0,
            spi: &[],
            kind: NAT_DESTINATION,
            data: &[0; 20],
        };
    });
    let out = handle(&mut r, &b, 0);
    assert_eq!(out.event, Event::PendingCreated);
    assert_eq!(
        out.nat,
        Some(NatStatus {
            source_changed: true,
            destination_changed: true
        })
    );
}
#[test]
fn invalid_policy_and_oversize() {
    for policy in [
        Policy {
            max_pending: 0,
            ..Policy::default()
        },
        Policy {
            max_pending: 4097,
            ..Policy::default()
        },
        Policy {
            per_source: 129,
            ..Policy::default()
        },
        Policy {
            lifetime_secs: 61,
            ..Policy::default()
        },
        Policy {
            max_response_bytes: 255,
            ..Policy::default()
        },
        Policy {
            cookie_threshold: 1025,
            ..Policy::default()
        },
    ] {
        assert!(policy.validate().is_err());
    }
    let (mut r, calls) = responder(Policy::default());
    assert_eq!(handle(&mut r, &vec![0; 4097], 0).event, Event::Dropped);
    assert_eq!(calls.load(Ordering::Relaxed), 0);
}

#[test]
fn select_only_approved_alternative_preserves_proposal_number() {
    let bytes = reencode(&request(), |m| {
        if let Body::Sa(p) = &mut m.payloads[0].body {
            p[0].transforms[0].id = 12;
            p.push(selected_proposal(2));
        }
    });
    let (mut r, _) = responder(Policy::default());
    let out = handle(&mut r, &bytes, 0);
    assert_eq!(out.event, Event::PendingCreated);
    let b = out.response.unwrap();
    let m = ikev2_wire::decode(&b, Limits::default()).unwrap();
    assert!(matches!(&m.payloads[0].body,Body::Sa(p) if p.len()==1 && p[0]==selected_proposal(2)));
    let mut future = request();
    future[17] = 0x30;
    let (mut r, _) = responder(Policy::default());
    assert_eq!(handle(&mut r, &future, 0).event, Event::Rejected(5));
}
#[test]
fn multiple_source_nat_hashes_and_bad_cookie_or_cookie_position() {
    let bytes = request();
    let multiple = reencode(&bytes, |m| {
        m.payloads.insert(
            3,
            Payload {
                offset: 0,
                critical: false,
                body: Body::Notify {
                    protocol: 0,
                    spi: &[],
                    kind: NAT_SOURCE,
                    data: &[0; 20],
                },
            },
        )
    });
    let (mut r, _) = responder(Policy::default());
    assert_eq!(
        handle(&mut r, &multiple, 0).nat,
        Some(NatStatus {
            source_changed: false,
            destination_changed: false
        })
    );
    let bad = reencode(&bytes, |m| {
        m.payloads.insert(
            0,
            Payload {
                offset: 0,
                critical: false,
                body: Body::Notify {
                    protocol: 0,
                    spi: &[],
                    kind: COOKIE,
                    data: &[0; 40],
                },
            },
        )
    });
    let (mut r, calls) = responder(Policy::default());
    assert_eq!(handle(&mut r, &bad, 0).event, Event::CookieChallenge);
    assert_eq!(calls.load(Ordering::Relaxed), 0);
    let misplaced = reencode(&bad, |m| m.payloads.swap(0, 1));
    assert_eq!(
        handle(&mut r, &misplaced, 0).event,
        Event::Rejected(INVALID_SYNTAX)
    );
}
#[test]
fn entropy_failure_is_fail_closed_without_pending_state() {
    use std::sync::atomic::AtomicBool;
    struct Fault {
        fail: Arc<AtomicBool>,
    }
    impl CryptoProvider for Fault {
        type Dh = FakeDh;
        fn random(&mut self, b: &mut [u8]) -> Result<(), ikev2_crypto::Error> {
            if self.fail.load(Ordering::Relaxed) {
                return Err(ikev2_crypto::Error::Provider);
            }
            b.fill(1);
            Ok(())
        }
        fn generate_p256(&mut self) -> Result<FakeDh, ikev2_crypto::Error> {
            Ok(FakeDh)
        }
    }
    let fail = Arc::new(AtomicBool::new(true));
    assert!(
        Responder::new(
            Fault { fail: fail.clone() },
            Policy::default(),
            Limits::default()
        )
        .is_err()
    );
    fail.store(false, Ordering::Relaxed);
    let mut r = Responder::new(
        Fault { fail: fail.clone() },
        Policy::default(),
        Limits::default(),
    )
    .unwrap();
    fail.store(true, Ordering::Relaxed);
    assert_eq!(
        r.handle(&request(), peer(), local(), Duration::ZERO).err(),
        Some(Error::Crypto)
    );
    assert_eq!(r.pending_count(), 0);
    assert_eq!(r.stats().crypto_errors, 1);
}

#[test]
fn certreq_critical_bit_is_ignored_without_processing_contents() {
    let original = request();
    for data in [&[4][..], &b"opaque-test-only-CERTREQ"[..]] {
        let mut replies = Vec::new();
        for critical in [false, true] {
            let bytes = reencode(&original, |m| {
                m.payloads.push(Payload {
                    offset: 0,
                    critical,
                    body: Body::Opaque {
                        kind: 38,
                        next_inner: 0,
                        data,
                    },
                })
            });
            let (mut r, calls) = responder(Policy::default());
            let out = handle(&mut r, &bytes, 0);
            assert_eq!(out.event, Event::PendingCreated);
            assert_eq!(calls.load(Ordering::Relaxed), 1);
            replies.push(out.response);
        }
        // Deterministic provider: bit and opaque contents have no negotiation effect.
        assert_eq!(replies[0], replies[1]);
    }
}

#[test]
fn admission_precedes_decode_cookie_crypto_and_all_replies() {
    let policy = Policy {
        work_burst: 2,
        source_work_burst: 2,
        work_per_second: 1,
        source_work_per_second: 1,
        lifetime_secs: 1,
        ..Policy::default()
    };
    let (mut r, calls) = responder(policy);
    let bytes = request();
    assert_eq!(handle(&mut r, &bytes, 0).event, Event::PendingCreated);
    assert_eq!(handle(&mut r, &bytes, 0).event, Event::Retransmit);
    for packet in [&bytes[..], &[0; 28][..], &vec![0; 4097][..]] {
        let out = handle(&mut r, packet, 0);
        assert_eq!(out.event, Event::RateLimited);
        assert!(out.response.is_none());
        assert!(out.offers.is_empty());
    }
    assert_eq!(calls.load(Ordering::Relaxed), 1);
    assert_eq!(r.pending_count(), 1);
    // A new SPI is also blocked before cookie or DH work.
    assert_eq!(
        handle(&mut r, &reencode(&bytes, |m| m.header.initiator_spi = 7), 0).event,
        Event::RateLimited
    );
    assert_eq!(handle(&mut r, &bytes, 1).event, Event::PendingCreated);
    assert_eq!(r.stats().expired, 1);
    assert_eq!(calls.load(Ordering::Relaxed), 2);
    assert_eq!(
        r.handle(&bytes, peer(), local(), Duration::ZERO).err(),
        Some(Error::ClockWentBackwards)
    );
}

#[test]
fn port_changes_do_not_bypass_source_quota_and_other_sources_can_progress() {
    let (mut r, calls) = responder(Policy {
        work_burst: 4,
        source_work_burst: 1,
        ..Policy::default()
    });
    let bytes = request();
    assert_eq!(handle(&mut r, &bytes, 0).event, Event::PendingCreated);
    let mut changed_port = peer();
    changed_port.set_port(4500);
    assert_eq!(
        r.handle(&bytes, changed_port, local(), Duration::ZERO)
            .unwrap()
            .event,
        Event::RateLimited
    );
    assert_eq!(
        r.handle(
            &bytes,
            "198.51.100.11:500".parse().unwrap(),
            local(),
            Duration::ZERO
        )
        .unwrap()
        .event,
        Event::PendingCreated
    );
    assert_eq!(calls.load(Ordering::Relaxed), 2);
}

#[test]
fn cookie_retry_and_pending_limits_survive_work_exhaustion() {
    let policy = Policy {
        work_burst: 3,
        source_work_burst: 3,
        cookie_threshold: 1,
        max_pending: 2,
        per_source: 2,
        ..Policy::default()
    };
    let (mut r, calls) = responder(policy);
    handle(&mut r, &request(), 0);
    let bytes = reencode(&request(), |m| m.header.initiator_spi = 7);
    let challenge = handle(&mut r, &bytes, 0).response.unwrap();
    let retry = cookie_retry(&bytes, &challenge);
    assert_eq!(handle(&mut r, &retry, 0).event, Event::PendingCreated);
    assert_eq!(handle(&mut r, &retry, 0).event, Event::RateLimited);
    assert_eq!(calls.load(Ordering::Relaxed), 2);
    assert_eq!(r.pending_count(), 2);
    let next = reencode(&request(), |m| m.header.initiator_spi = 8);
    let challenge = handle(&mut r, &next, 1).response.unwrap();
    assert_eq!(
        handle(&mut r, &cookie_retry(&next, &challenge), 1).event,
        Event::Busy
    );
    assert_eq!(calls.load(Ordering::Relaxed), 2);
    assert_eq!(r.pending_count(), 2);
}

#[test]
fn diagnostics_bound_numeric_offers_and_mark_omitted_attributes() {
    let bytes = reencode(&request(), |m| {
        if let Body::Sa(p) = &mut m.payloads[0].body {
            p[0].transforms[0].id = 65000;
            p[0].transforms[0]
                .attributes
                .push(ikev2_wire::Attribute::Tlv {
                    kind: 123,
                    value: b"DO-NOT-LOG-ATTRIBUTE",
                });
            let extra = p[0].transforms[0].clone();
            for _ in 0..8 {
                p[0].transforms.push(extra.clone());
            }
            let first = p[0].clone();
            for number in 2..=6 {
                let mut next = first.clone();
                next.number = number;
                p.push(next);
            }
        }
    });
    let (mut r, _) = responder(Policy::default());
    let out = handle(&mut r, &bytes, 0);
    assert_eq!(out.event, Event::Rejected(NO_PROPOSAL));
    assert!(out.selected_proposal.is_none());
    assert_eq!(out.offers.len(), 4);
    assert!(out.offers_truncated);
    assert_eq!(out.offers[0].transforms.len(), 8);
    assert!(out.offers[0].transforms_truncated);
    assert_eq!(out.offers[0].transforms[0].id, 65000);
    assert_eq!(out.offers[0].transforms[0].key_bits, Some(256));
    assert!(out.offers[0].transforms[0].attributes_omitted);
    assert!(!format!("{:?}", out.offers).contains("DO-NOT-LOG"));
    let (mut r, _) = responder(Policy::default());
    let accepted = handle(&mut r, &request(), 0);
    let duplicate = handle(&mut r, &request(), 0);
    assert_eq!(accepted.selected_proposal, Some(1));
    assert_eq!(accepted.offers, duplicate.offers);
    assert_eq!(accepted.nat, duplicate.nat);
}

#[test]
fn diagnostic_truncation_does_not_change_selection_or_imply_nat_detection() {
    let bytes = reencode(&request(), |m| {
        m.payloads.retain(|p| {
            !matches!(
                p.body,
                Body::Notify {
                    kind: NAT_SOURCE | NAT_DESTINATION,
                    ..
                }
            )
        });
        if let Body::Sa(p) = &mut m.payloads[0].body {
            p.clear();
            for number in 1..=6 {
                let mut proposal = selected_proposal(number);
                if number < 6 {
                    proposal.transforms[0].id = 65000;
                }
                p.push(proposal);
            }
        }
    });
    let (mut r, _) = responder(Policy::default());
    let out = handle(&mut r, &bytes, 0);
    assert_eq!(out.event, Event::PendingCreated);
    assert_eq!(out.selected_proposal, Some(6));
    assert!(out.offers_truncated);
    assert_eq!(out.offers.len(), 4);
    assert!(out.nat.is_none());
}

struct TestSigner {
    key: openssl::pkey::PKey<openssl::pkey::Private>,
    certs: Vec<Vec<u8>>,
}
impl ikev2_crypto::identity::ServerSigner for TestSigner {
    fn hostname(&self) -> &str {
        ikev2_crypto::identity::HOSTNAME
    }
    fn certificates(&self) -> &[Vec<u8>] {
        &self.certs
    }
    fn sign(&self, input: &[u8]) -> Result<Vec<u8>, ikev2_crypto::Error> {
        let mut s = openssl::sign::Signer::new(openssl::hash::MessageDigest::sha256(), &self.key)?;
        s.update(input)?;
        let mut signature = hex("0f300d06092a864886f70d01010b0500");
        signature.extend_from_slice(&s.sign_to_vec()?);
        Ok(signature)
    }
}
fn auth_context() -> (AuthContext, openssl::pkey::PKey<openssl::pkey::Public>) {
    let key = openssl::pkey::PKey::from_rsa(openssl::rsa::Rsa::generate(3072).unwrap()).unwrap();
    let public =
        openssl::pkey::PKey::public_key_from_der(&key.public_key_to_der().unwrap()).unwrap();
    let master = SecretBytes::new(vec![9; 32]);
    let hash = ikev2_crypto::mschap::MschapProvider::new()
        .unwrap()
        .nt_hash("clientPass")
        .unwrap();
    let user = vpn_auth::encrypt_user(&master, b"User", true, &hash).unwrap();
    let file = vpn_auth::encode_file(&[user]).unwrap();
    let store = vpn_auth::AuthStore::from_encrypted(&file, master).unwrap();
    (
        AuthContext::new(
            Box::new(TestSigner {
                key,
                certs: vec![b"synthetic test certificate envelope".to_vec()],
            }),
            store,
        )
        .unwrap(),
        public,
    )
}
fn hmac(key: &[u8], parts: &[&[u8]]) -> Vec<u8> {
    let key = openssl::pkey::PKey::hmac(key).unwrap();
    let mut h = openssl::sign::Signer::new(openssl::hash::MessageDigest::sha256(), &key).unwrap();
    for p in parts {
        h.update(p).unwrap();
    }
    h.sign_to_vec().unwrap()
}
fn initiator_signed(initial: &[u8], nonce: &[u8], sk_p: &[u8], id: &[u8]) -> Vec<u8> {
    let mut out = initial.to_vec();
    out.extend_from_slice(nonce);
    out.extend_from_slice(&hmac(sk_p, &[id]));
    out
}
fn final_auth(msk: &[u8], signed: &[u8]) -> Vec<u8> {
    hmac(&hmac(msk, &[b"Key Pad for IKEv2"]), &[signed])
}
fn auth_payload(body: ikev2_wire::auth::Body<'_>) -> ikev2_wire::auth::Payload<'_> {
    ikev2_wire::auth::Payload {
        critical: false,
        body,
    }
}
#[test]
fn protected_multiround_auth_nat_port_move_retransmit_final_auth_and_no_child() {
    auth_scenario(AuthCase::Success);
}
#[test]
fn invalid_final_auth_is_terminal_and_caches_only_encrypted_failure() {
    auth_scenario(AuthCase::BadFinal);
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum AuthCase {
    Success,
    BadFinal,
    UnknownCritical,
    NoSignatureHash,
    Timeout,
    WrongPassword,
    Child,
    ChildBadFinal,
    ChildInstallFailure,
    ChildExpiry,
}
#[test]
fn unsupported_critical_auth_payload_is_reported_inside_authenticated_sk() {
    auth_scenario(AuthCase::UnknownCritical);
}
#[test]
fn absent_rfc7427_support_fails_without_sha1_fallback() {
    auth_scenario(AuthCase::NoSignatureHash);
}
#[test]
fn auth_deadline_cannot_be_extended_by_retransmission() {
    auth_scenario(AuthCase::Timeout);
}
#[test]
fn wrong_password_completes_failure_sequence_without_authenticating() {
    auth_scenario(AuthCase::WrongPassword);
}
struct TestChildBackend {
    count: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    fail: bool,
}
struct TestChildResource(std::sync::Arc<std::sync::atomic::AtomicUsize>);
impl ikev2_core::child::ChildResource for TestChildResource {}
impl Drop for TestChildResource {
    fn drop(&mut self) {
        self.0.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
    }
}
impl ikev2_core::child::ChildBackend for TestChildBackend {
    fn install(
        &mut self,
        s: &ikev2_core::child::ChildSpec,
    ) -> Result<Box<dyn ikev2_core::child::ChildResource>, ikev2_core::Error> {
        assert_eq!(s.address, std::net::Ipv4Addr::new(10, 77, 0, 10));
        assert!(s.udp_encap);
        assert_eq!(s.outbound_spi, 0x1007);
        assert!(s.inbound_spi >= 256);
        assert_eq!(s.inbound_key.expose().len(), 36);
        assert_ne!(s.inbound_key.expose(), s.outbound_key.expose());
        if self.fail {
            return Err(ikev2_core::Error::Crypto);
        }
        self.count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(Box::new(TestChildResource(self.count.clone())))
    }
}
#[test]
fn child_success_cp_nat_liveness_delete_and_retransmit() {
    auth_scenario(AuthCase::Child);
}
#[test]
fn child_never_installed_before_valid_final_auth() {
    auth_scenario(AuthCase::ChildBadFinal);
}
#[test]
fn child_install_failure_does_not_acknowledge_tunnel() {
    auth_scenario(AuthCase::ChildInstallFailure);
}
#[test]
fn child_session_expiry_releases_owned_resources() {
    auth_scenario(AuthCase::ChildExpiry);
}
fn auth_scenario(case: AuthCase) {
    use ikev2_crypto::{
        mschap::MschapProvider,
        protected::{self, Direction},
    };
    use ikev2_wire::auth::{self, Body as A, Eap, Identity};
    let (mut context, public) = auth_context();
    let is_child = matches!(
        case,
        AuthCase::Child
            | AuthCase::ChildBadFinal
            | AuthCase::ChildInstallFailure
            | AuthCase::ChildExpiry
    );
    let count = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    if is_child {
        context = context.with_child(
            ikev2_core::child::ChildService::new(
                ikev2_core::child::ChildConfig {
                    pool_start: "10.77.0.10".parse().unwrap(),
                    pool_end: "10.77.0.10".parse().unwrap(),
                    dns: vec!["1.1.1.1".parse().unwrap()],
                    lifetime_secs: 1800,
                },
                Box::new(TestChildBackend {
                    count: count.clone(),
                    fail: case == AuthCase::ChildInstallFailure,
                }),
            )
            .unwrap(),
        );
    }
    let (r, _) = responder(Policy {
        max_request_bytes: 16384,
        max_response_bytes: 16384,
        ..Policy::default()
    });
    let mut r = r.with_auth(context).unwrap();
    let init = reencode(&request(), |m| {
        if case == AuthCase::NoSignatureHash {
            return;
        }
        m.payloads.push(Payload {
            offset: 0,
            critical: false,
            body: Body::Notify {
                protocol: 0,
                spi: &[],
                kind: 16431,
                data: &[0, 2],
            },
        })
    });
    let initial_response = handle(&mut r, &init, 0).response.unwrap();
    let decoded = ikev2_wire::decode(&initial_response, Limits::default()).unwrap();
    let spir = decoded.header.responder_spi;
    let ni = match ikev2_wire::decode(&init, Limits::default())
        .unwrap()
        .payloads[2]
        .body
    {
        Body::Nonce(n) => n.to_vec(),
        _ => unreachable!(),
    };
    let nr = match decoded.payloads[2].body {
        Body::Nonce(n) => n.to_vec(),
        _ => unreachable!(),
    };
    assert!(decoded.payloads.iter().any(|p| matches!(
        p.body,
        Body::Notify {
            kind: 16431,
            data: [0, 2],
            ..
        }
    )));
    let mut provider = OpenSslProvider::new().unwrap();
    let mut keys = ikev2_crypto::derive_keys(
        &mut provider,
        &hex("d6840f6b42f6edafd13116e0e12565202fef8e9ece7dce03812464d04b9442de"),
        &ni,
        &nr,
        decoded.header.initiator_spi,
        spir,
    )
    .unwrap();
    let mut child = hex("0000001801030401000000070000000c01000014800e0100");
    if is_child {
        child[8..12].copy_from_slice(&0x1007u32.to_be_bytes());
    }
    let ts = hex("01000000070000100000ffff00000000ffffffff");
    let id = Identity {
        kind: 11,
        reserved: [0; 3],
        data: b"User",
    };
    let mut payloads = vec![
        auth_payload(A::Idi(id)),
        auth_payload(A::Sa(&child)),
        auth_payload(A::Ts {
            responder: false,
            data: &ts,
        }),
        auth_payload(A::Ts {
            responder: true,
            data: &ts,
        }),
    ];
    if is_child {
        payloads.push(auth_payload(A::Config(&[
            1, 0, 0, 0, 0, 1, 0, 0, 0, 3, 0, 0,
        ])));
    }
    if case == AuthCase::UnknownCritical {
        payloads.push(auth::Payload {
            critical: true,
            body: A::Unknown {
                kind: 250,
                data: &[],
            },
        });
    }
    let (first, mut inner) = auth::encode_chain(&payloads, Limits::default()).unwrap();
    inner[1] = 128; // Known IDi Critical bit is ignored.
    inner[5..8].copy_from_slice(&[1, 2, 3]); // Reserved bytes still belong to signed IDi body.
    let mut h = ikev2_wire::Header {
        initiator_spi: decoded.header.initiator_spi,
        responder_spi: spir,
        version: 0x20,
        exchange: 35,
        flags: 8,
        message_id: 1,
    };
    let peer_auth = "198.51.100.10:4500".parse().unwrap();
    let local_auth = "192.0.2.1:4500".parse().unwrap();
    let send = |r: &mut Responder<Fake>, bytes: &[u8]| {
        r.handle(bytes, peer_auth, local_auth, Duration::ZERO)
            .unwrap()
    };
    let first_request = protected::seal(
        &mut keys,
        Direction::Initiator,
        h.clone(),
        first,
        &inner,
        Limits::default(),
    )
    .unwrap();
    let mut skipped_header = h.clone();
    skipped_header.message_id = 9;
    let skipped = protected::seal(
        &mut keys,
        Direction::Initiator,
        skipped_header,
        first,
        &inner,
        Limits::default(),
    )
    .unwrap();
    assert!(send(&mut r, &skipped).response.is_none());
    let mut wrong_spi_header = h.clone();
    wrong_spi_header.responder_spi ^= 1;
    let wrong_spi = protected::seal(
        &mut keys,
        Direction::Initiator,
        wrong_spi_header,
        first,
        &inner,
        Limits::default(),
    )
    .unwrap();
    assert!(send(&mut r, &wrong_spi).response.is_none());
    let mut bad = first_request.clone();
    *bad.last_mut().unwrap() ^= 1;
    assert!(send(&mut r, &bad).response.is_none());
    let first_response = send(&mut r, &first_request).response.unwrap();
    assert_eq!(
        send(&mut r, &first_request).response.unwrap(),
        first_response
    );
    assert!(
        r.handle(&first_request, peer(), local_auth, Duration::ZERO)
            .unwrap()
            .response
            .is_none()
    );
    let altered_duplicate = protected::seal(
        &mut keys,
        Direction::Initiator,
        h.clone(),
        first,
        &inner,
        Limits::default(),
    )
    .unwrap();
    assert!(send(&mut r, &altered_duplicate).response.is_none());
    let opened = protected::open(
        &keys,
        Direction::Responder,
        &first_response,
        Limits::default(),
    )
    .unwrap();
    let response = auth::decode_chain(
        opened.plaintext.expose(),
        opened.first_inner,
        Limits::default(),
    )
    .unwrap();
    if matches!(case, AuthCase::UnknownCritical | AuthCase::NoSignatureHash) {
        let (expected_kind, expected_data) = if case == AuthCase::UnknownCritical {
            (1, &[250][..])
        } else {
            (24, &[][..])
        };
        assert!(
            matches!(response.as_slice(),[auth::Payload{body:A::Notify{kind,data,..},..}] if *kind==expected_kind && *data==expected_data)
        );
        assert_eq!(r.stats().authenticated, 0);
        assert_eq!(r.stats().authentication_failed, 1);
        r.expire(Duration::from_secs(5)).unwrap();
        assert_eq!(r.pending_count(), 0);
        return;
    }

    let mut idr_body = vec![2, 0, 0, 0];
    idr_body.extend_from_slice(ikev2_crypto::identity::HOSTNAME.as_bytes());
    let signed = initiator_signed(&initial_response, &ni, keys.sk_pr.expose(), &idr_body);
    let signature = response
        .iter()
        .find_map(|p| {
            if let A::Auth { method: 14, data } = p.body {
                Some(data)
            } else {
                None
            }
        })
        .unwrap();
    ikev2_crypto::identity::ServerIdentity::verify_auth(&public, &signed, signature).unwrap();
    let identity_request = response
        .iter()
        .find_map(|p| {
            if let A::Eap(e) = p.body {
                Some(e)
            } else {
                None
            }
        })
        .unwrap();
    assert_eq!(identity_request.method, Some(1));
    let mut eap_response = Eap {
        code: 2,
        identifier: identity_request.identifier,
        method: Some(1),
        data: b"User",
    }
    .encode()
    .unwrap();
    let provider = MschapProvider::new().unwrap();
    let nt_hash = provider.nt_hash("clientPass").unwrap();
    let mut msk = None;
    for round in 2..=4 {
        h.message_id = round;
        let e = Eap::decode(&eap_response).unwrap();
        let (first, inner) =
            auth::encode_chain(&[auth_payload(A::Eap(e))], Limits::default()).unwrap();
        let request = protected::seal(
            &mut keys,
            Direction::Initiator,
            h.clone(),
            first,
            &inner,
            Limits::default(),
        )
        .unwrap();
        let wire = send(&mut r, &request).response.unwrap();
        assert_eq!(send(&mut r, &request).response.unwrap(), wire);
        let opened =
            protected::open(&keys, Direction::Responder, &wire, Limits::default()).unwrap();
        let payloads = auth::decode_chain(
            opened.plaintext.expose(),
            opened.first_inner,
            Limits::default(),
        )
        .unwrap();
        let A::Eap(e) = payloads[0].body else {
            panic!("EAP required")
        };
        if round == 2 {
            let auth_challenge: &[u8; 16] = e.data[5..21].try_into().unwrap();
            let peer_challenge = [0x23; 16];
            let nt = provider
                .nt_response(nt_hash.expose(), auth_challenge, &peer_challenge, b"User")
                .unwrap();
            let method_keys = provider
                .result(
                    nt_hash.expose(),
                    nt.expose().try_into().unwrap(),
                    auth_challenge,
                    &peer_challenge,
                    b"User",
                )
                .unwrap();
            let mut response = vec![2, e.data[1], 0, 58, 49];
            response.extend_from_slice(&peer_challenge);
            response.extend_from_slice(&[0; 8]);
            response.extend_from_slice(nt.expose());
            response.push(0);
            response.extend_from_slice(b"User");
            if case == AuthCase::WrongPassword {
                response[29] ^= 1;
            }
            eap_response = Eap {
                code: 2,
                identifier: e.identifier,
                method: Some(26),
                data: &response,
            }
            .encode()
            .unwrap();
            msk = Some(method_keys);
        } else if round == 3 && case == AuthCase::WrongPassword {
            assert_eq!(e.data[0], 4);
            assert!(e.data[4..].starts_with(b"E=691 R=0 C="));
            eap_response = Eap {
                code: 2,
                identifier: e.identifier,
                method: Some(26),
                data: &[4],
            }
            .encode()
            .unwrap();
        } else if round == 3 {
            assert_eq!(&e.data[4..46], msk.as_ref().unwrap().authenticator.expose());
            eap_response = Eap {
                code: 2,
                identifier: e.identifier,
                method: Some(26),
                data: &[3],
            }
            .encode()
            .unwrap();
        } else if case == AuthCase::WrongPassword {
            assert_eq!(e.code, 4);
            assert_eq!(r.stats().authenticated, 0);
            assert_eq!(r.stats().authentication_failed, 1);
            r.expire(Duration::from_secs(5)).unwrap();
            assert_eq!(r.pending_count(), 0);
            return;
        } else {
            assert_eq!(e.code, 3);
            assert_eq!(r.stats().authenticated, 0);
        }
    }
    // MSK confirmation, never EAP Success alone, authenticates the IKE SA.
    h.message_id = 5;
    let mut idi_body = vec![11, 1, 2, 3];
    idi_body.extend_from_slice(b"User");
    let signed = initiator_signed(&init, &nr, keys.sk_pi.expose(), &idi_body);
    let mut proof = final_auth(msk.as_ref().unwrap().msk.expose(), &signed);
    if matches!(case, AuthCase::BadFinal | AuthCase::ChildBadFinal) {
        proof[0] ^= 1;
    }
    let (first, inner) = auth::encode_chain(
        &[auth_payload(A::Auth {
            method: 2,
            data: &proof,
        })],
        Limits::default(),
    )
    .unwrap();
    let request = protected::seal(
        &mut keys,
        Direction::Initiator,
        h.clone(),
        first,
        &inner,
        Limits::default(),
    )
    .unwrap();
    if case == AuthCase::Timeout {
        r.expire(Duration::from_secs(60)).unwrap();
        assert_eq!(r.pending_count(), 0);
        assert!(
            r.handle(&request, peer_auth, local_auth, Duration::from_secs(60))
                .unwrap()
                .response
                .is_none()
        );
        assert_eq!(r.stats().authenticated, 0);
        return;
    }
    assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 0);
    let response = send(&mut r, &request).response.unwrap();
    assert_eq!(send(&mut r, &request).response.unwrap(), response);
    if matches!(
        case,
        AuthCase::BadFinal | AuthCase::ChildBadFinal | AuthCase::ChildInstallFailure
    ) {
        assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert_eq!(r.stats().authenticated, 0);
        assert_eq!(r.stats().authentication_failed, 1);
        let opened =
            protected::open(&keys, Direction::Responder, &response, Limits::default()).unwrap();
        let p = auth::decode_chain(
            opened.plaintext.expose(),
            opened.first_inner,
            Limits::default(),
        )
        .unwrap();
        assert!(matches!(
            p.as_slice(),
            [auth::Payload {
                body: A::Notify { kind: 24, .. },
                ..
            }]
        ));
        assert!(send(&mut r, &first_request).response.is_none());
        r.expire(Duration::from_secs(5)).unwrap();
        assert_eq!(r.pending_count(), 0);
        return;
    }
    assert_eq!(r.stats().authenticated, 1);
    let opened =
        protected::open(&keys, Direction::Responder, &response, Limits::default()).unwrap();
    let p = auth::decode_chain(
        opened.plaintext.expose(),
        opened.first_inner,
        Limits::default(),
    )
    .unwrap();
    if is_child {
        assert_eq!(p.len(), 5);
        assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 1);
        let A::Config(cp) = p[1].body else {
            panic!("CP missing")
        };
        assert_eq!(&cp[8..12], &[10, 77, 0, 10]);
        assert_eq!(&cp[16..20], &[1, 1, 1, 1]);
        let A::Sa(sa) = p[2].body else {
            panic!("SA missing")
        };
        let proposals = ikev2_wire::decode_sa(sa, Limits::default()).unwrap();
        let inbound_spi = proposals[0].spi.to_vec();
        assert_eq!(proposals[0].protocol, 3);
        assert_eq!(proposals[0].transforms[0].id, 20);
        if case == AuthCase::ChildExpiry {
            r.expire(Duration::from_secs(1800)).unwrap();
            assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 0);
            return;
        }
        h.exchange = 37;
        h.message_id = 6;
        let ping = protected::seal(
            &mut keys,
            Direction::Initiator,
            h.clone(),
            0,
            &[],
            Limits::default(),
        )
        .unwrap();
        let pong = send(&mut r, &ping).response.unwrap();
        assert_eq!(send(&mut r, &ping).response.unwrap(), pong);
        let pong = protected::open(&keys, Direction::Responder, &pong, Limits::default()).unwrap();
        assert!(pong.plaintext.expose().is_empty());
        h.message_id = 7;
        let mut del = vec![3, 4, 0, 1];
        del.extend_from_slice(&0x1007u32.to_be_bytes());
        let (first, inner) = auth::encode_chain(
            &[auth_payload(A::Unknown {
                kind: 42,
                data: &del,
            })],
            Limits::default(),
        )
        .unwrap();
        let del = protected::seal(
            &mut keys,
            Direction::Initiator,
            h.clone(),
            first,
            &inner,
            Limits::default(),
        )
        .unwrap();
        let ack = send(&mut r, &del).response.unwrap();
        assert_eq!(send(&mut r, &del).response.unwrap(), ack);
        assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 0);
        let ack = protected::open(&keys, Direction::Responder, &ack, Limits::default()).unwrap();
        let ack =
            auth::decode_chain(ack.plaintext.expose(), ack.first_inner, Limits::default()).unwrap();
        assert!(matches!(ack[0].body,A::Unknown{kind:42,data} if data[4..]==inbound_spi));
        h.message_id = 8;
        let (first, inner) = auth::encode_chain(
            &[auth_payload(A::Unknown {
                kind: 42,
                data: &[1, 0, 0, 0],
            })],
            Limits::default(),
        )
        .unwrap();
        let del = protected::seal(
            &mut keys,
            Direction::Initiator,
            h,
            first,
            &inner,
            Limits::default(),
        )
        .unwrap();
        let ack = send(&mut r, &del).response.unwrap();
        assert_eq!(send(&mut r, &del).response.unwrap(), ack);
        assert_eq!(r.stats().authentication_failed, 0);
        r.expire(Duration::from_secs(5)).unwrap();
        assert_eq!(r.pending_count(), 0);
        return;
    }
    assert_eq!(p.len(), 2);
    assert!(matches!(p[1].body, A::Notify { kind: 14, .. }));
    let expected = final_auth(
        msk.as_ref().unwrap().msk.expose(),
        &initiator_signed(&initial_response, &ni, keys.sk_pr.expose(), &idr_body),
    );
    assert!(matches!(p[0].body,A::Auth{method:2,data} if data==expected));
    assert!(send(&mut r, &first_request).response.is_none());
    r.expire(Duration::from_secs(60)).unwrap();
    assert_eq!(r.pending_count(), 0);
}
