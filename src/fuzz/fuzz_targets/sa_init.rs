#![no_main]
use ikev2_core::{Event, Policy, Responder};
use ikev2_crypto::OpenSslProvider;
use ikev2_wire::Limits;
use libfuzzer_sys::fuzz_target;
use std::time::Duration;
fn exercise(bytes: &[u8]) {
    let policy = Policy {
        max_pending: 2,
        per_source: 2,
        cookie_threshold: 1,
        lifetime_secs: 1,
        max_request_bytes: 1024,
        max_response_bytes: 512,
        ..Policy::default()
    };
    let mut r = Responder::new(OpenSslProvider::new().unwrap(), policy, Limits::default()).unwrap();
    let peer = "198.51.100.10:500".parse().unwrap();
    let local = "192.0.2.1:500".parse().unwrap();
    if let Ok(out) = r.handle(bytes, peer, local, Duration::ZERO) {
        assert!(out.offers.len() <= 4);
        assert!(out.offers.iter().all(|p| p.transforms.len() <= 8));
        if let Some(reply) = &out.response {
            assert!(reply.len() <= 512);
            let m = ikev2_wire::decode(reply, Limits::default()).unwrap();
            assert_eq!(m.header.flags, 32);
        }
        if out.event == Event::PendingCreated {
            let again = r.handle(bytes, peer, local, Duration::ZERO).unwrap();
            assert_eq!(again.event, Event::Retransmit);
            assert_eq!(out.response, again.response);
            // A second SPI crosses the cookie threshold. Echo the challenge
            // through the wire codec, then exercise the bounded second state.
            let mut second = bytes.to_vec();
            let spi = u64::from_be_bytes(second[..8].try_into().unwrap());
            second[..8].copy_from_slice(&spi.wrapping_add(1).max(1).to_be_bytes());
            let challenge = r.handle(&second, peer, local, Duration::ZERO).unwrap();
            assert_eq!(challenge.event, Event::CookieChallenge);
            let challenge_bytes = challenge.response.unwrap();
            let challenge_message =
                ikev2_wire::decode(&challenge_bytes, Limits::default()).unwrap();
            let mut retry = ikev2_wire::decode(&second, Limits::default()).unwrap();
            retry
                .payloads
                .insert(0, challenge_message.payloads[0].clone());
            if let Ok(retry) = ikev2_wire::encode(&retry, Limits::default()) {
                let result = r.handle(&retry, peer, local, Duration::ZERO).unwrap();
                if retry.len() <= policy.max_request_bytes {
                    assert_eq!(result.event, Event::PendingCreated);
                    assert_eq!(r.pending_count(), 2);
                }
            }
        }
    }
    assert!(r.pending_count() <= 2);
    r.expire(Duration::from_secs(2)).unwrap();
    assert_eq!(r.pending_count(), 0);
}
fuzz_target!(|bytes: &[u8]| {
    exercise(bytes);
    // Any packet, including malformed inputs and cache duplicates, consumes admission.
    let policy = Policy {
        work_burst: 1,
        source_work_burst: 1,
        work_per_second: 1,
        source_work_per_second: 1,
        ..Policy::default()
    };
    let mut limited =
        Responder::new(OpenSslProvider::new().unwrap(), policy, Limits::default()).unwrap();
    let peer = "198.51.100.10:500".parse().unwrap();
    let local = "192.0.2.1:500".parse().unwrap();
    let _ = limited.handle(bytes, peer, local, Duration::ZERO).unwrap();
    let denied = limited.handle(bytes, peer, local, Duration::ZERO).unwrap();
    assert_eq!(denied.event, Event::RateLimited);
    assert!(denied.response.is_none());
    assert!(denied.offers.is_empty());
    limited.expire(Duration::from_secs(60)).unwrap();
    assert_eq!(limited.pending_count(), 0);
    if (28..=1024).contains(&bytes.len()) {
        let mut fixed = bytes.to_vec();
        fixed[24..28].copy_from_slice(&(bytes.len() as u32).to_be_bytes());
        exercise(&fixed);
    }
    for channel in [
        ikev2_transport::Channel::Ike,
        ikev2_transport::Channel::NatT,
    ] {
        if let Ok(ikev2_transport::Datagram::Ike(body)) =
            ikev2_transport::decode(channel, bytes, 1024)
        {
            exercise(body);
        }
    }
});
