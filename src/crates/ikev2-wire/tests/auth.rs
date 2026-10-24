use ikev2_wire::{Limits, auth::*};
#[test]
fn independent_identity_auth_eap_goldens_and_truncations() {
    // Hand-composed RFC generic payload, IDr and EAP Request/Identity headers.
    let bytes = [
        48, 0, 0, 23, 2, 0, 0, 0, b'v', b'p', b'n', b'.', b'e', b'x', b'a', b'm', b'p', b'l', b'e',
        b'.', b'o', b'r', b'g', 0, 0, 0, 9, 1, 7, 0, 5, 1,
    ];
    let p = decode_chain(&bytes, 36, Limits::default()).unwrap();
    assert_eq!(p.len(), 2);
    assert!(matches!(
        p[0].body,
        Body::Idr(Identity {
            kind: 2,
            reserved: _,
            data: b"vpn.example.org"
        })
    ));
    let (_, encoded) = encode_chain(&p, Limits::default()).unwrap();
    assert_eq!(encoded, bytes);
    for n in 0..bytes.len() {
        assert!(decode_chain(&bytes[..n], 36, Limits::default()).is_err());
    }
    for bad in [&[1, 0, 0, 4][..], &[3, 0, 0, 5, 26][..], &[0, 0, 0, 4][..]] {
        assert!(Eap::decode(bad).is_err());
    }
}
#[test]
fn unknown_critical_and_known_critical_behavior() {
    let id = [0, 128, 0, 9, 11, 0, 0, 0, b'u'];
    let p = decode_chain(&id, 35, Limits::default()).unwrap();
    check_critical(&p).unwrap();
    let unknown = [0, 128, 0, 4];
    let p = decode_chain(&unknown, 250, Limits::default()).unwrap();
    assert!(check_critical(&p).is_err());
    let nested = [0, 0, 0, 4];
    assert!(decode_chain(&nested, 46, Limits::default()).is_err());
}
#[test]
fn bounded_envelopes_and_serializers() {
    for kind in [35, 36, 39, 44, 45, 47, 48] {
        for n in 0..4 {
            let mut v = vec![0, 0, 0, (4 + n) as u8];
            v.extend(vec![0; n]);
            assert!(decode_chain(&v, kind, Limits::default()).is_err());
        }
    }
    let p = Payload {
        critical: false,
        body: Body::Unknown {
            kind: 250,
            data: &[0; 100],
        },
    };
    assert!(
        encode_chain(
            &[p],
            Limits {
                message_bytes: 50,
                ..Limits::default()
            }
        )
        .is_err()
    );
}
