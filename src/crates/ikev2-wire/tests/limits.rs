use ikev2_wire::*;
fn header() -> Header {
    Header {
        initiator_spi: 1,
        responder_spi: 0,
        version: 0x20,
        exchange: 34,
        flags: 8,
        message_id: 0,
    }
}
fn message(body: Body<'_>) -> Message<'_> {
    Message {
        header: header(),
        payloads: vec![Payload {
            offset: 28,
            critical: false,
            body,
        }],
    }
}
fn sa(proposals: usize, transforms: usize, attributes: usize) -> Body<'static> {
    Body::Sa(
        (1..=proposals)
            .map(|n| Proposal {
                number: n as u8,
                protocol: 1,
                spi: &[],
                transforms: (0..transforms)
                    .map(|_| Transform {
                        kind: 250,
                        id: 65000,
                        attributes: (1..=attributes)
                            .map(|n| Attribute::Tv {
                                kind: n as u16,
                                value: 128,
                            })
                            .collect(),
                    })
                    .collect(),
            })
            .collect(),
    )
}
#[test]
fn every_policy_field_has_a_hard_ceiling_and_lower_bound() {
    for field in 0..5 {
        for value in [0, usize::MAX] {
            let mut l = Limits::default();
            match field {
                0 => l.message_bytes = value,
                1 => l.payloads = value,
                2 => l.proposals = value,
                3 => l.transforms = value,
                _ => l.attributes = value,
            }
            assert_eq!(l.validate().unwrap_err().kind, ErrorKind::InvalidLimits);
            assert!(decode(&[], l).is_err());
            assert!(raw::decode(&[], l).is_err());
            assert!(decode_sa(&[], l).is_err());
            assert!(encode(&message(Body::VendorId(&[])), l).is_err());
        }
    }
    assert!(
        Limits {
            message_bytes: 28,
            payloads: 1,
            proposals: 1,
            transforms: 1,
            attributes: 1
        }
        .validate()
        .is_ok()
    );
    assert!(Limits::HARD.validate().is_ok());
}
#[test]
fn message_size_at_ceiling_and_beyond() {
    let data = vec![0; 65_503];
    let b = encode(&message(Body::VendorId(&data)), Limits::HARD).unwrap();
    assert_eq!(b.len(), 65_535);
    assert!(decode(&b, Limits::HARD).is_ok());
    let mut too_large = b.clone();
    too_large.push(0);
    assert!(matches!(
        decode(&too_large, Limits::HARD).err().unwrap().kind,
        ErrorKind::Limit(_)
    ));
    let small = Limits {
        message_bytes: 65_534,
        ..Limits::HARD
    };
    assert!(encode(&message(Body::VendorId(&data)), small).is_err());
    assert!(decode(&b, small).is_err());
}
#[test]
fn each_element_limit_accepts_boundary_and_rejects_one_more() {
    for field in 0..4 {
        let max = if field == 0 { 128 } else { 64 };
        for count in [max, max + 1] {
            let mut m = message(Body::VendorId(&[]));
            match field {
                0 => {
                    m.payloads = vec![
                        Payload {
                            offset: 0,
                            critical: false,
                            body: Body::VendorId(&[])
                        };
                        count
                    ]
                }
                1 => m.payloads[0].body = sa(count, 1, 0),
                2 => m.payloads[0].body = sa(1, count, 0),
                _ => m.payloads[0].body = sa(1, 1, count),
            }
            assert_eq!(encode(&m, Limits::HARD).is_ok(), count == max);
        }
        // Lowered policy is exercised on both decode and encode, at and above it.
        let mut l = Limits::HARD;
        match field {
            0 => l.payloads = 2,
            1 => l.proposals = 2,
            2 => l.transforms = 2,
            _ => l.attributes = 2,
        }
        for count in [2, 3] {
            let mut m = message(Body::VendorId(&[]));
            match field {
                0 => {
                    m.payloads = vec![
                        Payload {
                            offset: 0,
                            critical: false,
                            body: Body::VendorId(&[])
                        };
                        count
                    ]
                }
                1 => m.payloads[0].body = sa(count, 1, 0),
                2 => m.payloads[0].body = sa(1, count, 0),
                _ => m.payloads[0].body = sa(1, 1, count),
            }
            let bytes = encode(&m, Limits::HARD).unwrap();
            assert_eq!(decode(&bytes, l).is_ok(), count == 2);
            assert_eq!(encode(&m, l).is_ok(), count == 2);
        }
    }
}
#[test]
fn invalid_sa_models_are_rejected() {
    for body in [sa(0, 0, 0), sa(1, 0, 0)] {
        assert!(encode(&message(body), Limits::default()).is_err());
    }
    let cases = vec![
        Proposal {
            number: 1,
            protocol: 3,
            spi: &[],
            transforms: vec![Transform {
                kind: 1,
                id: 20,
                attributes: vec![],
            }],
        },
        Proposal {
            number: 0,
            protocol: 1,
            spi: &[],
            transforms: vec![Transform {
                kind: 1,
                id: 20,
                attributes: vec![],
            }],
        },
        Proposal {
            number: 1,
            protocol: 1,
            spi: &[],
            transforms: vec![Transform {
                kind: 1,
                id: 20,
                attributes: vec![
                    Attribute::Tv {
                        kind: 14,
                        value: 128,
                    },
                    Attribute::Tv {
                        kind: 14,
                        value: 256,
                    },
                ],
            }],
        },
        Proposal {
            number: 1,
            protocol: 1,
            spi: &[],
            transforms: vec![Transform {
                kind: 1,
                id: 20,
                attributes: vec![Attribute::Tv {
                    kind: 0xffff,
                    value: 128,
                }],
            }],
        },
    ];
    for p in cases {
        assert!(encode(&message(Body::Sa(vec![p])), Limits::default()).is_err());
    }
}
