use ikev2_wire::*;
use proptest::prelude::*;

fn hex(text: &str) -> Vec<u8> {
    let s: String = text.split_whitespace().collect();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}
fn golden() -> Vec<u8> {
    hex(include_str!("fixtures/sa-init.hex"))
}
fn header() -> Header {
    Header {
        initiator_spi: 0x0102030405060708,
        responder_spi: 0,
        version: 0x20,
        exchange: 34,
        flags: 8,
        message_id: 0,
    }
}
fn expected<'a>() -> Message<'a> {
    Message {
        header: header(),
        payloads: vec![
            Payload {
                offset: 28,
                critical: false,
                body: Body::Sa(vec![Proposal {
                    number: 1,
                    protocol: 1,
                    spi: &[],
                    transforms: vec![
                        Transform {
                            kind: 1,
                            id: 20,
                            attributes: vec![Attribute::Tv {
                                kind: 14,
                                value: 128,
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
                }]),
            },
            Payload {
                offset: 68,
                critical: false,
                body: Body::KeyExchange {
                    group: 19,
                    data: &[0xde, 0xad, 0xbe, 0xef],
                },
            },
            Payload {
                offset: 80,
                critical: false,
                body: Body::Nonce(&[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]),
            },
        ],
    }
}
fn packet(kind: u8, body: &[u8], critical: bool) -> Vec<u8> {
    let mut b = hex("0102030405060708 0000000000000000 00 20 22 08 00000000 00000000");
    b[16] = kind;
    b.extend_from_slice(&[0, if critical { 0x80 } else { 0 }]);
    b.extend_from_slice(&u16::try_from(body.len() + 4).unwrap().to_be_bytes());
    b.extend_from_slice(body);
    let n = b.len() as u32;
    b[24..28].copy_from_slice(&n.to_be_bytes());
    b
}
fn malformed(bytes: &[u8]) {
    assert!(matches!(
        decode(bytes, Limits::default()),
        Err(Error {
            kind: ErrorKind::Malformed(_),
            ..
        })
    ));
}

#[test]
fn independent_golden_decode_and_encode() {
    let b = golden();
    let m = decode(&b, Limits::default()).unwrap();
    assert!(m == expected());
    assert_eq!(encode(&expected(), Limits::default()).unwrap(), b);
    check_support(&m).unwrap();
}
#[test]
fn notify_vendor_golden_fields_and_bytes() {
    let b = hex(include_str!("fixtures/notify-vendor.hex"));
    let mut h = header();
    h.responder_spi = 0x1112131415161718;
    h.exchange = 37;
    h.flags = 32;
    h.message_id = 0x01020304;
    let expected = Message {
        header: h,
        payloads: vec![
            Payload {
                offset: 28,
                critical: false,
                body: Body::Notify {
                    protocol: 0,
                    spi: &[],
                    kind: 65000,
                    data: &[1, 2, 3, 4],
                },
            },
            Payload {
                offset: 40,
                critical: false,
                body: Body::VendorId(b"vend"),
            },
        ],
    };
    assert!(decode(&b, Limits::default()).unwrap() == expected);
    assert_eq!(encode(&expected, Limits::default()).unwrap(), b);
}
#[test]
fn encrypted_next_is_inner_and_unsupported() {
    let b = hex(include_str!("fixtures/encrypted.hex"));
    let m = decode(&b, Limits::default()).unwrap();
    assert_eq!(m.payloads.len(), 1);
    assert!(matches!(
        m.payloads[0].body,
        Body::Encrypted {
            first_inner: 35,
            ..
        }
    ));
    assert!(matches!(
        check_support(&m),
        Err(Error {
            kind: ErrorKind::Unsupported(_),
            ..
        })
    ));
    assert_eq!(encode(&m, Limits::default()).unwrap(), b);
    let mut bad = b.clone();
    bad.extend_from_slice(&[0; 4]);
    let n = bad.len() as u32;
    bad[24..28].copy_from_slice(&n.to_be_bytes());
    malformed(&bad);
}
#[test]
fn truncation_at_every_byte() {
    for text in [
        include_str!("fixtures/sa-init.hex"),
        include_str!("fixtures/notify-vendor.hex"),
        include_str!("fixtures/encrypted.hex"),
    ] {
        let b = hex(text);
        for end in 0..b.len() {
            malformed(&b[..end]);
        }
    }
}
#[test]
fn malformed_envelopes_and_nested_fields() {
    for (at, value) in [
        (24, 1),
        (27, 99),
        (30, 0xff),
        (31, 3), // message/payload lengths
        (32, 2),
        (34, 0xff),
        (35, 7),
        (36, 0),
        (38, 4),
        (39, 2), // proposal
        (40, 0),
        (42, 0xff),
        (43, 7),
        (48, 0),
    ] {
        // transform/TLV
        let mut b = golden();
        b[at] = value;
        malformed(&b);
    }
    let mut b = golden();
    b[80] = 43;
    malformed(&b); // dangling next
    let mut b = golden();
    b[16] = 0;
    malformed(&b); // chain absent but body present
    for kind in [33, 34, 41] {
        malformed(&packet(kind, &[], false));
    }
    malformed(&packet(41, &[3, 4, 0, 1, 1], false)); // SPI overrun
}
#[test]
fn unknown_payloads_versions_and_algorithms_are_not_malformed() {
    for critical in [false, true] {
        let b = packet(250, &[1, 2, 3], critical);
        let m = decode(&b, Limits::default()).unwrap();
        assert_eq!(check_support(&m).is_err(), critical);
        assert_eq!(encode(&m, Limits::default()).unwrap(), b);
    }
    for (at, value, supported) in [(17, 0x21, true), (17, 0x30, false), (18, 250, false)] {
        let mut b = golden();
        b[at] = value;
        let m = decode(&b, Limits::default()).unwrap();
        assert_eq!(check_support(&m).is_ok(), supported);
    }
    let mut b = golden();
    b[44] = 250;
    b[46] = 255;
    b[47] = 255;
    assert!(decode(&b, Limits::default()).is_ok()); // no negotiation policy
    let b = packet(49, &[0, 1, 0, 1, 2, 3], false);
    assert!(check_support(&decode(&b, Limits::default()).unwrap()).is_err());
}
#[test]
fn raw_decode_is_separate_from_body_validation() {
    let b = packet(40, &[0; 2], false);
    assert!(raw::decode(&b, Limits::default()).is_ok());
    malformed(&b);
    // State checks are deliberately absent: SPI zero, ID nonzero still decode.
    let mut b = golden();
    b[..16].fill(0);
    b[23] = 99;
    assert!(decode(&b, Limits::default()).is_ok());
}
#[test]
fn nonce_boundaries_and_tlv() {
    for size in [0, 15, 16, 256, 257] {
        let b = packet(40, &vec![0; size], false);
        assert_eq!(
            decode(&b, Limits::default()).is_ok(),
            (16..=256).contains(&size)
        );
    }
    let body = hex("00000016 01010001 0000000e 01000014 000f0002 abcd");
    let b = packet(33, &body, false);
    let m = decode(&b, Limits::default()).unwrap();
    assert_eq!(encode(&m, Limits::default()).unwrap(), b);
    let mut bad = body.clone();
    bad[16] = 0;
    bad[17] = 14; // Key Length TLV forbidden
    malformed(&packet(33, &bad, false));
}
#[test]
fn reserved_bits_are_ignored_and_normalized() {
    let mut b = golden();
    for at in [19, 29, 33, 41, 45, 53, 57, 61, 65, 74, 75] {
        b[at] |= if at == 19 { 0xc7 } else { 0x7f };
    }
    // Critical on an understood RFC payload is ignored by support checking.
    b[29] |= 0x80;
    let m = decode(&b, Limits::default()).unwrap();
    check_support(&m).unwrap();
    assert_eq!(encode(&m, Limits::default()).unwrap(), golden());
}
#[test]
fn empty_message_and_structural_response_proposal_number() {
    let b = hex("0102030405060708 1112131415161718 00 20 25 20 00000002 0000001c");
    let m = decode(&b, Limits::default()).unwrap();
    assert_eq!(m.header.message_id, 2);
    assert!(m.payloads.is_empty());
    assert_eq!(encode(&m, Limits::default()).unwrap(), b);
    let mut b = golden();
    b[36] = 7;
    assert!(decode(&b, Limits::default()).is_ok()); // accepted response number needs request context
}
#[test]
fn serializer_rejects_invalid_models_and_small_output() {
    let mut m = expected();
    m.payloads[2].body = Body::Nonce(&[0; 15]);
    assert!(encode(&m, Limits::default()).is_err());
    let mut m = expected();
    m.payloads.push(Payload {
        offset: 0,
        critical: false,
        body: Body::Opaque {
            kind: 0,
            next_inner: 0,
            data: &[],
        },
    });
    assert!(encode(&m, Limits::default()).is_err());
    let mut m = expected();
    m.payloads[0].body = Body::Opaque {
        kind: 33,
        next_inner: 0,
        data: &[],
    };
    assert!(encode(&m, Limits::default()).is_err());
    let mut m = expected();
    m.payloads[0].body = Body::Encrypted {
        first_inner: 35,
        data: &[],
    };
    assert!(encode(&m, Limits::default()).is_err());
    assert!(
        encode(
            &expected(),
            Limits {
                message_bytes: 99,
                ..Limits::default()
            }
        )
        .is_err()
    );
    let data = vec![0; 65_532];
    let m = Message {
        header: header(),
        payloads: vec![Payload {
            offset: 0,
            critical: false,
            body: Body::VendorId(&data),
        }],
    };
    assert!(matches!(
        encode(&m, Limits::default()),
        Err(Error {
            kind: ErrorKind::Limit(_),
            ..
        })
    ));
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]
    #[test]
    fn arbitrary_input_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..4096)) {
        let _ = raw::decode(&bytes, Limits::default());
        let _ = decode_sa(&bytes, Limits::default());
        if let Ok(m) = decode(&bytes, Limits::default()) {
            let out = encode(&m, Limits::default()).unwrap();
            let again = decode(&out, Limits::default()).unwrap();
            prop_assert_eq!(encode(&again, Limits::default()).unwrap(), out);
        }
    }
    #[test]
    fn generated_typed_messages_round_trip(spi in any::<u64>(), id in any::<u32>(),
        data in prop::collection::vec(any::<u8>(),16..257), vendor in prop::collection::vec(any::<u8>(),0..256)) {
        let mut h = header(); h.initiator_spi=spi; h.message_id=id;
        let m = Message {header:h,payloads:vec![Payload {offset:28,critical:false,body:Body::Nonce(&data)},
            Payload {offset:32+data.len(),critical:false,body:Body::VendorId(&vendor)}]};
        let bytes = encode(&m, Limits::default()).unwrap();
        prop_assert!(decode(&bytes, Limits::default()).unwrap() == m);
        prop_assert!(bytes.len() <= Limits::HARD.message_bytes);
    }
}

#[test]
fn multiple_proposals_and_malformed_numbering() {
    let body = hex(include_str!("fixtures/multiple-proposals.hex"));
    let proposals = decode_sa(&body, Limits::default()).unwrap();
    assert_eq!(proposals.len(), 2);
    assert_eq!(proposals[1].number, 2);
    assert_eq!(proposals[1].transforms[0].id, 65001);
    let expected = Message {
        header: header(),
        payloads: vec![Payload {
            offset: 28,
            critical: false,
            body: Body::Sa(proposals),
        }],
    };
    assert_eq!(
        encode(&expected, Limits::default()).unwrap(),
        packet(33, &body, false)
    );
    for (at, value) in [(0, 0), (16, 2), (20, 3), (23, 0)] {
        let mut bad = body.clone();
        bad[at] = value;
        assert!(matches!(
            decode_sa(&bad, Limits::default()),
            Err(Error {
                kind: ErrorKind::Malformed(_),
                ..
            })
        ));
    }
}
#[test]
fn unknown_noncritical_payload_continues_chain_and_opaque_coverage_is_explicit() {
    let mut b = packet(250, &[1, 2, 3], false);
    b[28] = 43;
    b.extend_from_slice(&[0, 0, 0, 8, 1, 2, 3, 4]);
    let n = b.len() as u32;
    b[24..28].copy_from_slice(&n.to_be_bytes());
    let m = decode(&b, Limits::default()).unwrap();
    assert_eq!(m.payloads.len(), 2);
    check_support(&m).unwrap();
    assert_eq!(encode(&m, Limits::default()).unwrap(), b);
    let b = packet(35, &[0; 4], false);
    assert!(matches!(
        check_support(&decode(&b, Limits::default()).unwrap()),
        Err(Error {
            kind: ErrorKind::Unsupported(_),
            ..
        })
    ));
}
#[test]
fn valid_spi_sizes_unknown_protocol_and_notify_spi() {
    for (protocol, spi) in [
        (1, vec![]),
        (1, vec![1; 8]),
        (2, vec![1; 4]),
        (3, vec![1; 4]),
        (250, vec![1; 3]),
    ] {
        let m = Message {
            header: header(),
            payloads: vec![Payload {
                offset: 28,
                critical: false,
                body: Body::Sa(vec![Proposal {
                    number: 7,
                    protocol,
                    spi: &spi,
                    transforms: vec![Transform {
                        kind: 250,
                        id: 65535,
                        attributes: vec![],
                    }],
                }]),
            }],
        };
        let b = encode(&m, Limits::default()).unwrap();
        assert!(decode(&b, Limits::default()).unwrap() == m);
    }
    let body = hex("03 04 fde8 01020304 aabb");
    let b = packet(41, &body, false);
    let m = decode(&b, Limits::default()).unwrap();
    assert!(matches!(
        m.payloads[0].body,
        Body::Notify {
            protocol: 3,
            spi: &[1, 2, 3, 4],
            kind: 65000,
            data: &[0xaa, 0xbb]
        }
    ));
    assert_eq!(encode(&m, Limits::default()).unwrap(), b);
}
#[test]
fn duplicate_attributes_and_adjusted_length_truncations() {
    let body = hex("0000001c 01010001 00000014 01000014 800e0080 800e0100 800f0001");
    malformed(&packet(33, &body, false));
    let b = golden();
    // Keep outer length correct: exercise nested checks at every partial body.
    for end in 29..b.len() {
        let mut bad = b[..end].to_vec();
        bad[24..28].copy_from_slice(&(end as u32).to_be_bytes());
        malformed(&bad);
    }
}
