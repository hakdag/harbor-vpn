#![no_main]
use ikev2_wire::*;
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    if data.len() < 16 {
        return;
    }
    let attrs = data[16..]
        .chunks(4)
        .take(65)
        .map(|b| {
            if b.len() == 4 {
                Attribute::Tv {
                    kind: u16::from_be_bytes([b[0], b[1]]) & 0x7fff,
                    value: u16::from_be_bytes([b[2], b[3]]),
                }
            } else {
                Attribute::Tlv { kind: 15, value: b }
            }
        })
        .collect();
    let body = match data[0] % 7 {
        0 => Body::Nonce(&data[16..]),
        1 => Body::VendorId(&data[16..]),
        2 => Body::KeyExchange {
            group: u16::from_be_bytes([data[1], data[2]]),
            data: &data[16..],
        },
        3 => Body::Notify {
            protocol: data[1],
            spi: &data[8..16],
            kind: u16::from_be_bytes([data[2], data[3]]),
            data: &data[16..],
        },
        4 => Body::Sa(vec![Proposal {
            number: data[1],
            protocol: data[2],
            spi: &[],
            transforms: vec![Transform {
                kind: data[3],
                id: u16::from_be_bytes([data[4], data[5]]),
                attributes: attrs,
            }],
        }]),
        5 => Body::Encrypted {
            first_inner: data[1],
            data: &data[16..],
        },
        _ => Body::Opaque {
            kind: data[1],
            next_inner: 0,
            data: &data[16..],
        },
    };
    let m = Message {
        header: Header {
            initiator_spi: u64::from_be_bytes(data[0..8].try_into().unwrap()),
            responder_spi: 0,
            version: data[6],
            exchange: data[7],
            flags: data[8],
            message_id: u32::from_be_bytes(data[9..13].try_into().unwrap()),
        },
        payloads: vec![Payload {
            offset: 0,
            critical: data[13] & 1 != 0,
            body,
        }],
    };
    let limits = Limits {
        message_bytes: 28 + usize::from(data[14]) * 257,
        payloads: 1,
        proposals: 1,
        transforms: 1,
        attributes: 1 + usize::from(data[15] % 64),
    };
    if let Ok(encoded) = encode(&m, limits) {
        assert!(encoded.len() <= limits.message_bytes);
        let again = decode(&encoded, limits).unwrap();
        assert_eq!(encode(&again, limits).unwrap(), encoded);
    }
});
