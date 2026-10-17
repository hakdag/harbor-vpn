#![no_main]
use ikev2_wire::*;
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    if let Ok(proposals) = decode_sa(data, Limits::default()) {
        let message = Message {
            header: Header {
                initiator_spi: 1,
                responder_spi: 0,
                version: 0x20,
                exchange: 34,
                flags: 8,
                message_id: 0,
            },
            payloads: vec![Payload {
                offset: 28,
                critical: false,
                body: Body::Sa(proposals),
            }],
        };
        // A standalone body can be too large once the envelope is added.
        if let Ok(encoded) = encode(&message, Limits::default()) {
            let again = decode(&encoded, Limits::default()).unwrap();
            assert_eq!(encode(&again, Limits::default()).unwrap(), encoded);
        }
    }
});
