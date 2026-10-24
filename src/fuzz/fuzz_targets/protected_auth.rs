#![no_main]
use ikev2_crypto::{
    OpenSslProvider, derive_keys,
    protected::{self, Direction},
};
use ikev2_wire::{Header, Limits, auth};
use libfuzzer_sys::fuzz_target;
fuzz_target!(|bytes: &[u8]| {
    let mut provider = OpenSslProvider::new().unwrap();
    let mut keys = derive_keys(&mut provider, &[1; 32], &[2; 32], &[3; 32], 1, 2).unwrap();
    let limits = Limits::default();
    // Raw ciphertext boundary: no inner decode until tag verification succeeds.
    if let Ok(opened) = protected::open(&keys, Direction::Initiator, bytes, limits) {
        let _ = auth::decode_chain(opened.plaintext.expose(), opened.first_inner, limits);
    }
    if bytes.len() < 16300 {
        let first = bytes.first().copied().unwrap_or(0);
        let inner = bytes.get(1..).unwrap_or(&[]);
        let wire = protected::seal(
            &mut keys,
            Direction::Initiator,
            Header {
                initiator_spi: 1,
                responder_spi: 2,
                version: 0x20,
                exchange: 35,
                flags: 8,
                message_id: 1,
            },
            first,
            inner,
            limits,
        )
        .unwrap();
        let opened = protected::open(&keys, Direction::Initiator, &wire, limits).unwrap();
        assert_eq!(opened.plaintext.expose(), inner);
        if let Ok(payloads) = auth::decode_chain(inner, first, limits) {
            let _ = auth::check_critical(&payloads);
            let _ = auth::encode_chain(&payloads, limits);
        }
        let mut tampered = wire.clone();
        if let Some(last) = tampered.last_mut() {
            *last ^= 1;
        }
        assert!(protected::open(&keys, Direction::Initiator, &tampered, limits).is_err());
    }
});
