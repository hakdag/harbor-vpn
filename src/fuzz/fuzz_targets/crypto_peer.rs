#![no_main]
use ikev2_crypto::*;
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    if validate_p256(data).is_ok() {
        let mut provider = OpenSslProvider::new().unwrap();
        let key = provider.generate_p256().unwrap();
        assert_eq!(key.shared_secret(data).unwrap().expose().len(), 32);
    }
    if data.len() > 4096 {
        return;
    }
    // Public, fixed synthetic shared material belongs only to this fuzz harness.
    let mut provider = OpenSslProvider::new().unwrap();
    let mut keys = derive_keys(&mut provider, &[1; 32], &[2; 32], &[3; 32], 1, 2).unwrap();
    let aad = &data[..data.len().min(32)];
    let sealed = keys.initiator.seal(aad, data).unwrap();
    assert!(constant_time_eq(
        keys.initiator.open(aad, &sealed).unwrap().expose(),
        data
    ));
    let mut changed = sealed.clone();
    changed.tag[0] ^= 1;
    assert!(keys.initiator.open(aad, &changed).is_err());
    if data.len() >= 24 {
        let invalid = Sealed {
            iv: data[..8].try_into().unwrap(),
            tag: data[8..24].try_into().unwrap(),
            ciphertext: data[24..].to_vec(),
        };
        let _ = keys.responder.open(aad, &invalid);
    }
});
