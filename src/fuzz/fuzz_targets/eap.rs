#![no_main]
use ikev2_crypto::{SecretBytes, mschap::MschapProvider};
use ikev2_wire::auth::Eap;
use libfuzzer_sys::fuzz_target;
use std::time::Duration;
fuzz_target!(|bytes: &[u8]| {
    let _ = Eap::decode(bytes);
    if bytes.len() > 4096 {
        return;
    }
    // Synthetic fixed verifier only. No real credentials or password inputs.
    let master = SecretBytes::new(vec![9; 32]);
    let hash = SecretBytes::new(vec![1; 16]);
    let user = vpn_auth::encrypt_user(&master, b"User", true, &hash).unwrap();
    let file = vpn_auth::encode_file(&[user]).unwrap();
    let mut store = vpn_auth::AuthStore::from_encrypted(&file, master).unwrap();
    let mut session = vpn_auth::EapSession::new().unwrap();
    let _ = session.step(bytes, &mut store, Duration::ZERO);
    assert!(session.take_msk().is_err());
    // Drive actual challenge/response processing with both valid and mutated responses.
    let mut session = vpn_auth::EapSession::new().unwrap();
    let identity = session.start().unwrap();
    let e = Eap::decode(&identity).unwrap();
    let id = Eap {
        code: 2,
        identifier: e.identifier,
        method: Some(1),
        data: b"User",
    }
    .encode()
    .unwrap();
    let challenge = session.step(&id, &mut store, Duration::ZERO).unwrap();
    let c = Eap::decode(&challenge).unwrap();
    let auth = c.data[5..21].try_into().unwrap();
    let peer = [2; 16];
    let provider = MschapProvider::new().unwrap();
    let nt = provider
        .nt_response(hash.expose(), auth, &peer, b"User")
        .unwrap();
    let mut method = vec![2, c.data[1], 0, 58, 49];
    method.extend_from_slice(&peer);
    method.extend_from_slice(&[0; 8]);
    method.extend_from_slice(nt.expose());
    method.push(0);
    method.extend_from_slice(b"User");
    if bytes.len() >= 2 {
        let pos = usize::from(bytes[0]) % method.len();
        method[pos] ^= bytes[1];
    }
    let response = Eap {
        code: 2,
        identifier: c.identifier,
        method: Some(26),
        data: &method,
    }
    .encode()
    .unwrap();
    let answer = session.step(&response, &mut store, Duration::ZERO).unwrap();
    let a = Eap::decode(&answer).unwrap();
    assert!(session.take_msk().is_err());
    let confirmation = Eap {
        code: 2,
        identifier: a.identifier,
        method: Some(26),
        data: &[3],
    }
    .encode()
    .unwrap();
    let _ = session.step(&confirmation, &mut store, Duration::ZERO);
    // No IKE SA authentication is performed by this EAP-only harness.
});
