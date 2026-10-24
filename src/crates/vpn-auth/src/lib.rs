//! File-backed Phase 1 challenge-response verification. No plaintext password API.
pub mod credentials;
mod eap;
mod store;
pub use eap::{EapSession, EapState};
pub use ikev2_crypto::Error;
pub use store::{AuthStore, EncryptedUser, encode_file, encrypt_user};
pub fn valid_username(name: &[u8]) -> bool {
    !name.is_empty() && name.len() <= 128 && name.iter().all(|b| (33..=126).contains(b))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ikev2_crypto::{SecretBytes, mschap::MschapProvider};
    use ikev2_wire::auth::Eap;
    use std::time::Duration;
    fn hash() -> SecretBytes {
        MschapProvider::new()
            .unwrap()
            .nt_hash("clientPass")
            .unwrap()
    }
    fn fixture(enabled: bool) -> (Vec<u8>, SecretBytes) {
        let master = SecretBytes::new(vec![9; 32]);
        let record = encrypt_user(&master, b"User", enabled, &hash()).unwrap();
        (encode_file(&[record]).unwrap(), master)
    }
    fn eap(code: u8, id: u8, method: Option<u8>, data: &[u8]) -> Vec<u8> {
        Eap {
            code,
            identifier: id,
            method,
            data,
        }
        .encode()
        .unwrap()
    }
    #[test]
    fn encrypted_store_rejects_tamper_truncation_wrong_keys_and_bad_records() {
        let (file, _) = fixture(true);
        for n in 0..file.len() {
            assert!(AuthStore::from_encrypted(&file[..n], SecretBytes::new(vec![9; 32])).is_err());
        }
        for i in 7..file.len() {
            let mut bytes = file.clone();
            bytes[i] ^= 1;
            assert!(AuthStore::from_encrypted(&bytes, SecretBytes::new(vec![9; 32])).is_err());
        }
        assert!(AuthStore::from_encrypted(&file, SecretBytes::new(vec![0; 32])).is_err());
        let (mut f, _) = fixture(true);
        f.push(0);
        assert!(AuthStore::from_encrypted(&f, SecretBytes::new(vec![9; 32])).is_err());
    }
    #[test]
    fn multiround_eap_verifies_mutual_response_and_releases_msk_only_after_ack() {
        let (file, key) = fixture(true);
        let mut store = AuthStore::from_encrypted(&file, key).unwrap();
        let mut session = EapSession::new().unwrap();
        assert!(session.take_msk().is_err());
        let start = session.start().unwrap();
        let identity = Eap::decode(&start).unwrap();
        let challenge = session
            .step(
                &eap(2, identity.identifier, Some(1), b"User"),
                &mut store,
                Duration::ZERO,
            )
            .unwrap();
        let c = Eap::decode(&challenge).unwrap();
        assert_eq!(c.method, Some(26));
        let auth: &[u8; 16] = c.data[5..21].try_into().unwrap();
        let peer = [0x23; 16];
        let provider = MschapProvider::new().unwrap();
        let nt = provider
            .nt_response(hash().expose(), auth, &peer, b"User")
            .unwrap();
        let expected = provider
            .result(
                hash().expose(),
                nt.expose().try_into().unwrap(),
                auth,
                &peer,
                b"User",
            )
            .unwrap();
        let mut body = vec![2, c.data[1], 0, 58, 49];
        body.extend_from_slice(&peer);
        body.extend_from_slice(&[0; 8]);
        body.extend_from_slice(nt.expose());
        body.push(0);
        body.extend_from_slice(b"User");
        let success = session
            .step(
                &eap(2, c.identifier, Some(26), &body),
                &mut store,
                Duration::ZERO,
            )
            .unwrap();
        let s = Eap::decode(&success).unwrap();
        assert_eq!(s.data[0], 3);
        assert_eq!(&s.data[4..46], expected.authenticator.expose());
        assert!(session.take_msk().is_err());
        let final_eap = session
            .step(
                &eap(2, s.identifier, Some(26), &[3]),
                &mut store,
                Duration::ZERO,
            )
            .unwrap();
        assert_eq!(Eap::decode(&final_eap).unwrap().code, 3);
        assert_eq!(session.take_msk().unwrap().expose(), expected.msk.expose());
    }
    #[test]
    fn unknown_disabled_wrong_name_and_cooldown_fail_with_same_api_result() {
        let (file, key) = fixture(true);
        let mut store = AuthStore::from_encrypted(&file, key).unwrap();
        let provider = MschapProvider::new().unwrap();
        let auth = [1; 16];
        let peer = [2; 16];
        let nt = provider
            .nt_response(hash().expose(), &auth, &peer, b"User")
            .unwrap();
        let nt: &[u8; 24] = nt.expose().try_into().unwrap();
        for _ in 0..5 {
            assert!(
                store
                    .verify(b"User", b"Other", &auth, &peer, nt, Duration::ZERO)
                    .unwrap()
                    .is_none()
            );
        }
        assert!(
            store
                .verify(b"User", b"User", &auth, &peer, nt, Duration::from_secs(1))
                .unwrap()
                .is_none()
        );
        assert!(
            store
                .verify(b"User", b"User", &auth, &peer, nt, Duration::from_secs(30))
                .unwrap()
                .is_some()
        );
        assert!(
            store
                .verify(
                    b"Unknown",
                    b"Unknown",
                    &auth,
                    &peer,
                    nt,
                    Duration::from_secs(30)
                )
                .unwrap()
                .is_none()
        );
        let (file, key) = fixture(false);
        let mut store = AuthStore::from_encrypted(&file, key).unwrap();
        assert!(
            store
                .verify(b"User", b"User", &auth, &peer, nt, Duration::ZERO)
                .unwrap()
                .is_none()
        );
    }
}
