use super::*;
use openssl::bn::BigNum;
fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}
fn fixed_key(scalar: &str) -> P256Key {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let private = BigNum::from_hex_str(scalar).unwrap();
    let mut ctx = BigNumContext::new().unwrap();
    let mut point = EcPoint::new(&group).unwrap();
    point.mul_generator2(&group, &private, &mut ctx).unwrap();
    P256Key(
        PKey::from_ec_key(EcKey::from_private_components(&group, &private, &point).unwrap())
            .unwrap(),
    )
}
#[test]
fn rfc5903_group19_and_invalid_points() {
    let a = fixed_key("C88F01F510D9AC3F70A292DAA2316DE544E9AAB8AFE84049C62A9C57862D1433");
    let b = fixed_key("C6EF9C5D78AE012A011164ACB397CE2088685D8F06BF9BE0B283AB46476BEE53");
    assert_eq!(
        a.public_value().unwrap().as_slice(),
        hex(
            "dad0b65394221cf9b051e1feca5787d098dfe637fc90b9ef945d0c37725811805271a0461cdb8252d61f1c456fa3e59ab1f45b33accf5f58389e0577b8990bb3"
        )
    );
    assert_eq!(
        b.public_value().unwrap().as_slice(),
        hex(
            "d12dfb5289c8d4f81208b70270398c342296970a0bccb74c736fc7554494bf6356fbf3ca366cc23e8157854c13c58d6aac23f046ada30f8353e74f33039872ab"
        )
    );
    let expected = hex("d6840f6b42f6edafd13116e0e12565202fef8e9ece7dce03812464d04b9442de");
    assert_eq!(
        a.shared_secret(&b.public_value().unwrap())
            .unwrap()
            .expose(),
        expected
    );
    assert_eq!(
        b.shared_secret(&a.public_value().unwrap())
            .unwrap()
            .expose(),
        expected
    );
    for input in [vec![], vec![0; 64], vec![255; 64], vec![0; 65]] {
        assert!(a.shared_secret(&input).is_err());
    }
}
#[test]
fn rfc4231_hmac_sha256_case1() {
    let value = prf(&[0x0b; 20], &[b"Hi There"]).unwrap();
    assert_eq!(
        value.expose(),
        hex("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")
    );
}
fn reference(field: &str) -> Vec<u8> {
    let text = include_str!("../tests/fixtures/schedule.json");
    let line = text
        .lines()
        .find(|line| line.contains(&format!("\"{field}\"")))
        .unwrap();
    hex(line.split('"').nth(3).unwrap())
}
struct TestRandom;
impl CryptoProvider for TestRandom {
    type Dh = P256Key;
    fn random(&mut self, out: &mut [u8]) -> Result<(), Error> {
        out.fill(0);
        Ok(())
    }
    fn generate_p256(&mut self) -> Result<P256Key, Error> {
        OpenSslProvider::new()?.generate_p256()
    }
}
#[test]
fn independent_python_schedule_and_nat_vector() {
    let shared = hex("d6840f6b42f6edafd13116e0e12565202fef8e9ece7dce03812464d04b9442de");
    let ni: Vec<u8> = (0..32).collect();
    let nr: Vec<u8> = (32..64).collect();
    let mut nonces = ni.clone();
    nonces.extend_from_slice(&nr);
    assert_eq!(
        prf(&nonces, &[&shared]).unwrap().expose(),
        reference("skeyseed")
    );
    let keys = derive_keys(
        &mut TestRandom,
        &shared,
        &ni,
        &nr,
        0x0102030405060708,
        0x1112131415161718,
    )
    .unwrap();
    let mut actual = Vec::new();
    for key in [
        keys.sk_d.expose(),
        keys.initiator.material.expose(),
        keys.responder.material.expose(),
        keys.sk_pi.expose(),
        keys.sk_pr.expose(),
    ] {
        actual.extend_from_slice(key);
    }
    assert_eq!(actual, reference("material"));
    assert_eq!(
        nat_detection(0x0102030405060708, 0, "192.0.2.10:500".parse().unwrap()).as_slice(),
        reference("nat_source")
    );
    assert!(prf_plus(&[1; 32], &[], 8161).is_err());
    assert!(derive_keys(&mut TestRandom, &shared, &ni[..15], &nr, 1, 2).is_err());
    assert!(derive_keys(&mut TestRandom, &shared, &ni, &nr, 0, 2).is_err());
}
#[test]
fn nist_aes256_gcm_zero_key_vector_and_no_unauthenticated_plaintext() {
    let mut key = GcmKey::new(&[0; 36], &mut TestRandom).unwrap();
    let sealed = key.seal(&[], &[0; 16]).unwrap();
    assert_eq!(sealed.iv, [0; 8]);
    assert_eq!(sealed.ciphertext, hex("cea7403d4d606b6e074ec5d3baf39d18"));
    assert_eq!(
        sealed.tag.as_slice(),
        hex("d0d1c8a799996bf0265b98b5d48ab919")
    );
    assert_eq!(key.open(&[], &sealed).unwrap().expose(), [0; 16]);
    assert!(key.open(b"changed AAD", &sealed).is_err());
    let mut bad = sealed.clone();
    bad.tag[0] ^= 1;
    assert!(key.open(&[], &bad).is_err());
    let mut bad = sealed.clone();
    bad.ciphertext[0] ^= 1;
    assert!(key.open(&[], &bad).is_err());
    let mut bad = sealed.clone();
    bad.iv[0] ^= 1;
    assert!(key.open(&[], &bad).is_err());
    let next = key.seal(b"header", b"plaintext").unwrap();
    assert_ne!(next.iv, sealed.iv);
    key.next_iv = Some(u64::MAX);
    key.seal(&[], &[]).unwrap();
    assert_eq!(key.seal(&[], &[]).err(), Some(Error::IvExhausted));
    assert!(key.seal(&vec![0; 65_536], &[]).is_err());
}
#[test]
fn real_random_ephemeral_exchange_and_redaction() {
    let mut provider = OpenSslProvider::new().unwrap();
    let a = provider.generate_p256().unwrap();
    let b = provider.generate_p256().unwrap();
    assert_ne!(a.public_value().unwrap(), b.public_value().unwrap());
    assert!(constant_time_eq(
        a.shared_secret(&b.public_value().unwrap())
            .unwrap()
            .expose(),
        b.shared_secret(&a.public_value().unwrap())
            .unwrap()
            .expose()
    ));
    assert!(!constant_time_eq(&[1], &[1, 2]));
    assert_eq!(
        format!("{:?}", SecretBytes::new(vec![42; 32])),
        "SecretBytes([REDACTED])"
    );
}

#[test]
fn protected_sk_direction_aad_and_tamper_checks() {
    use crate::protected::{self, Direction};
    let mut provider = OpenSslProvider::new().unwrap();
    let mut keys = derive_keys(&mut provider, &[1; 32], &[2; 32], &[3; 32], 1, 2).unwrap();
    let header = ikev2_wire::Header {
        initiator_spi: 1,
        responder_spi: 2,
        version: 0x20,
        exchange: 35,
        flags: 8,
        message_id: 1,
    };
    let inner = [0, 0, 0, 9, 11, 0, 0, 0, b'u'];
    let wire = protected::seal(
        &mut keys,
        Direction::Initiator,
        header.clone(),
        35,
        &inner,
        ikev2_wire::Limits::default(),
    )
    .unwrap();
    let open = protected::open(
        &keys,
        Direction::Initiator,
        &wire,
        ikev2_wire::Limits::default(),
    )
    .unwrap();
    assert_eq!(open.plaintext.expose(), inner);
    let informational_flags = protected::seal(
        &mut keys,
        Direction::Initiator,
        ikev2_wire::Header {
            flags: 0xdf,
            ..header.clone()
        },
        35,
        &inner,
        ikev2_wire::Limits::default(),
    )
    .unwrap();
    assert!(
        protected::open(
            &keys,
            Direction::Initiator,
            &informational_flags,
            ikev2_wire::Limits::default()
        )
        .is_ok()
    );
    assert!(
        protected::open(
            &keys,
            Direction::Responder,
            &wire,
            ikev2_wire::Limits::default()
        )
        .is_err()
    );
    for index in [0, 8, 24, 28, 32, 40, wire.len() - 1] {
        let mut changed = wire.clone();
        changed[index] ^= 1;
        assert!(
            protected::open(
                &keys,
                Direction::Initiator,
                &changed,
                ikev2_wire::Limits::default()
            )
            .is_err()
        );
    }
    for n in 0..wire.len() {
        assert!(
            protected::open(
                &keys,
                Direction::Initiator,
                &wire[..n],
                ikev2_wire::Limits::default()
            )
            .is_err()
        );
    }
    let next = protected::seal(
        &mut keys,
        Direction::Initiator,
        header,
        35,
        &inner,
        ikev2_wire::Limits::default(),
    )
    .unwrap();
    assert_ne!(&wire[32..40], &next[32..40]);
}

#[test]
fn independent_python_sk_signed_octets_signature_and_final_auth_goldens() {
    use crate::protected::{self, Direction};
    struct Fixed;
    impl CryptoProvider for Fixed {
        type Dh = P256Key;
        fn random(&mut self, b: &mut [u8]) -> Result<(), Error> {
            for (i, v) in b.iter_mut().enumerate() {
                *v = (i + 1) as u8;
            }
            Ok(())
        }
        fn generate_p256(&mut self) -> Result<P256Key, Error> {
            Err(Error::Provider)
        }
    }
    let data: serde_json::Value =
        serde_json::from_str(include_str!("../tests/fixtures/auth-reference.json")).unwrap();
    let bytes = |key: &str| {
        let s = data[key].as_str().unwrap();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect::<Vec<_>>()
    };
    let mut keys = derive_keys(&mut Fixed, &[1; 32], &[2; 32], &[3; 32], 1, 2).unwrap();
    let h = ikev2_wire::Header {
        initiator_spi: 1,
        responder_spi: 2,
        version: 0x20,
        exchange: 35,
        flags: 8,
        message_id: 1,
    };
    let mut inner = vec![0, 0, 0, 12, 11, 0, 0, 0];
    inner.extend_from_slice(b"User");
    let actual = protected::seal(
        &mut keys,
        Direction::Initiator,
        h,
        35,
        &inner,
        ikev2_wire::Limits::default(),
    )
    .unwrap();
    assert_eq!(actual, bytes("protected_ike_hex"));
    let mut idr = vec![2, 0, 0, 0];
    idr.extend_from_slice(b"vpn.hypervault.biz");
    let signed = identity::signed_octets(
        b"synthetic INIT response",
        &[2; 32],
        keys.sk_pr.expose(),
        &idr,
    )
    .unwrap();
    assert_eq!(signed.expose(), bytes("signed_octets_hex"));
    let public = openssl::pkey::PKey::public_key_from_pem(
        data["public_key_pem"].as_str().unwrap().as_bytes(),
    )
    .unwrap();
    identity::ServerIdentity::verify_auth(&public, signed.expose(), &bytes("signature_auth_hex"))
        .unwrap();
    let msk: Vec<u8> = (0..64).collect();
    assert_eq!(
        identity::eap_auth(&msk, signed.expose()).unwrap().expose(),
        bytes("final_auth_hex")
    );
}

#[test]
fn initial_child_keymat_independent_python_hmac_golden() {
    let expected = hex(
        "b53f3d4dbad2752bb1f422d95d2407494c4ddb94d11d424b546e4b36b8211bbd02456879771e4cec02aa4d740530f2a94d26016e471692e77ed8489a27af912160fc33d5d9703a10",
    );
    assert_eq!(
        initial_child_keymat(&[1; 32], &[2; 32], &[3; 32])
            .unwrap()
            .expose(),
        expected
    );
    assert!(initial_child_keymat(&[1; 31], &[2; 32], &[3; 32]).is_err());
    assert!(initial_child_keymat(&[1; 32], &[2; 15], &[3; 32]).is_err());
}
