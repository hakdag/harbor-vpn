//! RSA/SHA-256 IKE AUTH, separate from local trust/provisioning policy.
use crate::{Error, SecretBytes, prf};
use openssl::{
    hash::MessageDigest,
    pkey::{PKey, Private},
    rsa::Padding,
    sign::{Signer, Verifier},
    stack::Stack,
    x509::{
        X509, X509PurposeId, X509StoreContext,
        store::X509StoreBuilder,
        verify::{X509CheckFlags, X509VerifyParam},
    },
};

pub const HOSTNAME: &str = "vpn.hypervault.biz";
const SHA256_RSA_DER: &[u8] = &[
    0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00,
];
pub trait ServerSigner: Send + Sync {
    fn hostname(&self) -> &str;
    fn certificates(&self) -> &[Vec<u8>];
    fn sign(&self, signed_octets: &[u8]) -> Result<Vec<u8>, Error>;
}
pub struct ServerIdentity {
    key: PKey<Private>,
    leaf: X509,
    chain: Vec<Vec<u8>>,
}
impl ServerIdentity {
    /// Inputs must come from the restricted file/provisioning boundary. No custom CA fallback.
    pub fn load(chain_pem: &[u8], private_pem: &[u8]) -> Result<Self, Error> {
        let mut builder = X509StoreBuilder::new()?;
        // Fixed Ubuntu system trust bundle; deliberately ignore SSL_CERT_FILE/DIR overrides.
        builder
            .add_lookup(openssl::x509::store::X509Lookup::file())?
            .load_cert_file(
                "/etc/ssl/certs/ca-certificates.crt",
                openssl::ssl::SslFiletype::PEM,
            )?;
        Self::validate(chain_pem, private_pem, builder, HOSTNAME)
    }
    fn validate(
        chain_pem: &[u8],
        private_pem: &[u8],
        mut store: X509StoreBuilder,
        hostname: &str,
    ) -> Result<Self, Error> {
        if chain_pem.len() > 65536 || private_pem.len() > 16384 {
            return Err(Error::InvalidLength);
        }
        let certificates = X509::stack_from_pem(chain_pem)?;
        if certificates.is_empty() || certificates.len() > 4 {
            return Err(Error::Authentication);
        }
        let key = PKey::private_key_from_pem(private_pem)?;
        if key.id() != openssl::pkey::Id::RSA
            || key.rsa()?.size() != 384
            || !certificates[0].public_key()?.public_eq(&key)
        {
            return Err(Error::Authentication);
        }
        let leaf_der = certificates[0].to_der()?;
        let (rest, leaf) =
            x509_parser::parse_x509_certificate(&leaf_der).map_err(|_| Error::Authentication)?;
        if leaf.is_ca()
            || !rest.is_empty()
            || leaf
                .key_usage()
                .map_err(|_| Error::Authentication)?
                .is_none_or(|x| !x.value.digital_signature())
            || leaf
                .extended_key_usage()
                .map_err(|_| Error::Authentication)?
                .is_none_or(|x| !x.value.server_auth)
        {
            return Err(Error::Authentication);
        }
        // Initial public-CA candidate requires serverAuth. iOS/IKE usage remains a native gate.
        let mut param = X509VerifyParam::new()?;
        param.set_hostflags(
            X509CheckFlags::NEVER_CHECK_SUBJECT | X509CheckFlags::NO_PARTIAL_WILDCARDS,
        );
        param.set_host(hostname)?;
        param.set_depth(4);
        param.set_purpose(X509PurposeId::SSL_SERVER)?;
        let mut untrusted = Stack::new()?;
        for cert in certificates.iter().skip(1) {
            untrusted.push(cert.clone())?;
        }
        let mut ctx = X509StoreContext::new()?;
        store.set_param(&param)?;
        let store = store.build();
        let valid = ctx.init(&store, &certificates[0], &untrusted, |c| c.verify_cert())?;
        if !valid {
            return Err(Error::Authentication);
        }
        let chain: Vec<Vec<u8>> = certificates
            .iter()
            .map(|c| c.to_der())
            .collect::<Result<_, _>>()?;
        if chain.iter().map(Vec::len).sum::<usize>() > 12000 {
            return Err(Error::InvalidLength);
        }
        Ok(Self {
            key,
            leaf: certificates[0].clone(),
            chain,
        })
    }
    pub fn verify_auth(
        public: &openssl::pkey::PKeyRef<openssl::pkey::Public>,
        octets: &[u8],
        auth: &[u8],
    ) -> Result<(), Error> {
        if auth.len() != 1 + SHA256_RSA_DER.len() + 384
            || auth[0] != 15
            || &auth[1..16] != SHA256_RSA_DER
        {
            return Err(Error::Authentication);
        }
        let mut v = Verifier::new(MessageDigest::sha256(), public)?;
        v.set_rsa_padding(Padding::PKCS1)?;
        v.update(octets)?;
        if !v.verify(&auth[16..])? {
            return Err(Error::Authentication);
        }
        Ok(())
    }
}
impl ServerSigner for ServerIdentity {
    fn hostname(&self) -> &str {
        HOSTNAME
    }
    fn certificates(&self) -> &[Vec<u8>] {
        &self.chain
    }
    fn sign(&self, octets: &[u8]) -> Result<Vec<u8>, Error> {
        if octets.len() > 131072 {
            return Err(Error::InvalidLength);
        }
        let now = openssl::asn1::Asn1Time::days_from_now(0)?;
        if self.leaf.not_before().compare(&now)? == std::cmp::Ordering::Greater
            || self.leaf.not_after().compare(&now)? != std::cmp::Ordering::Greater
        {
            return Err(Error::Authentication);
        }
        let mut s = Signer::new(MessageDigest::sha256(), &self.key)?;
        s.set_rsa_padding(Padding::PKCS1)?;
        s.update(octets)?;
        let mut out = vec![15];
        out.extend_from_slice(SHA256_RSA_DER);
        out.extend_from_slice(&s.sign_to_vec()?);
        Ok(out)
    }
}
/// RFC 7296 signed octets: exact initial packet || other nonce || prf(SK_p, ID body).
pub fn signed_octets(
    initial: &[u8],
    other_nonce: &[u8],
    sk_p: &[u8],
    id_body: &[u8],
) -> Result<SecretBytes, Error> {
    if initial.len() > 65535
        || !(16..=256).contains(&other_nonce.len())
        || sk_p.len() != 32
        || !(5..=257).contains(&id_body.len())
    {
        return Err(Error::InvalidLength);
    }
    let mac = prf(sk_p, &[id_body])?;
    let mut out =
        zeroize::Zeroizing::new(Vec::with_capacity(initial.len() + other_nonce.len() + 32));
    out.extend_from_slice(initial);
    out.extend_from_slice(other_nonce);
    out.extend_from_slice(mac.expose());
    Ok(SecretBytes::new(out.to_vec()))
}
pub fn eap_auth(msk: &[u8], octets: &[u8]) -> Result<SecretBytes, Error> {
    if msk.len() != 64 || octets.len() > 131072 {
        return Err(Error::InvalidLength);
    }
    let key = prf(msk, &[b"Key Pad for IKEv2"])?;
    prf(key.expose(), &[octets])
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::{
        asn1::Asn1Time,
        bn::BigNum,
        rsa::Rsa,
        x509::{
            X509NameBuilder,
            extension::{BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectAlternativeName},
        },
    };
    #[derive(Clone, Copy)]
    enum Usage {
        Server,
        WrongKey,
        WrongExtended,
    }
    fn certificate(
        key: &PKey<Private>,
        issuer: Option<&X509>,
        issuer_key: &PKey<Private>,
        host: &str,
        ca: bool,
        usage: Usage,
        expired: bool,
    ) -> X509 {
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", host).unwrap();
        let name = name.build();
        let mut b = X509::builder().unwrap();
        b.set_version(2).unwrap();
        let serial = BigNum::from_u32(if ca { 1 } else { 2 })
            .unwrap()
            .to_asn1_integer()
            .unwrap();
        b.set_serial_number(&serial).unwrap();
        b.set_subject_name(&name).unwrap();
        b.set_issuer_name(issuer.map_or(&name, |c| c.subject_name()))
            .unwrap();
        b.set_pubkey(key).unwrap();
        b.set_not_before(&Asn1Time::from_unix(1).unwrap()).unwrap();
        let after = if expired {
            Asn1Time::from_unix(2).unwrap()
        } else {
            Asn1Time::days_from_now(2).unwrap()
        };
        b.set_not_after(&after).unwrap();
        if ca {
            b.append_extension(BasicConstraints::new().critical().ca().build().unwrap())
                .unwrap();
            b.append_extension(KeyUsage::new().key_cert_sign().crl_sign().build().unwrap())
                .unwrap();
        } else {
            b.append_extension(BasicConstraints::new().critical().build().unwrap())
                .unwrap();
            b.append_extension(if !matches!(usage, Usage::WrongKey) {
                KeyUsage::new().digital_signature().build().unwrap()
            } else {
                KeyUsage::new().key_encipherment().build().unwrap()
            })
            .unwrap();
            let mut eku = ExtendedKeyUsage::new();
            if matches!(usage, Usage::WrongExtended) {
                eku.client_auth();
            } else {
                eku.server_auth();
            }
            b.append_extension(eku.build().unwrap()).unwrap();
            let san = SubjectAlternativeName::new()
                .dns(host)
                .build(&b.x509v3_context(issuer.map(|c| c.as_ref()), None))
                .unwrap();
            b.append_extension(san).unwrap();
        }
        b.sign(issuer_key, MessageDigest::sha256()).unwrap();
        b.build()
    }
    #[test]
    fn synthetic_local_identity_validation_and_auth_framing() {
        // Ephemeral unit-test CA only. No private CA configuration exists in production loader.
        let ca_key = PKey::from_rsa(Rsa::generate(3072).unwrap()).unwrap();
        let ca = certificate(
            &ca_key,
            None,
            &ca_key,
            "test-only CA",
            true,
            Usage::Server,
            false,
        );
        let key = PKey::from_rsa(Rsa::generate(3072).unwrap()).unwrap();
        let pem = zeroize::Zeroizing::new(key.private_key_to_pem_pkcs8().unwrap());
        let trust = || {
            let mut store = X509StoreBuilder::new().unwrap();
            store.add_cert(ca.clone()).unwrap();
            store
        };
        let leaf = certificate(
            &key,
            Some(&ca),
            &ca_key,
            HOSTNAME,
            false,
            Usage::Server,
            false,
        );
        let identity =
            ServerIdentity::validate(&leaf.to_pem().unwrap(), &pem, trust(), HOSTNAME).unwrap();
        let signature = identity.sign(b"synthetic signed transcript").unwrap();
        let public = leaf.public_key().unwrap();
        ServerIdentity::verify_auth(&public, b"synthetic signed transcript", &signature).unwrap();
        assert!(ServerIdentity::verify_auth(&public, b"changed transcript", &signature).is_err());
        let mut broken = signature.clone();
        broken[3] ^= 1;
        assert!(
            ServerIdentity::verify_auth(&public, b"synthetic signed transcript", &broken).is_err()
        );
        assert!(
            ServerIdentity::validate(&leaf.to_pem().unwrap(), &pem, trust(), "wrong.example")
                .is_err()
        );
        let wrong = zeroize::Zeroizing::new(ca_key.private_key_to_pem_pkcs8().unwrap());
        assert!(
            ServerIdentity::validate(&leaf.to_pem().unwrap(), &wrong, trust(), HOSTNAME).is_err()
        );
        assert!(
            ServerIdentity::validate(
                &leaf.to_pem().unwrap(),
                &pem,
                X509StoreBuilder::new().unwrap(),
                HOSTNAME
            )
            .is_err()
        );
        for (usage, expired) in [
            (Usage::WrongKey, false),
            (Usage::WrongExtended, false),
            (Usage::Server, true),
        ] {
            let c = certificate(&key, Some(&ca), &ca_key, HOSTNAME, false, usage, expired);
            assert!(
                ServerIdentity::validate(&c.to_pem().unwrap(), &pem, trust(), HOSTNAME).is_err()
            );
        }
    }
}
