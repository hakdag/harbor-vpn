//! ADR-002 provider boundary. Protocol composition only; primitives are OpenSSL.
//! All keys are unauthenticated until a future, separately implemented IKE_AUTH.
pub mod identity;
pub mod mschap;
pub mod protected;
use openssl::{
    bn::BigNumContext,
    derive::Deriver,
    ec::{EcGroup, EcKey, EcPoint, PointConversionForm},
    hash::MessageDigest,
    nid::Nid,
    pkey::{PKey, Private},
    sign::Signer,
    symm::{Cipher, Crypter, Mode},
};
use std::fmt;
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Provider,
    UnsupportedVersion,
    InvalidPeer,
    InvalidLength,
    Authentication,
    IvExhausted,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "crypto operation failed: {self:?}")
    }
}
impl std::error::Error for Error {}
impl From<openssl::error::ErrorStack> for Error {
    fn from(_: openssl::error::ErrorStack) -> Self {
        Self::Provider
    }
}

pub struct SecretBytes(Zeroizing<Vec<u8>>);
impl SecretBytes {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(Zeroizing::new(bytes))
    }
    pub fn random<P: CryptoProvider>(provider: &mut P, length: usize) -> Result<Self, Error> {
        if length > 8160 {
            return Err(Error::InvalidLength);
        }
        let mut secret = Self::new(vec![0; length]);
        provider.random(&mut secret.0)?;
        Ok(secret)
    }
    /// Secret-bearing data. Never log or retain a second unprotected copy.
    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}
impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretBytes([REDACTED])")
    }
}

pub trait EphemeralDh {
    fn public_value(&self) -> Result<[u8; 64], Error>;
    fn shared_secret(&self, peer: &[u8]) -> Result<SecretBytes, Error>;
}
/// Production implementations must supply a cryptographically secure RNG and
/// fresh private key per call. Deterministic providers belong only in tests.
pub trait CryptoProvider {
    type Dh: EphemeralDh;
    fn random(&mut self, output: &mut [u8]) -> Result<(), Error>;
    fn generate_p256(&mut self) -> Result<Self::Dh, Error>;
}
pub struct OpenSslProvider {
    _private: (),
}
impl OpenSslProvider {
    pub fn new() -> Result<Self, Error> {
        let v = openssl::version::number();
        if !(0x3000_0000..0x4000_0000).contains(&v) {
            return Err(Error::UnsupportedVersion);
        }
        Ok(Self { _private: () })
    }
    pub fn version() -> &'static str {
        openssl::version::version()
    }
}
pub struct P256Key(PKey<Private>);
impl CryptoProvider for OpenSslProvider {
    type Dh = P256Key;
    fn random(&mut self, output: &mut [u8]) -> Result<(), Error> {
        openssl::rand::rand_bytes(output)?;
        Ok(())
    }
    fn generate_p256(&mut self) -> Result<P256Key, Error> {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
        Ok(P256Key(PKey::from_ec_key(EcKey::generate(&group)?)?))
    }
}
impl EphemeralDh for P256Key {
    fn public_value(&self) -> Result<[u8; 64], Error> {
        let key = self.0.ec_key()?;
        let mut ctx = BigNumContext::new()?;
        let bytes =
            key.public_key()
                .to_bytes(key.group(), PointConversionForm::UNCOMPRESSED, &mut ctx)?;
        if bytes.len() != 65 || bytes[0] != 4 {
            return Err(Error::Provider);
        }
        bytes[1..].try_into().map_err(|_| Error::Provider)
    }
    fn shared_secret(&self, peer: &[u8]) -> Result<SecretBytes, Error> {
        let public = parse_peer(peer)?;
        let mut deriver = Deriver::new(&self.0)?;
        deriver.set_peer(&public).map_err(|_| Error::InvalidPeer)?;
        let secret = SecretBytes::new(deriver.derive_to_vec()?);
        if secret.expose().len() != 32 {
            return Err(Error::Provider);
        }
        Ok(secret)
    }
}

fn parse_peer(peer: &[u8]) -> Result<PKey<openssl::pkey::Public>, Error> {
    if peer.len() != 64 {
        return Err(Error::InvalidPeer);
    }
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
    let mut ctx = BigNumContext::new()?;
    let mut encoded = [0u8; 65];
    encoded[0] = 4;
    encoded[1..].copy_from_slice(peer);
    let point = EcPoint::from_bytes(&group, &encoded, &mut ctx).map_err(|_| Error::InvalidPeer)?;
    if point.is_infinity(&group)
        || !point
            .is_on_curve(&group, &mut ctx)
            .map_err(|_| Error::InvalidPeer)?
    {
        return Err(Error::InvalidPeer);
    }
    let key = EcKey::from_public_key(&group, &point).map_err(|_| Error::InvalidPeer)?;
    key.check_key().map_err(|_| Error::InvalidPeer)?;
    Ok(PKey::from_ec_key(key)?)
}

pub fn validate_p256(peer: &[u8]) -> Result<(), Error> {
    parse_peer(peer).map(|_| ())
}

pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && openssl::memcmp::eq(a, b)
}
pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    openssl::sha::sha256(bytes)
}
/// SHA-1 is mandated for NAT identifiers, never selected as an IKE PRF/integrity suite.
pub fn nat_detection(spii: u64, spir: u64, endpoint: std::net::SocketAddrV4) -> [u8; 20] {
    let mut bytes = [0u8; 22];
    bytes[..8].copy_from_slice(&spii.to_be_bytes());
    bytes[8..16].copy_from_slice(&spir.to_be_bytes());
    bytes[16..20].copy_from_slice(&endpoint.ip().octets());
    bytes[20..].copy_from_slice(&endpoint.port().to_be_bytes());
    openssl::sha::sha1(&bytes)
}
pub fn prf(key: &[u8], parts: &[&[u8]]) -> Result<SecretBytes, Error> {
    let key = PKey::hmac(key)?;
    let mut signer = Signer::new(MessageDigest::sha256(), &key)?;
    for part in parts {
        signer.update(part)?;
    }
    Ok(SecretBytes::new(signer.sign_to_vec()?))
}
/// RFC 7296 prf+ composition of library HMAC, not a custom HMAC primitive.
pub fn prf_plus(key: &[u8], seed: &[u8], length: usize) -> Result<SecretBytes, Error> {
    if length > 255 * 32 || seed.len() > 1024 {
        return Err(Error::InvalidLength);
    }
    let mut output = Zeroizing::new(Vec::with_capacity(length));
    let mut previous = SecretBytes::new(Vec::new());
    for i in 1..=length.div_ceil(32) {
        previous = prf(key, &[previous.expose(), seed, &[i as u8]])?;
        let count = (length - output.len()).min(32);
        output.extend_from_slice(&previous.expose()[..count]);
    }
    Ok(SecretBytes(output))
}

pub struct IkeKeys {
    pub sk_d: SecretBytes,
    pub initiator: GcmKey,
    pub responder: GcmKey,
    pub sk_pi: SecretBytes,
    pub sk_pr: SecretBytes,
}
impl fmt::Debug for IkeKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("IkeKeys([REDACTED])")
    }
}
/// AES-GCM: SK_ai/SK_ar have zero length; each SK_e is 32-byte key + 4-byte salt.
pub fn derive_keys<P: CryptoProvider>(
    provider: &mut P,
    shared: &[u8],
    ni: &[u8],
    nr: &[u8],
    spii: u64,
    spir: u64,
) -> Result<IkeKeys, Error> {
    if shared.len() != 32
        || !(16..=256).contains(&ni.len())
        || !(16..=256).contains(&nr.len())
        || spii == 0
        || spir == 0
    {
        return Err(Error::InvalidLength);
    }
    let mut nonces = Zeroizing::new(Vec::with_capacity(ni.len() + nr.len()));
    nonces.extend_from_slice(ni);
    nonces.extend_from_slice(nr);
    let skeyseed = prf(&nonces, &[shared])?;
    let mut seed = Vec::with_capacity(nonces.len() + 16);
    seed.extend_from_slice(&nonces);
    seed.extend_from_slice(&spii.to_be_bytes());
    seed.extend_from_slice(&spir.to_be_bytes());
    let material = prf_plus(skeyseed.expose(), &seed, 168)?;
    let m = material.expose();
    Ok(IkeKeys {
        sk_d: SecretBytes::new(m[..32].to_vec()),
        initiator: GcmKey::new(&m[32..68], provider)?,
        responder: GcmKey::new(&m[68..104], provider)?,
        sk_pi: SecretBytes::new(m[104..136].to_vec()),
        sk_pr: SecretBytes::new(m[136..168].to_vec()),
    })
}

pub struct GcmKey {
    material: SecretBytes,
    next_iv: Option<u64>,
}
impl fmt::Debug for GcmKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("GcmKey([REDACTED])")
    }
}
#[derive(Clone)]
pub struct Sealed {
    pub iv: [u8; 8],
    pub ciphertext: Vec<u8>,
    pub tag: [u8; 16],
}
impl GcmKey {
    fn new<P: CryptoProvider>(material: &[u8], provider: &mut P) -> Result<Self, Error> {
        if material.len() != 36 {
            return Err(Error::InvalidLength);
        }
        let mut iv = [0; 8];
        provider.random(&mut iv)?;
        Ok(Self {
            material: SecretBytes::new(material.to_vec()),
            next_iv: Some(u64::from_be_bytes(iv)),
        })
    }
    pub fn seal(&mut self, aad: &[u8], plaintext: &[u8]) -> Result<Sealed, Error> {
        if aad.len() > 65_535 || plaintext.len() > 65_535 {
            return Err(Error::InvalidLength);
        }
        let counter = self.next_iv.ok_or(Error::IvExhausted)?;
        self.next_iv = counter.checked_add(1); // Consume IV even if encryption fails.
        let iv = counter.to_be_bytes();
        let nonce = self.nonce(&iv);
        let mut tag = [0; 16];
        let ciphertext = openssl::symm::encrypt_aead(
            Cipher::aes_256_gcm(),
            &self.material.expose()[..32],
            Some(&nonce),
            aad,
            plaintext,
            &mut tag,
        )?;
        Ok(Sealed {
            iv,
            ciphertext,
            tag,
        })
    }
    pub fn open(&self, aad: &[u8], sealed: &Sealed) -> Result<SecretBytes, Error> {
        if aad.len() > 65_535 || sealed.ciphertext.len() > 65_535 {
            return Err(Error::InvalidLength);
        }
        let nonce = self.nonce(&sealed.iv);
        let mut cipher = Crypter::new(
            Cipher::aes_256_gcm(),
            Mode::Decrypt,
            &self.material.expose()[..32],
            Some(&nonce),
        )?;
        cipher.aad_update(aad)?;
        cipher.set_tag(&sealed.tag)?;
        let mut out = Zeroizing::new(vec![0u8; sealed.ciphertext.len() + 16]);
        let count = cipher.update(&sealed.ciphertext, &mut out)?;
        let rest = cipher
            .finalize(&mut out[count..])
            .map_err(|_| Error::Authentication)?;
        out.truncate(count + rest);
        Ok(SecretBytes(out))
    }
    fn nonce(&self, iv: &[u8; 8]) -> [u8; 12] {
        let mut nonce = [0; 12];
        nonce[..4].copy_from_slice(&self.material.expose()[32..]);
        nonce[4..].copy_from_slice(iv);
        nonce
    }
}

/// Initial CHILD_SA: RFC 7296 KEYMAT = prf+(SK_d, Ni || Nr).
/// ESP AES-256-GCM: initiator->responder key32+salt4, then reverse direction.
pub fn initial_child_keymat(sk_d: &[u8], ni: &[u8], nr: &[u8]) -> Result<SecretBytes, Error> {
    if sk_d.len() != 32 || !(16..=256).contains(&ni.len()) || !(16..=256).contains(&nr.len()) {
        return Err(Error::InvalidLength);
    }
    let mut seed = Vec::with_capacity(ni.len() + nr.len());
    seed.extend_from_slice(ni);
    seed.extend_from_slice(nr);
    prf_plus(sk_d, &seed, 72)
}

#[cfg(test)]
mod tests;
