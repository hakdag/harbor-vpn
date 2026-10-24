//! RFC 2759/3079 protocol composition, using OpenSSL primitives only.
//! Legacy MD4/DES are fetched in a PRIVATE context, never the global IKE context.
use crate::{Error, SecretBytes};
use openssl::{
    cipher::Cipher, cipher_ctx::CipherCtx, lib_ctx::LibCtx, md::Md, md_ctx::MdCtx,
    provider::Provider, sha::Sha1,
};
use zeroize::Zeroizing;

pub struct MschapProvider {
    md4: Md,
    des: Cipher,
    _legacy: Provider,
    _context: LibCtx,
}
impl MschapProvider {
    pub fn new() -> Result<Self, Error> {
        let context = LibCtx::new()?;
        let legacy = Provider::load(Some(&context), "legacy")?;
        let md4 = Md::fetch(Some(&context), "MD4", Some("provider=legacy"))?;
        let des = Cipher::fetch(Some(&context), "DES-ECB", Some("provider=legacy"))?;
        Ok(Self {
            md4,
            des,
            _legacy: legacy,
            _context: context,
        })
    }
    pub fn md4(&self, input: &[u8]) -> Result<SecretBytes, Error> {
        if input.len() > 1024 {
            return Err(Error::InvalidLength);
        }
        let mut c = MdCtx::new()?;
        c.digest_init(&self.md4)?;
        c.digest_update(input)?;
        let mut out = Zeroizing::new(vec![0; 16]);
        if c.digest_final(&mut out)? != 16 {
            return Err(Error::Provider);
        }
        Ok(SecretBytes::new(out.to_vec()))
    }
    /// Provisioning only: never accept a plaintext password via the VPN protocol.
    pub fn nt_hash(&self, password: &str) -> Result<SecretBytes, Error> {
        let mut unicode = Zeroizing::new(Vec::new());
        for c in password.encode_utf16() {
            if unicode.len() >= 512 {
                return Err(Error::InvalidLength);
            }
            unicode.extend_from_slice(&c.to_le_bytes());
        }
        self.md4(&unicode)
    }
    fn des_encrypt(&self, key7: &[u8], challenge: &[u8; 8]) -> Result<[u8; 8], Error> {
        if key7.len() != 7 {
            return Err(Error::InvalidLength);
        }
        // RFC 2759: insert parity into the 56 key bits. This is key framing, not DES.
        let mut key = Zeroizing::new([0u8; 8]);
        key[0] = key7[0] & 254;
        for i in 1..7 {
            key[i] = ((key7[i - 1] << (8 - i)) | (key7[i] >> i)) & 254;
        }
        key[7] = (key7[6] << 1) & 254;
        for b in key.iter_mut() {
            *b |= u8::from(b.count_ones() % 2 == 0);
        }
        let mut c = CipherCtx::new()?;
        c.encrypt_init(Some(&self.des), Some(&key[..]), None)?;
        c.set_padding(false);
        let mut out = [0; 16];
        let n = c.cipher_update(challenge, Some(&mut out))?;
        let n = n + c.cipher_final(&mut out[n..])?;
        if n != 8 {
            return Err(Error::Provider);
        }
        out[..8].try_into().map_err(|_| Error::Provider)
    }
    pub fn nt_response(
        &self,
        hash: &[u8],
        auth: &[u8; 16],
        peer: &[u8; 16],
        username: &[u8],
    ) -> Result<SecretBytes, Error> {
        if hash.len() != 16 || username.is_empty() || username.len() > 253 {
            return Err(Error::InvalidLength);
        }
        let challenge = challenge_hash(auth, peer, username);
        let mut padded = Zeroizing::new([0; 21]);
        padded[..16].copy_from_slice(hash);
        let mut out = Zeroizing::new(Vec::with_capacity(24));
        for key in padded.chunks_exact(7) {
            out.extend_from_slice(&self.des_encrypt(key, &challenge)?);
        }
        Ok(SecretBytes::new(out.to_vec()))
    }
    pub fn result(
        &self,
        hash: &[u8],
        nt: &[u8; 24],
        auth: &[u8; 16],
        peer: &[u8; 16],
        username: &[u8],
    ) -> Result<MethodKeys, Error> {
        if hash.len() != 16 || username.is_empty() || username.len() > 253 {
            return Err(Error::InvalidLength);
        }
        let hh = self.md4(hash)?;
        let challenge = challenge_hash(auth, peer, username);
        let first = Zeroizing::new(sha1(&[
            hh.expose(),
            nt,
            b"Magic server to client signing constant",
        ]));
        let answer = Zeroizing::new(sha1(&[
            &first[..],
            &challenge,
            b"Pad to make it do more than one iteration",
        ]));
        let mut text = Zeroizing::new(Vec::with_capacity(42));
        text.extend_from_slice(b"S=");
        const HEX: &[u8] = b"0123456789ABCDEF";
        for b in answer.iter() {
            text.push(HEX[usize::from(b >> 4)]);
            text.push(HEX[usize::from(b & 15)]);
        }
        let master = Zeroizing::new(sha1(&[hh.expose(), nt, b"This is the MPPE Master Key"]));
        let receive = Zeroizing::new(sha1(&[
            &master[..16],
            &[0; 40],
            b"On the client side, this is the send key; on the server side, it is the receive key.",
            &[0xf2; 40],
        ]));
        let send = Zeroizing::new(sha1(&[
            &master[..16],
            &[0; 40],
            b"On the client side, this is the receive key; on the server side, it is the send key.",
            &[0xf2; 40],
        ]));
        // MS-CHAP MSK: authenticator receive || send || 32 zero bytes.
        let mut msk = Zeroizing::new(vec![0; 64]);
        msk[..16].copy_from_slice(&receive[..16]);
        msk[16..32].copy_from_slice(&send[..16]);
        Ok(MethodKeys {
            authenticator: SecretBytes::new(text.to_vec()),
            msk: SecretBytes::new(msk.to_vec()),
        })
    }
}
pub struct MethodKeys {
    pub authenticator: SecretBytes,
    pub msk: SecretBytes,
}
fn sha1(parts: &[&[u8]]) -> [u8; 20] {
    let mut h = Sha1::new();
    for p in parts {
        h.update(p);
    }
    h.finish()
}
pub fn challenge_hash(auth: &[u8; 16], peer: &[u8; 16], username: &[u8]) -> [u8; 8] {
    let name = username.rsplit(|b| *b == b'\\').next().unwrap_or(username);
    let h = sha1(&[peer, auth, name]);
    let mut out = [0; 8];
    out.copy_from_slice(&h[..8]);
    out
}
#[cfg(test)]
mod tests {
    use super::*;
    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }
    #[test]
    fn rfc2759_rfc3079_and_context_isolation() {
        let before = Md::fetch(None, "MD4", Some("provider=legacy")).is_ok();
        let p = MschapProvider::new().unwrap();
        let hash = p.nt_hash("clientPass").unwrap();
        assert_eq!(hash.expose(), hex("44ebba8d5312b8d611474411f56989ae"));
        let auth = hex("5b5d7c7d7b3f2f3e3c2c602132262628").try_into().unwrap();
        let peer = hex("21402324255e262a28295f2b3a337c7e").try_into().unwrap();
        assert_eq!(
            &challenge_hash(&auth, &peer, b"DOMAIN\\User"),
            hex("d02e4386bce91226").as_slice()
        );
        let nt = p.nt_response(hash.expose(), &auth, &peer, b"User").unwrap();
        assert_eq!(
            nt.expose(),
            hex("82309ecd8d708b5ea08faa3981cd83544233114a3d85d6df")
        );
        let keys = p
            .result(
                hash.expose(),
                nt.expose().try_into().unwrap(),
                &auth,
                &peer,
                b"User",
            )
            .unwrap();
        assert_eq!(
            keys.authenticator.expose(),
            b"S=407A5589115FD0D6209F510FE9C04566932CDA56"
        );
        assert_eq!(
            &keys.msk.expose()[16..32],
            hex("8b7cdc149b993a1ba118cb153f56dccb").as_slice()
        );
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../tests/fixtures/auth-reference.json")).unwrap();
        assert_eq!(
            keys.msk.expose(),
            hex(fixture["rfc3079_msk_hex"].as_str().unwrap())
        );
        assert_eq!(
            Md::fetch(None, "MD4", Some("provider=legacy")).is_ok(),
            before
        );
    }
}
