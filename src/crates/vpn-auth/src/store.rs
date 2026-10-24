use crate::{Error, valid_username};
use ikev2_crypto::{
    SecretBytes, constant_time_eq,
    mschap::{MethodKeys, MschapProvider},
};
use openssl::symm::{Cipher, Crypter, Mode, encrypt_aead};
use std::{collections::HashMap, time::Duration};
use zeroize::Zeroizing;
const MAX_USERS: usize = 1024;
const MAX_FILE: usize = 200000;
const MAGIC: &[u8] = b"HVNT\x01";
pub struct EncryptedUser {
    name: Vec<u8>,
    enabled: bool,
    nonce: [u8; 12],
    ciphertext: Vec<u8>,
    tag: [u8; 16],
}
fn aad(name: &[u8], enabled: bool) -> Vec<u8> {
    let mut out = b"harbor-nt-verifier-v1".to_vec();
    out.push(name.len() as u8);
    out.extend_from_slice(name);
    out.push(u8::from(enabled));
    out
}
pub fn encrypt_user(
    master: &SecretBytes,
    name: &[u8],
    enabled: bool,
    nt_hash: &SecretBytes,
) -> Result<EncryptedUser, Error> {
    if master.expose().len() != 32 || nt_hash.expose().len() != 16 || !valid_username(name) {
        return Err(Error::InvalidLength);
    }
    let mut nonce = [0; 12];
    openssl::rand::rand_bytes(&mut nonce)?;
    let mut tag = [0; 16];
    let ciphertext = encrypt_aead(
        Cipher::aes_256_gcm(),
        master.expose(),
        Some(&nonce),
        &aad(name, enabled),
        nt_hash.expose(),
        &mut tag,
    )?;
    Ok(EncryptedUser {
        name: name.to_vec(),
        enabled,
        nonce,
        ciphertext,
        tag,
    })
}
fn decrypt(master: &SecretBytes, user: &EncryptedUser) -> Result<SecretBytes, Error> {
    let mut c = Crypter::new(
        Cipher::aes_256_gcm(),
        Mode::Decrypt,
        master.expose(),
        Some(&user.nonce),
    )?;
    c.aad_update(&aad(&user.name, user.enabled))?;
    c.set_tag(&user.tag)?;
    let mut out = Zeroizing::new(vec![0; user.ciphertext.len() + 16]);
    let n = c.update(&user.ciphertext, &mut out)?;
    let end = n + c
        .finalize(&mut out[n..])
        .map_err(|_| Error::Authentication)?;
    if end != 16 {
        return Err(Error::Authentication);
    }
    out.truncate(end);
    Ok(SecretBytes::new(out.to_vec()))
}

pub fn encode_file(users: &[EncryptedUser]) -> Result<Vec<u8>, Error> {
    if users.is_empty() || users.len() > MAX_USERS {
        return Err(Error::InvalidLength);
    }
    let mut out = MAGIC.to_vec();
    out.extend_from_slice(&(users.len() as u16).to_be_bytes());
    for u in users {
        if !valid_username(&u.name) || u.ciphertext.len() != 16 {
            return Err(Error::InvalidLength);
        }
        out.push(u.name.len() as u8);
        out.extend_from_slice(&u.name);
        out.push(u8::from(u.enabled));
        out.extend_from_slice(&u.nonce);
        out.extend_from_slice(&u.ciphertext);
        out.extend_from_slice(&u.tag);
    }
    Ok(out)
}
struct Entry {
    encrypted: EncryptedUser,
    failures: u8,
    blocked_until: Duration,
}
pub struct AuthStore {
    master: SecretBytes,
    users: HashMap<Vec<u8>, Entry>,
    dummy: EncryptedUser,
    provider: MschapProvider,
    last: Duration,
}
impl AuthStore {
    pub fn from_encrypted(bytes: &[u8], master: SecretBytes) -> Result<Self, Error> {
        if master.expose().len() != 32
            || bytes.len() > MAX_FILE
            || !bytes.starts_with(MAGIC)
            || bytes.len() < 7
        {
            return Err(Error::InvalidLength);
        }
        let count = usize::from(u16::from_be_bytes([bytes[5], bytes[6]]));
        if count == 0 || count > MAX_USERS {
            return Err(Error::InvalidLength);
        }
        let mut rest = &bytes[7..];
        let mut users = HashMap::new();
        for _ in 0..count {
            let n = usize::from(*rest.first().ok_or(Error::Authentication)?);
            rest = &rest[1..];
            if n > 128 || rest.len() < n + 45 {
                return Err(Error::Authentication);
            }
            let name = rest[..n].to_vec();
            if !valid_username(&name) || rest[n] > 1 {
                return Err(Error::Authentication);
            }
            let u = EncryptedUser {
                name: name.clone(),
                enabled: rest[n] == 1,
                nonce: rest[n + 1..n + 13]
                    .try_into()
                    .map_err(|_| Error::Authentication)?,
                ciphertext: rest[n + 13..n + 29].to_vec(),
                tag: rest[n + 29..n + 45]
                    .try_into()
                    .map_err(|_| Error::Authentication)?,
            };
            decrypt(&master, &u)?;
            rest = &rest[n + 45..];
            if users
                .insert(
                    name,
                    Entry {
                        encrypted: u,
                        failures: 0,
                        blocked_until: Duration::ZERO,
                    },
                )
                .is_some()
            {
                return Err(Error::Authentication);
            }
        }
        if !rest.is_empty() {
            return Err(Error::Authentication);
        }
        let mut dummy_hash = Zeroizing::new(vec![0; 16]);
        openssl::rand::rand_bytes(&mut dummy_hash)?;
        let dummy = encrypt_user(
            &master,
            b"unknown-user",
            false,
            &SecretBytes::new(dummy_hash.to_vec()),
        )?;
        Ok(Self {
            master,
            users,
            dummy,
            provider: MschapProvider::new()?,
            last: Duration::ZERO,
        })
    }
    pub fn verify(
        &mut self,
        name: &[u8],
        response_name: &[u8],
        auth: &[u8; 16],
        peer: &[u8; 16],
        nt: &[u8; 24],
        now: Duration,
    ) -> Result<Option<MethodKeys>, Error> {
        if now < self.last || !valid_username(name) {
            return Err(Error::Authentication);
        }
        self.last = now;
        let entry = self.users.get(name);
        let user = entry.map_or(&self.dummy, |e| &e.encrypted);
        let hash = decrypt(&self.master, user)?;
        let expected = self.provider.nt_response(hash.expose(), auth, peer, name)?;
        // Do the same method derivation for known/unknown/disabled/cooldown failures.
        let keys = self.provider.result(hash.expose(), nt, auth, peer, name)?;
        let valid = constant_time_eq(expected.expose(), nt)
            && constant_time_eq(name, response_name)
            && entry.is_some_and(|e| e.encrypted.enabled && now >= e.blocked_until);
        if let Some(e) = self.users.get_mut(name) {
            if valid {
                e.failures = 0;
            } else if now >= e.blocked_until {
                e.failures = e.failures.saturating_add(1);
                if e.failures >= 5 {
                    e.blocked_until = now.saturating_add(Duration::from_secs(30));
                    e.failures = 0;
                }
            }
        }
        Ok(if valid { Some(keys) } else { None })
    }
    pub fn enabled(&self, name: &[u8]) -> bool {
        self.users.get(name).is_some_and(|e| e.encrypted.enabled)
    }
}
