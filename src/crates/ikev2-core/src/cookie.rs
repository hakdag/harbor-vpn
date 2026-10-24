use crate::Error;
use ikev2_crypto::{CryptoProvider, SecretBytes, constant_time_eq, prf};
use std::net::SocketAddrV4;

pub(crate) struct CookieKeys {
    epoch: u64,
    current: SecretBytes,
    previous: Option<(u64, SecretBytes)>,
}
impl CookieKeys {
    pub fn new<P: CryptoProvider>(provider: &mut P) -> Result<Self, Error> {
        Ok(Self {
            epoch: 0,
            current: Self::secret(provider)?,
            previous: None,
        })
    }
    fn secret<P: CryptoProvider>(provider: &mut P) -> Result<SecretBytes, Error> {
        Ok(SecretBytes::random(provider, 32)?)
    }
    pub fn rotate<P: CryptoProvider>(&mut self, provider: &mut P, epoch: u64) -> Result<(), Error> {
        if epoch == self.epoch {
            return Ok(());
        }
        let next = Self::secret(provider)?;
        let old = std::mem::replace(&mut self.current, next);
        self.previous = if epoch == self.epoch.saturating_add(1) {
            Some((self.epoch, old))
        } else {
            None
        };
        self.epoch = epoch;
        Ok(())
    }
    fn mac(
        key: &[u8],
        epoch: u64,
        ni: &[u8],
        spii: u64,
        peer: SocketAddrV4,
        local: SocketAddrV4,
    ) -> Result<SecretBytes, Error> {
        Ok(prf(
            key,
            &[
                b"harbor-ikev2-cookie-v1",
                &epoch.to_be_bytes(),
                &(ni.len() as u16).to_be_bytes(),
                ni,
                &spii.to_be_bytes(),
                &peer.ip().octets(),
                &peer.port().to_be_bytes(),
                &local.ip().octets(),
                &local.port().to_be_bytes(),
            ],
        )?)
    }
    pub fn make(
        &self,
        ni: &[u8],
        spii: u64,
        peer: SocketAddrV4,
        local: SocketAddrV4,
    ) -> Result<Vec<u8>, Error> {
        let mac = Self::mac(self.current.expose(), self.epoch, ni, spii, peer, local)?;
        let mut cookie = Vec::with_capacity(40);
        cookie.extend_from_slice(&self.epoch.to_be_bytes());
        cookie.extend_from_slice(mac.expose());
        Ok(cookie)
    }
    pub fn verify(
        &self,
        cookie: &[u8],
        ni: &[u8],
        spii: u64,
        peer: SocketAddrV4,
        local: SocketAddrV4,
    ) -> Result<bool, Error> {
        if cookie.len() != 40 {
            return Ok(false);
        }
        let epoch = u64::from_be_bytes(cookie[..8].try_into().map_err(|_| Error::InvalidPolicy)?);
        let secret = if epoch == self.epoch {
            Some(&self.current)
        } else {
            self.previous
                .as_ref()
                .filter(|(n, _)| *n == epoch)
                .map(|(_, key)| key)
        };
        let Some(secret) = secret else {
            return Ok(false);
        };
        let mac = Self::mac(secret.expose(), epoch, ni, spii, peer, local)?;
        Ok(constant_time_eq(&cookie[8..], mac.expose()))
    }
}
