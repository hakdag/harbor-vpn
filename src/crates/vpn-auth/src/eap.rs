use crate::{AuthStore, Error, valid_username};
use ikev2_crypto::SecretBytes;
use ikev2_wire::auth::Eap;
use std::time::Duration;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EapState {
    Identity,
    Challenge,
    SuccessConfirmation,
    FailureConfirmation,
    Complete,
    Failed,
}
pub struct EapSession {
    state: EapState,
    id: u8,
    method_id: u8,
    challenge: [u8; 16],
    name: Option<Vec<u8>>,
    msk: Option<SecretBytes>,
}
impl EapSession {
    pub fn new() -> Result<Self, Error> {
        let mut random = [0; 17];
        openssl::rand::rand_bytes(&mut random)?;
        Ok(Self {
            state: EapState::Identity,
            id: random[0],
            method_id: 0,
            challenge: random[1..].try_into().map_err(|_| Error::Provider)?,
            name: None,
            msk: None,
        })
    }
    pub fn state(&self) -> EapState {
        self.state
    }
    pub fn username(&self) -> Option<&[u8]> {
        self.name.as_deref()
    }
    pub fn start(&self) -> Result<Vec<u8>, Error> {
        packet(1, self.id, Some(1), b"")
    }
    pub fn take_msk(&mut self) -> Result<SecretBytes, Error> {
        if self.state != EapState::Complete {
            return Err(Error::Authentication);
        }
        self.msk.take().ok_or(Error::Authentication)
    }
    fn fail(&mut self) -> Result<Vec<u8>, Error> {
        self.msk = None;
        self.state = EapState::Failed;
        packet(4, self.id, None, b"")
    }
    pub fn step(
        &mut self,
        bytes: &[u8],
        store: &mut AuthStore,
        now: Duration,
    ) -> Result<Vec<u8>, Error> {
        if bytes.len() > 512 {
            return self.fail();
        }
        let e = match Eap::decode(bytes) {
            Ok(e) => e,
            Err(_) => return self.fail(),
        };
        if e.code != 2 || e.identifier != self.id {
            return self.fail();
        }
        match self.state {
            EapState::Identity => {
                if e.method != Some(1) || !valid_username(e.data) {
                    return self.fail();
                }
                self.name = Some(e.data.to_vec());
                self.id = self.id.wrapping_add(1);
                self.method_id = self.id;
                self.state = EapState::Challenge;
                let mut body = vec![16];
                body.extend_from_slice(&self.challenge);
                body.extend_from_slice(b"Harbor");
                self.method_packet(1, &body)
            }
            EapState::Challenge => {
                let b = e.data;
                if e.method != Some(26)
                    || b.len() < 55
                    || b.len() > 182
                    || b[0] != 2
                    || b[1] != self.method_id
                    || usize::from(u16::from_be_bytes([b[2], b[3]])) != b.len()
                    || b[4] != 49
                    || b[21..29] != [0; 8]
                    || b[53] != 0
                {
                    return self.fail();
                }
                let peer: &[u8; 16] = b[5..21].try_into().map_err(|_| Error::Authentication)?;
                let nt: &[u8; 24] = b[29..53].try_into().map_err(|_| Error::Authentication)?;
                let name = self.name.as_deref().ok_or(Error::Authentication)?;
                let keys = store.verify(name, &b[54..], &self.challenge, peer, nt, now)?;
                self.id = self.id.wrapping_add(1);
                if let Some(keys) = keys.filter(|_| &b[54..] == name) {
                    self.msk = Some(keys.msk);
                    self.state = EapState::SuccessConfirmation;
                    let mut message = keys.authenticator.expose().to_vec();
                    message.extend_from_slice(b" M=Authenticated");
                    self.method_packet(3, &message)
                } else {
                    self.state = EapState::FailureConfirmation;
                    let mut message = b"E=691 R=0 C=".to_vec();
                    for b in self.challenge {
                        message.extend_from_slice(format!("{b:02X}").as_bytes());
                    }
                    message.extend_from_slice(b" V=3");
                    self.method_packet(4, &message)
                }
            }
            EapState::SuccessConfirmation => {
                if e.method != Some(26) || e.data != [3] {
                    return self.fail();
                }
                self.state = EapState::Complete;
                packet(3, self.id, None, b"")
            }
            EapState::FailureConfirmation => self.fail(),
            EapState::Complete | EapState::Failed => self.fail(),
        }
    }
    fn method_packet(&self, opcode: u8, data: &[u8]) -> Result<Vec<u8>, Error> {
        let n = u16::try_from(data.len() + 4).map_err(|_| Error::InvalidLength)?;
        let mut body = vec![opcode, self.method_id];
        body.extend_from_slice(&n.to_be_bytes());
        body.extend_from_slice(data);
        packet(1, self.id, Some(26), &body)
    }
}
fn packet(code: u8, identifier: u8, method: Option<u8>, data: &[u8]) -> Result<Vec<u8>, Error> {
    Eap {
        code,
        identifier,
        method,
        data,
    }
    .encode()
    .map_err(|_| Error::Authentication)
}
