//! Validated codec, initial-handshake limits and explicit IPv4 bind addresses.
use ikev2_wire::Limits;
use serde::Deserialize;

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub codec: CodecConfig,
    pub handshake: HandshakeConfig,
    pub udp: UdpConfig,
    pub authentication: AuthenticationConfig,
    pub poc: PocConfig,
}
#[derive(Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CodecConfig {
    pub message_bytes: usize,
    pub payloads: usize,
    pub proposals: usize,
    pub transforms: usize,
    pub attributes: usize,
}
impl Default for CodecConfig {
    fn default() -> Self {
        let l = Limits::default();
        Self {
            message_bytes: l.message_bytes,
            payloads: l.payloads,
            proposals: l.proposals,
            transforms: l.transforms,
            attributes: l.attributes,
        }
    }
}
impl Config {
    pub fn parse(input: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let config: Self = toml::from_str(input)?;
        config.limits()?;
        config.handshake_policy()?;
        config.udp.validate()?;
        config
            .poc
            .validate(config.authentication.enabled, &config.udp)?;
        Ok(config)
    }
    pub fn handshake_policy(&self) -> Result<ikev2_core::Policy, ikev2_core::Error> {
        let h = &self.handshake;
        ikev2_core::Policy {
            work_per_second: h.work_per_second,
            work_burst: h.work_burst,
            source_work_per_second: h.source_work_per_second,
            source_work_burst: h.source_work_burst,
            max_pending: h.max_pending,
            per_source: h.per_source,
            cookie_threshold: h.cookie_threshold,
            lifetime_secs: h.lifetime_secs,
            cookie_rotation_secs: h.cookie_rotation_secs,
            max_request_bytes: h.max_request_bytes,
            max_response_bytes: h.max_response_bytes,
        }
        .validate()
    }
    pub fn limits(&self) -> Result<Limits, ikev2_wire::Error> {
        let c = &self.codec;
        Limits {
            message_bytes: c.message_bytes,
            payloads: c.payloads,
            proposals: c.proposals,
            transforms: c.transforms,
            attributes: c.attributes,
        }
        .validate()
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn defaults_and_overrides() {
        assert_eq!(
            Config::parse("").unwrap().limits().unwrap(),
            Limits::default()
        );
        assert_eq!(
            Config::parse("[codec]\npayloads = 8")
                .unwrap()
                .limits()
                .unwrap()
                .payloads,
            8
        );
    }
    #[test]
    fn reject_invalid_or_unknown_settings() {
        for text in [
            "[codec]\npayloads = 0",
            "[codec]\npayloads = 129",
            "[codec]\nmessage_bytes = 27",
            "[codec]\nattributes = -1",
            "listen = '0.0.0.0'",
            "[codec]\nunknown = 1",
        ] {
            assert!(Config::parse(text).is_err());
        }
    }
}

#[derive(Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct HandshakeConfig {
    pub work_per_second: u32,
    pub work_burst: u32,
    pub source_work_per_second: u32,
    pub source_work_burst: u32,
    pub max_pending: usize,
    pub per_source: usize,
    pub cookie_threshold: usize,
    pub lifetime_secs: u64,
    pub cookie_rotation_secs: u64,
    pub max_request_bytes: usize,
    pub max_response_bytes: usize,
}
impl Default for HandshakeConfig {
    fn default() -> Self {
        let p = ikev2_core::Policy::default();
        Self {
            work_per_second: p.work_per_second,
            work_burst: p.work_burst,
            source_work_per_second: p.source_work_per_second,
            source_work_burst: p.source_work_burst,
            max_pending: p.max_pending,
            per_source: p.per_source,
            cookie_threshold: p.cookie_threshold,
            lifetime_secs: p.lifetime_secs,
            cookie_rotation_secs: p.cookie_rotation_secs,
            max_request_bytes: p.max_request_bytes,
            max_response_bytes: p.max_response_bytes,
        }
    }
}
#[derive(Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct UdpConfig {
    pub ike: std::net::SocketAddrV4,
    pub natt: std::net::SocketAddrV4,
}
impl Default for UdpConfig {
    fn default() -> Self {
        Self {
            ike: std::net::SocketAddrV4::new(std::net::Ipv4Addr::LOCALHOST, 500),
            natt: std::net::SocketAddrV4::new(std::net::Ipv4Addr::LOCALHOST, 4500),
        }
    }
}
impl UdpConfig {
    pub fn validate(&self) -> Result<(), std::io::Error> {
        for addr in [self.ike, self.natt] {
            if addr.ip().is_unspecified() || addr.ip().is_multicast() || addr.ip().is_broadcast() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "an explicit unicast IPv4 bind address is required",
                ));
            }
        }
        if self.ike == self.natt && self.ike.port() != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "IKE and NAT-T sockets must be distinct",
            ));
        }
        Ok(())
    }
}
#[cfg(test)]
mod handshake_tests {
    use super::*;
    #[test]
    fn safe_limits_and_unicast_binds() {
        for text in [
            "[handshake]\nwork_per_second=0",
            "[handshake]\nwork_per_second=2001",
            "[handshake]\nwork_burst=8193",
            "[handshake]\nsource_work_per_second=2001",
            "[handshake]\nsource_work_burst=4097",
            "[handshake]\nmax_pending=0",
            "[handshake]\nmax_pending=4097",
            "[handshake]\nper_source=129",
            "[handshake]\nlifetime_secs=61",
            "[handshake]\ncookie_rotation_secs=0",
            "[handshake]\nmax_request_bytes=16385",
            "[udp]\nike='0.0.0.0:500'",
            "[udp]\nike='[::1]:500'",
            "[udp]\nike='224.0.0.1:500'",
            "[udp]\nike='127.0.0.1:4500'",
            "[handshake]\nencryption='aes128'",
        ] {
            assert!(Config::parse(text).is_err(), "{text}");
        }
        let c=Config::parse("[handshake]\nmax_pending=2\nper_source=1\ncookie_threshold=1\n[udp]\nike='127.0.0.1:15000'\nnatt='127.0.0.1:14500'").unwrap();
        assert_eq!(c.handshake_policy().unwrap().max_pending, 2);
        assert_eq!(c.udp.ike.port(), 15000);
    }
}

/// Explicit M3 opt-in; secrets are supplied exclusively through systemd credentials.
#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AuthenticationConfig {
    pub enabled: bool,
}

/// Explicit IPv4 PoC; host networking is operator managed.
#[derive(Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PocConfig {
    pub enabled: bool,
    pub pool_start: std::net::Ipv4Addr,
    pub pool_end: std::net::Ipv4Addr,
    pub dns: Vec<std::net::Ipv4Addr>,
    pub lifetime_secs: u64,
    pub reqid_start: u32,
    pub policy_priority: u32,
}
impl Default for PocConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            pool_start: "10.77.0.10".parse().expect("constant IPv4"),
            pool_end: "10.77.0.20".parse().expect("constant IPv4"),
            dns: vec![std::net::Ipv4Addr::new(1, 1, 1, 1)],
            lifetime_secs: 1800,
            reqid_start: 65536,
            policy_priority: 10000,
        }
    }
}
impl PocConfig {
    pub fn child(&self) -> ikev2_core::child::ChildConfig {
        ikev2_core::child::ChildConfig {
            pool_start: self.pool_start,
            pool_end: self.pool_end,
            dns: self.dns.clone(),
            lifetime_secs: self.lifetime_secs,
        }
    }
    fn validate(&self, auth: bool, udp: &UdpConfig) -> Result<(), Box<dyn std::error::Error>> {
        self.child().validate()?;
        if self.enabled
            && (!auth
                || udp.ike.port() != 500
                || udp.natt.port() != 4500
                || udp.ike.ip() != udp.natt.ip()
                || !(65536..=0xffff0000).contains(&self.reqid_start)
                || self.policy_priority == 0)
        {
            return Err(
                "PoC requires authentication, same-IP UDP500/4500, reserved reqid and priority"
                    .into(),
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod poc_tests {
    use super::*;
    #[test]
    fn poc_requires_auth_ports_bounded_pool_and_dns() {
        for config in [
            "[poc]\nenabled=true",
            "[authentication]\nenabled=true\n[poc]\nenabled=true\n[udp]\nike='127.0.0.1:15000'",
            "[poc]\npool_start='8.8.8.8'",
            "[poc]\ndns=[]",
            "[poc]\nlifetime_secs=3601",
        ] {
            assert!(Config::parse(config).is_err(), "{config}");
        }
        assert!(Config::parse(include_str!("../../../config/iphone-poc.toml")).is_ok());
    }
}
