//! Foundation configuration only. No network, authentication, or suite policy.
use ikev2_wire::Limits;
use serde::Deserialize;

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub codec: CodecConfig,
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
        Ok(config)
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
