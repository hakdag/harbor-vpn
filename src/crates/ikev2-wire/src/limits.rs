use crate::{Error, ErrorKind};

/// Resource policy, not an RFC validity rule. Every entry point revalidates it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    pub message_bytes: usize,
    pub payloads: usize,
    pub proposals: usize,
    pub transforms: usize,
    pub attributes: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            message_bytes: 65_535,
            payloads: 128,
            proposals: 64,
            transforms: 64,
            attributes: 64,
        }
    }
}
impl Limits {
    /// Fixed safety ceilings. Operators may lower every limit.
    pub const HARD: Self = Self {
        message_bytes: 65_535,
        payloads: 128,
        proposals: 64,
        transforms: 64,
        attributes: 64,
    };
    pub fn validate(self) -> Result<Self, Error> {
        if !(28..=Self::HARD.message_bytes).contains(&self.message_bytes)
            || !(1..=Self::HARD.payloads).contains(&self.payloads)
            || !(1..=Self::HARD.proposals).contains(&self.proposals)
            || !(1..=Self::HARD.transforms).contains(&self.transforms)
            || !(1..=Self::HARD.attributes).contains(&self.attributes)
        {
            return Err(Error::new(0, ErrorKind::InvalidLimits));
        }
        Ok(self)
    }
    pub(crate) fn count(
        value: usize,
        max: usize,
        at: usize,
        name: &'static str,
    ) -> Result<(), Error> {
        if value > max {
            Err(Error::new(at, ErrorKind::Limit(name)))
        } else {
            Ok(())
        }
    }
}
