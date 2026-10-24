use crate::Error;
#[derive(Clone, Copy, Debug)]
pub struct Policy {
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
impl Default for Policy {
    fn default() -> Self {
        Self {
            work_per_second: 200,
            work_burst: 400,
            source_work_per_second: 20,
            source_work_burst: 40,
            max_pending: 1024,
            per_source: 32,
            cookie_threshold: 512,
            lifetime_secs: 10,
            cookie_rotation_secs: 60,
            max_request_bytes: 4096,
            max_response_bytes: 2048,
        }
    }
}
impl Policy {
    pub fn validate(self) -> Result<Self, Error> {
        if !(1..=2000).contains(&self.work_per_second)
            || !(1..=8192).contains(&self.work_burst)
            || !(1..=2000).contains(&self.source_work_per_second)
            || !(1..=4096).contains(&self.source_work_burst)
            || !(1..=4096).contains(&self.max_pending)
            || !(1..=128).contains(&self.per_source)
            || self.per_source > self.max_pending
            || !(1..=self.max_pending).contains(&self.cookie_threshold)
            || !(1..=60).contains(&self.lifetime_secs)
            || !(10..=300).contains(&self.cookie_rotation_secs)
            || !(256..=16_384).contains(&self.max_request_bytes)
            || !(256..=16_384).contains(&self.max_response_bytes)
        {
            return Err(Error::InvalidPolicy);
        }
        Ok(self)
    }
}
