//! Admission before decoding, cookies, point validation or key generation.
use crate::{Error, Policy};
use std::{collections::HashMap, net::Ipv4Addr, time::Duration};

const UNIT: u128 = 1_000_000_000;
const SOURCE_CAPACITY: usize = 1024;
const SOURCE_IDLE: Duration = Duration::from_secs(60);

struct Bucket {
    credit: u128,
    updated: Duration,
}
impl Bucket {
    fn full(burst: u32, now: Duration) -> Self {
        Self {
            credit: u128::from(burst) * UNIT,
            updated: now,
        }
    }
    fn take(&mut self, rate: u32, burst: u32, now: Duration) -> bool {
        self.credit = self
            .credit
            .saturating_add(
                now.saturating_sub(self.updated)
                    .as_nanos()
                    .saturating_mul(u128::from(rate)),
            )
            .min(u128::from(burst) * UNIT);
        self.updated = now;
        if self.credit < UNIT {
            return false;
        }
        self.credit -= UNIT;
        true
    }
}
struct Source {
    bucket: Bucket,
    admitted: Duration,
}
pub(crate) struct WorkLimiter {
    global: Bucket,
    sources: HashMap<Ipv4Addr, Source>,
    last_time: Duration,
    last_sweep: Duration,
    source_idle: Duration,
}
impl WorkLimiter {
    pub fn new(policy: Policy) -> Self {
        Self {
            global: Bucket::full(policy.work_burst, Duration::ZERO),
            sources: HashMap::new(),
            last_time: Duration::ZERO,
            last_sweep: Duration::ZERO,
            // Never reset a partially refilled bucket by expiring its entry.
            source_idle: SOURCE_IDLE.max(Duration::from_secs(u64::from(
                policy
                    .source_work_burst
                    .div_ceil(policy.source_work_per_second),
            ))),
        }
    }
    pub fn expire(&mut self, now: Duration) -> Result<(), Error> {
        if now < self.last_time {
            return Err(Error::ClockWentBackwards);
        }
        self.last_time = now;
        if now.saturating_sub(self.last_sweep) >= Duration::from_secs(1) {
            self.sources
                .retain(|_, s| now.saturating_sub(s.admitted) < self.source_idle);
            self.last_sweep = now;
        }
        Ok(())
    }
    pub fn admit(&mut self, ip: Ipv4Addr, now: Duration, policy: Policy) -> Result<bool, Error> {
        // Failed admissions still advance the clock. No input can refill by reversal.
        self.expire(now)?;
        // Charge globally even for a source denial; no unbounded source allocation.
        if !self
            .global
            .take(policy.work_per_second, policy.work_burst, now)
        {
            return Ok(false);
        }
        if !self.sources.contains_key(&ip) && self.sources.len() >= SOURCE_CAPACITY {
            return Ok(false);
        }
        let source = self.sources.entry(ip).or_insert_with(|| Source {
            bucket: Bucket::full(policy.source_work_burst, now),
            admitted: now,
        });
        if !source
            .bucket
            .take(policy.source_work_per_second, policy.source_work_burst, now)
        {
            return Ok(false);
        }
        source.admitted = now;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fractional_refill_burst_cap_and_clock_reversal() {
        let p = Policy {
            work_per_second: 2,
            work_burst: 2,
            source_work_per_second: 2,
            source_work_burst: 2,
            ..Policy::default()
        };
        let mut l = WorkLimiter::new(p);
        let ip = Ipv4Addr::LOCALHOST;
        assert!(l.admit(ip, Duration::ZERO, p).unwrap());
        assert!(l.admit(ip, Duration::ZERO, p).unwrap());
        assert!(!l.admit(ip, Duration::from_millis(499), p).unwrap());
        assert!(l.admit(ip, Duration::from_millis(500), p).unwrap());
        assert_eq!(
            l.admit(ip, Duration::ZERO, p),
            Err(Error::ClockWentBackwards)
        );
        assert!(l.admit(ip, Duration::from_secs(1000), p).unwrap());
        assert!(l.admit(ip, Duration::from_secs(1000), p).unwrap());
        assert!(!l.admit(ip, Duration::from_secs(1000), p).unwrap());
    }
    #[test]
    fn source_table_fails_closed_and_idle_tick_reclaims_capacity() {
        let p = Policy {
            work_burst: 2048,
            source_work_burst: 1,
            ..Policy::default()
        };
        let mut l = WorkLimiter::new(p);
        for i in 0..SOURCE_CAPACITY as u32 {
            assert!(l.admit(Ipv4Addr::from(i), Duration::ZERO, p).unwrap());
        }
        assert!(!l.admit(Ipv4Addr::LOCALHOST, Duration::ZERO, p).unwrap());
        assert_eq!(l.sources.len(), SOURCE_CAPACITY);
        l.expire(SOURCE_IDLE).unwrap();
        assert!(l.sources.is_empty());
        assert!(l.admit(Ipv4Addr::LOCALHOST, SOURCE_IDLE, p).unwrap());
    }
    #[test]
    fn source_limit_is_shared_across_ports_and_global_limit_across_addresses() {
        let p = Policy {
            work_burst: 3,
            source_work_burst: 1,
            ..Policy::default()
        };
        let mut l = WorkLimiter::new(p);
        assert!(l.admit(Ipv4Addr::LOCALHOST, Duration::ZERO, p).unwrap());
        assert!(!l.admit(Ipv4Addr::LOCALHOST, Duration::ZERO, p).unwrap());
        assert!(
            l.admit(Ipv4Addr::new(127, 0, 0, 2), Duration::ZERO, p)
                .unwrap()
        );
        assert!(
            !l.admit(Ipv4Addr::new(127, 0, 0, 3), Duration::ZERO, p)
                .unwrap()
        );
    }
}

#[cfg(test)]
mod retention_tests {
    use super::*;
    #[test]
    fn idle_expiry_cannot_reset_a_partly_refilled_bucket() {
        let p = Policy {
            work_burst: 8192,
            source_work_per_second: 1,
            source_work_burst: 100,
            ..Policy::default()
        };
        let mut l = WorkLimiter::new(p);
        for _ in 0..100 {
            assert!(l.admit(Ipv4Addr::LOCALHOST, Duration::ZERO, p).unwrap());
        }
        l.expire(Duration::from_secs(60)).unwrap();
        assert_eq!(l.sources.len(), 1);
        for _ in 0..60 {
            assert!(
                l.admit(Ipv4Addr::LOCALHOST, Duration::from_secs(60), p)
                    .unwrap()
            );
        }
        assert!(
            !l.admit(Ipv4Addr::LOCALHOST, Duration::from_secs(60), p)
                .unwrap()
        );
    }
}
