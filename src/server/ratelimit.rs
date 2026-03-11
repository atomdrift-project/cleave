//! Token bucket rate limiter for per-IP request throttling.

use dashmap::DashMap;
use std::net::IpAddr;
use std::time::Instant;

/// Maximum number of tracked IPs before forced eviction.
const MAX_TRACKED_IPS: usize = 50_000;

/// Token bucket rate limiter with per-IP tracking.
pub struct RateLimiter {
    buckets: DashMap<IpAddr, TokenBucket>,
    tokens_per_second: f64,
    max_tokens: f64,
}

impl std::fmt::Debug for RateLimiter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RateLimiter")
            .field("tokens_per_second", &self.tokens_per_second)
            .field("max_tokens", &self.max_tokens)
            .field("active_buckets", &self.buckets.len())
            .finish()
    }
}

#[derive(Debug)]
struct TokenBucket {
    tokens: f64,
    last_update: Instant,
}

impl RateLimiter {
    /// Create a new rate limiter with the given QPS limit.
    #[must_use]
    pub fn new(qps: u32) -> Self {
        Self {
            buckets: DashMap::new(),
            tokens_per_second: f64::from(qps),
            // Allow small burst (1 second worth of tokens)
            max_tokens: f64::from(qps),
        }
    }

    /// Number of IPs currently tracked by the rate limiter.
    #[must_use]
    pub fn active_count(&self) -> usize {
        self.buckets.len()
    }

    /// Check if a request from the given IP is allowed.
    /// Returns `true` if allowed, `false` if rate limited.
    /// A QPS of 0 means unlimited (no rate limiting).
    #[must_use]
    pub fn check(&self, ip: IpAddr) -> bool {
        if self.tokens_per_second == 0.0 {
            return true;
        }

        // Prevent unbounded growth from distributed attacks.
        // If we hit the cap, force an aggressive cleanup first.
        if self.buckets.len() >= MAX_TRACKED_IPS {
            self.cleanup(60);
            // If still over capacity after cleanup, evict everything older than 10s
            if self.buckets.len() >= MAX_TRACKED_IPS {
                self.cleanup(10);
            }
        }

        let now = Instant::now();

        let mut entry = self.buckets.entry(ip).or_insert_with(|| TokenBucket {
            tokens: self.max_tokens,
            last_update: now,
        });

        let bucket = entry.value_mut();

        // Refill tokens based on elapsed time
        let elapsed = now.duration_since(bucket.last_update).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * self.tokens_per_second).min(self.max_tokens);
        bucket.last_update = now;

        // Try to consume one token
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Remove stale entries older than the given duration.
    /// Call periodically to prevent memory growth from many unique IPs.
    pub fn cleanup(&self, max_age_secs: u64) {
        let now = Instant::now();
        self.buckets
            .retain(|_, bucket| now.duration_since(bucket.last_update).as_secs() < max_age_secs);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_allows_within_limit() {
        let limiter = RateLimiter::new(10);
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

        // Should allow burst up to max_tokens
        for _ in 0..10 {
            assert!(limiter.check(ip));
        }
    }

    #[test]
    fn test_blocks_over_limit() {
        let limiter = RateLimiter::new(5);
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

        // Consume all tokens
        for _ in 0..5 {
            assert!(limiter.check(ip));
        }

        // Next request should be blocked
        assert!(!limiter.check(ip));
    }

    #[test]
    fn test_zero_qps_means_unlimited() {
        let limiter = RateLimiter::new(0);
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

        for _ in 0..1000 {
            assert!(limiter.check(ip));
        }
    }

    #[test]
    fn test_different_ips_independent() {
        let limiter = RateLimiter::new(2);
        let ip1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let ip2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

        // Exhaust ip1's tokens
        assert!(limiter.check(ip1));
        assert!(limiter.check(ip1));
        assert!(!limiter.check(ip1));

        // ip2 should still have tokens
        assert!(limiter.check(ip2));
    }
}
