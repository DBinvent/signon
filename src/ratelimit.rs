//! In-process sliding-window rate limiting.
//!
//! Scope, stated plainly: this counts within one process. Every one of the
//! four services is a single instance behind a tunnel, so that is the whole
//! population today — but if any of them is ever run as more than one
//! process, this becomes per-process and the effective limit multiplies.
//! Moving the counters to Postgres or Redis is the fix at that point; nothing
//! else in the crate has to change, since only [`RateLimiter::check`] is
//! called from the handlers.
//!
//! What it protects: the unauthenticated endpoints that either send mail or
//! test a credential. The per-account resend cooldown in `routes.rs` is a
//! different guard for a different attack (one address, hammered); this one
//! covers the volume attacks (many addresses from one source).

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// How many prunes to skip before sweeping the whole map. Sweeping on every
/// call would make the limiter O(keys) per request.
const SWEEP_EVERY: u32 = 512;

pub struct RateLimiter {
    inner: Mutex<Inner>,
}

struct Inner {
    hits: HashMap<String, Vec<Instant>>,
    calls_since_sweep: u32,
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

impl RateLimiter {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(Inner { hits: HashMap::new(), calls_since_sweep: 0 }),
        }
    }

    /// `true` if this event is within budget (and records it), `false` if the
    /// caller has spent `limit` events in the last `window`.
    ///
    /// A poisoned mutex fails *open* rather than rejecting every request from
    /// then on: a rate limiter that turns into a permanent outage after one
    /// panic elsewhere is worse than one that stops limiting.
    pub fn check(&self, key: &str, limit: usize, window: Duration) -> bool {
        let now = Instant::now();
        let mut inner = match self.inner.lock() {
            Ok(g) => g,
            Err(poisoned) => {
                tracing::warn!("rate limiter mutex poisoned — continuing without limiting");
                poisoned.into_inner()
            }
        };

        inner.calls_since_sweep += 1;
        if inner.calls_since_sweep >= SWEEP_EVERY {
            inner.calls_since_sweep = 0;
            inner.hits.retain(|_, times| {
                times.retain(|t| now.duration_since(*t) < window);
                !times.is_empty()
            });
        }

        let times = inner.hits.entry(key.to_string()).or_default();
        times.retain(|t| now.duration_since(*t) < window);
        if times.len() >= limit {
            return false;
        }
        times.push(now);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_up_to_the_limit_then_refuses() {
        let rl = RateLimiter::new();
        let window = Duration::from_secs(60);
        assert!(rl.check("a", 3, window));
        assert!(rl.check("a", 3, window));
        assert!(rl.check("a", 3, window));
        assert!(!rl.check("a", 3, window));
    }

    #[test]
    fn keys_are_independent() {
        let rl = RateLimiter::new();
        let window = Duration::from_secs(60);
        assert!(rl.check("a", 1, window));
        assert!(!rl.check("a", 1, window));
        assert!(rl.check("b", 1, window));
    }

    #[test]
    fn events_fall_out_of_the_window() {
        let rl = RateLimiter::new();
        let window = Duration::from_millis(30);
        assert!(rl.check("a", 1, window));
        assert!(!rl.check("a", 1, window));
        std::thread::sleep(Duration::from_millis(45));
        assert!(rl.check("a", 1, window), "the earlier hit should have aged out");
    }
}
