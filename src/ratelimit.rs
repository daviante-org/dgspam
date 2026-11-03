use ipnet::IpNet;
use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

const WINDOW_DURATION: Duration = Duration::from_secs(60);
const MAX_TRACKED_KEYS: usize = 65_536;

#[derive(Debug, Clone)]
pub struct RateLimitDecision {
    pub allowed: bool,
    pub limit: u32,
    pub remaining: u32,
    pub reset_seconds: u64,
    pub retry_after_seconds: Option<u64>,
}

impl RateLimitDecision {
    pub fn headers(&self) -> Vec<(&'static str, String)> {
        let mut out = vec![
            ("x-ratelimit-limit", self.limit.to_string()),
            ("x-ratelimit-remaining", self.remaining.to_string()),
            ("x-ratelimit-reset", self.reset_seconds.to_string()),
        ];
        if let Some(ra) = self.retry_after_seconds {
            out.push(("retry-after", ra.to_string()));
        }
        out
    }
}

struct LimiterInner {
    limit_per_minute: u32,
    buckets: HashMap<String, VecDeque<Instant>>,
    ops_since_sweep: usize,
}

pub struct SlidingWindowRateLimiter {
    inner: Mutex<LimiterInner>,
}

impl SlidingWindowRateLimiter {
    pub fn new(limit_per_minute: u32) -> Self {
        Self {
            inner: Mutex::new(LimiterInner {
                limit_per_minute: limit_per_minute.max(1),
                buckets: HashMap::new(),
                ops_since_sweep: 0,
            }),
        }
    }

    pub fn set_limit(&self, limit_per_minute: u32) {
        if let Ok(mut guard) = self.inner.lock() {
            guard.limit_per_minute = limit_per_minute.max(1);
        }
    }

    pub fn check(&self, caller_key: &str) -> RateLimitDecision {
        let now = Instant::now();
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let limit = guard.limit_per_minute;

        guard.ops_since_sweep += 1;
        if guard.ops_since_sweep >= 1024 || guard.buckets.len() > MAX_TRACKED_KEYS {
            guard.ops_since_sweep = 0;
            guard.buckets.retain(|_, q| {
                while let Some(&front) = q.front() {
                    if now.duration_since(front) >= WINDOW_DURATION {
                        q.pop_front();
                    } else {
                        break;
                    }
                }
                !q.is_empty()
            });
            if guard.buckets.len() > MAX_TRACKED_KEYS {
                guard.buckets.clear();
            }
        }

        let q = guard.buckets.entry(caller_key.to_string()).or_default();
        while let Some(&front) = q.front() {
            if now.duration_since(front) >= WINDOW_DURATION {
                q.pop_front();
            } else {
                break;
            }
        }

        if (q.len() as u32) >= limit {
            let oldest = q.front().copied().unwrap_or(now);
            let elapsed = now.duration_since(oldest);
            let wait = WINDOW_DURATION
                .checked_sub(elapsed)
                .unwrap_or(Duration::from_secs(1))
                .as_secs()
                .max(1);
            RateLimitDecision {
                allowed: false,
                limit,
                remaining: 0,
                reset_seconds: wait,
                retry_after_seconds: Some(wait),
            }
        } else {
            q.push_back(now);
            let remaining = limit.saturating_sub(q.len() as u32);
            let oldest = q.front().copied().unwrap_or(now);
            let reset_seconds = WINDOW_DURATION
                .checked_sub(now.duration_since(oldest))
                .unwrap_or(Duration::from_secs(60))
                .as_secs()
                .max(1);
            RateLimitDecision {
                allowed: true,
                limit,
                remaining,
                reset_seconds,
                retry_after_seconds: None,
            }
        }
    }
}

/// Safely extract caller IP using right-to-left X-Forwarded-For evaluation when peer is trusted.
pub fn extract_client_ip(
    peer_ip: &IpAddr,
    xff_header: Option<&str>,
    trusted_proxies: &[IpNet],
) -> String {
    let peer_trusted = trusted_proxies.iter().any(|net| net.contains(peer_ip));
    if !peer_trusted {
        return peer_ip.to_string();
    }
    let Some(xff) = xff_header else {
        return peer_ip.to_string();
    };
    let hops: Vec<IpAddr> = xff
        .split(',')
        .filter_map(|part| part.trim().parse::<IpAddr>().ok())
        .collect();
    if hops.is_empty() {
        return peer_ip.to_string();
    }
    for candidate in hops.iter().rev() {
        let is_trusted = trusted_proxies.iter().any(|net| net.contains(candidate));
        if !is_trusted {
            return candidate.to_string();
        }
    }
    hops[0].to_string()
}
