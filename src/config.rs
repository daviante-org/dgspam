use crate::types::{DgspamguardError, DgspamguardResult};
use std::env;
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct Settings {
    pub database_url: String,
    pub db_pool_min_size: usize,
    pub db_pool_max_size: usize,
    pub host: String,
    pub port: u16,
    pub swagger_enabled: bool,
    pub assets_dir: PathBuf,
    pub cache_dir: PathBuf,
    pub bootstrap_on_startup: bool,
    pub bootstrap_bundle_url_override: Option<String>,
    pub sync_scheduler_enabled: bool,
    pub sync_interval_seconds: u64,
    pub snapshot_interval_seconds: u64,
    pub sync_http_timeout_seconds: f64,
    pub retention_days: i64,
    pub rate_limit_per_minute_override: Option<u32>,
    pub trusted_proxies_override: Option<String>,
    pub abusech_auth_key_override: Option<String>,
    pub log_level: String,
}

impl Settings {
    pub fn from_env() -> DgspamguardResult<Self> {
        let _ = dotenvy::dotenv();

        let database_url = env::var("DGSPAMGUARD_DATABASE_URL")
            .or_else(|_| env::var("DATABASE_URL"))
            .unwrap_or_else(|_| {
                "postgresql://dgspamguard:dgspamguard@127.0.0.1:5432/dgspamguard".to_string()
            });

        if database_url.trim().is_empty() {
            return Err(DgspamguardError::Validation(
                "DGSPAMGUARD_DATABASE_URL must not be empty.".to_string(),
            ));
        }

        let db_pool_min_size = parse_usize("DGSPAMGUARD_DB_POOL_MIN_SIZE", 2, 1, 128)?;
        let db_pool_max_size = parse_usize("DGSPAMGUARD_DB_POOL_MAX_SIZE", 16, 1, 256)?;
        if db_pool_min_size > db_pool_max_size {
            return Err(DgspamguardError::Validation(
                "DGSPAMGUARD_DB_POOL_MIN_SIZE cannot exceed DGSPAMGUARD_DB_POOL_MAX_SIZE."
                    .to_string(),
            ));
        }

        let host = env::var("DGSPAMGUARD_HOST").unwrap_or_else(|_| "0.0.0.0".to_string());
        let port = parse_u16("DGSPAMGUARD_PORT", 8091)?;
        let swagger_enabled = parse_bool("DGSPAMGUARD_SWAGGER_ENABLED", true)?;

        let assets_dir = env::var("DGSPAMGUARD_ASSETS_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("assets"));
        let cache_dir = env::var("DGSPAMGUARD_CACHE_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| env::temp_dir().join("dgspamguard-cache"));

        let bootstrap_on_startup = parse_bool("DGSPAMGUARD_BOOTSTRAP_ON_STARTUP", true)?;
        let bootstrap_bundle_url_override = env::var("DGSPAMGUARD_BOOTSTRAP_BUNDLE_URL")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());

        let sync_scheduler_enabled = parse_bool("DGSPAMGUARD_SYNC_SCHEDULER_ENABLED", true)?;
        // Per-feed deadline scheduler max check interval (default 60s; legacy 7200s values remain valid without throttling fast 15m feeds)
        let sync_interval_seconds =
            parse_u64("DGSPAMGUARD_SYNC_INTERVAL_SECONDS", 60, 15, 604_800)?;
        // Rolling snapshot tarball packaging interval (default 4 hours = 14400s; live A/B slot swaps remain immediate on 15m/30m feeds)
        let snapshot_interval_seconds = parse_u64(
            "DGSPAMGUARD_SNAPSHOT_INTERVAL_SECONDS",
            14_400,
            300,
            604_800,
        )?;
        let sync_http_timeout_seconds =
            parse_f64("DGSPAMGUARD_SYNC_HTTP_TIMEOUT_SECONDS", 90.0, 5.0, 600.0)?;
        // Default 7-day rolling retention
        let retention_days = parse_i64("DGSPAMGUARD_RETENTION_DAYS", 7, 1, 90)?;

        let rate_limit_per_minute_override = match env::var("DGSPAMGUARD_RATE_LIMIT_PER_MINUTE") {
            Ok(v) if !v.trim().is_empty() => {
                let parsed: u32 = v.trim().parse().map_err(|_| {
                    DgspamguardError::Validation(format!(
                        "Invalid DGSPAMGUARD_RATE_LIMIT_PER_MINUTE value: {v}"
                    ))
                })?;
                if parsed == 0 || parsed > 1_000_000 {
                    return Err(DgspamguardError::Validation(
                        "DGSPAMGUARD_RATE_LIMIT_PER_MINUTE must be between 1 and 1000000."
                            .to_string(),
                    ));
                }
                Some(parsed)
            }
            _ => None,
        };

        let trusted_proxies_override = env::var("DGSPAMGUARD_TRUSTED_PROXIES")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());

        let abusech_auth_key_override = env::var("DGSPAMGUARD_ABUSECH_AUTH_KEY")
            .or_else(|_| env::var("ABUSECH_AUTH_KEY"))
            .ok()
            .map(|s| s.trim().trim_matches('"').trim_matches('\'').to_string())
            .filter(|s| !s.is_empty());

        let log_level = env::var("DGSPAMGUARD_LOG_LEVEL").unwrap_or_else(|_| "info".to_string());

        Ok(Self {
            database_url,
            db_pool_min_size,
            db_pool_max_size,
            host,
            port,
            swagger_enabled,
            assets_dir,
            cache_dir,
            bootstrap_on_startup,
            bootstrap_bundle_url_override,
            sync_scheduler_enabled,
            sync_interval_seconds,
            snapshot_interval_seconds,
            sync_http_timeout_seconds,
            retention_days,
            rate_limit_per_minute_override,
            trusted_proxies_override,
            abusech_auth_key_override,
            log_level,
        })
    }
}

fn parse_bool(key: &str, default: bool) -> DgspamguardResult<bool> {
    match env::var(key) {
        Ok(raw) => match raw.trim().to_ascii_lowercase().as_str() {
            "" => Ok(default),
            "1" | "true" | "yes" | "on" => Ok(true),
            "0" | "false" | "no" | "off" => Ok(false),
            other => Err(DgspamguardError::Validation(format!(
                "Invalid boolean in {key}: {other}"
            ))),
        },
        Err(_) => Ok(default),
    }
}

fn parse_u16(key: &str, default: u16) -> DgspamguardResult<u16> {
    match env::var(key) {
        Ok(raw) if !raw.trim().is_empty() => {
            let v: u16 = raw.trim().parse().map_err(|_| {
                DgspamguardError::Validation(format!("Invalid port in {key}: {raw}"))
            })?;
            if v == 0 {
                return Err(DgspamguardError::Validation(format!(
                    "{key} must be between 1 and 65535."
                )));
            }
            Ok(v)
        }
        _ => Ok(default),
    }
}

fn parse_usize(key: &str, default: usize, min: usize, max: usize) -> DgspamguardResult<usize> {
    match env::var(key) {
        Ok(raw) if !raw.trim().is_empty() => {
            let v: usize = raw.trim().parse().map_err(|_| {
                DgspamguardError::Validation(format!("Invalid integer in {key}: {raw}"))
            })?;
            if v < min || v > max {
                return Err(DgspamguardError::Validation(format!(
                    "{key} must be between {min} and {max} (got {v})."
                )));
            }
            Ok(v)
        }
        _ => Ok(default),
    }
}

fn parse_u64(key: &str, default: u64, min: u64, max: u64) -> DgspamguardResult<u64> {
    match env::var(key) {
        Ok(raw) if !raw.trim().is_empty() => {
            let v: u64 = raw.trim().parse().map_err(|_| {
                DgspamguardError::Validation(format!("Invalid integer in {key}: {raw}"))
            })?;
            if v < min || v > max {
                return Err(DgspamguardError::Validation(format!(
                    "{key} must be between {min} and {max} (got {v})."
                )));
            }
            Ok(v)
        }
        _ => Ok(default),
    }
}

fn parse_i64(key: &str, default: i64, min: i64, max: i64) -> DgspamguardResult<i64> {
    match env::var(key) {
        Ok(raw) if !raw.trim().is_empty() => {
            let v: i64 = raw.trim().parse().map_err(|_| {
                DgspamguardError::Validation(format!("Invalid integer in {key}: {raw}"))
            })?;
            if v < min || v > max {
                return Err(DgspamguardError::Validation(format!(
                    "{key} must be between {min} and {max} (got {v})."
                )));
            }
            Ok(v)
        }
        _ => Ok(default),
    }
}

fn parse_f64(key: &str, default: f64, min: f64, max: f64) -> DgspamguardResult<f64> {
    match env::var(key) {
        Ok(raw) if !raw.trim().is_empty() => {
            let v: f64 = raw.trim().parse().map_err(|_| {
                DgspamguardError::Validation(format!("Invalid float in {key}: {raw}"))
            })?;
            if !v.is_finite() || v < min || v > max {
                return Err(DgspamguardError::Validation(format!(
                    "{key} must be between {min} and {max} (got {v})."
                )));
            }
            Ok(v)
        }
        _ => Ok(default),
    }
}
