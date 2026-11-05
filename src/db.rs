use crate::config::Settings;
use crate::models::{
    BatchCheckItemResult, BatchCheckResponse, DomainLookupResponse, DomainTaxonomyInfo,
    DomainThreatInfo, HashLookupResponse, HealthReadyResponse, IpLookupResponse,
    SnapshotDetailResponse, SnapshotFileItem, SnapshotListResponse, SnapshotSummaryItem,
    TldReputation, UrlCheckResponse,
};
use crate::normalize::{
    canonicalize_url_with_ip, classify_indicator, domain_lookup_chain, extract_tld, gunzip_bounded,
    is_public_routable_ip, normalize_domain, normalize_ip_literal, normalize_sha256,
    IndicatorInput, PslMatcher,
};
use crate::release_notes::{format_snapshot_version, utc_timestamp_base_tag};
use crate::seed_data::{
    build_default_feed_sources, default_allowlist_rules, default_tld_risk_rules,
    extract_seed_memory_sets, DEFAULT_ALLOWED_HOSTS, DEFAULT_BOOTSTRAP_BUNDLE_URL,
};
use crate::types::{
    AllowlistRule, ArtifactSource, CachedArtifact, CompiledThreatSet, DgspamguardError,
    DgspamguardResult, FeedSourceSpec, PackagedSnapshot, RuntimeCatalog, SnapshotArtifactMeta,
    TldRiskRule, DATASET_FILENAMES,
};
use bytes::Bytes;
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use deadpool_postgres::{Manager, ManagerConfig, Pool, RecyclingMethod, Runtime, Transaction};
use futures_util::SinkExt;
use ipnet::IpNet;
use rustls::ClientConfig;
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::io::Write;
use std::net::IpAddr;
use std::path::PathBuf;
use std::pin::pin;
use std::sync::{Arc, RwLock as StdRwLock};
use tokio::sync::Mutex as AsyncMutex;
use tokio_postgres::config::SslMode;
use tokio_postgres::CopyInSink;
use tokio_postgres_rustls::MakeRustlsConnect;

pub const ADVISORY_LOCK_KEY: i64 = 0x4447_5350_414d_0001; // "DGSPAMGUARD\x00\x01"

pub const SCHEMA_SQL: &str = r#"
CREATE TABLE IF NOT EXISTS dgspamguard_state (
    id                      SMALLINT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    catalog_seeded          BOOLEAN NOT NULL DEFAULT FALSE,
    catalog_version         BIGINT NOT NULL DEFAULT 1,
    initial_bootstrapped    BOOLEAN NOT NULL DEFAULT FALSE,
    active_slot             TEXT NOT NULL DEFAULT '',
    active_version          TEXT,
    live_fingerprint        TEXT,
    live_updated_at         TIMESTAMPTZ,
    last_sync_attempt_at    TIMESTAMPTZ,
    last_sync_success_at    TIMESTAMPTZ,
    last_sync_error         TEXT,
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT now()
);

INSERT INTO dgspamguard_state (id) VALUES (1) ON CONFLICT (id) DO NOTHING;

CREATE TABLE IF NOT EXISTS dgspamguard_config (
    key         TEXT PRIMARY KEY,
    value_json  JSONB NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS dgspamguard_feed_sources (
    feed_key                  TEXT PRIMARY KEY,
    category                  TEXT NOT NULL,
    parser_kind               TEXT NOT NULL,
    source_url                TEXT NOT NULL,
    refresh_interval_seconds  BIGINT NOT NULL DEFAULT 7200,
    min_records               INTEGER NOT NULL DEFAULT 100,
    max_compressed_bytes      BIGINT NOT NULL DEFAULT 67108864,
    max_uncompressed_bytes    BIGINT NOT NULL DEFAULT 134217728,
    confidence_weight         SMALLINT NOT NULL DEFAULT 60,
    enabled                   BOOLEAN NOT NULL DEFAULT TRUE,
    display_order             SMALLINT NOT NULL DEFAULT 10,
    etag                      TEXT,
    last_modified             TEXT,
    last_fetched_at           TIMESTAMPTZ,
    cached_payload            BYTEA,
    updated_at                TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS dgspamguard_allowed_hosts (
    hostname    TEXT PRIMARY KEY,
    enabled     BOOLEAN NOT NULL DEFAULT TRUE,
    notes       TEXT NOT NULL DEFAULT '',
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS dgspamguard_allowlist (
    domain      TEXT PRIMARY KEY,
    kind        TEXT NOT NULL CHECK (kind IN ('trusted', 'shared_hosting')),
    notes       TEXT NOT NULL DEFAULT '',
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS dgspamguard_tld_risk (
    tld         TEXT PRIMARY KEY,
    risk_score  SMALLINT NOT NULL,
    risk_level  TEXT NOT NULL,
    notes       TEXT NOT NULL DEFAULT '',
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS dgspamguard_snapshots (
    version             TEXT PRIMARY KEY,
    release_title       TEXT NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    fingerprint         TEXT NOT NULL,
    threat_domains      BIGINT NOT NULL DEFAULT 0,
    threat_urls         BIGINT NOT NULL DEFAULT 0,
    threat_ips          BIGINT NOT NULL DEFAULT 0,
    disposable_domains  BIGINT NOT NULL DEFAULT 0,
    free_domains        BIGINT NOT NULL DEFAULT 0,
    redirector_domains  BIGINT NOT NULL DEFAULT 0,
    malware_hashes      BIGINT NOT NULL DEFAULT 0,
    bundle_sha256       TEXT NOT NULL,
    bundle_size_bytes   BIGINT NOT NULL,
    manifest_json       JSONB NOT NULL,
    release_notes_md    TEXT NOT NULL DEFAULT '',
    has_blobs           BOOLEAN NOT NULL DEFAULT TRUE
);

ALTER TABLE dgspamguard_snapshots ADD COLUMN IF NOT EXISTS threat_ips BIGINT NOT NULL DEFAULT 0;

CREATE TABLE IF NOT EXISTS dgspamguard_snapshot_files (
    version      TEXT NOT NULL REFERENCES dgspamguard_snapshots(version) ON DELETE CASCADE,
    filename     TEXT NOT NULL,
    content_type TEXT NOT NULL,
    sha256       TEXT NOT NULL,
    size_bytes   BIGINT NOT NULL,
    record_count BIGINT,
    payload      BYTEA NOT NULL,
    PRIMARY KEY (version, filename)
);

CREATE TABLE IF NOT EXISTS dgspamguard_domains_a (
    domain            TEXT PRIMARY KEY,
    registered_domain TEXT NOT NULL,
    threat_category   TEXT,
    confidence        SMALLINT NOT NULL,
    source_count      SMALLINT NOT NULL,
    sources           TEXT NOT NULL,
    email_kind        TEXT
);

CREATE TABLE IF NOT EXISTS dgspamguard_domains_b (
    domain            TEXT PRIMARY KEY,
    registered_domain TEXT NOT NULL,
    threat_category   TEXT,
    confidence        SMALLINT NOT NULL,
    source_count      SMALLINT NOT NULL,
    sources           TEXT NOT NULL,
    email_kind        TEXT
);

CREATE TABLE IF NOT EXISTS dgspamguard_urls_a (
    url_sha256      CHAR(64) PRIMARY KEY,
    domain          TEXT NOT NULL,
    canonical_url   TEXT NOT NULL,
    threat_category TEXT NOT NULL,
    confidence      SMALLINT NOT NULL,
    source_count    SMALLINT NOT NULL,
    sources         TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS dgspamguard_urls_b (
    url_sha256      CHAR(64) PRIMARY KEY,
    domain          TEXT NOT NULL,
    canonical_url   TEXT NOT NULL,
    threat_category TEXT NOT NULL,
    confidence      SMALLINT NOT NULL,
    source_count    SMALLINT NOT NULL,
    sources         TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS dgspamguard_hashes_a (
    sha256         CHAR(64) PRIMARY KEY,
    malware_family TEXT NOT NULL,
    confidence     SMALLINT NOT NULL,
    sources        TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS dgspamguard_hashes_b (
    sha256         CHAR(64) PRIMARY KEY,
    malware_family TEXT NOT NULL,
    confidence     SMALLINT NOT NULL,
    sources        TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS dgspamguard_ips_a (
    network         CIDR PRIMARY KEY,
    threat_category TEXT NOT NULL,
    confidence      SMALLINT NOT NULL,
    source_count    SMALLINT NOT NULL,
    sources         TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_dgspamguard_ips_a_gist ON dgspamguard_ips_a USING gist (network inet_ops);

CREATE TABLE IF NOT EXISTS dgspamguard_ips_b (
    network         CIDR PRIMARY KEY,
    threat_category TEXT NOT NULL,
    confidence      SMALLINT NOT NULL,
    source_count    SMALLINT NOT NULL,
    sources         TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_dgspamguard_ips_b_gist ON dgspamguard_ips_b USING gist (network inet_ops);
"#;

#[derive(Debug, Clone)]
pub struct DbStateSnapshot {
    pub initial_bootstrapped: bool,
    pub active_slot: String,
    pub active_version: Option<String>,
    pub live_fingerprint: Option<String>,
    pub live_updated_at: Option<DateTime<Utc>>,
    pub last_sync_attempt_at: Option<DateTime<Utc>>,
    pub last_sync_success_at: Option<DateTime<Utc>>,
    pub last_sync_error: Option<String>,
}

struct InMemoryLookupMeta {
    psl: PslMatcher,
    trusted_domains: HashSet<String>,
    shared_hosting_domains: HashSet<String>,
    tld_map: HashMap<String, TldRiskRule>,
    active_slot: String,
    active_version: String,
    live_updated_at: Option<DateTime<Utc>>,
}

impl Default for InMemoryLookupMeta {
    fn default() -> Self {
        let psl = PslMatcher::default();
        let mut trusted_domains = HashSet::new();
        let mut shared_hosting_domains: HashSet<String> = psl.private_roots().clone();
        if let Ok((seed_trusted, _)) = extract_seed_memory_sets() {
            trusted_domains.extend(seed_trusted);
        }
        for r in default_allowlist_rules() {
            if r.kind == "shared_hosting" {
                shared_hosting_domains.insert(r.domain);
            } else {
                trusted_domains.insert(r.domain);
            }
        }
        let mut tld_map = HashMap::new();
        for t in default_tld_risk_rules() {
            tld_map.insert(t.tld.clone(), t);
        }
        Self {
            psl,
            trusted_domains,
            shared_hosting_domains,
            tld_map,
            active_slot: String::new(),
            active_version: String::new(),
            live_updated_at: None,
        }
    }
}

#[derive(Clone)]
pub struct Database {
    pool: Pool,
    settings: Settings,
    meta: Arc<StdRwLock<InMemoryLookupMeta>>,
    sync_mutex: Arc<AsyncMutex<()>>,
}

impl Database {
    pub async fn connect(settings: &Settings) -> DgspamguardResult<Self> {
        let pg_cfg: tokio_postgres::Config = settings
            .database_url
            .parse()
            .map_err(|e| DgspamguardError::Database(format!("Invalid PostgreSQL URL: {e}")))?;

        let mut root_store = rustls::RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let tls_cfg =
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .map_err(|e| DgspamguardError::Database(format!("TLS init failed: {e}")))?
                .with_root_certificates(root_store)
                .with_no_client_auth();

        let tls_connector = MakeRustlsConnect::new(tls_cfg);
        let mgr_cfg = ManagerConfig {
            recycling_method: RecyclingMethod::Fast,
        };
        let mgr = if pg_cfg.get_ssl_mode() == SslMode::Disable {
            Manager::from_config(pg_cfg, tokio_postgres::NoTls, mgr_cfg)
        } else {
            Manager::from_config(pg_cfg, tls_connector, mgr_cfg)
        };

        let pool = Pool::builder(mgr)
            .max_size(settings.db_pool_max_size)
            .runtime(Runtime::Tokio1)
            .build()
            .map_err(|e| DgspamguardError::Database(format!("Pool creation failed: {e}")))?;

        let db = Self {
            pool,
            settings: settings.clone(),
            meta: Arc::new(StdRwLock::new(InMemoryLookupMeta::default())),
            sync_mutex: Arc::new(AsyncMutex::new(())),
        };
        db.init_schema_and_seed().await?;
        db.refresh_in_memory_meta().await?;
        Ok(db)
    }

    pub fn sync_mutex(&self) -> Arc<AsyncMutex<()>> {
        Arc::clone(&self.sync_mutex)
    }

    async fn init_schema_and_seed(&self) -> DgspamguardResult<()> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| DgspamguardError::Database(format!("DB connection failed: {e}")))?;

        client
            .batch_execute(SCHEMA_SQL)
            .await
            .map_err(|e| DgspamguardError::Database(format!("Schema migration failed: {e}")))?;

        let row = client
            .query_one(
                "SELECT catalog_seeded FROM dgspamguard_state WHERE id = 1",
                &[],
            )
            .await
            .map_err(|e| DgspamguardError::Database(e.to_string()))?;
        let seeded: bool = row.get(0);

        // Always ensure default config keys exist via ON CONFLICT DO NOTHING
        let default_configs: &[(&str, Value, &str)] = &[
            (
                "bootstrap_bundle_url",
                json!(DEFAULT_BOOTSTRAP_BUNDLE_URL),
                "Release bundle URL used for fast cold-start bootstrap",
            ),
            (
                "rate_limit_per_minute",
                json!(240),
                "Per-client sliding-window HTTP rate limit per minute",
            ),
            (
                "trusted_proxies",
                json!([
                    "127.0.0.1/32",
                    "::1/128",
                    "10.0.0.0/8",
                    "172.16.0.0/12",
                    "192.168.0.0/16"
                ]),
                "Trusted reverse-proxy CIDRs for X-Forwarded-For extraction",
            ),
            (
                "swagger_enabled",
                json!(true),
                "Expose /docs and /openapi.json endpoints",
            ),
            (
                "retention_days",
                json!(self.settings.retention_days),
                "Rolling snapshot retention window in days",
            ),
            (
                "version_prefix",
                json!("v"),
                "Prefix for UTC timestamp snapshot tags (vYYYYMMDD.HHMM)",
            ),
            (
                "release_title_template",
                json!("{version}"),
                "Template for rolling snapshot release titles",
            ),
            (
                "snapshot_seq_map",
                json!({}),
                "Monotonic intra-minute UTC snapshot collision counter map",
            ),
        ];

        for (k, v, desc) in default_configs {
            client
                .execute(
                    "INSERT INTO dgspamguard_config (key, value_json, description) VALUES ($1, $2, $3) ON CONFLICT (key) DO NOTHING",
                    &[k, v, desc],
                )
                .await
                .map_err(|e| DgspamguardError::Database(e.to_string()))?;
        }

        // Always ensure built-in allowed hosts and default feeds exist via ON CONFLICT DO NOTHING
        // so upgrades automatically register newly added authoritative feeds without overwriting operator edits.
        for &host in DEFAULT_ALLOWED_HOSTS {
            client
                .execute(
                    "INSERT INTO dgspamguard_allowed_hosts (hostname, enabled, notes) VALUES ($1, TRUE, 'Default feed host') ON CONFLICT (hostname) DO NOTHING",
                    &[&host],
                )
                .await
                .map_err(|e| DgspamguardError::Database(e.to_string()))?;
        }

        let default_feeds = build_default_feed_sources();
        for spec in &default_feeds {
            client
                .execute(
                    r#"INSERT INTO dgspamguard_feed_sources (
                        feed_key, category, parser_kind, source_url, refresh_interval_seconds,
                        min_records, max_compressed_bytes, max_uncompressed_bytes,
                        confidence_weight, enabled, display_order
                    ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
                    ON CONFLICT (feed_key) DO NOTHING"#,
                    &[
                        &spec.feed_key,
                        &spec.category,
                        &spec.parser_kind,
                        &spec.source_url,
                        &spec.refresh_interval_seconds,
                        &spec.min_records,
                        &spec.max_compressed_bytes,
                        &spec.max_uncompressed_bytes,
                        &spec.confidence_weight,
                        &spec.enabled,
                        &spec.display_order,
                    ],
                )
                .await
                .map_err(|e| DgspamguardError::Database(e.to_string()))?;
        }

        // One-time migration to per-feed native refresh intervals (15m/30m/1h/4h/12h/24h)
        // without overwriting subsequent operator customizations via `dgspamguard feed set-ttl`.
        let ttl_v2_applied = client
            .query_opt(
                "SELECT value_json FROM dgspamguard_config WHERE key = 'feed_ttl_schedule_v2'",
                &[],
            )
            .await
            .map_err(|e| DgspamguardError::Database(e.to_string()))?
            .and_then(|r| r.get::<_, Value>(0).as_bool())
            .unwrap_or(false);

        if !ttl_v2_applied {
            for spec in &default_feeds {
                client
                    .execute(
                        "UPDATE dgspamguard_feed_sources SET refresh_interval_seconds = $2, updated_at = now() WHERE feed_key = $1",
                        &[&spec.feed_key, &spec.refresh_interval_seconds],
                    )
                    .await
                    .map_err(|e| DgspamguardError::Database(e.to_string()))?;
            }
            client
                .execute(
                    "INSERT INTO dgspamguard_config (key, value_json, description, updated_at) VALUES ('feed_ttl_schedule_v2', $1, 'Per-feed native refresh schedule migration applied', now()) ON CONFLICT (key) DO UPDATE SET value_json = EXCLUDED.value_json, updated_at = now()",
                    &[&json!(true)],
                )
                .await
                .map_err(|e| DgspamguardError::Database(e.to_string()))?;
        }

        if !seeded {
            for rule in default_allowlist_rules() {
                client
                    .execute(
                        "INSERT INTO dgspamguard_allowlist (domain, kind, notes) VALUES ($1, $2, $3) ON CONFLICT (domain) DO NOTHING",
                        &[&rule.domain, &rule.kind, &rule.notes],
                    )
                    .await
                    .map_err(|e| DgspamguardError::Database(e.to_string()))?;
            }

            for tld in default_tld_risk_rules() {
                client
                    .execute(
                        "INSERT INTO dgspamguard_tld_risk (tld, risk_score, risk_level, notes) VALUES ($1, $2, $3, $4) ON CONFLICT (tld) DO NOTHING",
                        &[&tld.tld, &tld.risk_score, &tld.risk_level, &tld.notes],
                    )
                    .await
                    .map_err(|e| DgspamguardError::Database(e.to_string()))?;
            }

            client
                .execute(
                    "UPDATE dgspamguard_state SET catalog_seeded = TRUE, updated_at = now() WHERE id = 1",
                    &[],
                )
                .await
                .map_err(|e| DgspamguardError::Database(e.to_string()))?;
        }

        Ok(())
    }

    pub async fn refresh_in_memory_meta(&self) -> DgspamguardResult<()> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| DgspamguardError::Database(e.to_string()))?;

        let state_row = client
            .query_one(
                "SELECT active_slot, COALESCE(active_version, ''), live_updated_at FROM dgspamguard_state WHERE id = 1",
                &[],
            )
            .await
            .map_err(|e| DgspamguardError::Database(e.to_string()))?;

        let active_slot: String = state_row.get(0);
        let active_version: String = state_row.get(1);
        let live_updated_at: Option<DateTime<Utc>> = state_row.get(2);

        // Load cached PSL if available
        let psl_row = client
            .query_opt(
                "SELECT cached_payload FROM dgspamguard_feed_sources WHERE parser_kind = 'psl_dat' AND cached_payload IS NOT NULL ORDER BY display_order LIMIT 1",
                &[],
            )
            .await
            .map_err(|e| DgspamguardError::Database(e.to_string()))?;

        let psl = if let Some(r) = psl_row {
            let bytes: Vec<u8> = r.get(0);
            let decoded = if bytes.len() >= 2 && bytes[0] == 0x1f && bytes[1] == 0x8b {
                gunzip_bounded(&bytes, 16 * 1024 * 1024).unwrap_or_default()
            } else {
                bytes
            };
            if decoded.is_empty() {
                PslMatcher::default()
            } else {
                PslMatcher::from_psl_dat(&String::from_utf8_lossy(&decoded))
            }
        } else {
            PslMatcher::default()
        };

        let mut trusted_domains = HashSet::new();
        let mut shared_hosting_domains: HashSet<String> = psl.private_roots().clone();
        if let Ok((seed_trusted, _)) = extract_seed_memory_sets() {
            trusted_domains.extend(seed_trusted);
        }

        let allow_rows = client
            .query("SELECT domain, kind FROM dgspamguard_allowlist", &[])
            .await
            .map_err(|e| DgspamguardError::Database(e.to_string()))?;
        for r in allow_rows {
            let dom: String = r.get(0);
            let kind: String = r.get(1);
            if kind == "shared_hosting" {
                shared_hosting_domains.insert(dom);
            } else {
                trusted_domains.insert(dom);
            }
        }

        let tld_rows = client
            .query(
                "SELECT tld, risk_score, risk_level, notes FROM dgspamguard_tld_risk",
                &[],
            )
            .await
            .map_err(|e| DgspamguardError::Database(e.to_string()))?;
        let mut tld_map = HashMap::with_capacity(tld_rows.len());
        for r in tld_rows {
            let rule = TldRiskRule {
                tld: r.get(0),
                risk_score: r.get(1),
                risk_level: r.get(2),
                notes: r.get(3),
            };
            tld_map.insert(rule.tld.clone(), rule);
        }

        let mut guard = self.meta.write().unwrap_or_else(|e| e.into_inner());
        *guard = InMemoryLookupMeta {
            psl,
            trusted_domains,
            shared_hosting_domains,
            tld_map,
            active_slot,
            active_version,
            live_updated_at,
        };
        Ok(())
    }

    pub async fn get_state(&self) -> DgspamguardResult<DbStateSnapshot> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| DgspamguardError::Database(e.to_string()))?;
        let r = client
            .query_one(
                r#"SELECT initial_bootstrapped, active_slot, active_version, live_fingerprint,
                          live_updated_at, last_sync_attempt_at, last_sync_success_at, last_sync_error
                   FROM dgspamguard_state WHERE id = 1"#,
                &[],
            )
            .await
            .map_err(|e| DgspamguardError::Database(e.to_string()))?;

        Ok(DbStateSnapshot {
            initial_bootstrapped: r.get(0),
            active_slot: r.get(1),
            active_version: r.get(2),
            live_fingerprint: r.get(3),
            live_updated_at: r.get(4),
            last_sync_attempt_at: r.get(5),
            last_sync_success_at: r.get(6),
            last_sync_error: r.get(7),
        })
    }

    pub async fn readiness(&self) -> DgspamguardResult<HealthReadyResponse> {
        let st = self.get_state().await?;
        let ready = st.initial_bootstrapped && (st.active_slot == "a" || st.active_slot == "b");
        Ok(HealthReadyResponse {
            status: if ready {
                "ready".to_string()
            } else {
                "initializing".to_string()
            },
            active_slot: if st.active_slot.is_empty() {
                None
            } else {
                Some(st.active_slot)
            },
            active_version: st.active_version,
            initial_bootstrapped: st.initial_bootstrapped,
        })
    }

    pub async fn load_runtime_catalog(&self) -> DgspamguardResult<RuntimeCatalog> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| DgspamguardError::Database(e.to_string()))?;

        let cfg_rows = client
            .query("SELECT key, value_json FROM dgspamguard_config", &[])
            .await
            .map_err(|e| DgspamguardError::Database(e.to_string()))?;
        let mut cfg_map: HashMap<String, Value> = HashMap::new();
        for r in cfg_rows {
            cfg_map.insert(r.get(0), r.get(1));
        }

        let bootstrap_bundle_url = self
            .settings
            .bootstrap_bundle_url_override
            .clone()
            .or_else(|| {
                cfg_map
                    .get("bootstrap_bundle_url")
                    .and_then(Value::as_str)
                    .map(String::from)
            })
            .unwrap_or_else(|| DEFAULT_BOOTSTRAP_BUNDLE_URL.to_string());

        let rate_limit_per_minute = self
            .settings
            .rate_limit_per_minute_override
            .or_else(|| {
                cfg_map
                    .get("rate_limit_per_minute")
                    .and_then(Value::as_u64)
                    .map(|v| v as u32)
            })
            .unwrap_or(240)
            .max(1);

        let swagger_enabled = self.settings.swagger_enabled
            && cfg_map
                .get("swagger_enabled")
                .and_then(Value::as_bool)
                .unwrap_or(true);

        let retention_days = cfg_map
            .get("retention_days")
            .and_then(Value::as_i64)
            .unwrap_or(self.settings.retention_days)
            .clamp(1, 90);

        let version_prefix = cfg_map
            .get("version_prefix")
            .and_then(Value::as_str)
            .unwrap_or("v")
            .to_string();

        let release_title_template = cfg_map
            .get("release_title_template")
            .and_then(Value::as_str)
            .unwrap_or("{version}")
            .to_string();

        let abusech_auth_key = self
            .settings
            .abusech_auth_key_override
            .clone()
            .or_else(|| {
                cfg_map
                    .get("abusech_auth_key")
                    .and_then(Value::as_str)
                    .map(|s| s.trim().to_string())
            })
            .filter(|s| !s.is_empty());

        let trusted_proxies: Vec<IpNet> =
            if let Some(raw_override) = &self.settings.trusted_proxies_override {
                raw_override
                    .split(',')
                    .filter_map(|s| s.trim().parse::<IpNet>().ok())
                    .collect()
            } else if let Some(arr) = cfg_map.get("trusted_proxies").and_then(Value::as_array) {
                arr.iter()
                    .filter_map(|v| v.as_str().and_then(|s| s.trim().parse::<IpNet>().ok()))
                    .collect()
            } else {
                Vec::new()
            };

        let host_rows = client
            .query(
                "SELECT hostname FROM dgspamguard_allowed_hosts WHERE enabled = TRUE",
                &[],
            )
            .await
            .map_err(|e| DgspamguardError::Database(e.to_string()))?;
        let mut allowed_source_hosts = HashSet::new();
        for r in host_rows {
            let h: String = r.get(0);
            allowed_source_hosts.insert(h.to_ascii_lowercase());
        }

        let allow_rows = client
            .query(
                "SELECT domain, kind, notes FROM dgspamguard_allowlist ORDER BY domain",
                &[],
            )
            .await
            .map_err(|e| DgspamguardError::Database(e.to_string()))?;
        let allowlist = allow_rows
            .into_iter()
            .map(|r| AllowlistRule {
                domain: r.get(0),
                kind: r.get(1),
                notes: r.get(2),
            })
            .collect();

        let tld_rows = client
            .query(
                "SELECT tld, risk_score, risk_level, notes FROM dgspamguard_tld_risk ORDER BY tld",
                &[],
            )
            .await
            .map_err(|e| DgspamguardError::Database(e.to_string()))?;
        let tld_risks = tld_rows
            .into_iter()
            .map(|r| TldRiskRule {
                tld: r.get(0),
                risk_score: r.get(1),
                risk_level: r.get(2),
                notes: r.get(3),
            })
            .collect();

        Ok(RuntimeCatalog {
            bootstrap_bundle_url,
            allowed_source_hosts,
            trusted_proxies,
            rate_limit_per_minute,
            swagger_enabled,
            retention_days,
            version_prefix,
            release_title_template,
            abusech_auth_key,
            allowlist,
            tld_risks,
        })
    }

    pub async fn list_feed_sources(&self) -> DgspamguardResult<Vec<FeedSourceSpec>> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| DgspamguardError::Database(e.to_string()))?;
        let rows = client
            .query(
                r#"SELECT feed_key, category, parser_kind, source_url, refresh_interval_seconds,
                          min_records, max_compressed_bytes, max_uncompressed_bytes,
                          confidence_weight, enabled, display_order, etag, last_modified, last_fetched_at
                   FROM dgspamguard_feed_sources
                   ORDER BY display_order, feed_key"#,
                &[],
            )
            .await
            .map_err(|e| DgspamguardError::Database(e.to_string()))?;

        Ok(rows
            .into_iter()
            .map(|r| FeedSourceSpec {
                feed_key: r.get(0),
                category: r.get(1),
                parser_kind: r.get(2),
                source_url: r.get(3),
                refresh_interval_seconds: r.get(4),
                min_records: r.get(5),
                max_compressed_bytes: r.get(6),
                max_uncompressed_bytes: r.get(7),
                confidence_weight: r.get(8),
                enabled: r.get(9),
                display_order: r.get(10),
                etag: r.get(11),
                last_modified: r.get(12),
                last_fetched_at: r.get(13),
            })
            .collect())
    }

    pub async fn get_cached_feed_payload(
        &self,
        feed_key: &str,
    ) -> DgspamguardResult<Option<Vec<u8>>> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| DgspamguardError::Database(e.to_string()))?;
        let row = client
            .query_opt(
                "SELECT cached_payload FROM dgspamguard_feed_sources WHERE feed_key = $1",
                &[&feed_key],
            )
            .await
            .map_err(|e| DgspamguardError::Database(e.to_string()))?;
        Ok(row.and_then(|r| r.get::<_, Option<Vec<u8>>>(0)))
    }

    pub async fn save_feed_fetch_state(
        &self,
        feed_key: &str,
        etag: Option<&str>,
        last_modified: Option<&str>,
        fetched_at: DateTime<Utc>,
        compressed_payload: Option<&[u8]>,
    ) -> DgspamguardResult<()> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| DgspamguardError::Database(e.to_string()))?;
        if let Some(payload) = compressed_payload {
            client
                .execute(
                    r#"UPDATE dgspamguard_feed_sources
                       SET etag = $2, last_modified = $3, last_fetched_at = $4,
                           cached_payload = $5, updated_at = now()
                       WHERE feed_key = $1"#,
                    &[&feed_key, &etag, &last_modified, &fetched_at, &payload],
                )
                .await
                .map_err(|e| DgspamguardError::Database(e.to_string()))?;
        } else {
            client
                .execute(
                    r#"UPDATE dgspamguard_feed_sources
                       SET etag = COALESCE($2, etag),
                           last_modified = COALESCE($3, last_modified),
                           last_fetched_at = $4,
                           updated_at = now()
                       WHERE feed_key = $1"#,
                    &[&feed_key, &etag, &last_modified, &fetched_at],
                )
                .await
                .map_err(|e| DgspamguardError::Database(e.to_string()))?;
        }
        Ok(())
    }

    pub async fn record_sync_attempt(&self) -> DgspamguardResult<()> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| DgspamguardError::Database(e.to_string()))?;
        client
            .execute(
                "UPDATE dgspamguard_state SET last_sync_attempt_at = now(), updated_at = now() WHERE id = 1",
                &[],
            )
            .await
            .map_err(|e| DgspamguardError::Database(e.to_string()))?;
        Ok(())
    }

    pub async fn record_sync_error(&self, err_msg: &str) -> DgspamguardResult<()> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| DgspamguardError::Database(e.to_string()))?;
        client
            .execute(
                "UPDATE dgspamguard_state SET last_sync_error = $1, updated_at = now() WHERE id = 1",
                &[&err_msg],
            )
            .await
            .map_err(|e| DgspamguardError::Database(e.to_string()))?;
        Ok(())
    }

    pub async fn record_sync_no_change(&self) -> DgspamguardResult<()> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| DgspamguardError::Database(e.to_string()))?;
        client
            .execute(
                "UPDATE dgspamguard_state SET last_sync_success_at = now(), last_sync_error = NULL, updated_at = now() WHERE id = 1",
                &[],
            )
            .await
            .map_err(|e| DgspamguardError::Database(e.to_string()))?;
        Ok(())
    }

    /// Allocate the next monotonic UTC timestamp snapshot tag (`v20261103.1600`, `v20261103.1600.1`, ...).
    /// Persists sequence state in `dgspamguard_config.snapshot_seq_map` so 7-day pruning or manual rebuilds never reuse a tag.
    pub async fn allocate_next_version(
        &self,
        prefix: &str,
        ts: DateTime<Utc>,
    ) -> DgspamguardResult<String> {
        let mut client = self
            .pool
            .get()
            .await
            .map_err(|e| DgspamguardError::Database(e.to_string()))?;
        let tx = client
            .transaction()
            .await
            .map_err(|e| DgspamguardError::Database(e.to_string()))?;

        let row = tx
            .query_opt(
                "SELECT value_json FROM dgspamguard_config WHERE key = 'snapshot_seq_map' FOR UPDATE",
                &[],
            )
            .await
            .map_err(|e| DgspamguardError::Database(e.to_string()))?;

        let mut map_obj = row
            .and_then(|r| r.get::<_, Value>(0).as_object().cloned())
            .unwrap_or_default();

        let base_tag = utc_timestamp_base_tag(prefix, ts);
        let next_seq: u32 = match map_obj.get(&base_tag).and_then(Value::as_u64) {
            Some(prev) => (prev as u32).saturating_add(1),
            None => 0,
        };

        // Keep only the most recent 64 UTC snapshot slots in snapshot_seq_map to prevent unbounded growth
        map_obj.insert(base_tag, json!(next_seq));
        if map_obj.len() > 64 {
            let mut keys: Vec<String> = map_obj.keys().cloned().collect();
            keys.sort();
            while keys.len() > 64 {
                let oldest = keys.remove(0);
                map_obj.remove(&oldest);
            }
        }

        let updated_val = Value::Object(map_obj);
        tx.execute(
            "INSERT INTO dgspamguard_config (key, value_json, description, updated_at) VALUES ('snapshot_seq_map', $1, 'Monotonic UTC snapshot counter', now()) ON CONFLICT (key) DO UPDATE SET value_json = EXCLUDED.value_json, updated_at = now()",
            &[&updated_val],
        )
        .await
        .map_err(|e| DgspamguardError::Database(e.to_string()))?;

        tx.commit()
            .await
            .map_err(|e| DgspamguardError::Database(e.to_string()))?;

        Ok(format_snapshot_version(prefix, ts, next_seq))
    }

    /// Return `(created_at, fingerprint, threat_domains, threat_urls, threat_ips, disposable_domains, malware_hashes)`
    /// of the currently active snapshot row, if any.
    #[allow(clippy::type_complexity)]
    pub async fn get_active_snapshot_meta(
        &self,
    ) -> DgspamguardResult<Option<(DateTime<Utc>, String, i64, i64, i64, i64, i64)>> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| DgspamguardError::Database(e.to_string()))?;
        let row = client
            .query_opt(
                r#"SELECT s.created_at, s.fingerprint, s.threat_domains, s.threat_urls,
                          s.threat_ips, s.disposable_domains, s.malware_hashes
                   FROM dgspamguard_snapshots s
                   JOIN dgspamguard_state st ON st.id = 1 AND st.active_version = s.version"#,
                &[],
            )
            .await
            .map_err(|e| DgspamguardError::Database(e.to_string()))?;
        Ok(row.map(|r| {
            (
                r.get(0),
                r.get(1),
                r.get(2),
                r.get(3),
                r.get(4),
                r.get(5),
                r.get(6),
            )
        }))
    }

    async fn copy_compiled_into_slot(
        tx: &Transaction<'_>,
        target_slot: &str,
        compiled: &CompiledThreatSet,
    ) -> DgspamguardResult<()> {
        let (dom_tbl, url_tbl, hash_tbl, ip_tbl) = if target_slot == "a" {
            (
                "dgspamguard_domains_a",
                "dgspamguard_urls_a",
                "dgspamguard_hashes_a",
                "dgspamguard_ips_a",
            )
        } else {
            (
                "dgspamguard_domains_b",
                "dgspamguard_urls_b",
                "dgspamguard_hashes_b",
                "dgspamguard_ips_b",
            )
        };

        tx.batch_execute(&format!(
            "TRUNCATE TABLE {dom_tbl}; TRUNCATE TABLE {url_tbl}; TRUNCATE TABLE {hash_tbl}; TRUNCATE TABLE {ip_tbl};"
        ))
        .await
        .map_err(|e| DgspamguardError::Database(format!("Slot truncate failed: {e}")))?;

        // Bulk COPY domains
        {
            let sink: CopyInSink<Bytes> = tx
                .copy_in(&format!(
                    "COPY {dom_tbl} (domain, registered_domain, threat_category, confidence, source_count, sources, email_kind) FROM STDIN WITH (FORMAT text)"
                ))
                .await
                .map_err(|e| DgspamguardError::Database(format!("COPY domains init failed: {e}")))?;
            let mut pinned = pin!(sink);
            let mut chunk = Vec::with_capacity(256 * 1024);

            for row in &compiled.domains {
                write_pg_text_col(&mut chunk, &row.domain);
                chunk.push(b'\t');
                write_pg_text_col(&mut chunk, &row.registered_domain);
                chunk.push(b'\t');
                write_pg_opt_col(&mut chunk, row.threat_category.as_deref());
                chunk.push(b'\t');
                let _ = write!(chunk, "{}\t{}\t", row.confidence, row.source_count);
                write_pg_text_col(&mut chunk, &row.sources);
                chunk.push(b'\t');
                write_pg_opt_col(&mut chunk, row.email_kind.as_deref());
                chunk.push(b'\n');

                if chunk.len() >= 220 * 1024 {
                    pinned
                        .send(Bytes::copy_from_slice(&chunk))
                        .await
                        .map_err(|e| {
                            DgspamguardError::Database(format!("COPY domains send: {e}"))
                        })?;
                    chunk.clear();
                }
            }
            if !chunk.is_empty() {
                pinned
                    .send(Bytes::copy_from_slice(&chunk))
                    .await
                    .map_err(|e| DgspamguardError::Database(format!("COPY domains flush: {e}")))?;
            }
            pinned
                .close()
                .await
                .map_err(|e| DgspamguardError::Database(format!("COPY domains close: {e}")))?;
        }

        // Bulk COPY URLs
        {
            let sink: CopyInSink<Bytes> = tx
                .copy_in(&format!(
                    "COPY {url_tbl} (url_sha256, domain, canonical_url, threat_category, confidence, source_count, sources) FROM STDIN WITH (FORMAT text)"
                ))
                .await
                .map_err(|e| DgspamguardError::Database(format!("COPY urls init failed: {e}")))?;
            let mut pinned = pin!(sink);
            let mut chunk = Vec::with_capacity(256 * 1024);

            for row in &compiled.urls {
                write_pg_text_col(&mut chunk, &row.url_sha256);
                chunk.push(b'\t');
                write_pg_text_col(&mut chunk, &row.domain);
                chunk.push(b'\t');
                write_pg_text_col(&mut chunk, &row.canonical_url);
                chunk.push(b'\t');
                write_pg_text_col(&mut chunk, &row.threat_category);
                let _ = write!(chunk, "\t{}\t{}\t", row.confidence, row.source_count);
                write_pg_text_col(&mut chunk, &row.sources);
                chunk.push(b'\n');

                if chunk.len() >= 220 * 1024 {
                    pinned
                        .send(Bytes::copy_from_slice(&chunk))
                        .await
                        .map_err(|e| DgspamguardError::Database(format!("COPY urls send: {e}")))?;
                    chunk.clear();
                }
            }
            if !chunk.is_empty() {
                pinned
                    .send(Bytes::copy_from_slice(&chunk))
                    .await
                    .map_err(|e| DgspamguardError::Database(format!("COPY urls flush: {e}")))?;
            }
            pinned
                .close()
                .await
                .map_err(|e| DgspamguardError::Database(format!("COPY urls close: {e}")))?;
        }

        // Bulk COPY SHA-256 hashes
        {
            let sink: CopyInSink<Bytes> = tx
                .copy_in(&format!(
                    "COPY {hash_tbl} (sha256, malware_family, confidence, sources) FROM STDIN WITH (FORMAT text)"
                ))
                .await
                .map_err(|e| DgspamguardError::Database(format!("COPY hashes init failed: {e}")))?;
            let mut pinned = pin!(sink);
            let mut chunk = Vec::with_capacity(64 * 1024);

            for row in &compiled.hashes {
                write_pg_text_col(&mut chunk, &row.sha256);
                chunk.push(b'\t');
                write_pg_text_col(&mut chunk, &row.malware_family);
                let _ = write!(chunk, "\t{}\t", row.confidence);
                write_pg_text_col(&mut chunk, &row.sources);
                chunk.push(b'\n');

                if chunk.len() >= 56 * 1024 {
                    pinned
                        .send(Bytes::copy_from_slice(&chunk))
                        .await
                        .map_err(|e| {
                            DgspamguardError::Database(format!("COPY hashes send: {e}"))
                        })?;
                    chunk.clear();
                }
            }
            if !chunk.is_empty() {
                pinned
                    .send(Bytes::copy_from_slice(&chunk))
                    .await
                    .map_err(|e| DgspamguardError::Database(format!("COPY hashes flush: {e}")))?;
            }
            pinned
                .close()
                .await
                .map_err(|e| DgspamguardError::Database(format!("COPY hashes close: {e}")))?;
        }

        // Bulk COPY SMTP threat IPs & hijacked subnets
        {
            let sink: CopyInSink<Bytes> = tx
                .copy_in(&format!(
                    "COPY {ip_tbl} (network, threat_category, confidence, source_count, sources) FROM STDIN WITH (FORMAT text)"
                ))
                .await
                .map_err(|e| DgspamguardError::Database(format!("COPY ips init failed: {e}")))?;
            let mut pinned = pin!(sink);
            let mut chunk = Vec::with_capacity(128 * 1024);

            for row in &compiled.ips {
                write_pg_text_col(&mut chunk, &row.network);
                chunk.push(b'\t');
                write_pg_text_col(&mut chunk, &row.threat_category);
                let _ = write!(chunk, "\t{}\t{}\t", row.confidence, row.source_count);
                write_pg_text_col(&mut chunk, &row.sources);
                chunk.push(b'\n');

                if chunk.len() >= 112 * 1024 {
                    pinned
                        .send(Bytes::copy_from_slice(&chunk))
                        .await
                        .map_err(|e| DgspamguardError::Database(format!("COPY ips send: {e}")))?;
                    chunk.clear();
                }
            }
            if !chunk.is_empty() {
                pinned
                    .send(Bytes::copy_from_slice(&chunk))
                    .await
                    .map_err(|e| DgspamguardError::Database(format!("COPY ips flush: {e}")))?;
            }
            pinned
                .close()
                .await
                .map_err(|e| DgspamguardError::Database(format!("COPY ips close: {e}")))?;
        }

        Ok(())
    }

    /// Lightweight live A/B slot swap for high-frequency (`15m`/`30m`/`1h`) feed refreshes.
    /// Updates live API lookup tables immediately without packaging a `~115 MB` snapshot bundle.
    pub async fn activate_live_compiled_slot(
        &self,
        compiled: &CompiledThreatSet,
        fingerprint: &str,
    ) -> DgspamguardResult<()> {
        let mut client = self
            .pool
            .get()
            .await
            .map_err(|e| DgspamguardError::Database(e.to_string()))?;

        let tx = client
            .transaction()
            .await
            .map_err(|e| DgspamguardError::Database(e.to_string()))?;

        tx.execute("SELECT pg_advisory_xact_lock($1)", &[&ADVISORY_LOCK_KEY])
            .await
            .map_err(|e| DgspamguardError::Database(e.to_string()))?;

        let cur_slot: String = tx
            .query_one(
                "SELECT active_slot FROM dgspamguard_state WHERE id = 1",
                &[],
            )
            .await
            .map_err(|e| DgspamguardError::Database(e.to_string()))?
            .get(0);

        let target_slot = if cur_slot == "a" { "b" } else { "a" };
        Self::copy_compiled_into_slot(&tx, target_slot, compiled).await?;

        tx.execute(
            r#"UPDATE dgspamguard_state
               SET initial_bootstrapped = TRUE,
                   active_slot = $1,
                   live_fingerprint = $2,
                   live_updated_at = now(),
                   last_sync_success_at = now(),
                   last_sync_error = NULL,
                   updated_at = now()
               WHERE id = 1"#,
            &[&target_slot, &fingerprint],
        )
        .await
        .map_err(|e| DgspamguardError::Database(e.to_string()))?;

        tx.commit()
            .await
            .map_err(|e| DgspamguardError::Database(e.to_string()))?;

        self.refresh_in_memory_meta().await?;
        Ok(())
    }

    /// Atomically bulk-load a compiled `PackagedSnapshot` into the inactive A/B slot, store snapshot blobs,
    /// flip `active_slot`, refresh in-RAM metadata, and prune snapshots older than `retention_days`.
    pub async fn activate_packaged_snapshot(
        &self,
        packaged: &PackagedSnapshot,
        fingerprint: &str,
        retention_days: i64,
    ) -> DgspamguardResult<()> {
        let mut client = self
            .pool
            .get()
            .await
            .map_err(|e| DgspamguardError::Database(e.to_string()))?;

        // Acquire PostgreSQL session-level advisory lock check inside transaction
        let tx = client
            .transaction()
            .await
            .map_err(|e| DgspamguardError::Database(e.to_string()))?;

        tx.execute("SELECT pg_advisory_xact_lock($1)", &[&ADVISORY_LOCK_KEY])
            .await
            .map_err(|e| DgspamguardError::Database(e.to_string()))?;

        let cur_slot: String = tx
            .query_one(
                "SELECT active_slot FROM dgspamguard_state WHERE id = 1",
                &[],
            )
            .await
            .map_err(|e| DgspamguardError::Database(e.to_string()))?
            .get(0);

        let target_slot = if cur_slot == "a" { "b" } else { "a" };
        Self::copy_compiled_into_slot(&tx, target_slot, &packaged.compiled).await?;

        let manifest_val: Value =
            serde_json::from_slice(&packaged.manifest_json).unwrap_or_else(|_| json!({}));

        tx.execute(
            r#"INSERT INTO dgspamguard_snapshots (
                version, release_title, created_at, fingerprint,
                threat_domains, threat_urls, threat_ips, disposable_domains, free_domains,
                redirector_domains, malware_hashes, bundle_sha256, bundle_size_bytes,
                manifest_json, release_notes_md, has_blobs
            ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,TRUE)
            ON CONFLICT (version) DO UPDATE SET
                release_title = EXCLUDED.release_title,
                created_at = EXCLUDED.created_at,
                fingerprint = EXCLUDED.fingerprint,
                threat_domains = EXCLUDED.threat_domains,
                threat_urls = EXCLUDED.threat_urls,
                threat_ips = EXCLUDED.threat_ips,
                disposable_domains = EXCLUDED.disposable_domains,
                free_domains = EXCLUDED.free_domains,
                redirector_domains = EXCLUDED.redirector_domains,
                malware_hashes = EXCLUDED.malware_hashes,
                bundle_sha256 = EXCLUDED.bundle_sha256,
                bundle_size_bytes = EXCLUDED.bundle_size_bytes,
                manifest_json = EXCLUDED.manifest_json,
                release_notes_md = EXCLUDED.release_notes_md,
                has_blobs = TRUE"#,
            &[
                &packaged.version,
                &packaged.release_title,
                &packaged.generated_at,
                &fingerprint,
                &packaged.compiled.threat_domain_count,
                &(packaged.compiled.urls.len() as i64),
                &(packaged.compiled.ips.len() as i64),
                &packaged.compiled.disposable_domain_count,
                &packaged.compiled.free_domain_count,
                &packaged.compiled.redirector_domain_count,
                &(packaged.compiled.hashes.len() as i64),
                &packaged.bundle_sha256,
                &(packaged.bundle_bytes.len() as i64),
                &manifest_val,
                &packaged.release_notes_md,
            ],
        )
        .await
        .map_err(|e| DgspamguardError::Database(format!("Snapshot upsert failed: {e}")))?;

        tx.execute(
            "DELETE FROM dgspamguard_snapshot_files WHERE version = $1",
            &[&packaged.version],
        )
        .await
        .map_err(|e| DgspamguardError::Database(e.to_string()))?;

        // Store bundle.tar.gz, SHA256SUMS.txt, manifest.json, and all 8 dataset files
        let special_files: &[(&str, &str, &str, &[u8])] = &[
            (
                "bundle.tar.gz",
                "application/gzip",
                &packaged.bundle_sha256,
                &packaged.bundle_bytes,
            ),
            (
                "SHA256SUMS.txt",
                "text/plain; charset=utf-8",
                &packaged.sha256sums_sha256,
                &packaged.sha256sums_txt,
            ),
            (
                "manifest.json",
                "application/json",
                &packaged.manifest_sha256,
                &packaged.manifest_json,
            ),
        ];
        for &(fname, ctype, sha, bytes) in special_files {
            tx.execute(
                r#"INSERT INTO dgspamguard_snapshot_files (version, filename, content_type, sha256, size_bytes, record_count, payload)
                   VALUES ($1, $2, $3, $4, $5, NULL, $6)"#,
                &[
                    &packaged.version,
                    &fname,
                    &ctype,
                    &sha,
                    &(bytes.len() as i64),
                    &bytes,
                ],
            )
            .await
            .map_err(|e| DgspamguardError::Database(e.to_string()))?;
        }

        for (meta, bytes) in packaged.dataset_artifacts.values() {
            tx.execute(
                r#"INSERT INTO dgspamguard_snapshot_files (version, filename, content_type, sha256, size_bytes, record_count, payload)
                   VALUES ($1, $2, $3, $4, $5, $6, $7)"#,
                &[
                    &packaged.version,
                    &meta.filename,
                    &meta.content_type,
                    &meta.sha256,
                    &meta.size_bytes,
                    &meta.record_count,
                    &bytes,
                ],
            )
            .await
            .map_err(|e| DgspamguardError::Database(e.to_string()))?;
        }

        tx.execute(
            r#"UPDATE dgspamguard_state
               SET initial_bootstrapped = TRUE,
                   active_slot = $1,
                   active_version = $2,
                   live_fingerprint = $3,
                   live_updated_at = $4,
                   last_sync_success_at = now(),
                   last_sync_error = NULL,
                   updated_at = now()
               WHERE id = 1"#,
            &[
                &target_slot,
                &packaged.version,
                &fingerprint,
                &packaged.generated_at,
            ],
        )
        .await
        .map_err(|e| DgspamguardError::Database(e.to_string()))?;

        tx.commit()
            .await
            .map_err(|e| DgspamguardError::Database(e.to_string()))?;

        self.refresh_in_memory_meta().await?;
        self.evict_non_active_cache_dirs(Some(&packaged.version)).await;
        let _ = self.prune_expired_snapshots(retention_days).await;
        Ok(())
    }

    /// Delete non-active snapshots older than `retention_days` (default 7 days) so DB & disk stay bounded.
    pub async fn prune_expired_snapshots(&self, retention_days: i64) -> DgspamguardResult<u64> {
        let cutoff = Utc::now() - ChronoDuration::days(retention_days.max(1));
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| DgspamguardError::Database(e.to_string()))?;

        let expired_rows = client
            .query(
                r#"SELECT s.version
                   FROM dgspamguard_snapshots s
                   WHERE s.created_at < $1
                     AND s.version <> COALESCE((SELECT active_version FROM dgspamguard_state WHERE id = 1), '')"#,
                &[&cutoff],
            )
            .await
            .map_err(|e| DgspamguardError::Database(e.to_string()))?;

        let mut deleted = 0u64;
        for r in expired_rows {
            let ver: String = r.get(0);
            deleted += client
                .execute(
                    "DELETE FROM dgspamguard_snapshots WHERE version = $1",
                    &[&ver],
                )
                .await
                .map_err(|e| DgspamguardError::Database(e.to_string()))?;
            let cache_sub = self.settings.cache_dir.join(&ver);
            let _ = tokio::fs::remove_dir_all(&cache_sub).await;
        }
        Ok(deleted)
    }

    // =========================================================================
    // Low-Latency Threat & Taxonomy Lookups
    // =========================================================================

    pub async fn lookup_domain(&self, raw_domain: &str) -> DgspamguardResult<DomainLookupResponse> {
        let (ascii_domain, unicode_domain) = normalize_domain(raw_domain).ok_or_else(|| {
            DgspamguardError::Validation(format!(
                "Invalid domain name '{raw_domain}'. Expected a valid FQDN such as 'example.com'."
            ))
        })?;

        let (
            slot,
            snapshot_version,
            live_updated_at,
            registered_domain,
            chain,
            tld_rep,
            is_shared_hosting,
            is_catalog_trusted,
        ) = {
            let guard = self.meta.read().unwrap_or_else(|e| e.into_inner());
            if guard.active_slot != "a" && guard.active_slot != "b" {
                return Err(DgspamguardError::Unavailable(
                    "DGSPAMGUARD dataset is still initializing; please retry shortly.".to_string(),
                ));
            }
            if guard.psl.is_icann_public_suffix(&ascii_domain) {
                return Err(DgspamguardError::Validation(format!(
                    "'{ascii_domain}' is a bare public suffix rather than a registrable domain."
                )));
            }
            let reg = guard.psl.registered_domain(&ascii_domain);
            let ch = domain_lookup_chain(&ascii_domain, &reg);
            let tld_str = extract_tld(&ascii_domain);
            let tld_rep = guard
                .tld_map
                .get(tld_str)
                .map(|r| TldReputation {
                    tld: r.tld.clone(),
                    risk_score: r.risk_score,
                    risk_level: r.risk_level.clone(),
                })
                .unwrap_or_else(|| TldReputation {
                    tld: tld_str.to_string(),
                    risk_score: 8,
                    risk_level: "low".to_string(),
                });

            let is_shared = guard.shared_hosting_domains.contains(&ascii_domain)
                || guard.psl.is_private_public_suffix(&ascii_domain);
            let is_trusted = !is_shared
                && ch.iter().any(|cand| {
                    guard.trusted_domains.contains(cand)
                        && !guard.shared_hosting_domains.contains(cand)
                });

            (
                guard.active_slot.clone(),
                guard.active_version.clone(),
                guard.live_updated_at,
                reg,
                ch,
                tld_rep,
                is_shared,
                is_trusted,
            )
        };

        let dom_tbl = if slot == "a" {
            "dgspamguard_domains_a"
        } else {
            "dgspamguard_domains_b"
        };

        let client = self
            .pool
            .get()
            .await
            .map_err(|e| DgspamguardError::Database(e.to_string()))?;

        let rows = client
            .query(
                &format!(
                    "SELECT domain, threat_category, confidence, source_count, sources, email_kind FROM {dom_tbl} WHERE domain = ANY($1)"
                ),
                &[&chain],
            )
            .await
            .map_err(|e| DgspamguardError::Database(e.to_string()))?;

        struct RowHit {
            threat_category: Option<String>,
            confidence: i16,
            source_count: i16,
            sources: String,
            email_kind: Option<String>,
        }
        let mut hit_map: HashMap<String, RowHit> = HashMap::with_capacity(rows.len());
        for r in rows {
            hit_map.insert(
                r.get(0),
                RowHit {
                    threat_category: r.get(1),
                    confidence: r.get(2),
                    source_count: r.get(3),
                    sources: r.get(4),
                    email_kind: r.get(5),
                },
            );
        }

        let mut is_disposable_email = false;
        let mut is_free_email = false;
        let mut is_url_redirector = false;
        let mut is_trusted = is_catalog_trusted;

        let mut matched_threat: Option<(String, String, i16, i16, Vec<String>)> = None;

        for cand in &chain {
            if let Some(hit) = hit_map.get(cand) {
                match hit.email_kind.as_deref() {
                    Some("disposable") => is_disposable_email = true,
                    Some("free_provider") => is_free_email = true,
                    Some("url_redirector") => is_url_redirector = true,
                    Some("trusted") => is_trusted = true,
                    _ => {}
                }
                if matched_threat.is_none() && !is_trusted {
                    if let Some(cat) = &hit.threat_category {
                        let srcs: Vec<String> = hit
                            .sources
                            .split(',')
                            .filter(|s| !s.is_empty())
                            .map(String::from)
                            .collect();
                        matched_threat = Some((
                            cand.clone(),
                            cat.clone(),
                            hit.confidence,
                            hit.source_count,
                            srcs,
                        ));
                    }
                }
            }
        }

        if is_trusted || is_free_email {
            is_disposable_email = false;
        }

        let threat = match matched_threat {
            Some((m_dom, cat, conf, sc, srcs)) if !is_trusted && !is_shared_hosting => {
                DomainThreatInfo {
                    is_threat: true,
                    category: Some(cat),
                    matched_domain: Some(m_dom),
                    confidence: conf,
                    source_count: sc,
                    sources: srcs,
                }
            }
            _ => DomainThreatInfo {
                is_threat: false,
                category: None,
                matched_domain: None,
                confidence: 0,
                source_count: 0,
                sources: Vec::new(),
            },
        };

        let (verdict, risk_score) = if threat.is_threat {
            ("malicious".to_string(), threat.confidence.max(75))
        } else if is_trusted {
            ("clean".to_string(), 0)
        } else if is_disposable_email {
            (
                "suspicious".to_string(),
                (58 + tld_rep.risk_score / 3).clamp(55, 74),
            )
        } else if is_url_redirector {
            (
                "elevated".to_string(),
                (35 + tld_rep.risk_score / 2).clamp(35, 55),
            )
        } else if tld_rep.risk_score >= 30 {
            ("elevated".to_string(), tld_rep.risk_score)
        } else {
            ("clean".to_string(), tld_rep.risk_score)
        };

        Ok(DomainLookupResponse {
            domain: ascii_domain,
            unicode_domain,
            registered_domain,
            verdict,
            risk_score,
            threat,
            taxonomy: DomainTaxonomyInfo {
                is_disposable_email,
                is_free_email,
                is_url_redirector,
                is_trusted,
                is_shared_hosting,
            },
            tld: tld_rep,
            snapshot_version,
            live_updated_at,
        })
    }

    pub async fn lookup_ip(&self, raw_ip: &str) -> DgspamguardResult<IpLookupResponse> {
        let ip: IpAddr = normalize_ip_literal(raw_ip).ok_or_else(|| {
            DgspamguardError::Validation(format!(
                "Invalid IPv4 or IPv6 address '{raw_ip}'. Expected a valid IP literal such as '198.51.100.10' or '2606:4700:4700::1111'."
            ))
        })?;

        let (slot, snapshot_version, live_updated_at) = {
            let guard = self.meta.read().unwrap_or_else(|e| e.into_inner());
            if guard.active_slot != "a" && guard.active_slot != "b" {
                return Err(DgspamguardError::Unavailable(
                    "DGSPAMGUARD dataset is still initializing; please retry shortly.".to_string(),
                ));
            }
            (
                guard.active_slot.clone(),
                guard.active_version.clone(),
                guard.live_updated_at,
            )
        };

        let ip_version: u8 = match ip {
            IpAddr::V4(_) => 4,
            IpAddr::V6(_) => 6,
        };
        let ip_str = ip.to_string();
        let is_public_routable = is_public_routable_ip(ip);

        if !is_public_routable {
            return Ok(IpLookupResponse {
                ip: ip_str,
                ip_version,
                is_public_routable: false,
                verdict: "clean".to_string(),
                risk_score: 0,
                is_threat: false,
                matched_network: None,
                match_scope: None,
                category: None,
                confidence: 0,
                source_count: 0,
                sources: Vec::new(),
                snapshot_version,
                live_updated_at,
            });
        }

        let ip_tbl = if slot == "a" {
            "dgspamguard_ips_a"
        } else {
            "dgspamguard_ips_b"
        };

        let client = self
            .pool
            .get()
            .await
            .map_err(|e| DgspamguardError::Database(e.to_string()))?;

        let row = client
            .query_opt(
                &format!(
                    "SELECT network::text, threat_category, confidence, source_count, sources FROM {ip_tbl} WHERE network >>= $1::text::inet ORDER BY masklen(network) DESC LIMIT 1"
                ),
                &[&ip_str],
            )
            .await
            .map_err(|e| DgspamguardError::Database(e.to_string()))?;

        if let Some(r) = row {
            let net_str: String = r.get(0);
            let category: String = r.get(1);
            let confidence: i16 = r.get(2);
            let source_count: i16 = r.get(3);
            let srcs_raw: String = r.get(4);
            let sources: Vec<String> = srcs_raw
                .split(',')
                .filter(|s| !s.is_empty())
                .map(String::from)
                .collect();
            let is_host_mask = (ip_version == 4 && net_str.ends_with("/32"))
                || (ip_version == 6 && net_str.ends_with("/128"));
            let scope = if is_host_mask {
                "exact_ip"
            } else {
                "cidr_subnet"
            };

            Ok(IpLookupResponse {
                ip: ip_str,
                ip_version,
                is_public_routable: true,
                verdict: "malicious".to_string(),
                risk_score: confidence.max(78),
                is_threat: true,
                matched_network: Some(net_str),
                match_scope: Some(scope.to_string()),
                category: Some(category),
                confidence,
                source_count,
                sources,
                snapshot_version,
                live_updated_at,
            })
        } else {
            Ok(IpLookupResponse {
                ip: ip_str,
                ip_version,
                is_public_routable: true,
                verdict: "clean".to_string(),
                risk_score: 0,
                is_threat: false,
                matched_network: None,
                match_scope: None,
                category: None,
                confidence: 0,
                source_count: 0,
                sources: Vec::new(),
                snapshot_version,
                live_updated_at,
            })
        }
    }

    pub async fn lookup_url(&self, raw_url: &str) -> DgspamguardResult<UrlCheckResponse> {
        let (canonical_url, host_key, url_sha256, opt_ip) = canonicalize_url_with_ip(raw_url)
            .ok_or_else(|| {
                DgspamguardError::Validation(
                    "Invalid HTTP/HTTPS URL or non-routable hostname/IP.".to_string(),
                )
            })?;

        let slot = {
            let guard = self.meta.read().unwrap_or_else(|e| e.into_inner());
            if guard.active_slot != "a" && guard.active_slot != "b" {
                return Err(DgspamguardError::Unavailable(
                    "DGSPAMGUARD dataset is still initializing; please retry shortly.".to_string(),
                ));
            }
            guard.active_slot.clone()
        };
        let url_tbl = if slot == "a" {
            "dgspamguard_urls_a"
        } else {
            "dgspamguard_urls_b"
        };

        let client = self
            .pool
            .get()
            .await
            .map_err(|e| DgspamguardError::Database(e.to_string()))?;
        let url_row = client
            .query_opt(
                &format!(
                    "SELECT threat_category, confidence, sources FROM {url_tbl} WHERE url_sha256 = $1"
                ),
                &[&url_sha256],
            )
            .await
            .map_err(|e| DgspamguardError::Database(e.to_string()))?;

        // Branch A: URL hosted on a raw public IPv4/IPv6 literal (common in URLhaus / Mirai / Mozi feeds)
        if let Some(ip_addr) = opt_ip {
            let ip_resp = self.lookup_ip(&ip_addr.to_string()).await?;
            let ip_tax = DomainTaxonomyInfo {
                is_disposable_email: false,
                is_free_email: false,
                is_url_redirector: false,
                is_trusted: false,
                is_shared_hosting: false,
            };
            let ip_tld = TldReputation {
                tld: "ip".to_string(),
                risk_score: 25,
                risk_level: "high".to_string(),
            };

            if let Some(r) = url_row {
                let cat: String = r.get(0);
                let conf: i16 = r.get(1);
                let srcs_raw: String = r.get(2);
                let sources: Vec<String> = srcs_raw
                    .split(',')
                    .filter(|s| !s.is_empty())
                    .map(String::from)
                    .collect();
                return Ok(UrlCheckResponse {
                    input_url: raw_url.trim().to_string(),
                    canonical_url,
                    url_sha256,
                    domain: host_key.clone(),
                    registered_domain: host_key,
                    verdict: "malicious".to_string(),
                    risk_score: conf.max(88),
                    is_threat: true,
                    match_scope: Some("exact_url".to_string()),
                    category: Some(cat),
                    confidence: conf,
                    sources,
                    taxonomy: ip_tax,
                    tld: ip_tld,
                    snapshot_version: ip_resp.snapshot_version,
                    live_updated_at: ip_resp.live_updated_at,
                });
            }

            if ip_resp.is_threat {
                return Ok(UrlCheckResponse {
                    input_url: raw_url.trim().to_string(),
                    canonical_url,
                    url_sha256,
                    domain: host_key.clone(),
                    registered_domain: host_key,
                    verdict: "malicious".to_string(),
                    risk_score: ip_resp.risk_score,
                    is_threat: true,
                    match_scope: ip_resp.match_scope,
                    category: ip_resp.category,
                    confidence: ip_resp.confidence,
                    sources: ip_resp.sources,
                    taxonomy: ip_tax,
                    tld: ip_tld,
                    snapshot_version: ip_resp.snapshot_version,
                    live_updated_at: ip_resp.live_updated_at,
                });
            }

            return Ok(UrlCheckResponse {
                input_url: raw_url.trim().to_string(),
                canonical_url,
                url_sha256,
                domain: host_key.clone(),
                registered_domain: host_key,
                verdict: "elevated".to_string(),
                risk_score: 25,
                is_threat: false,
                match_scope: None,
                category: None,
                confidence: 0,
                sources: Vec::new(),
                taxonomy: ip_tax,
                tld: ip_tld,
                snapshot_version: ip_resp.snapshot_version,
                live_updated_at: ip_resp.live_updated_at,
            });
        }

        // Branch B: Standard FQDN URL
        let dom_resp = self.lookup_domain(&host_key).await?;

        if let Some(r) = url_row {
            let cat: String = r.get(0);
            let conf: i16 = r.get(1);
            let srcs_raw: String = r.get(2);
            let sources: Vec<String> = srcs_raw
                .split(',')
                .filter(|s| !s.is_empty())
                .map(String::from)
                .collect();
            return Ok(UrlCheckResponse {
                input_url: raw_url.trim().to_string(),
                canonical_url,
                url_sha256,
                domain: dom_resp.domain,
                registered_domain: dom_resp.registered_domain,
                verdict: "malicious".to_string(),
                risk_score: conf.max(85),
                is_threat: true,
                match_scope: Some("exact_url".to_string()),
                category: Some(cat),
                confidence: conf,
                sources,
                taxonomy: dom_resp.taxonomy,
                tld: dom_resp.tld,
                snapshot_version: dom_resp.snapshot_version,
                live_updated_at: dom_resp.live_updated_at,
            });
        }

        if dom_resp.threat.is_threat {
            let scope =
                if dom_resp.threat.matched_domain.as_deref() == Some(dom_resp.domain.as_str()) {
                    "domain"
                } else {
                    "parent_domain"
                };
            return Ok(UrlCheckResponse {
                input_url: raw_url.trim().to_string(),
                canonical_url,
                url_sha256,
                domain: dom_resp.domain,
                registered_domain: dom_resp.registered_domain,
                verdict: "malicious".to_string(),
                risk_score: dom_resp.risk_score,
                is_threat: true,
                match_scope: Some(scope.to_string()),
                category: dom_resp.threat.category,
                confidence: dom_resp.threat.confidence,
                sources: dom_resp.threat.sources,
                taxonomy: dom_resp.taxonomy,
                tld: dom_resp.tld,
                snapshot_version: dom_resp.snapshot_version,
                live_updated_at: dom_resp.live_updated_at,
            });
        }

        Ok(UrlCheckResponse {
            input_url: raw_url.trim().to_string(),
            canonical_url,
            url_sha256,
            domain: dom_resp.domain,
            registered_domain: dom_resp.registered_domain,
            verdict: dom_resp.verdict,
            risk_score: dom_resp.risk_score,
            is_threat: false,
            match_scope: None,
            category: None,
            confidence: 0,
            sources: Vec::new(),
            taxonomy: dom_resp.taxonomy,
            tld: dom_resp.tld,
            snapshot_version: dom_resp.snapshot_version,
            live_updated_at: dom_resp.live_updated_at,
        })
    }

    pub async fn lookup_hash(&self, raw_hash: &str) -> DgspamguardResult<HashLookupResponse> {
        let sha256 = normalize_sha256(raw_hash).ok_or_else(|| {
            DgspamguardError::Validation(
                "Invalid SHA-256 digest. Expected a 64-character hexadecimal string.".to_string(),
            )
        })?;

        let (slot, snapshot_version, live_updated_at) = {
            let guard = self.meta.read().unwrap_or_else(|e| e.into_inner());
            if guard.active_slot != "a" && guard.active_slot != "b" {
                return Err(DgspamguardError::Unavailable(
                    "DGSPAMGUARD dataset is still initializing; please retry shortly.".to_string(),
                ));
            }
            (
                guard.active_slot.clone(),
                guard.active_version.clone(),
                guard.live_updated_at,
            )
        };
        let hash_tbl = if slot == "a" {
            "dgspamguard_hashes_a"
        } else {
            "dgspamguard_hashes_b"
        };

        let client = self
            .pool
            .get()
            .await
            .map_err(|e| DgspamguardError::Database(e.to_string()))?;
        let row = client
            .query_opt(
                &format!(
                    "SELECT malware_family, confidence, sources FROM {hash_tbl} WHERE sha256 = $1"
                ),
                &[&sha256],
            )
            .await
            .map_err(|e| DgspamguardError::Database(e.to_string()))?;

        if let Some(r) = row {
            let family: String = r.get(0);
            let confidence: i16 = r.get(1);
            let srcs_raw: String = r.get(2);
            let sources: Vec<String> = srcs_raw
                .split(',')
                .filter(|s| !s.is_empty())
                .map(String::from)
                .collect();
            Ok(HashLookupResponse {
                sha256,
                found: true,
                verdict: "malicious".to_string(),
                malware_family: Some(family),
                confidence,
                sources,
                snapshot_version,
                live_updated_at,
            })
        } else {
            Ok(HashLookupResponse {
                sha256,
                found: false,
                verdict: "clean".to_string(),
                malware_family: None,
                confidence: 0,
                sources: Vec::new(),
                snapshot_version,
                live_updated_at,
            })
        }
    }

    pub async fn lookup_batch(&self, items: &[String]) -> DgspamguardResult<BatchCheckResponse> {
        let snapshot_version = {
            let guard = self.meta.read().unwrap_or_else(|e| e.into_inner());
            if guard.active_slot != "a" && guard.active_slot != "b" {
                return Err(DgspamguardError::Unavailable(
                    "DGSPAMGUARD dataset is still initializing; please retry shortly.".to_string(),
                ));
            }
            guard.active_version.clone()
        };

        let mut results = Vec::with_capacity(items.len());
        for raw in items {
            match classify_indicator(raw) {
                Ok(IndicatorInput::Sha256(h)) => match self.lookup_hash(&h).await {
                    Ok(hr) => results.push(BatchCheckItemResult {
                        input: raw.clone(),
                        kind: "sha256".to_string(),
                        valid: true,
                        error: None,
                        verdict: Some(hr.verdict.clone()),
                        risk_score: Some(if hr.found { hr.confidence.max(85) } else { 0 }),
                        domain_result: None,
                        url_result: None,
                        ip_result: None,
                        hash_result: Some(hr),
                    }),
                    Err(e) => results.push(BatchCheckItemResult {
                        input: raw.clone(),
                        kind: "sha256".to_string(),
                        valid: false,
                        error: Some(e.to_string()),
                        verdict: None,
                        risk_score: None,
                        domain_result: None,
                        url_result: None,
                        ip_result: None,
                        hash_result: None,
                    }),
                },
                Ok(IndicatorInput::Ip(ip)) => match self.lookup_ip(&ip.to_string()).await {
                    Ok(ir) => results.push(BatchCheckItemResult {
                        input: raw.clone(),
                        kind: "ip".to_string(),
                        valid: true,
                        error: None,
                        verdict: Some(ir.verdict.clone()),
                        risk_score: Some(ir.risk_score),
                        domain_result: None,
                        url_result: None,
                        ip_result: Some(ir),
                        hash_result: None,
                    }),
                    Err(e) => results.push(BatchCheckItemResult {
                        input: raw.clone(),
                        kind: "ip".to_string(),
                        valid: false,
                        error: Some(e.to_string()),
                        verdict: None,
                        risk_score: None,
                        domain_result: None,
                        url_result: None,
                        ip_result: None,
                        hash_result: None,
                    }),
                },
                Ok(IndicatorInput::Url { canonical_url, .. }) => {
                    match self.lookup_url(&canonical_url).await {
                        Ok(ur) => results.push(BatchCheckItemResult {
                            input: raw.clone(),
                            kind: "url".to_string(),
                            valid: true,
                            error: None,
                            verdict: Some(ur.verdict.clone()),
                            risk_score: Some(ur.risk_score),
                            domain_result: None,
                            url_result: Some(ur),
                            ip_result: None,
                            hash_result: None,
                        }),
                        Err(e) => results.push(BatchCheckItemResult {
                            input: raw.clone(),
                            kind: "url".to_string(),
                            valid: false,
                            error: Some(e.to_string()),
                            verdict: None,
                            risk_score: None,
                            domain_result: None,
                            url_result: None,
                            ip_result: None,
                            hash_result: None,
                        }),
                    }
                }
                Ok(IndicatorInput::Email { ascii_domain, .. }) => {
                    match self.lookup_domain(&ascii_domain).await {
                        Ok(dr) => results.push(BatchCheckItemResult {
                            input: raw.clone(),
                            kind: "email".to_string(),
                            valid: true,
                            error: None,
                            verdict: Some(dr.verdict.clone()),
                            risk_score: Some(dr.risk_score),
                            domain_result: Some(dr),
                            url_result: None,
                            ip_result: None,
                            hash_result: None,
                        }),
                        Err(e) => results.push(BatchCheckItemResult {
                            input: raw.clone(),
                            kind: "email".to_string(),
                            valid: false,
                            error: Some(e.to_string()),
                            verdict: None,
                            risk_score: None,
                            domain_result: None,
                            url_result: None,
                            ip_result: None,
                            hash_result: None,
                        }),
                    }
                }
                Ok(IndicatorInput::Domain { ascii_domain, .. }) => {
                    match self.lookup_domain(&ascii_domain).await {
                        Ok(dr) => results.push(BatchCheckItemResult {
                            input: raw.clone(),
                            kind: "domain".to_string(),
                            valid: true,
                            error: None,
                            verdict: Some(dr.verdict.clone()),
                            risk_score: Some(dr.risk_score),
                            domain_result: Some(dr),
                            url_result: None,
                            ip_result: None,
                            hash_result: None,
                        }),
                        Err(e) => results.push(BatchCheckItemResult {
                            input: raw.clone(),
                            kind: "domain".to_string(),
                            valid: false,
                            error: Some(e.to_string()),
                            verdict: None,
                            risk_score: None,
                            domain_result: None,
                            url_result: None,
                            ip_result: None,
                            hash_result: None,
                        }),
                    }
                }
                Err(msg) => results.push(BatchCheckItemResult {
                    input: raw.clone(),
                    kind: "unknown".to_string(),
                    valid: false,
                    error: Some(msg),
                    verdict: None,
                    risk_score: None,
                    domain_result: None,
                    url_result: None,
                    ip_result: None,
                    hash_result: None,
                }),
            }
        }

        Ok(BatchCheckResponse {
            count: results.len(),
            snapshot_version,
            results,
        })
    }

    // =========================================================================
    // Snapshot Inspection & Artifact Streaming Cache
    // =========================================================================

    pub async fn list_snapshots(&self) -> DgspamguardResult<SnapshotListResponse> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| DgspamguardError::Database(e.to_string()))?;

        let active_ver: Option<String> = client
            .query_one(
                "SELECT active_version FROM dgspamguard_state WHERE id = 1",
                &[],
            )
            .await
            .map_err(|e| DgspamguardError::Database(e.to_string()))?
            .get(0);

        let rows = client
            .query(
                r#"SELECT version, release_title, created_at, threat_domains, threat_urls,
                          threat_ips, disposable_domains, malware_hashes, bundle_sha256, bundle_size_bytes
                   FROM dgspamguard_snapshots
                   WHERE has_blobs = TRUE
                   ORDER BY created_at DESC
                   LIMIT 100"#,
                &[],
            )
            .await
            .map_err(|e| DgspamguardError::Database(e.to_string()))?;

        let snapshots: Vec<SnapshotSummaryItem> = rows
            .into_iter()
            .map(|r| {
                let version: String = r.get(0);
                let is_active = active_ver.as_deref() == Some(version.as_str());
                let detail_path = format!("/v1/snapshots/{version}");
                SnapshotSummaryItem {
                    version,
                    release_title: r.get(1),
                    created_at: r.get(2),
                    is_active,
                    threat_domains: r.get(3),
                    threat_urls: r.get(4),
                    threat_ips: r.get(5),
                    disposable_domains: r.get(6),
                    malware_hashes: r.get(7),
                    bundle_sha256: r.get(8),
                    bundle_size_bytes: r.get(9),
                    detail_path,
                }
            })
            .collect();

        Ok(SnapshotListResponse {
            count: snapshots.len(),
            active_version: active_ver,
            snapshots,
        })
    }

    pub async fn resolve_snapshot_version(&self, requested: &str) -> DgspamguardResult<String> {
        if requested == "latest" {
            let st = self.get_state().await?;
            st.active_version.ok_or_else(|| {
                DgspamguardError::Unavailable(
                    "No active DGSPAMGUARD snapshot is loaded yet.".to_string(),
                )
            })
        } else {
            Ok(requested.to_string())
        }
    }

    pub async fn get_snapshot_detail(
        &self,
        requested: &str,
    ) -> DgspamguardResult<SnapshotDetailResponse> {
        let version = self.resolve_snapshot_version(requested).await?;
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| DgspamguardError::Database(e.to_string()))?;

        let active_ver: Option<String> = client
            .query_one(
                "SELECT active_version FROM dgspamguard_state WHERE id = 1",
                &[],
            )
            .await
            .map_err(|e| DgspamguardError::Database(e.to_string()))?
            .get(0);

        let row = client
            .query_opt(
                r#"SELECT version, release_title, created_at, threat_domains, threat_urls,
                          threat_ips, disposable_domains, free_domains, redirector_domains,
                          malware_hashes, bundle_sha256, bundle_size_bytes, release_notes_md
                   FROM dgspamguard_snapshots
                   WHERE version = $1 AND has_blobs = TRUE"#,
                &[&version],
            )
            .await
            .map_err(|e| DgspamguardError::Database(e.to_string()))?
            .ok_or_else(|| {
                DgspamguardError::NotFound(format!("Snapshot '{version}' not found."))
            })?;

        let file_rows = client
            .query(
                r#"SELECT filename, content_type, size_bytes, sha256, record_count
                   FROM dgspamguard_snapshot_files
                   WHERE version = $1
                   ORDER BY filename"#,
                &[&version],
            )
            .await
            .map_err(|e| DgspamguardError::Database(e.to_string()))?;

        let mut files = Vec::with_capacity(file_rows.len());
        for fr in file_rows {
            let fname: String = fr.get(0);
            if fname == "bundle.tar.gz" {
                continue;
            }
            files.push(SnapshotFileItem {
                download_path: format!("/v1/snapshots/{version}/files/{fname}"),
                filename: fname,
                content_type: fr.get(1),
                size_bytes: fr.get(2),
                sha256: fr.get(3),
                record_count: fr.get(4),
            });
        }

        let is_active = active_ver.as_deref() == Some(version.as_str());
        Ok(SnapshotDetailResponse {
            bundle_download_path: format!("/v1/snapshots/{version}/bundle.tar.gz"),
            sha256sums_download_path: format!("/v1/snapshots/{version}/files/SHA256SUMS.txt"),
            version: row.get(0),
            release_title: row.get(1),
            created_at: row.get(2),
            is_active,
            threat_domains: row.get(3),
            threat_urls: row.get(4),
            threat_ips: row.get(5),
            disposable_domains: row.get(6),
            free_domains: row.get(7),
            redirector_domains: row.get(8),
            malware_hashes: row.get(9),
            bundle_sha256: row.get(10),
            bundle_size_bytes: row.get(11),
            release_notes_md: row.get(12),
            files,
        })
    }

    /// Purge any cached snapshot directories other than `keep_version` and clean up
    /// stale `*.tmp` files so bounded `/tmp` tmpfs volumes never accumulate across 4h cuts.
    pub async fn evict_non_active_cache_dirs(&self, keep_version: Option<&str>) {
        purge_cache_dir_except(&self.settings.cache_dir, keep_version).await;
    }

    pub async fn get_artifact_meta(
        &self,
        requested_version: &str,
        filename: &str,
    ) -> DgspamguardResult<SnapshotArtifactMeta> {
        let allowed = filename == "bundle.tar.gz"
            || filename == "SHA256SUMS.txt"
            || filename == "manifest.json"
            || DATASET_FILENAMES.contains(&filename);
        if !allowed {
            return Err(DgspamguardError::NotFound(format!(
                "Artifact '{filename}' is not a published DGSPAMGUARD dataset file."
            )));
        }

        let version = self.resolve_snapshot_version(requested_version).await?;
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| DgspamguardError::Database(e.to_string()))?;

        let meta_row = client
            .query_opt(
                r#"SELECT f.content_type,
                          f.sha256,
                          f.size_bytes,
                          (f.version = COALESCE((SELECT active_version FROM dgspamguard_state WHERE id = 1), '')) AS is_active
                   FROM dgspamguard_snapshot_files f
                   WHERE f.version = $1 AND f.filename = $2"#,
                &[&version, &filename],
            )
            .await
            .map_err(|e| DgspamguardError::Database(e.to_string()))?
            .ok_or_else(|| {
                DgspamguardError::NotFound(format!(
                    "Artifact '{filename}' not found on snapshot '{version}'."
                ))
            })?;

        let content_type: String = meta_row.get(0);
        let sha256: String = meta_row.get(1);
        let size_bytes_i64: i64 = meta_row.get(2);
        let is_active: bool = meta_row.get(3);

        Ok(SnapshotArtifactMeta {
            version,
            is_active,
            filename: filename.to_string(),
            content_type,
            sha256,
            size_bytes: size_bytes_i64.max(0) as u64,
        })
    }

    pub async fn fetch_artifact_bytes(&self, version: &str, filename: &str) -> DgspamguardResult<Bytes> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| DgspamguardError::Database(e.to_string()))?;

        let payload_row = client
            .query_opt(
                "SELECT payload FROM dgspamguard_snapshot_files WHERE version = $1 AND filename = $2",
                &[&version, &filename],
            )
            .await
            .map_err(|e| DgspamguardError::Database(e.to_string()))?
            .ok_or_else(|| {
                DgspamguardError::NotFound(format!(
                    "Artifact '{filename}' not found on snapshot '{version}'."
                ))
            })?;
        let bytes: Vec<u8> = payload_row.get(0);
        Ok(Bytes::from(bytes))
    }

    pub async fn materialize_artifact(
        &self,
        meta: &SnapshotArtifactMeta,
    ) -> DgspamguardResult<CachedArtifact> {
        if meta.is_active {
            let dir: PathBuf = self.settings.cache_dir.join(&meta.version);
            let target_path = dir.join(&meta.filename);
            if let Ok(md) = tokio::fs::metadata(&target_path).await {
                if md.len() == meta.size_bytes {
                    return Ok(CachedArtifact {
                        version: meta.version.clone(),
                        filename: meta.filename.clone(),
                        content_type: meta.content_type.clone(),
                        sha256: meta.sha256.clone(),
                        size_bytes: meta.size_bytes,
                        source: ArtifactSource::CachedFile(target_path),
                    });
                }
            }

            self.evict_non_active_cache_dirs(Some(&meta.version)).await;
            let bytes = self.fetch_artifact_bytes(&meta.version, &meta.filename).await?;

            if tokio::fs::create_dir_all(&dir).await.is_ok() {
                let tmp_path = dir.join(format!(".{}.{}.tmp", meta.filename, rand::random::<u32>()));
                match tokio::fs::write(&tmp_path, &bytes).await {
                    Ok(()) => {
                        if tokio::fs::rename(&tmp_path, &target_path).await.is_ok() {
                            return Ok(CachedArtifact {
                                version: meta.version.clone(),
                                filename: meta.filename.clone(),
                                content_type: meta.content_type.clone(),
                                sha256: meta.sha256.clone(),
                                size_bytes: bytes.len() as u64,
                                source: ArtifactSource::CachedFile(target_path),
                            });
                        }
                        let _ = tokio::fs::remove_file(&tmp_path).await;
                    }
                    Err(err) => {
                        let _ = tokio::fs::remove_file(&tmp_path).await;
                        tracing::debug!(
                            version = %meta.version,
                            filename = %meta.filename,
                            error = %err,
                            "Cache write skipped (disk full or read-only); serving artifact directly from memory"
                        );
                    }
                }
            }

            return Ok(CachedArtifact {
                version: meta.version.clone(),
                filename: meta.filename.clone(),
                content_type: meta.content_type.clone(),
                sha256: meta.sha256.clone(),
                size_bytes: bytes.len() as u64,
                source: ArtifactSource::InMemory(bytes),
            });
        }

        // Historical backfill snapshots stream directly from PostgreSQL without touching `/tmp`.
        let bytes = self.fetch_artifact_bytes(&meta.version, &meta.filename).await?;
        Ok(CachedArtifact {
            version: meta.version.clone(),
            filename: meta.filename.clone(),
            content_type: meta.content_type.clone(),
            sha256: meta.sha256.clone(),
            size_bytes: bytes.len() as u64,
            source: ArtifactSource::InMemory(bytes),
        })
    }

    pub async fn get_cached_artifact(
        &self,
        requested_version: &str,
        filename: &str,
    ) -> DgspamguardResult<CachedArtifact> {
        let meta = self.get_artifact_meta(requested_version, filename).await?;
        self.materialize_artifact(&meta).await
    }

    // =========================================================================
    // Operator CLI Helpers (Feeds, Allowlist, Config)
    // =========================================================================

    pub async fn set_feed_enabled(&self, feed_key: &str, enabled: bool) -> DgspamguardResult<()> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| DgspamguardError::Database(e.to_string()))?;
        let updated = client
            .execute(
                "UPDATE dgspamguard_feed_sources SET enabled = $2, updated_at = now() WHERE feed_key = $1",
                &[&feed_key, &enabled],
            )
            .await
            .map_err(|e| DgspamguardError::Database(e.to_string()))?;
        if updated == 0 {
            return Err(DgspamguardError::NotFound(format!(
                "Feed '{feed_key}' does not exist."
            )));
        }
        Ok(())
    }

    pub async fn set_feed_url(&self, feed_key: &str, url: &str) -> DgspamguardResult<()> {
        let parsed = url::Url::parse(url)
            .map_err(|e| DgspamguardError::Validation(format!("Invalid URL '{url}': {e}")))?;
        if parsed.scheme() != "https" {
            return Err(DgspamguardError::Validation(
                "Feed source URLs must use https://.".to_string(),
            ));
        }
        let host = parsed
            .host_str()
            .ok_or_else(|| DgspamguardError::Validation("URL missing hostname.".to_string()))?
            .to_ascii_lowercase();

        let client = self
            .pool
            .get()
            .await
            .map_err(|e| DgspamguardError::Database(e.to_string()))?;
        client
            .execute(
                "INSERT INTO dgspamguard_allowed_hosts (hostname, enabled, notes) VALUES ($1, TRUE, 'Added via CLI') ON CONFLICT (hostname) DO UPDATE SET enabled = TRUE, updated_at = now()",
                &[&host],
            )
            .await
            .map_err(|e| DgspamguardError::Database(e.to_string()))?;

        let updated = client
            .execute(
                "UPDATE dgspamguard_feed_sources SET source_url = $2, etag = NULL, last_modified = NULL, last_fetched_at = NULL, updated_at = now() WHERE feed_key = $1",
                &[&feed_key, &url],
            )
            .await
            .map_err(|e| DgspamguardError::Database(e.to_string()))?;
        if updated == 0 {
            return Err(DgspamguardError::NotFound(format!(
                "Feed '{feed_key}' does not exist."
            )));
        }
        Ok(())
    }

    pub async fn set_feed_ttl(&self, feed_key: &str, seconds: i64) -> DgspamguardResult<()> {
        if !(300..=604_800).contains(&seconds) {
            return Err(DgspamguardError::Validation(
                "Feed refresh TTL must be between 300s (5m) and 604800s (7d).".to_string(),
            ));
        }
        if feed_key.starts_with("ip-spamhaus-") && seconds < 3_600 {
            return Err(DgspamguardError::Validation(
                "Spamhaus DROP feeds require a refresh interval >= 3600s (1h) per Spamhaus fair-use policy."
                    .to_string(),
            ));
        }
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| DgspamguardError::Database(e.to_string()))?;
        let updated = client
            .execute(
                "UPDATE dgspamguard_feed_sources SET refresh_interval_seconds = $2, updated_at = now() WHERE feed_key = $1",
                &[&feed_key, &seconds],
            )
            .await
            .map_err(|e| DgspamguardError::Database(e.to_string()))?;
        if updated == 0 {
            return Err(DgspamguardError::NotFound(format!(
                "Feed '{feed_key}' does not exist."
            )));
        }
        Ok(())
    }

    pub async fn upsert_allowlist(
        &self,
        raw_domain: &str,
        kind: &str,
        notes: &str,
    ) -> DgspamguardResult<String> {
        if kind != "trusted" && kind != "shared_hosting" {
            return Err(DgspamguardError::Validation(
                "Allowlist kind must be 'trusted' or 'shared_hosting'.".to_string(),
            ));
        }
        let (ascii, _) = normalize_domain(raw_domain).ok_or_else(|| {
            DgspamguardError::Validation(format!("Invalid domain '{raw_domain}'."))
        })?;
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| DgspamguardError::Database(e.to_string()))?;
        client
            .execute(
                "INSERT INTO dgspamguard_allowlist (domain, kind, notes, updated_at) VALUES ($1, $2, $3, now()) ON CONFLICT (domain) DO UPDATE SET kind = EXCLUDED.kind, notes = EXCLUDED.notes, updated_at = now()",
                &[&ascii, &kind, &notes],
            )
            .await
            .map_err(|e| DgspamguardError::Database(e.to_string()))?;
        self.refresh_in_memory_meta().await?;
        Ok(ascii)
    }

    pub async fn remove_allowlist(&self, raw_domain: &str) -> DgspamguardResult<()> {
        let (ascii, _) = normalize_domain(raw_domain).ok_or_else(|| {
            DgspamguardError::Validation(format!("Invalid domain '{raw_domain}'."))
        })?;
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| DgspamguardError::Database(e.to_string()))?;
        let n = client
            .execute(
                "DELETE FROM dgspamguard_allowlist WHERE domain = $1",
                &[&ascii],
            )
            .await
            .map_err(|e| DgspamguardError::Database(e.to_string()))?;
        if n == 0 {
            return Err(DgspamguardError::NotFound(format!(
                "Domain '{ascii}' was not in dgspamguard_allowlist."
            )));
        }
        self.refresh_in_memory_meta().await?;
        Ok(())
    }

    pub async fn list_config_entries(&self) -> DgspamguardResult<Vec<(String, Value, String)>> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| DgspamguardError::Database(e.to_string()))?;
        let rows = client
            .query(
                "SELECT key, value_json, description FROM dgspamguard_config ORDER BY key",
                &[],
            )
            .await
            .map_err(|e| DgspamguardError::Database(e.to_string()))?;
        Ok(rows
            .into_iter()
            .map(|r| (r.get(0), r.get(1), r.get(2)))
            .collect())
    }

    pub async fn set_config_json(&self, key: &str, raw_json: &str) -> DgspamguardResult<Value> {
        let val: Value =
            serde_json::from_str(raw_json).unwrap_or_else(|_| Value::String(raw_json.to_string()));
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| DgspamguardError::Database(e.to_string()))?;
        client
            .execute(
                "INSERT INTO dgspamguard_config (key, value_json, description, updated_at) VALUES ($1, $2, 'Updated via CLI', now()) ON CONFLICT (key) DO UPDATE SET value_json = EXCLUDED.value_json, updated_at = now()",
                &[&key, &val],
            )
            .await
            .map_err(|e| DgspamguardError::Database(e.to_string()))?;
        Ok(val)
    }
}

fn write_pg_text_col(buf: &mut Vec<u8>, s: &str) {
    for b in s.bytes() {
        match b {
            b'\\' => buf.extend_from_slice(b"\\\\"),
            b'\t' => buf.extend_from_slice(b"\\t"),
            b'\n' => buf.extend_from_slice(b"\\n"),
            b'\r' => buf.extend_from_slice(b"\\r"),
            other => buf.push(other),
        }
    }
}

fn write_pg_opt_col(buf: &mut Vec<u8>, opt: Option<&str>) {
    match opt {
        Some(s) => write_pg_text_col(buf, s),
        None => buf.extend_from_slice(b"\\N"),
    }
}

/// Remove cached snapshot subdirectories other than `keep_version` and clean up stale `*.tmp` files.
pub async fn purge_cache_dir_except(cache_dir: &std::path::Path, keep_version: Option<&str>) {
    let Ok(mut entries) = tokio::fs::read_dir(cache_dir).await else {
        return;
    };
    while let Ok(Some(entry)) = entries.next_entry().await {
        let path = entry.path();
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if name_str.starts_with('.') || name_str.ends_with(".tmp") {
            let _ = tokio::fs::remove_file(&path).await;
            continue;
        }
        if keep_version != Some(name_str.as_ref()) {
            if tokio::fs::remove_dir_all(&path).await.is_err() {
                let _ = tokio::fs::remove_file(&path).await;
            }
        } else if let Ok(mut sub) = tokio::fs::read_dir(&path).await {
            while let Ok(Some(sub_entry)) = sub.next_entry().await {
                let sub_name = sub_entry.file_name();
                let sub_str = sub_name.to_string_lossy();
                if sub_str.starts_with('.') && sub_str.ends_with(".tmp") {
                    if let Ok(md) = sub_entry.metadata().await {
                        let stale = md
                            .modified()
                            .ok()
                            .and_then(|m| m.elapsed().ok())
                            .is_none_or(|age| age.as_secs() > 120);
                        if stale {
                            let _ = tokio::fs::remove_file(sub_entry.path()).await;
                        }
                    }
                }
            }
        }
    }
}
