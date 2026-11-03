use chrono::{DateTime, Utc};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use std::path::PathBuf;
use thiserror::Error;

pub const APP_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Canonical snapshot dataset filenames packaged into every DGSPAMGUARD release.
pub const DATASET_FILENAMES: [&str; 9] = [
    "dgspamguard-threat-domains.rpz.gz",
    "dgspamguard-threat-domains.csv.gz",
    "dgspamguard-threat-domains.txt.gz",
    "dgspamguard-threat-urls.csv.gz",
    "dgspamguard-smtp-ips.csv.gz",
    "dgspamguard-email-domains.csv.gz",
    "dgspamguard-malware-hashes.csv.gz",
    "dgspamguard-tld-risk.csv.gz",
    "dgmail-rules.json.gz",
];

#[derive(Debug, Error)]
pub enum DgspamguardError {
    #[error("Database error: {0}")]
    Database(String),
    #[error("Validation error: {0}")]
    Validation(String),
    #[error("Not found: {0}")]
    NotFound(String),
    #[error("Service unavailable: {0}")]
    Unavailable(String),
    #[error("Sync error: {0}")]
    Sync(String),
    #[error("Compilation error: {0}")]
    Compile(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

pub type DgspamguardResult<T> = Result<T, DgspamguardError>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeedSourceSpec {
    pub feed_key: String,
    pub category: String,
    pub parser_kind: String,
    pub source_url: String,
    pub refresh_interval_seconds: i64,
    pub min_records: i32,
    pub max_compressed_bytes: i64,
    pub max_uncompressed_bytes: i64,
    pub confidence_weight: i16,
    pub enabled: bool,
    pub display_order: i16,
    pub etag: Option<String>,
    pub last_modified: Option<String>,
    pub last_fetched_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AllowlistRule {
    pub domain: String,
    /// `"trusted"` (never block domain or subdomains) or `"shared_hosting"` (never block bare root; allow subdomain/URL blocks).
    pub kind: String,
    pub notes: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TldRiskRule {
    pub tld: String,
    pub risk_score: i16,
    pub risk_level: String,
    pub notes: String,
}

#[derive(Debug, Clone)]
pub struct RuntimeCatalog {
    pub bootstrap_bundle_url: String,
    pub allowed_source_hosts: HashSet<String>,
    pub trusted_proxies: Vec<IpNet>,
    pub rate_limit_per_minute: u32,
    pub swagger_enabled: bool,
    pub retention_days: i64,
    pub version_prefix: String,
    pub release_title_template: String,
    pub abusech_auth_key: Option<String>,
    pub allowlist: Vec<AllowlistRule>,
    pub tld_risks: Vec<TldRiskRule>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompiledDomainRow {
    pub domain: String,
    pub registered_domain: String,
    /// `Some("phishing")`, `Some("malware")`, `Some("c2")`, or `None` (for benign taxonomy-only rows).
    pub threat_category: Option<String>,
    pub confidence: i16,
    pub source_count: i16,
    pub sources: String,
    /// `Some("disposable")`, `Some("free_provider")`, `Some("url_redirector")`, `Some("trusted")`, or `None`.
    pub email_kind: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompiledUrlRow {
    pub url_sha256: String,
    pub domain: String,
    pub canonical_url: String,
    pub threat_category: String,
    pub confidence: i16,
    pub source_count: i16,
    pub sources: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompiledHashRow {
    pub sha256: String,
    pub malware_family: String,
    pub confidence: i16,
    pub sources: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompiledIpRow {
    pub network: String,
    pub threat_category: String,
    pub confidence: i16,
    pub source_count: i16,
    pub sources: String,
}

#[derive(Debug, Clone)]
pub struct CompiledThreatSet {
    pub domains: Vec<CompiledDomainRow>,
    pub urls: Vec<CompiledUrlRow>,
    pub ips: Vec<CompiledIpRow>,
    pub hashes: Vec<CompiledHashRow>,
    pub tld_risks: Vec<TldRiskRule>,
    pub shared_hosting_roots: HashSet<String>,
    pub threat_domain_count: i64,
    pub disposable_domain_count: i64,
    pub free_domain_count: i64,
    pub redirector_domain_count: i64,
    pub trusted_domain_count: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatasetArtifactMeta {
    pub filename: String,
    pub content_type: String,
    pub size_bytes: i64,
    pub sha256: String,
    pub record_count: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct PackagedSnapshot {
    pub version: String,
    pub generated_at: DateTime<Utc>,
    pub release_title: String,
    pub release_notes_md: String,
    pub manifest_json: Vec<u8>,
    pub manifest_sha256: String,
    pub sha256sums_txt: Vec<u8>,
    pub sha256sums_sha256: String,
    pub bundle_bytes: Vec<u8>,
    pub bundle_sha256: String,
    /// Keyed by canonical filename from `DATASET_FILENAMES`.
    pub dataset_artifacts: BTreeMap<String, (DatasetArtifactMeta, Vec<u8>)>,
    pub compiled: CompiledThreatSet,
}

#[derive(Debug, Clone)]
pub struct CachedArtifact {
    pub filename: String,
    pub content_type: String,
    pub sha256: String,
    pub size_bytes: u64,
    pub path: PathBuf,
}
