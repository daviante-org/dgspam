use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

pub const PROBLEM_JSON_CONTENT_TYPE: &str = "application/problem+json";
pub const MAX_BATCH_ITEMS: usize = 250;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProblemDetails {
    #[serde(rename = "type")]
    pub problem_type: String,
    pub title: String,
    pub status: u16,
    pub detail: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instance: Option<String>,
}

impl ProblemDetails {
    pub fn new(
        status: u16,
        title: impl Into<String>,
        detail: impl Into<String>,
        instance: Option<String>,
    ) -> Self {
        Self {
            problem_type: "about:blank".to_string(),
            title: title.into(),
            status,
            detail: detail.into(),
            instance,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthLiveResponse {
    pub status: String,
    pub service: String,
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthReadyResponse {
    pub status: String,
    pub active_slot: Option<String>,
    pub active_version: Option<String>,
    pub initial_bootstrapped: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TldReputation {
    pub tld: String,
    pub risk_score: i16,
    pub risk_level: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainThreatInfo {
    pub is_threat: bool,
    pub category: Option<String>,
    pub matched_domain: Option<String>,
    pub confidence: i16,
    pub source_count: i16,
    pub sources: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainTaxonomyInfo {
    pub is_disposable_email: bool,
    pub is_free_email: bool,
    pub is_url_redirector: bool,
    pub is_trusted: bool,
    pub is_shared_hosting: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainLookupResponse {
    pub domain: String,
    pub unicode_domain: String,
    pub registered_domain: String,
    pub verdict: String,
    pub risk_score: i16,
    pub threat: DomainThreatInfo,
    pub taxonomy: DomainTaxonomyInfo,
    pub tld: TldReputation,
    pub snapshot_version: String,
    pub live_updated_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UrlCheckRequest {
    pub url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UrlCheckResponse {
    pub input_url: String,
    pub canonical_url: String,
    pub url_sha256: String,
    pub domain: String,
    pub registered_domain: String,
    pub verdict: String,
    pub risk_score: i16,
    pub is_threat: bool,
    pub match_scope: Option<String>,
    pub category: Option<String>,
    pub confidence: i16,
    pub sources: Vec<String>,
    pub taxonomy: DomainTaxonomyInfo,
    pub tld: TldReputation,
    pub snapshot_version: String,
    pub live_updated_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashLookupResponse {
    pub sha256: String,
    pub found: bool,
    pub verdict: String,
    pub malware_family: Option<String>,
    pub confidence: i16,
    pub sources: Vec<String>,
    pub snapshot_version: String,
    pub live_updated_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpLookupResponse {
    pub ip: String,
    pub ip_version: u8,
    pub is_public_routable: bool,
    pub verdict: String,
    pub risk_score: i16,
    pub is_threat: bool,
    pub matched_network: Option<String>,
    pub match_scope: Option<String>,
    pub category: Option<String>,
    pub confidence: i16,
    pub source_count: i16,
    pub sources: Vec<String>,
    pub snapshot_version: String,
    pub live_updated_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchCheckRequest {
    pub items: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchCheckItemResult {
    pub input: String,
    pub kind: String,
    pub valid: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verdict: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub risk_score: Option<i16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain_result: Option<DomainLookupResponse>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url_result: Option<UrlCheckResponse>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip_result: Option<IpLookupResponse>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash_result: Option<HashLookupResponse>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchCheckResponse {
    pub count: usize,
    pub snapshot_version: String,
    pub results: Vec<BatchCheckItemResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotFileItem {
    pub filename: String,
    pub content_type: String,
    pub size_bytes: i64,
    pub sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub record_count: Option<i64>,
    pub download_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotDetailResponse {
    pub version: String,
    pub release_title: String,
    pub created_at: DateTime<Utc>,
    pub is_active: bool,
    pub threat_domains: i64,
    pub threat_urls: i64,
    pub threat_ips: i64,
    pub disposable_domains: i64,
    pub free_domains: i64,
    pub redirector_domains: i64,
    pub malware_hashes: i64,
    pub bundle_sha256: String,
    pub bundle_size_bytes: i64,
    pub bundle_download_path: String,
    pub sha256sums_download_path: String,
    pub release_notes_md: String,
    pub files: Vec<SnapshotFileItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotSummaryItem {
    pub version: String,
    pub release_title: String,
    pub created_at: DateTime<Utc>,
    pub is_active: bool,
    pub threat_domains: i64,
    pub threat_urls: i64,
    pub threat_ips: i64,
    pub disposable_domains: i64,
    pub malware_hashes: i64,
    pub bundle_sha256: String,
    pub bundle_size_bytes: i64,
    pub detail_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotListResponse {
    pub count: usize,
    pub active_version: Option<String>,
    pub snapshots: Vec<SnapshotSummaryItem>,
}
