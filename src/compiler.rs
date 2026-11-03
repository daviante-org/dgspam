use crate::normalize::{
    canonicalize_url_with_ip, extract_first_zip_entry, gunzip_bounded, normalize_domain,
    normalize_public_ip_or_cidr, normalize_sha256, sha256_hex, PslMatcher,
};
use crate::release_notes::{format_release_title, render_release_notes};
use crate::seed_data::{
    build_upgraded_dgmail_rules_json, extract_seed_memory_sets, FALLBACK_FREE_EMAIL_DOMAINS,
};
use crate::types::{
    CompiledDomainRow, CompiledHashRow, CompiledIpRow, CompiledThreatSet, CompiledUrlRow,
    DatasetArtifactMeta, DgspamguardError, DgspamguardResult, FeedSourceSpec, PackagedSnapshot,
    RuntimeCatalog, TldRiskRule, DATASET_FILENAMES,
};
use chrono::{DateTime, Utc};
use flate2::write::GzEncoder;
use flate2::Compression;
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::io::{Read, Write};
use tar::{Archive, Builder, Header};

/// Maximum compressed size for `dgmail-rules.json.gz` (strictly below DGMail's 500 KB fetch cap).
const MAX_DGMAIL_RULES_GZ_BYTES: usize = 440 * 1024;
/// Maximum uncompressed bytes accepted when unpacking a bootstrap `bundle.tar.gz`.
const MAX_BUNDLE_UNPACK_BYTES: usize = 384 * 1024 * 1024;

/// Path-based multi-tenant hosts where URLs may be malicious (`docs.google.com/forms/...`),
/// so exact URLs can be blocked, but the host domain itself must NEVER be domain-blocked.
const PATH_ONLY_SHARED_HOSTS: &[&str] = &[
    "docs.google.com",
    "drive.google.com",
    "sites.google.com",
    "forms.gle",
    "googleapis.com",
    "firebasestorage.googleapis.com",
    "googleusercontent.com",
    "onedrive.live.com",
    "1drv.ms",
    "dropbox.com",
    "dl.dropboxusercontent.com",
    "raw.githubusercontent.com",
    "gist.github.com",
    "discord.com",
    "discordapp.com",
    "cdn.discordapp.com",
    "t.me",
    "canva.com",
    "s3.amazonaws.com",
];

#[derive(Debug, Clone)]
pub struct RawFeedPayload {
    pub spec: FeedSourceSpec,
    pub raw_bytes: Vec<u8>,
}

#[derive(Default)]
struct DomainAcc {
    threat_category: Option<String>,
    max_threat_weight: i16,
    threat_sources: BTreeSet<String>,
    email_kind: Option<String>,
    max_email_weight: i16,
    email_sources: BTreeSet<String>,
}

struct UrlAcc {
    domain: String,
    canonical_url: String,
    threat_category: String,
    max_weight: i16,
    sources: BTreeSet<String>,
}

struct HashAcc {
    malware_family: String,
    max_weight: i16,
    sources: BTreeSet<String>,
}

struct IpAcc {
    threat_category: String,
    max_weight: i16,
    sources: BTreeSet<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotManifest {
    pub schema_version: u32,
    pub service: String,
    pub version: String,
    pub release_title: String,
    pub generated_at: DateTime<Utc>,
    pub counts: SnapshotManifestCounts,
    pub shared_hosting_roots: Vec<String>,
    pub files: Vec<DatasetArtifactMeta>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotManifestCounts {
    pub threat_domains: i64,
    pub threat_urls: i64,
    #[serde(default)]
    pub threat_ips: i64,
    pub disposable_domains: i64,
    pub free_domains: i64,
    pub redirector_domains: i64,
    pub trusted_domains: i64,
    pub malware_hashes: i64,
    pub tld_risks: i64,
}

fn category_priority(cat: &str) -> u8 {
    match cat {
        "c2" => 3,
        "malware" => 2,
        "phishing" => 1,
        _ => 0,
    }
}

fn ip_category_priority(cat: &str) -> u8 {
    match cat {
        "hijacked_cidr" => 5,
        "botnet_c2" | "c2" => 4,
        "smtp_attacker" => 3,
        "botnet_ip" => 2,
        "malware" | "phishing_ip" | "phishing" => 1,
        _ => 0,
    }
}

fn clean_csv_cell(s: &str) -> &str {
    s.trim().trim_matches('"').trim()
}

fn strip_hash_comment_lines(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        out.push_str(line);
        out.push('\n');
    }
    out
}

fn email_kind_priority(kind: &str) -> u8 {
    match kind {
        "trusted" => 4,
        "free_provider" => 3,
        "url_redirector" => 2,
        "disposable" => 1,
        _ => 0,
    }
}

fn combine_confidence(max_weight: i16, source_count: usize) -> i16 {
    let bonus = ((source_count.saturating_sub(1)) as i16).saturating_mul(12);
    max_weight.saturating_add(bonus).clamp(15, 99)
}

fn decode_feed_text(spec: &FeedSourceSpec, raw_bytes: &[u8]) -> DgspamguardResult<String> {
    let max_uncomp = (spec.max_uncompressed_bytes.max(1024)) as usize;
    let plain = if raw_bytes.len() >= 2 && raw_bytes[0] == 0x1f && raw_bytes[1] == 0x8b {
        gunzip_bounded(raw_bytes, max_uncomp)?
    } else if raw_bytes.len() >= 4 && &raw_bytes[0..4] == b"PK\x03\x04" {
        extract_first_zip_entry(raw_bytes, max_uncomp)?
    } else {
        if raw_bytes.len() > max_uncomp {
            return Err(DgspamguardError::Compile(format!(
                "Feed '{}' payload ({} bytes) exceeds uncompressed limit ({max_uncomp}).",
                spec.feed_key,
                raw_bytes.len()
            )));
        }
        raw_bytes.to_vec()
    };
    Ok(String::from_utf8_lossy(&plain).into_owned())
}

fn clean_domain_candidate(line: &str) -> Option<&str> {
    let no_comment = line
        .split('#')
        .next()
        .unwrap_or("")
        .split(';')
        .next()
        .unwrap_or("")
        .trim();
    if no_comment.is_empty() || no_comment.starts_with('!') || no_comment.starts_with('[') {
        return None;
    }

    // Adblock syntax: `||evil.example.com^` or `||evil.example.com^$all`
    if let Some(rest) = no_comment.strip_prefix("||") {
        let host = rest.split('^').next().unwrap_or(rest).trim();
        let host = host.strip_prefix("*.").unwrap_or(host);
        return if host.is_empty() { None } else { Some(host) };
    }

    // Hosts file syntax: `0.0.0.0 evil.example.com` or `127.0.0.1 evil.example.com`
    let mut parts = no_comment.split_whitespace();
    let first = parts.next()?;
    let candidate = if first == "0.0.0.0" || first == "127.0.0.1" || first == "::1" || first == "::"
    {
        parts.next()?
    } else {
        first
    };

    let candidate = candidate.strip_prefix("*.").unwrap_or(candidate).trim();
    if candidate.is_empty() || candidate == "localhost" {
        None
    } else {
        Some(candidate)
    }
}

/// Compile raw upstream feeds + runtime catalog + embedded DGMail base seed into a normalized `CompiledThreatSet`.
pub fn compile_threat_feeds(
    payloads: &[RawFeedPayload],
    catalog: &RuntimeCatalog,
) -> DgspamguardResult<CompiledThreatSet> {
    // 1. Build Mozilla PSL matcher (Layer 0)
    let mut psl = PslMatcher::default();
    for item in payloads {
        if item.spec.enabled && item.spec.parser_kind == "psl_dat" {
            let text = decode_feed_text(&item.spec, &item.raw_bytes)?;
            let parsed = PslMatcher::from_psl_dat(&text);
            if (parsed.private_roots().len() as i32) < 20 {
                return Err(DgspamguardError::Compile(format!(
                    "PSL feed '{}' parsed suspiciously few private suffixes.",
                    item.spec.feed_key
                )));
            }
            psl = parsed;
        }
    }

    // 2. Build Allowlist & Shared-Hosting sets (Layer 0)
    let (seed_trusted, seed_redirectors) = extract_seed_memory_sets()?;

    let mut trusted_roots: HashSet<String> = HashSet::new();
    let mut shared_hosting_roots: HashSet<String> = psl.private_roots().clone();
    let mut path_only_shared: HashSet<String> = PATH_ONLY_SHARED_HOSTS
        .iter()
        .map(|s| (*s).to_string())
        .collect();

    for d in &seed_trusted {
        if let Some((ascii, _)) = normalize_domain(d) {
            trusted_roots.insert(ascii);
        }
    }
    for rule in &catalog.allowlist {
        if let Some((ascii, _)) = normalize_domain(&rule.domain) {
            if rule.kind == "shared_hosting" {
                shared_hosting_roots.insert(ascii.clone());
                // If not already a PSL private root where tenants get subdomains, protect if path-based
                if !psl.is_private_public_suffix(&ascii) {
                    path_only_shared.insert(ascii);
                }
            } else {
                trusted_roots.insert(ascii);
            }
        }
    }
    for h in &path_only_shared {
        shared_hosting_roots.insert(h.clone());
    }

    // Parse Tranco top-1m rank gate (top 100K exact safe domains; top 10K enterprise root protection)
    let mut top_100k_domains: HashSet<String> = HashSet::new();
    let mut top_10k_roots: HashSet<String> = HashSet::new();

    for item in payloads {
        if item.spec.enabled && item.spec.parser_kind == "tranco_csv_zip" {
            let text = decode_feed_text(&item.spec, &item.raw_bytes)?;
            let mut count = 0i32;
            for line in text.lines() {
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }
                let (rank_str, dom_raw) = match trimmed.split_once(',') {
                    Some(pair) => pair,
                    None => continue,
                };
                let Ok(rank) = rank_str.trim().parse::<u32>() else {
                    continue;
                };
                if rank > 100_000 {
                    continue;
                }
                if let Some((ascii, _)) = normalize_domain(dom_raw) {
                    count += 1;
                    if !shared_hosting_roots.contains(&ascii) {
                        top_100k_domains.insert(ascii.clone());
                        if rank <= 10_000 {
                            top_10k_roots.insert(ascii);
                        }
                    }
                }
            }
            if count < item.spec.min_records {
                return Err(DgspamguardError::Compile(format!(
                    "Allowlist feed '{}' yielded only {count} top-100K domains (minimum {}).",
                    item.spec.feed_key, item.spec.min_records
                )));
            }
        }
    }

    let is_domain_block_forbidden = |ascii_dom: &str| -> bool {
        if psl.is_icann_public_suffix(ascii_dom) || psl.is_private_public_suffix(ascii_dom) {
            return true;
        }
        if shared_hosting_roots.contains(ascii_dom) || path_only_shared.contains(ascii_dom) {
            return true;
        }
        if top_100k_domains.contains(ascii_dom) || trusted_roots.contains(ascii_dom) {
            return true;
        }

        // Check parent suffixes: if under a path-only shared host, forbid domain-level block unless PSL private tenant
        let mut cur = ascii_dom;
        while let Some(pos) = cur.find('.') {
            cur = &cur[pos + 1..];
            if shared_hosting_roots.contains(cur) {
                // Allowed ONLY when `cur` is a subdomain-isolated PSL private suffix (e.g. `pages.dev`, `github.io`)
                // AND `ascii_dom` is not bare `cur`
                if psl.is_private_public_suffix(cur) && !path_only_shared.contains(cur) {
                    return false;
                }
                return true;
            }
            if trusted_roots.contains(cur) || top_10k_roots.contains(cur) {
                return true;
            }
        }
        false
    };

    let mut domain_map: HashMap<String, DomainAcc> = HashMap::with_capacity(550_000);
    let mut url_map: HashMap<String, UrlAcc> = HashMap::with_capacity(850_000);
    let mut hash_map: HashMap<String, HashAcc> = HashMap::with_capacity(96_000);
    let mut ip_map: HashMap<String, IpAcc> = HashMap::with_capacity(65_536);
    let mut compromised_legit_hosts: HashSet<String> = HashSet::new();

    // Seed trusted, redirector, and fallback free email domains into taxonomy
    for dom in &trusted_roots {
        if !psl.is_icann_public_suffix(dom) && !shared_hosting_roots.contains(dom) {
            let entry = domain_map.entry(dom.clone()).or_default();
            entry.email_kind = Some("trusted".to_string());
            entry.max_email_weight = 95;
            entry.email_sources.insert("daviante-seed".to_string());
        }
    }

    for dom in &seed_redirectors {
        if let Some((ascii, _)) = normalize_domain(dom) {
            let entry = domain_map.entry(ascii).or_default();
            if entry
                .email_kind
                .as_deref()
                .is_none_or(|k| email_kind_priority("url_redirector") > email_kind_priority(k))
            {
                entry.email_kind = Some("url_redirector".to_string());
            }
            entry.max_email_weight = entry.max_email_weight.max(90);
            entry.email_sources.insert("daviante-seed".to_string());
        }
    }

    for &dom in FALLBACK_FREE_EMAIL_DOMAINS {
        if let Some((ascii, _)) = normalize_domain(dom) {
            let entry = domain_map.entry(ascii).or_default();
            if entry
                .email_kind
                .as_deref()
                .is_none_or(|k| email_kind_priority("free_provider") > email_kind_priority(k))
            {
                entry.email_kind = Some("free_provider".to_string());
            }
            entry.max_email_weight = entry.max_email_weight.max(92);
            entry.email_sources.insert("daviante-seed".to_string());
        }
    }

    // Order feeds so `urlhaus_v1_urls_json` runs first and populates `compromised_legit_hosts`
    // (`spamhaus_dbl == "abused_legit_*"`) before bulk CSV/TXT feeds promote hostnames to RPZ!
    let mut ordered_payloads: Vec<&RawFeedPayload> = payloads
        .iter()
        .filter(|p| {
            p.spec.enabled
                && p.spec.parser_kind != "psl_dat"
                && p.spec.parser_kind != "tranco_csv_zip"
        })
        .collect();
    ordered_payloads.sort_by_key(|p| {
        if p.spec.parser_kind == "urlhaus_v1_urls_json" {
            0u8
        } else {
            1u8
        }
    });

    // Helper closures for inserting into ip_map, domain_map, url_map, and hash_map
    let insert_ip = |ip_map: &mut HashMap<String, IpAcc>,
                     net: IpNet,
                     cat: &str,
                     weight: i16,
                     feed_key: &str| {
        let key = net.to_string();
        let entry = ip_map.entry(key).or_insert_with(|| IpAcc {
            threat_category: cat.to_string(),
            max_weight: weight,
            sources: BTreeSet::new(),
        });
        if ip_category_priority(cat) > ip_category_priority(&entry.threat_category) {
            entry.threat_category = cat.to_string();
        }
        entry.max_weight = entry.max_weight.max(weight);
        entry.sources.insert(feed_key.to_string());
    };

    let insert_hash = |hash_map: &mut HashMap<String, HashAcc>,
                       digest: String,
                       family: String,
                       weight: i16,
                       feed_key: &str| {
        let h_entry = hash_map.entry(digest).or_insert_with(|| HashAcc {
            malware_family: family.clone(),
            max_weight: weight,
            sources: BTreeSet::new(),
        });
        if h_entry.malware_family == "malware" && family != "malware" {
            h_entry.malware_family = family;
        }
        h_entry.max_weight = h_entry.max_weight.max(weight);
        h_entry.sources.insert(feed_key.to_string());
    };

    // 3. Process Layer 1–4 feeds
    for item in ordered_payloads {
        let spec = &item.spec;
        let text = decode_feed_text(spec, &item.raw_bytes)?;
        let mut parsed_records = 0i32;

        match spec.parser_kind.as_str() {
            "domains_txt" => {
                let is_threat = matches!(spec.category.as_str(), "phishing" | "malware" | "c2");
                for line in text.lines() {
                    let Some(cand) = clean_domain_candidate(line) else {
                        continue;
                    };
                    let Some((ascii, _)) = normalize_domain(cand) else {
                        continue;
                    };
                    parsed_records += 1;

                    if is_threat {
                        if is_domain_block_forbidden(&ascii)
                            || compromised_legit_hosts.contains(&ascii)
                        {
                            continue;
                        }
                        let entry = domain_map.entry(ascii).or_default();
                        if entry.threat_category.as_deref().is_none_or(|prev| {
                            category_priority(&spec.category) > category_priority(prev)
                        }) {
                            entry.threat_category = Some(spec.category.clone());
                        }
                        entry.max_threat_weight =
                            entry.max_threat_weight.max(spec.confidence_weight);
                        entry.threat_sources.insert(spec.feed_key.clone());
                    } else {
                        // Email taxonomy feed (`disposable` or `free_provider`)
                        if psl.is_icann_public_suffix(&ascii) {
                            continue;
                        }
                        if spec.category == "disposable"
                            && (trusted_roots.contains(&ascii) || top_10k_roots.contains(&ascii))
                        {
                            continue;
                        }
                        let entry = domain_map.entry(ascii).or_default();
                        if entry.email_kind.as_deref().is_none_or(|prev| {
                            email_kind_priority(&spec.category) > email_kind_priority(prev)
                        }) {
                            entry.email_kind = Some(spec.category.clone());
                        }
                        entry.max_email_weight = entry.max_email_weight.max(spec.confidence_weight);
                        entry.email_sources.insert(spec.feed_key.clone());
                    }
                }
            }
            "urls_txt" => {
                let cat = if matches!(spec.category.as_str(), "phishing" | "malware" | "c2") {
                    spec.category.as_str()
                } else {
                    "phishing"
                };
                for line in text.lines() {
                    let trimmed = line.trim();
                    if trimmed.is_empty() || trimmed.starts_with('#') {
                        continue;
                    }
                    let Some((canonical_url, host_key, url_sha256, opt_ip)) =
                        canonicalize_url_with_ip(trimmed)
                    else {
                        continue;
                    };
                    parsed_records += 1;

                    let is_bare_root_path = canonical_url
                        .split_once("://")
                        .and_then(|(_, rest)| rest.split_once('/'))
                        .is_none_or(|(_, path)| path.is_empty());

                    if opt_ip.is_none()
                        && is_bare_root_path
                        && (trusted_roots.contains(&host_key)
                            || top_100k_domains.contains(&host_key)
                            || shared_hosting_roots.contains(&host_key))
                    {
                        continue;
                    }

                    let u_entry = url_map.entry(url_sha256).or_insert_with(|| UrlAcc {
                        domain: host_key.clone(),
                        canonical_url,
                        threat_category: cat.to_string(),
                        max_weight: spec.confidence_weight,
                        sources: BTreeSet::new(),
                    });
                    if category_priority(cat) > category_priority(&u_entry.threat_category) {
                        u_entry.threat_category = cat.to_string();
                    }
                    u_entry.max_weight = u_entry.max_weight.max(spec.confidence_weight);
                    u_entry.sources.insert(spec.feed_key.clone());

                    if let Some(ip) = opt_ip {
                        let ip_cat = if cat == "phishing" {
                            "phishing_ip"
                        } else {
                            cat
                        };
                        insert_ip(
                            &mut ip_map,
                            IpNet::from(ip),
                            ip_cat,
                            spec.confidence_weight,
                            &spec.feed_key,
                        );
                    } else if !is_domain_block_forbidden(&host_key)
                        && !compromised_legit_hosts.contains(&host_key)
                    {
                        let d_entry = domain_map.entry(host_key).or_default();
                        if d_entry
                            .threat_category
                            .as_deref()
                            .is_none_or(|prev| category_priority(cat) > category_priority(prev))
                        {
                            d_entry.threat_category = Some(cat.to_string());
                        }
                        d_entry.max_threat_weight =
                            d_entry.max_threat_weight.max(spec.confidence_weight);
                        d_entry.threat_sources.insert(spec.feed_key.clone());
                    }
                }
            }
            "ips_txt" => {
                for line in text.lines() {
                    let no_comment = line
                        .split('#')
                        .next()
                        .unwrap_or("")
                        .split(';')
                        .next()
                        .unwrap_or("")
                        .trim();
                    if no_comment.is_empty() {
                        continue;
                    }
                    let Some(token) = no_comment.split_whitespace().next() else {
                        continue;
                    };
                    let Some(net) = normalize_public_ip_or_cidr(token) else {
                        continue;
                    };
                    parsed_records += 1;
                    insert_ip(
                        &mut ip_map,
                        net,
                        &spec.category,
                        spec.confidence_weight,
                        &spec.feed_key,
                    );
                }
            }
            "spamhaus_drop_json" => {
                for line in text.lines() {
                    let trimmed = line.trim();
                    if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';') {
                        continue;
                    }
                    let Ok(val) = serde_json::from_str::<Value>(trimmed) else {
                        continue;
                    };
                    if val.get("type").and_then(Value::as_str) == Some("metadata") {
                        continue;
                    }
                    let Some(cidr_raw) = val.get("cidr").and_then(Value::as_str) else {
                        continue;
                    };
                    let Some(net) = normalize_public_ip_or_cidr(cidr_raw) else {
                        continue;
                    };
                    parsed_records += 1;
                    insert_ip(
                        &mut ip_map,
                        net,
                        &spec.category,
                        spec.confidence_weight,
                        &spec.feed_key,
                    );
                }
            }
            "urlhaus_v1_urls_json" => {
                let root: Value = serde_json::from_str(&text).map_err(|e| {
                    DgspamguardError::Compile(format!(
                        "Invalid JSON in URLhaus v1 URLs feed '{}': {e}",
                        spec.feed_key
                    ))
                })?;
                if let Some(arr) = root.get("urls").and_then(Value::as_array) {
                    for obj in arr {
                        let dbl_status = obj
                            .get("blacklists")
                            .and_then(|b| b.get("spamhaus_dbl"))
                            .and_then(Value::as_str)
                            .unwrap_or("");
                        if dbl_status.contains("abused_legit") {
                            if let Some(h) = obj.get("host").and_then(Value::as_str) {
                                if let Some((ascii, _)) = normalize_domain(h) {
                                    compromised_legit_hosts.insert(ascii);
                                }
                            }
                        }

                        let Some(raw_url) = obj.get("url").and_then(Value::as_str) else {
                            continue;
                        };
                        let Some((canonical_url, host_key, url_sha256, opt_ip)) =
                            canonicalize_url_with_ip(raw_url)
                        else {
                            continue;
                        };
                        parsed_records += 1;

                        let is_online = obj
                            .get("url_status")
                            .and_then(Value::as_str)
                            .is_some_and(|s| s.eq_ignore_ascii_case("online"));

                        if dbl_status.contains("abused_legit") && opt_ip.is_none() {
                            compromised_legit_hosts.insert(host_key.clone());
                        }

                        let is_bare_root_path = canonical_url
                            .split_once("://")
                            .and_then(|(_, rest)| rest.split_once('/'))
                            .is_none_or(|(_, path)| path.is_empty());
                        if opt_ip.is_none()
                            && is_bare_root_path
                            && (trusted_roots.contains(&host_key)
                                || top_100k_domains.contains(&host_key)
                                || shared_hosting_roots.contains(&host_key))
                        {
                            continue;
                        }

                        let u_entry = url_map.entry(url_sha256).or_insert_with(|| UrlAcc {
                            domain: host_key.clone(),
                            canonical_url,
                            threat_category: "malware".to_string(),
                            max_weight: spec.confidence_weight,
                            sources: BTreeSet::new(),
                        });
                        if category_priority("malware")
                            > category_priority(&u_entry.threat_category)
                        {
                            u_entry.threat_category = "malware".to_string();
                        }
                        u_entry.max_weight = u_entry.max_weight.max(spec.confidence_weight);
                        u_entry.sources.insert(spec.feed_key.clone());

                        // URLhaus official RPZ guidance: only promote ACTIVE online hosts that are not compromised legit sites
                        if is_online {
                            if let Some(ip) = opt_ip {
                                insert_ip(
                                    &mut ip_map,
                                    IpNet::from(ip),
                                    "malware",
                                    spec.confidence_weight,
                                    &spec.feed_key,
                                );
                            } else if !is_domain_block_forbidden(&host_key)
                                && !compromised_legit_hosts.contains(&host_key)
                            {
                                let d_entry = domain_map.entry(host_key).or_default();
                                if d_entry.threat_category.as_deref().is_none_or(|prev| {
                                    category_priority("malware") > category_priority(prev)
                                }) {
                                    d_entry.threat_category = Some("malware".to_string());
                                }
                                d_entry.max_threat_weight =
                                    d_entry.max_threat_weight.max(spec.confidence_weight);
                                d_entry.threat_sources.insert(spec.feed_key.clone());
                            }
                        }
                    }
                }
            }
            "urlhaus_v1_payloads_json" => {
                let root: Value = serde_json::from_str(&text).map_err(|e| {
                    DgspamguardError::Compile(format!(
                        "Invalid JSON in URLhaus v1 payloads feed '{}': {e}",
                        spec.feed_key
                    ))
                })?;
                if let Some(arr) = root.get("payloads").and_then(Value::as_array) {
                    for obj in arr {
                        let Some(raw_sha) = obj.get("sha256_hash").and_then(Value::as_str) else {
                            continue;
                        };
                        let Some(digest) = normalize_sha256(raw_sha) else {
                            continue;
                        };
                        let family = obj
                            .get("signature")
                            .and_then(Value::as_str)
                            .map(clean_csv_cell)
                            .filter(|s| {
                                !s.is_empty()
                                    && !s.eq_ignore_ascii_case("none")
                                    && !s.eq_ignore_ascii_case("n/a")
                                    && !s.eq_ignore_ascii_case("unknown")
                            })
                            .unwrap_or("malware")
                            .to_string();
                        parsed_records += 1;
                        insert_hash(
                            &mut hash_map,
                            digest,
                            family,
                            spec.confidence_weight,
                            &spec.feed_key,
                        );
                    }
                }
            }
            "urlhaus_csv" => {
                let cleaned = strip_hash_comment_lines(&text);
                let mut rdr = csv::ReaderBuilder::new()
                    .has_headers(false)
                    .flexible(true)
                    .trim(csv::Trim::All)
                    .from_reader(cleaned.as_bytes());
                for rec_res in rdr.records() {
                    let Ok(rec) = rec_res else {
                        continue;
                    };
                    if rec.len() < 4 {
                        continue;
                    }
                    let id_col = clean_csv_cell(&rec[0]);
                    let raw_url = clean_csv_cell(&rec[2]);
                    if id_col.eq_ignore_ascii_case("id") || raw_url.eq_ignore_ascii_case("url") {
                        continue;
                    }
                    let url_status = clean_csv_cell(&rec[3]);
                    let Some((canonical_url, host_key, url_sha256, opt_ip)) =
                        canonicalize_url_with_ip(raw_url)
                    else {
                        continue;
                    };
                    parsed_records += 1;

                    let is_bare_root_path = canonical_url
                        .split_once("://")
                        .and_then(|(_, rest)| rest.split_once('/'))
                        .is_none_or(|(_, path)| path.is_empty());
                    if opt_ip.is_none()
                        && is_bare_root_path
                        && (trusted_roots.contains(&host_key)
                            || top_100k_domains.contains(&host_key)
                            || shared_hosting_roots.contains(&host_key))
                    {
                        continue;
                    }

                    let u_entry = url_map.entry(url_sha256).or_insert_with(|| UrlAcc {
                        domain: host_key.clone(),
                        canonical_url,
                        threat_category: "malware".to_string(),
                        max_weight: spec.confidence_weight,
                        sources: BTreeSet::new(),
                    });
                    if category_priority("malware") > category_priority(&u_entry.threat_category) {
                        u_entry.threat_category = "malware".to_string();
                    }
                    u_entry.max_weight = u_entry.max_weight.max(spec.confidence_weight);
                    u_entry.sources.insert(spec.feed_key.clone());

                    // URLhaus RPZ false-positive rule: only promote `online` URLs to host/IP blocklists
                    if url_status.eq_ignore_ascii_case("online") {
                        if let Some(ip) = opt_ip {
                            insert_ip(
                                &mut ip_map,
                                IpNet::from(ip),
                                "malware",
                                spec.confidence_weight,
                                &spec.feed_key,
                            );
                        } else if !is_domain_block_forbidden(&host_key)
                            && !compromised_legit_hosts.contains(&host_key)
                        {
                            let d_entry = domain_map.entry(host_key).or_default();
                            if d_entry.threat_category.as_deref().is_none_or(|prev| {
                                category_priority("malware") > category_priority(prev)
                            }) {
                                d_entry.threat_category = Some("malware".to_string());
                            }
                            d_entry.max_threat_weight =
                                d_entry.max_threat_weight.max(spec.confidence_weight);
                            d_entry.threat_sources.insert(spec.feed_key.clone());
                        }
                    }
                }
            }
            "threatfox_csv" => {
                let cleaned = strip_hash_comment_lines(&text);
                let mut rdr = csv::ReaderBuilder::new()
                    .has_headers(false)
                    .flexible(true)
                    .trim(csv::Trim::All)
                    .from_reader(cleaned.as_bytes());
                for rec_res in rdr.records() {
                    let Ok(rec) = rec_res else {
                        continue;
                    };
                    if rec.len() < 5 {
                        continue;
                    }
                    let ioc_val = clean_csv_cell(&rec[2]);
                    let ioc_type = clean_csv_cell(&rec[3]);
                    if ioc_type.eq_ignore_ascii_case("ioc_type") || ioc_val.is_empty() {
                        continue;
                    }
                    let threat_type = clean_csv_cell(&rec[4]);
                    let printable = rec
                        .get(7)
                        .map(clean_csv_cell)
                        .filter(|s| {
                            !s.is_empty()
                                && !s.eq_ignore_ascii_case("unknown")
                                && !s.eq_ignore_ascii_case("n/a")
                                && !s.eq_ignore_ascii_case("none")
                        })
                        .unwrap_or("malware");
                    let dom_cat = if threat_type.eq_ignore_ascii_case("botnet_cc") {
                        "c2"
                    } else {
                        "malware"
                    };
                    let ip_cat = if threat_type.eq_ignore_ascii_case("botnet_cc") {
                        "botnet_c2"
                    } else {
                        "malware"
                    };

                    match ioc_type {
                        "url" => {
                            let Some((canonical_url, host_key, url_sha256, opt_ip)) =
                                canonicalize_url_with_ip(ioc_val)
                            else {
                                continue;
                            };
                            parsed_records += 1;
                            let is_bare_root_path = canonical_url
                                .split_once("://")
                                .and_then(|(_, rest)| rest.split_once('/'))
                                .is_none_or(|(_, path)| path.is_empty());
                            if opt_ip.is_none()
                                && is_bare_root_path
                                && (trusted_roots.contains(&host_key)
                                    || top_100k_domains.contains(&host_key)
                                    || shared_hosting_roots.contains(&host_key))
                            {
                                continue;
                            }
                            let u_entry = url_map.entry(url_sha256).or_insert_with(|| UrlAcc {
                                domain: host_key.clone(),
                                canonical_url,
                                threat_category: dom_cat.to_string(),
                                max_weight: spec.confidence_weight,
                                sources: BTreeSet::new(),
                            });
                            if category_priority(dom_cat)
                                > category_priority(&u_entry.threat_category)
                            {
                                u_entry.threat_category = dom_cat.to_string();
                            }
                            u_entry.max_weight = u_entry.max_weight.max(spec.confidence_weight);
                            u_entry.sources.insert(spec.feed_key.clone());

                            if let Some(ip) = opt_ip {
                                insert_ip(
                                    &mut ip_map,
                                    IpNet::from(ip),
                                    ip_cat,
                                    spec.confidence_weight,
                                    &spec.feed_key,
                                );
                            } else if !is_domain_block_forbidden(&host_key)
                                && !compromised_legit_hosts.contains(&host_key)
                            {
                                let d_entry = domain_map.entry(host_key).or_default();
                                if d_entry.threat_category.as_deref().is_none_or(|prev| {
                                    category_priority(dom_cat) > category_priority(prev)
                                }) {
                                    d_entry.threat_category = Some(dom_cat.to_string());
                                }
                                d_entry.max_threat_weight =
                                    d_entry.max_threat_weight.max(spec.confidence_weight);
                                d_entry.threat_sources.insert(spec.feed_key.clone());
                            }
                        }
                        "domain" => {
                            let Some((ascii, _)) = normalize_domain(ioc_val) else {
                                continue;
                            };
                            parsed_records += 1;
                            if !is_domain_block_forbidden(&ascii)
                                && !compromised_legit_hosts.contains(&ascii)
                            {
                                let d_entry = domain_map.entry(ascii).or_default();
                                if d_entry.threat_category.as_deref().is_none_or(|prev| {
                                    category_priority(dom_cat) > category_priority(prev)
                                }) {
                                    d_entry.threat_category = Some(dom_cat.to_string());
                                }
                                d_entry.max_threat_weight =
                                    d_entry.max_threat_weight.max(spec.confidence_weight);
                                d_entry.threat_sources.insert(spec.feed_key.clone());
                            }
                        }
                        "ip:port" | "ip" => {
                            let Some(net) = normalize_public_ip_or_cidr(ioc_val) else {
                                continue;
                            };
                            parsed_records += 1;
                            insert_ip(
                                &mut ip_map,
                                net,
                                ip_cat,
                                spec.confidence_weight,
                                &spec.feed_key,
                            );
                        }
                        "sha256_hash" => {
                            let Some(digest) = normalize_sha256(ioc_val) else {
                                continue;
                            };
                            parsed_records += 1;
                            insert_hash(
                                &mut hash_map,
                                digest,
                                printable.to_string(),
                                spec.confidence_weight,
                                &spec.feed_key,
                            );
                        }
                        _ => {}
                    }
                }
            }
            "bazaar_csv" => {
                let cleaned = strip_hash_comment_lines(&text);
                let mut rdr = csv::ReaderBuilder::new()
                    .has_headers(false)
                    .flexible(true)
                    .trim(csv::Trim::All)
                    .from_reader(cleaned.as_bytes());
                for rec_res in rdr.records() {
                    let Ok(rec) = rec_res else {
                        continue;
                    };
                    if rec.len() < 2 {
                        continue;
                    }
                    let raw_sha = clean_csv_cell(&rec[1]);
                    if raw_sha.eq_ignore_ascii_case("sha256_hash") {
                        continue;
                    }
                    let Some(digest) = normalize_sha256(raw_sha) else {
                        continue;
                    };
                    let family = rec
                        .get(8)
                        .map(clean_csv_cell)
                        .filter(|s| {
                            !s.is_empty()
                                && !s.eq_ignore_ascii_case("n/a")
                                && !s.eq_ignore_ascii_case("none")
                                && !s.eq_ignore_ascii_case("unknown")
                        })
                        .unwrap_or("malware")
                        .to_string();
                    parsed_records += 1;
                    insert_hash(
                        &mut hash_map,
                        digest,
                        family,
                        spec.confidence_weight,
                        &spec.feed_key,
                    );
                }
            }
            "free_csv" => {
                for line in text.lines() {
                    let trimmed = line.trim().trim_matches('"');
                    if trimmed.is_empty()
                        || trimmed.starts_with('#')
                        || trimmed.eq_ignore_ascii_case("domain")
                    {
                        continue;
                    }
                    let first_col = trimmed
                        .split(',')
                        .next()
                        .unwrap_or(trimmed)
                        .trim()
                        .trim_matches('"');
                    let Some((ascii, _)) = normalize_domain(first_col) else {
                        continue;
                    };
                    parsed_records += 1;
                    let entry = domain_map.entry(ascii).or_default();
                    if entry.email_kind.as_deref().is_none_or(|prev| {
                        email_kind_priority("free_provider") > email_kind_priority(prev)
                    }) {
                        entry.email_kind = Some("free_provider".to_string());
                    }
                    entry.max_email_weight = entry.max_email_weight.max(spec.confidence_weight);
                    entry.email_sources.insert(spec.feed_key.clone());
                }
            }
            "sha256_txt" => {
                for line in text.lines() {
                    let no_comment = line.split('#').next().unwrap_or("").trim();
                    if no_comment.is_empty() {
                        continue;
                    }
                    let mut parts = no_comment.split([',', '\t', ' ']).filter(|p| !p.is_empty());
                    let Some(first) = parts.next() else {
                        continue;
                    };
                    let Some(digest) = normalize_sha256(first) else {
                        continue;
                    };
                    let family = parts
                        .next()
                        .map(|s| s.trim().trim_matches('"').to_string())
                        .filter(|s| !s.is_empty())
                        .unwrap_or_else(|| "malware".to_string());
                    parsed_records += 1;
                    insert_hash(
                        &mut hash_map,
                        digest,
                        family,
                        spec.confidence_weight,
                        &spec.feed_key,
                    );
                }
            }
            other => {
                return Err(DgspamguardError::Compile(format!(
                    "Unknown parser_kind '{other}' on feed '{}'.",
                    spec.feed_key
                )));
            }
        }

        if parsed_records < spec.min_records {
            return Err(DgspamguardError::Compile(format!(
                "Feed '{}' yielded {parsed_records} valid records (below safety threshold {}).",
                spec.feed_key, spec.min_records
            )));
        }
    }

    // 4. Materialize deterministic sorted tables
    let mut domains: Vec<CompiledDomainRow> = Vec::with_capacity(domain_map.len());
    let mut threat_domain_count = 0i64;
    let mut disposable_domain_count = 0i64;
    let mut free_domain_count = 0i64;
    let mut redirector_domain_count = 0i64;
    let mut trusted_domain_count = 0i64;

    for (dom, acc) in domain_map {
        if acc.threat_category.is_none() && acc.email_kind.is_none() {
            continue;
        }
        let reg_dom = psl.registered_domain(&dom);

        let (confidence, source_count, sources) = if acc.threat_category.is_some() {
            threat_domain_count += 1;
            let sc = acc.threat_sources.len();
            let conf = combine_confidence(acc.max_threat_weight, sc);
            let srcs: Vec<&str> = acc.threat_sources.iter().map(String::as_str).collect();
            (conf, sc.min(i16::MAX as usize) as i16, srcs.join(","))
        } else {
            let sc = acc.email_sources.len().max(1);
            let conf = acc.max_email_weight.clamp(50, 99);
            let srcs: Vec<&str> = acc.email_sources.iter().map(String::as_str).collect();
            (conf, sc.min(i16::MAX as usize) as i16, srcs.join(","))
        };

        match acc.email_kind.as_deref() {
            Some("disposable") => disposable_domain_count += 1,
            Some("free_provider") => free_domain_count += 1,
            Some("url_redirector") => redirector_domain_count += 1,
            Some("trusted") => trusted_domain_count += 1,
            _ => {}
        }

        domains.push(CompiledDomainRow {
            domain: dom,
            registered_domain: reg_dom,
            threat_category: acc.threat_category,
            confidence,
            source_count,
            sources,
            email_kind: acc.email_kind,
        });
    }
    domains.sort_by(|a, b| a.domain.cmp(&b.domain));

    let mut urls: Vec<CompiledUrlRow> = Vec::with_capacity(url_map.len());
    for (url_sha256, acc) in url_map {
        let sc = acc.sources.len().max(1);
        let conf = combine_confidence(acc.max_weight, sc);
        let srcs: Vec<&str> = acc.sources.iter().map(String::as_str).collect();
        urls.push(CompiledUrlRow {
            url_sha256,
            domain: acc.domain,
            canonical_url: acc.canonical_url,
            threat_category: acc.threat_category,
            confidence: conf,
            source_count: sc.min(i16::MAX as usize) as i16,
            sources: srcs.join(","),
        });
    }
    urls.sort_by(|a, b| a.url_sha256.cmp(&b.url_sha256));

    let mut hashes: Vec<CompiledHashRow> = Vec::with_capacity(hash_map.len());
    for (sha256, acc) in hash_map {
        let sc = acc.sources.len().max(1);
        let conf = combine_confidence(acc.max_weight, sc);
        let srcs: Vec<&str> = acc.sources.iter().map(String::as_str).collect();
        hashes.push(CompiledHashRow {
            sha256,
            malware_family: acc.malware_family,
            confidence: conf,
            sources: srcs.join(","),
        });
    }
    hashes.sort_by(|a, b| a.sha256.cmp(&b.sha256));

    let mut ips: Vec<CompiledIpRow> = Vec::with_capacity(ip_map.len());
    for (network, acc) in ip_map {
        let sc = acc.sources.len().max(1);
        let conf = combine_confidence(acc.max_weight, sc);
        let srcs: Vec<&str> = acc.sources.iter().map(String::as_str).collect();
        ips.push(CompiledIpRow {
            network,
            threat_category: acc.threat_category,
            confidence: conf,
            source_count: sc.min(i16::MAX as usize) as i16,
            sources: srcs.join(","),
        });
    }
    ips.sort_by(|a, b| a.network.cmp(&b.network));

    let mut tld_risks: Vec<TldRiskRule> = catalog.tld_risks.clone();
    tld_risks.sort_by(|a, b| a.tld.cmp(&b.tld));

    Ok(CompiledThreatSet {
        domains,
        urls,
        hashes,
        ips,
        tld_risks,
        shared_hosting_roots,
        threat_domain_count,
        disposable_domain_count,
        free_domain_count,
        redirector_domain_count,
        trusted_domain_count,
    })
}

/// Deterministic SHA-256 fingerprint of compiled indicator data (ignores timestamps & release labels).
pub fn compute_compiled_fingerprint(compiled: &CompiledThreatSet) -> String {
    let mut hasher = Sha256::new();
    for d in &compiled.domains {
        hasher.update(d.domain.as_bytes());
        hasher.update(b"|");
        if let Some(cat) = &d.threat_category {
            hasher.update(cat.as_bytes());
        }
        hasher.update(b"|");
        if let Some(ek) = &d.email_kind {
            hasher.update(ek.as_bytes());
        }
        hasher.update(b"\n");
    }
    hasher.update(b"--URLS--\n");
    for u in &compiled.urls {
        hasher.update(u.url_sha256.as_bytes());
        hasher.update(b"|");
        hasher.update(u.threat_category.as_bytes());
        hasher.update(b"\n");
    }
    hasher.update(b"--IPS--\n");
    for ip in &compiled.ips {
        hasher.update(ip.network.as_bytes());
        hasher.update(b"|");
        hasher.update(ip.threat_category.as_bytes());
        hasher.update(b"\n");
    }
    hasher.update(b"--HASHES--\n");
    for h in &compiled.hashes {
        hasher.update(h.sha256.as_bytes());
        hasher.update(b"|");
        hasher.update(h.malware_family.as_bytes());
        hasher.update(b"\n");
    }
    hex::encode(hasher.finalize())
}

fn gzip_bytes(raw: &[u8], level: Compression) -> DgspamguardResult<Vec<u8>> {
    let mut enc = GzEncoder::new(Vec::new(), level);
    enc.write_all(raw)
        .map_err(|e| DgspamguardError::Compile(format!("GZIP encode error: {e}")))?;
    enc.finish()
        .map_err(|e| DgspamguardError::Compile(format!("GZIP finalize error: {e}")))
}

fn build_rpz_zone(
    version: &str,
    generated_at: DateTime<Utc>,
    domains: &[CompiledDomainRow],
) -> Vec<u8> {
    let serial = (generated_at.timestamp().max(1) as u64 % 4_000_000_000) as u32;
    let mut buf = String::with_capacity((domains.len().min(600_000)) * 42 + 512);
    buf.push_str(&format!(
        "; DGSPAMGUARD Protective DNS Response Policy Zone (RPZ)\n; Version: {version}\n; Generated: {}\n$TTL 300\n@ IN SOA localhost. hostmaster.daviante.org. ({serial} 3600 600 604800 300)\n@ IN NS localhost.\n\n",
        generated_at.format("%Y-%m-%dT%H:%M:%SZ")
    ));

    for row in domains {
        if row.threat_category.is_none() {
            continue;
        }
        buf.push_str(&row.domain);
        buf.push_str(" CNAME .\n");
        if row.domain.len() <= 250 {
            buf.push_str("*.");
            buf.push_str(&row.domain);
            buf.push_str(" CNAME .\n");
        }
    }
    buf.into_bytes()
}

/// Package a `CompiledThreatSet` into all 8 canonical `.gz` artifacts, `manifest.json`, `SHA256SUMS.txt`,
/// `RELEASE_NOTES.md`, and `bundle.tar.gz`.
pub fn package_snapshot(
    compiled: CompiledThreatSet,
    version: &str,
    release_title_template: &str,
    generated_at: DateTime<Utc>,
) -> DgspamguardResult<PackagedSnapshot> {
    let release_title = format_release_title(release_title_template, version, generated_at);
    let mut dataset_artifacts: BTreeMap<String, (DatasetArtifactMeta, Vec<u8>)> = BTreeMap::new();

    // 1. dgspamguard-threat-domains.rpz.gz
    let rpz_raw = build_rpz_zone(version, generated_at, &compiled.domains);
    let rpz_gz = gzip_bytes(&rpz_raw, Compression::default())?;
    dataset_artifacts.insert(
        "dgspamguard-threat-domains.rpz.gz".to_string(),
        (
            DatasetArtifactMeta {
                filename: "dgspamguard-threat-domains.rpz.gz".to_string(),
                content_type: "application/gzip".to_string(),
                size_bytes: rpz_gz.len() as i64,
                sha256: sha256_hex(&rpz_gz),
                record_count: Some(compiled.threat_domain_count),
            },
            rpz_gz,
        ),
    );

    // 2 & 3. dgspamguard-threat-domains.csv.gz & dgspamguard-threat-domains.txt.gz
    let mut dom_csv_wtr = csv::Writer::from_writer(Vec::new());
    dom_csv_wtr
        .write_record([
            "domain",
            "registered_domain",
            "threat_category",
            "confidence",
            "source_count",
            "sources",
        ])
        .map_err(|e| DgspamguardError::Compile(e.to_string()))?;

    let mut dom_txt = String::with_capacity((compiled.threat_domain_count as usize) * 24 + 256);
    dom_txt.push_str(&format!(
        "# DGSPAMGUARD Active Threat Domains ({version} — {})\n",
        generated_at.format("%Y-%m-%dT%H:%M:%SZ")
    ));

    for row in &compiled.domains {
        let Some(cat) = &row.threat_category else {
            continue;
        };
        dom_csv_wtr
            .write_record([
                row.domain.as_str(),
                row.registered_domain.as_str(),
                cat.as_str(),
                &row.confidence.to_string(),
                &row.source_count.to_string(),
                row.sources.as_str(),
            ])
            .map_err(|e| DgspamguardError::Compile(e.to_string()))?;
        dom_txt.push_str(&row.domain);
        dom_txt.push('\n');
    }
    let dom_csv_bytes = dom_csv_wtr
        .into_inner()
        .map_err(|e| DgspamguardError::Compile(e.to_string()))?;
    let dom_csv_gz = gzip_bytes(&dom_csv_bytes, Compression::default())?;
    dataset_artifacts.insert(
        "dgspamguard-threat-domains.csv.gz".to_string(),
        (
            DatasetArtifactMeta {
                filename: "dgspamguard-threat-domains.csv.gz".to_string(),
                content_type: "application/gzip".to_string(),
                size_bytes: dom_csv_gz.len() as i64,
                sha256: sha256_hex(&dom_csv_gz),
                record_count: Some(compiled.threat_domain_count),
            },
            dom_csv_gz,
        ),
    );

    let dom_txt_gz = gzip_bytes(dom_txt.as_bytes(), Compression::default())?;
    dataset_artifacts.insert(
        "dgspamguard-threat-domains.txt.gz".to_string(),
        (
            DatasetArtifactMeta {
                filename: "dgspamguard-threat-domains.txt.gz".to_string(),
                content_type: "application/gzip".to_string(),
                size_bytes: dom_txt_gz.len() as i64,
                sha256: sha256_hex(&dom_txt_gz),
                record_count: Some(compiled.threat_domain_count),
            },
            dom_txt_gz,
        ),
    );

    // 4. dgspamguard-threat-urls.csv.gz
    let mut url_csv_wtr = csv::Writer::from_writer(Vec::new());
    url_csv_wtr
        .write_record([
            "url_sha256",
            "domain",
            "canonical_url",
            "threat_category",
            "confidence",
            "source_count",
            "sources",
        ])
        .map_err(|e| DgspamguardError::Compile(e.to_string()))?;
    for u in &compiled.urls {
        url_csv_wtr
            .write_record([
                u.url_sha256.as_str(),
                u.domain.as_str(),
                u.canonical_url.as_str(),
                u.threat_category.as_str(),
                &u.confidence.to_string(),
                &u.source_count.to_string(),
                u.sources.as_str(),
            ])
            .map_err(|e| DgspamguardError::Compile(e.to_string()))?;
    }
    let url_csv_bytes = url_csv_wtr
        .into_inner()
        .map_err(|e| DgspamguardError::Compile(e.to_string()))?;
    let url_csv_gz = gzip_bytes(&url_csv_bytes, Compression::default())?;
    dataset_artifacts.insert(
        "dgspamguard-threat-urls.csv.gz".to_string(),
        (
            DatasetArtifactMeta {
                filename: "dgspamguard-threat-urls.csv.gz".to_string(),
                content_type: "application/gzip".to_string(),
                size_bytes: url_csv_gz.len() as i64,
                sha256: sha256_hex(&url_csv_gz),
                record_count: Some(compiled.urls.len() as i64),
            },
            url_csv_gz,
        ),
    );

    // 5. dgspamguard-email-domains.csv.gz
    let mut email_csv_wtr = csv::Writer::from_writer(Vec::new());
    email_csv_wtr
        .write_record([
            "domain",
            "registered_domain",
            "email_kind",
            "confidence",
            "sources",
        ])
        .map_err(|e| DgspamguardError::Compile(e.to_string()))?;
    let mut email_row_count = 0i64;
    for d in &compiled.domains {
        let Some(kind) = &d.email_kind else {
            continue;
        };
        email_row_count += 1;
        email_csv_wtr
            .write_record([
                d.domain.as_str(),
                d.registered_domain.as_str(),
                kind.as_str(),
                &d.confidence.to_string(),
                d.sources.as_str(),
            ])
            .map_err(|e| DgspamguardError::Compile(e.to_string()))?;
    }
    let email_csv_bytes = email_csv_wtr
        .into_inner()
        .map_err(|e| DgspamguardError::Compile(e.to_string()))?;
    let email_csv_gz = gzip_bytes(&email_csv_bytes, Compression::default())?;
    dataset_artifacts.insert(
        "dgspamguard-email-domains.csv.gz".to_string(),
        (
            DatasetArtifactMeta {
                filename: "dgspamguard-email-domains.csv.gz".to_string(),
                content_type: "application/gzip".to_string(),
                size_bytes: email_csv_gz.len() as i64,
                sha256: sha256_hex(&email_csv_gz),
                record_count: Some(email_row_count),
            },
            email_csv_gz,
        ),
    );

    // 6. dgspamguard-malware-hashes.csv.gz
    let mut hash_csv_wtr = csv::Writer::from_writer(Vec::new());
    hash_csv_wtr
        .write_record(["sha256", "malware_family", "confidence", "sources"])
        .map_err(|e| DgspamguardError::Compile(e.to_string()))?;
    for h in &compiled.hashes {
        hash_csv_wtr
            .write_record([
                h.sha256.as_str(),
                h.malware_family.as_str(),
                &h.confidence.to_string(),
                h.sources.as_str(),
            ])
            .map_err(|e| DgspamguardError::Compile(e.to_string()))?;
    }
    let hash_csv_bytes = hash_csv_wtr
        .into_inner()
        .map_err(|e| DgspamguardError::Compile(e.to_string()))?;
    let hash_csv_gz = gzip_bytes(&hash_csv_bytes, Compression::default())?;
    dataset_artifacts.insert(
        "dgspamguard-malware-hashes.csv.gz".to_string(),
        (
            DatasetArtifactMeta {
                filename: "dgspamguard-malware-hashes.csv.gz".to_string(),
                content_type: "application/gzip".to_string(),
                size_bytes: hash_csv_gz.len() as i64,
                sha256: sha256_hex(&hash_csv_gz),
                record_count: Some(compiled.hashes.len() as i64),
            },
            hash_csv_gz,
        ),
    );

    // 7. dgspamguard-smtp-ips.csv.gz
    let mut ip_csv_wtr = csv::Writer::from_writer(Vec::new());
    ip_csv_wtr
        .write_record([
            "network",
            "threat_category",
            "confidence",
            "source_count",
            "sources",
        ])
        .map_err(|e| DgspamguardError::Compile(e.to_string()))?;
    for ip in &compiled.ips {
        ip_csv_wtr
            .write_record([
                ip.network.as_str(),
                ip.threat_category.as_str(),
                &ip.confidence.to_string(),
                &ip.source_count.to_string(),
                ip.sources.as_str(),
            ])
            .map_err(|e| DgspamguardError::Compile(e.to_string()))?;
    }
    let ip_csv_bytes = ip_csv_wtr
        .into_inner()
        .map_err(|e| DgspamguardError::Compile(e.to_string()))?;
    let ip_csv_gz = gzip_bytes(&ip_csv_bytes, Compression::default())?;
    dataset_artifacts.insert(
        "dgspamguard-smtp-ips.csv.gz".to_string(),
        (
            DatasetArtifactMeta {
                filename: "dgspamguard-smtp-ips.csv.gz".to_string(),
                content_type: "application/gzip".to_string(),
                size_bytes: ip_csv_gz.len() as i64,
                sha256: sha256_hex(&ip_csv_gz),
                record_count: Some(compiled.ips.len() as i64),
            },
            ip_csv_gz,
        ),
    );

    // 8. dgspamguard-tld-risk.csv.gz
    let mut tld_csv_wtr = csv::Writer::from_writer(Vec::new());
    tld_csv_wtr
        .write_record(["tld", "risk_score", "risk_level", "notes"])
        .map_err(|e| DgspamguardError::Compile(e.to_string()))?;
    for t in &compiled.tld_risks {
        tld_csv_wtr
            .write_record([
                t.tld.as_str(),
                &t.risk_score.to_string(),
                t.risk_level.as_str(),
                t.notes.as_str(),
            ])
            .map_err(|e| DgspamguardError::Compile(e.to_string()))?;
    }
    let tld_csv_bytes = tld_csv_wtr
        .into_inner()
        .map_err(|e| DgspamguardError::Compile(e.to_string()))?;
    let tld_csv_gz = gzip_bytes(&tld_csv_bytes, Compression::default())?;
    dataset_artifacts.insert(
        "dgspamguard-tld-risk.csv.gz".to_string(),
        (
            DatasetArtifactMeta {
                filename: "dgspamguard-tld-risk.csv.gz".to_string(),
                content_type: "application/gzip".to_string(),
                size_bytes: tld_csv_gz.len() as i64,
                sha256: sha256_hex(&tld_csv_gz),
                record_count: Some(compiled.tld_risks.len() as i64),
            },
            tld_csv_gz,
        ),
    );

    // 9. dgmail-rules.json.gz — adaptive cap to guarantee <= 440 KB compressed (< 500 KB DGMail fetch_resource cap)
    let budget_tiers: &[(usize, usize, usize, usize)] = &[
        (14_000, 12_000, 1_500, 6_000),
        (9_000, 8_000, 1_000, 4_000),
        (5_000, 4_500, 500, 2_000),
        (2_500, 2_000, 250, 1_000),
        (1_000, 1_000, 100, 500),
    ];
    let mut chosen_rules_gz: Option<Vec<u8>> = None;
    for &(max_disp, max_threat, max_urls, max_ips) in budget_tiers {
        let json_bytes = build_upgraded_dgmail_rules_json(
            &compiled.domains,
            &compiled.urls,
            &compiled.ips,
            max_disp,
            max_threat,
            max_urls,
            max_ips,
        )?;
        let gz = gzip_bytes(&json_bytes, Compression::best())?;
        if gz.len() <= MAX_DGMAIL_RULES_GZ_BYTES {
            chosen_rules_gz = Some(gz);
            break;
        }
    }
    let dgmail_rules_gz = match chosen_rules_gz {
        Some(b) => b,
        None => {
            let minimal = build_upgraded_dgmail_rules_json(
                &compiled.domains,
                &compiled.urls,
                &compiled.ips,
                200,
                200,
                0,
                100,
            )?;
            gzip_bytes(&minimal, Compression::best())?
        }
    };
    dataset_artifacts.insert(
        "dgmail-rules.json.gz".to_string(),
        (
            DatasetArtifactMeta {
                filename: "dgmail-rules.json.gz".to_string(),
                content_type: "application/gzip".to_string(),
                size_bytes: dgmail_rules_gz.len() as i64,
                sha256: sha256_hex(&dgmail_rules_gz),
                record_count: None,
            },
            dgmail_rules_gz,
        ),
    );

    debug_assert_eq!(dataset_artifacts.len(), DATASET_FILENAMES.len());

    let mut shared_vec: Vec<String> = compiled.shared_hosting_roots.iter().cloned().collect();
    shared_vec.sort_unstable();

    let files_meta: Vec<DatasetArtifactMeta> = DATASET_FILENAMES
        .iter()
        .filter_map(|&name| dataset_artifacts.get(name).map(|(m, _)| m.clone()))
        .collect();

    let manifest_obj = SnapshotManifest {
        schema_version: 1,
        service: "dgspamguard".to_string(),
        version: version.to_string(),
        release_title: release_title.clone(),
        generated_at,
        counts: SnapshotManifestCounts {
            threat_domains: compiled.threat_domain_count,
            threat_urls: compiled.urls.len() as i64,
            threat_ips: compiled.ips.len() as i64,
            disposable_domains: compiled.disposable_domain_count,
            free_domains: compiled.free_domain_count,
            redirector_domains: compiled.redirector_domain_count,
            trusted_domains: compiled.trusted_domain_count,
            malware_hashes: compiled.hashes.len() as i64,
            tld_risks: compiled.tld_risks.len() as i64,
        },
        shared_hosting_roots: shared_vec,
        files: files_meta,
    };

    let manifest_json = serde_json::to_vec_pretty(&manifest_obj)
        .map_err(|e| DgspamguardError::Compile(format!("Manifest serialize error: {e}")))?;
    let manifest_sha256 = sha256_hex(&manifest_json);

    // SHA256SUMS.txt covering manifest.json + all 8 dataset files
    let mut sums = String::with_capacity(2048);
    sums.push_str(&format!("{manifest_sha256}  manifest.json\n"));
    for &fname in &DATASET_FILENAMES {
        if let Some((meta, _)) = dataset_artifacts.get(fname) {
            sums.push_str(&format!("{}  {}\n", meta.sha256, meta.filename));
        }
    }
    let sha256sums_txt = sums.into_bytes();
    let sha256sums_sha256 = sha256_hex(&sha256sums_txt);

    // Build deterministic bundle.tar.gz containing manifest.json, SHA256SUMS.txt, and all 8 dataset files
    let mtime = generated_at.timestamp().max(0) as u64;
    let bundle_bytes = {
        let gz_enc = GzEncoder::new(Vec::new(), Compression::fast());
        let mut tar_builder = Builder::new(gz_enc);

        append_tar_entry(&mut tar_builder, "manifest.json", &manifest_json, mtime)?;
        append_tar_entry(&mut tar_builder, "SHA256SUMS.txt", &sha256sums_txt, mtime)?;
        for &fname in &DATASET_FILENAMES {
            if let Some((_, bytes)) = dataset_artifacts.get(fname) {
                append_tar_entry(&mut tar_builder, fname, bytes, mtime)?;
            }
        }

        let gz_enc = tar_builder
            .into_inner()
            .map_err(|e| DgspamguardError::Compile(format!("TAR finalize error: {e}")))?;
        gz_enc
            .finish()
            .map_err(|e| DgspamguardError::Compile(format!("Bundle GZIP finalize error: {e}")))?
    };
    let bundle_sha256 = sha256_hex(&bundle_bytes);

    let release_notes_md = render_release_notes(
        version,
        &release_title,
        generated_at,
        &compiled,
        &dataset_artifacts,
        &bundle_sha256,
        bundle_bytes.len(),
    );

    Ok(PackagedSnapshot {
        version: version.to_string(),
        generated_at,
        release_title,
        release_notes_md,
        manifest_json,
        manifest_sha256,
        sha256sums_txt,
        sha256sums_sha256,
        bundle_bytes,
        bundle_sha256,
        dataset_artifacts,
        compiled,
    })
}

fn append_tar_entry<W: Write>(
    builder: &mut Builder<W>,
    name: &str,
    payload: &[u8],
    mtime: u64,
) -> DgspamguardResult<()> {
    let mut header = Header::new_gnu();
    header.set_size(payload.len() as u64);
    header.set_mode(0o644);
    header.set_uid(0);
    header.set_gid(0);
    header.set_mtime(mtime);
    header.set_cksum();
    builder
        .append_data(&mut header, name, payload)
        .map_err(|e| DgspamguardError::Compile(format!("TAR append '{name}' failed: {e}")))
}

/// Unpack and cryptographically verify a `bundle.tar.gz` snapshot archive into a `PackagedSnapshot`.
pub fn unpack_bootstrap_bundle(bundle_bytes: &[u8]) -> DgspamguardResult<PackagedSnapshot> {
    let tar_raw = gunzip_bounded(bundle_bytes, MAX_BUNDLE_UNPACK_BYTES)?;
    let mut archive = Archive::new(&tar_raw[..]);
    let mut extracted: HashMap<String, Vec<u8>> = HashMap::new();
    let mut total_bytes = 0usize;

    let entries = archive
        .entries()
        .map_err(|e| DgspamguardError::Compile(format!("Invalid TAR archive: {e}")))?;

    for entry_res in entries {
        let mut entry =
            entry_res.map_err(|e| DgspamguardError::Compile(format!("Corrupt TAR entry: {e}")))?;
        let path = entry
            .path()
            .map_err(|e| DgspamguardError::Compile(format!("Invalid TAR path: {e}")))?
            .into_owned();
        let path_str = path.to_string_lossy().to_string();
        if path_str.contains("..") || path_str.starts_with('/') || path_str.contains('\\') {
            return Err(DgspamguardError::Compile(format!(
                "Unsafe path in bootstrap bundle: {path_str}"
            )));
        }
        let fname = path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| DgspamguardError::Compile("Empty filename in TAR bundle.".to_string()))?
            .to_string();

        let mut buf = Vec::new();
        entry.read_to_end(&mut buf).map_err(|e| {
            DgspamguardError::Compile(format!("Failed reading TAR entry '{fname}': {e}"))
        })?;
        total_bytes = total_bytes.saturating_add(buf.len());
        if total_bytes > MAX_BUNDLE_UNPACK_BYTES {
            return Err(DgspamguardError::Compile(
                "Bootstrap bundle exceeded total uncompressed extraction limit.".to_string(),
            ));
        }
        extracted.insert(fname, buf);
    }

    let manifest_json = extracted
        .remove("manifest.json")
        .ok_or_else(|| DgspamguardError::Compile("Bundle missing manifest.json.".to_string()))?;
    let sha256sums_txt = extracted
        .remove("SHA256SUMS.txt")
        .ok_or_else(|| DgspamguardError::Compile("Bundle missing SHA256SUMS.txt.".to_string()))?;

    let manifest: SnapshotManifest = serde_json::from_slice(&manifest_json)
        .map_err(|e| DgspamguardError::Compile(format!("Invalid manifest.json in bundle: {e}")))?;

    // Verify SHA256SUMS.txt
    let sums_str = String::from_utf8_lossy(&sha256sums_txt);
    let mut expected_hashes: HashMap<String, String> = HashMap::new();
    for line in sums_str.lines() {
        let mut parts = line.split_whitespace();
        if let (Some(hash), Some(name)) = (parts.next(), parts.next()) {
            expected_hashes.insert(
                name.trim_start_matches('*').to_string(),
                hash.to_ascii_lowercase(),
            );
        }
    }

    let manifest_sha256 = sha256_hex(&manifest_json);
    if let Some(exp) = expected_hashes.get("manifest.json") {
        if exp != &manifest_sha256 {
            return Err(DgspamguardError::Compile(
                "SHA-256 mismatch on manifest.json in bootstrap bundle.".to_string(),
            ));
        }
    }

    let mut dataset_artifacts: BTreeMap<String, (DatasetArtifactMeta, Vec<u8>)> = BTreeMap::new();
    for &fname in &DATASET_FILENAMES {
        let bytes = extracted.remove(fname).ok_or_else(|| {
            DgspamguardError::Compile(format!("Bootstrap bundle missing required file '{fname}'."))
        })?;
        let actual_sha = sha256_hex(&bytes);
        if let Some(exp) = expected_hashes.get(fname) {
            if exp != &actual_sha {
                return Err(DgspamguardError::Compile(format!(
                    "SHA-256 mismatch on '{fname}' in bootstrap bundle."
                )));
            }
        }
        let meta = manifest
            .files
            .iter()
            .find(|m| m.filename == fname)
            .cloned()
            .unwrap_or(DatasetArtifactMeta {
                filename: fname.to_string(),
                content_type: "application/gzip".to_string(),
                size_bytes: bytes.len() as i64,
                sha256: actual_sha,
                record_count: None,
            });
        dataset_artifacts.insert(fname.to_string(), (meta, bytes));
    }

    // Reconstruct CompiledThreatSet from verified CSV datasets
    let mut dom_merged: BTreeMap<String, CompiledDomainRow> = BTreeMap::new();

    if let Some((_, gz)) = dataset_artifacts.get("dgspamguard-threat-domains.csv.gz") {
        let csv_raw = gunzip_bounded(gz, MAX_BUNDLE_UNPACK_BYTES)?;
        let mut rdr = csv::Reader::from_reader(&csv_raw[..]);
        for rec in rdr.records() {
            let r = rec.map_err(|e| DgspamguardError::Compile(e.to_string()))?;
            if r.len() < 6 {
                continue;
            }
            dom_merged.insert(
                r[0].to_string(),
                CompiledDomainRow {
                    domain: r[0].to_string(),
                    registered_domain: r[1].to_string(),
                    threat_category: Some(r[2].to_string()),
                    confidence: r[3].parse().unwrap_or(60),
                    source_count: r[4].parse().unwrap_or(1),
                    sources: r[5].to_string(),
                    email_kind: None,
                },
            );
        }
    }

    if let Some((_, gz)) = dataset_artifacts.get("dgspamguard-email-domains.csv.gz") {
        let csv_raw = gunzip_bounded(gz, MAX_BUNDLE_UNPACK_BYTES)?;
        let mut rdr = csv::Reader::from_reader(&csv_raw[..]);
        for rec in rdr.records() {
            let r = rec.map_err(|e| DgspamguardError::Compile(e.to_string()))?;
            if r.len() < 5 {
                continue;
            }
            let dom_key = r[0].to_string();
            if let Some(existing) = dom_merged.get_mut(&dom_key) {
                existing.email_kind = Some(r[2].to_string());
            } else {
                dom_merged.insert(
                    dom_key.clone(),
                    CompiledDomainRow {
                        domain: dom_key,
                        registered_domain: r[1].to_string(),
                        threat_category: None,
                        confidence: r[3].parse().unwrap_or(85),
                        source_count: 1,
                        sources: r[4].to_string(),
                        email_kind: Some(r[2].to_string()),
                    },
                );
            }
        }
    }

    let mut urls = Vec::new();
    if let Some((_, gz)) = dataset_artifacts.get("dgspamguard-threat-urls.csv.gz") {
        let csv_raw = gunzip_bounded(gz, MAX_BUNDLE_UNPACK_BYTES)?;
        let mut rdr = csv::Reader::from_reader(&csv_raw[..]);
        for rec in rdr.records() {
            let r = rec.map_err(|e| DgspamguardError::Compile(e.to_string()))?;
            if r.len() < 7 {
                continue;
            }
            urls.push(CompiledUrlRow {
                url_sha256: r[0].to_string(),
                domain: r[1].to_string(),
                canonical_url: r[2].to_string(),
                threat_category: r[3].to_string(),
                confidence: r[4].parse().unwrap_or(60),
                source_count: r[5].parse().unwrap_or(1),
                sources: r[6].to_string(),
            });
        }
    }

    let mut hashes = Vec::new();
    if let Some((_, gz)) = dataset_artifacts.get("dgspamguard-malware-hashes.csv.gz") {
        let csv_raw = gunzip_bounded(gz, MAX_BUNDLE_UNPACK_BYTES)?;
        let mut rdr = csv::Reader::from_reader(&csv_raw[..]);
        for rec in rdr.records() {
            let r = rec.map_err(|e| DgspamguardError::Compile(e.to_string()))?;
            if r.len() < 4 {
                continue;
            }
            hashes.push(CompiledHashRow {
                sha256: r[0].to_string(),
                malware_family: r[1].to_string(),
                confidence: r[2].parse().unwrap_or(80),
                sources: r[3].to_string(),
            });
        }
    }

    let mut ips = Vec::new();
    if let Some((_, gz)) = dataset_artifacts.get("dgspamguard-smtp-ips.csv.gz") {
        let csv_raw = gunzip_bounded(gz, MAX_BUNDLE_UNPACK_BYTES)?;
        let mut rdr = csv::Reader::from_reader(&csv_raw[..]);
        for rec in rdr.records() {
            let r = rec.map_err(|e| DgspamguardError::Compile(e.to_string()))?;
            if r.len() < 5 {
                continue;
            }
            ips.push(CompiledIpRow {
                network: r[0].to_string(),
                threat_category: r[1].to_string(),
                confidence: r[2].parse().unwrap_or(80),
                source_count: r[3].parse().unwrap_or(1),
                sources: r[4].to_string(),
            });
        }
    }

    let mut tld_risks = Vec::new();
    if let Some((_, gz)) = dataset_artifacts.get("dgspamguard-tld-risk.csv.gz") {
        let csv_raw = gunzip_bounded(gz, MAX_BUNDLE_UNPACK_BYTES)?;
        let mut rdr = csv::Reader::from_reader(&csv_raw[..]);
        for rec in rdr.records() {
            let r = rec.map_err(|e| DgspamguardError::Compile(e.to_string()))?;
            if r.len() < 4 {
                continue;
            }
            tld_risks.push(TldRiskRule {
                tld: r[0].to_string(),
                risk_score: r[1].parse().unwrap_or(10),
                risk_level: r[2].to_string(),
                notes: r[3].to_string(),
            });
        }
    }

    let domains: Vec<CompiledDomainRow> = dom_merged.into_values().collect();
    let shared_hosting_roots: HashSet<String> = manifest.shared_hosting_roots.into_iter().collect();

    let compiled = CompiledThreatSet {
        domains,
        urls,
        hashes,
        ips,
        tld_risks,
        shared_hosting_roots,
        threat_domain_count: manifest.counts.threat_domains,
        disposable_domain_count: manifest.counts.disposable_domains,
        free_domain_count: manifest.counts.free_domains,
        redirector_domain_count: manifest.counts.redirector_domains,
        trusted_domain_count: manifest.counts.trusted_domains,
    };

    let bundle_sha256 = sha256_hex(bundle_bytes);
    let sha256sums_sha256 = sha256_hex(&sha256sums_txt);
    let release_notes_md = render_release_notes(
        &manifest.version,
        &manifest.release_title,
        manifest.generated_at,
        &compiled,
        &dataset_artifacts,
        &bundle_sha256,
        bundle_bytes.len(),
    );

    let _ = json!(null); // keep json macro referenced cleanly
    Ok(PackagedSnapshot {
        version: manifest.version,
        generated_at: manifest.generated_at,
        release_title: manifest.release_title,
        release_notes_md,
        manifest_json,
        manifest_sha256,
        sha256sums_txt,
        sha256sums_sha256,
        bundle_bytes: bundle_bytes.to_vec(),
        bundle_sha256,
        dataset_artifacts,
        compiled,
    })
}
