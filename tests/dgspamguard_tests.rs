use chrono::{TimeZone, Utc};
use clap::Parser;
use dgspamguard::cli::{Cli, Commands, FeedCommands};
use dgspamguard::compiler::{
    compile_threat_feeds, compute_compiled_fingerprint, package_snapshot, unpack_bootstrap_bundle,
    RawFeedPayload,
};
use dgspamguard::http::csp_for_path;
use dgspamguard::normalize::{
    canonicalize_url, classify_indicator, domain_lookup_chain, extract_email_domain,
    extract_first_zip_entry, gunzip_bounded, normalize_domain, normalize_public_ip_or_cidr,
    normalize_sha256, IndicatorInput, PslMatcher,
};
use dgspamguard::ratelimit::{extract_client_ip, SlidingWindowRateLimiter};
use dgspamguard::release_notes::{
    format_release_title, format_snapshot_version, utc_timestamp_base_tag,
};
use dgspamguard::seed_data::{
    build_default_feed_sources, default_allowlist_rules, default_tld_risk_rules,
};
use dgspamguard::swagger::{
    build_branded_home_html, build_branded_openapi_schema, build_branded_swagger_html,
    resolve_brand_asset, DEFAULT_SWAGGER_TITLE, PUBLIC_OPENAPI_PATHS,
};
use dgspamguard::sync::{evaluate_snapshot_boundary, floor_snapshot_utc_boundary};
use dgspamguard::types::{FeedSourceSpec, RuntimeCatalog, DATASET_FILENAMES};
use flate2::write::DeflateEncoder;
use flate2::Compression;
use ipnet::IpNet;
use serde_json::Value;
use std::collections::HashSet;
use std::io::Write;
use std::net::IpAddr;

fn build_single_file_zip_deflate(filename: &str, content: &[u8]) -> Vec<u8> {
    let mut enc = DeflateEncoder::new(Vec::new(), Compression::default());
    enc.write_all(content).unwrap();
    let compressed = enc.finish().unwrap();

    let fname_bytes = filename.as_bytes();
    let mut zip = Vec::new();
    zip.extend_from_slice(b"PK\x03\x04");
    zip.extend_from_slice(&20u16.to_le_bytes()); // version needed
    zip.extend_from_slice(&0u16.to_le_bytes()); // flags
    zip.extend_from_slice(&8u16.to_le_bytes()); // method = 8 (Deflate)
    zip.extend_from_slice(&0u16.to_le_bytes()); // mod time
    zip.extend_from_slice(&0u16.to_le_bytes()); // mod date
    zip.extend_from_slice(&0u32.to_le_bytes()); // crc32 (unused by reader)
    zip.extend_from_slice(&(compressed.len() as u32).to_le_bytes());
    zip.extend_from_slice(&(content.len() as u32).to_le_bytes());
    zip.extend_from_slice(&(fname_bytes.len() as u16).to_le_bytes());
    zip.extend_from_slice(&0u16.to_le_bytes()); // extra len
    zip.extend_from_slice(fname_bytes);
    zip.extend_from_slice(&compressed);
    zip
}

fn make_feed_spec(key: &str, category: &str, parser_kind: &str, weight: i16) -> FeedSourceSpec {
    FeedSourceSpec {
        feed_key: key.to_string(),
        category: category.to_string(),
        parser_kind: parser_kind.to_string(),
        source_url: format!("https://example.org/{key}"),
        refresh_interval_seconds: 7200,
        min_records: 1,
        max_compressed_bytes: 16 * 1024 * 1024,
        max_uncompressed_bytes: 32 * 1024 * 1024,
        confidence_weight: weight,
        enabled: true,
        display_order: 1,
        etag: None,
        last_modified: None,
        last_fetched_at: None,
    }
}

#[test]
fn test_domain_idna_and_rejection_rules() {
    let (ascii, uni) = normalize_domain("  München-Verify.DE. ").expect("IDN should normalize");
    assert_eq!(ascii, "xn--mnchen-verify-wob.de");
    assert_eq!(uni, "münchen-verify.de");

    assert!(normalize_domain("192.168.1.1").is_none());
    assert!(normalize_domain("2001:db8::1").is_none());
    assert!(normalize_domain("localhost").is_none());
    assert!(normalize_domain("-bad.example.com").is_none());
    assert!(normalize_domain("*.wildcard.com").is_none());
    assert!(normalize_domain("https://example.com/path").is_none());

    let (em_ascii, _) = extract_email_domain("<Alerts@Sub.Mailinator.COM>").unwrap();
    assert_eq!(em_ascii, "sub.mailinator.com");
}

#[test]
fn test_psl_icann_vs_private_suffixes() {
    let sample_psl = r#"
// ===BEGIN ICANN DOMAINS===
com
co.uk
*.ck
!www.ck
// ===BEGIN PRIVATE DOMAINS===
github.io
pages.dev
// ===END PRIVATE DOMAINS===
"#;
    let psl = PslMatcher::from_psl_dat(sample_psl);
    assert!(psl.is_icann_public_suffix("co.uk"));
    assert!(!psl.is_icann_public_suffix("bbc.co.uk"));
    assert_eq!(psl.registered_domain("news.bbc.co.uk"), "bbc.co.uk");

    assert!(psl.is_private_public_suffix("pages.dev"));
    assert_eq!(
        psl.registered_domain("portal.evil-tenant.pages.dev"),
        "evil-tenant.pages.dev"
    );

    let chain = domain_lookup_chain("a.b.bbc.co.uk", &psl.registered_domain("a.b.bbc.co.uk"));
    assert_eq!(chain, vec!["a.b.bbc.co.uk", "b.bbc.co.uk", "bbc.co.uk"]);
}

#[test]
fn test_url_canonicalization_and_indicator_classifier() {
    let (c1, d1, h1) = canonicalize_url("HTTPS://Example.COM:443/Login/Verify?id=42#frag").unwrap();
    let (c2, d2, h2) = canonicalize_url("https://example.com/Login/Verify?id=42").unwrap();
    assert_eq!(c1, "https://example.com/Login/Verify?id=42");
    assert_eq!(c1, c2);
    assert_eq!(d1, d2);
    assert_eq!(h1, h2);

    let sample_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    assert_eq!(
        classify_indicator(&format!("SHA256:{sample_hash}")).unwrap(),
        IndicatorInput::Sha256(sample_hash.to_string())
    );
    assert!(normalize_sha256("not-a-sha256").is_none());

    // IP & CIDR normalization + public DNS / bogon / RFC 5737 documentation range protection
    assert_eq!(
        normalize_public_ip_or_cidr("45.142.212.100")
            .unwrap()
            .to_string(),
        "45.142.212.100/32"
    );
    assert_eq!(
        normalize_public_ip_or_cidr("185.220.101.44/24")
            .unwrap()
            .to_string(),
        "185.220.101.0/24"
    );
    assert_eq!(
        classify_indicator("45.142.212.100").unwrap(),
        IndicatorInput::Ip("45.142.212.100".parse().unwrap())
    );
    assert!(normalize_public_ip_or_cidr("127.0.0.1").is_none());
    assert!(normalize_public_ip_or_cidr("10.0.0.1").is_none());
    assert!(normalize_public_ip_or_cidr("198.51.100.44").is_none()); // RFC 5737 TEST-NET-2
    assert!(normalize_public_ip_or_cidr("1.1.1.1").is_none());
    assert!(normalize_public_ip_or_cidr("8.8.8.8").is_none());
    assert!(normalize_public_ip_or_cidr("2606:4700:4700::1111").is_none());
    assert!(normalize_public_ip_or_cidr("45.142.212.0/4").is_none());
}

#[test]
fn test_pure_rust_zip_deflate_and_bomb_limit() {
    let csv_data = b"1,google.com\n2,microsoft.com\n3,github.com\n";
    let zip_bytes = build_single_file_zip_deflate("top-1m.csv", csv_data);

    let extracted = extract_first_zip_entry(&zip_bytes, 1024).unwrap();
    assert_eq!(extracted, csv_data);

    // Exceeds max_uncompressed cap
    assert!(extract_first_zip_entry(&zip_bytes, 10).is_err());
}

#[test]
fn test_compiler_allowlist_shared_hosting_rpz_and_dgmail_bundle() {
    let psl_raw = b"// ===BEGIN ICANN DOMAINS===\ncom\ntop\norg\n// ===BEGIN PRIVATE DOMAINS===\npages.dev\ngithub.io\n// ===END PRIVATE DOMAINS===\n";
    let tranco_zip =
        build_single_file_zip_deflate("top-1m.csv", b"1,google.com\n2,chase.com\n3,pages.dev\n");

    // Attempt to poison google.com, chase.com, bare pages.dev, bare docs.google.com,
    // while also feeding legitimate threats: evil-phish.top, evil-login.pages.dev, and a docs.google.com form URL!
    let phish_domains = b"
# comment
0.0.0.0 google.com
||chase.com^
pages.dev
github.io
docs.google.com
evil-phish.top
evil-login.pages.dev
";
    let phish_urls = b"
https://docs.google.com/forms/d/e/1FAIpQLSePhishForm/viewform
https://docs.google.com/
https://evil-phish.top/account/unlock
";
    let disposable_domains = b"
mailinator.com
10minutemail.com
gmail.com
";
    let free_domains = b"domain\nproton.me\nfastmail.com\n";
    let hashes = b"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855,AgentTesla\n";

    // Abuse.ch URLhaus v1 JSON (marks compromised-bakery.org as abused_legit_malware!)
    let urlhaus_v1_urls = br#"{
        "query_status": "ok",
        "urls": [
            {
                "url": "http://compromised-bakery.org/wp-content/loader.exe",
                "url_status": "online",
                "threat": "malware_download",
                "blacklists": { "spamhaus_dbl": "abused_legit_malware", "surbl": "not listed" }
            },
            {
                "url": "http://dedicated-dropper.xyz/payload.bin",
                "url_status": "online",
                "threat": "malware_download",
                "blacklists": { "spamhaus_dbl": "botnet_cc", "surbl": "listed" }
            }
        ]
    }"#;

    // URLhaus v2 CSV: offline URL must NOT promote offline-only-host.biz to domain RPZ!
    let urlhaus_csv = b"# comment\n\"101\",\"2026-11-03 10:00:00\",\"http://offline-only-host.biz/old.exe\",\"offline\",\"2026-11-01 10:00:00\",\"malware_download\",\"emotet\",\"https://urlhaus.abuse.ch/url/101/\",\"anon\"\n\"102\",\"2026-11-03 11:00:00\",\"http://compromised-bakery.org/wp-content/loader.exe\",\"online\",\"\",\"malware_download\",\"qakbot\",\"https://urlhaus.abuse.ch/url/102/\",\"anon\"\n";

    // ThreatFox CSV + MalwareBazaar CSV + Spamhaus DROP JSON + IPsum TXT
    let threatfox_csv = b"# comment\n\"2026-11-03 11:00:00\", \"9001\", \"45.142.212.100:443\", \"ip:port\", \"botnet_cc\", \"win.pikabot\", \"Pikabot\", \"high\", \"100\"\n";
    let bazaar_csv = b"# comment\n\"2026-11-03 11:00:00\", \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\", \"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\", \"cccccccccccccccccccccccccccccccccccccccc\", \"anon\", \"invoice.exe\", \"exe\", \"application/x-dosexec\", \"Pikabot\", \"none\", \"0\", \"0\", \"none\"\n";
    let drop_json = b"{\"cidr\":\"185.220.101.0/24\",\"sblid\":\"SBL123456\",\"rir\":\"ripencc\"}\n{\"type\":\"metadata\",\"timestamp\":1762160000}\n";
    let ipsum_txt = b"# IPsum\n45.142.212.100\t5\n1.1.1.1\t9\n";

    let payloads = vec![
        RawFeedPayload {
            spec: make_feed_spec("psl", "psl", "psl_dat", 0),
            raw_bytes: psl_raw.to_vec(),
        },
        RawFeedPayload {
            spec: make_feed_spec("tranco", "allowlist", "tranco_csv_zip", 0),
            raw_bytes: tranco_zip,
        },
        RawFeedPayload {
            spec: make_feed_spec("urlhaus-v1", "malware", "urlhaus_v1_urls_json", 82),
            raw_bytes: urlhaus_v1_urls.to_vec(),
        },
        RawFeedPayload {
            spec: make_feed_spec("urlhaus-csv", "malware", "urlhaus_csv", 84),
            raw_bytes: urlhaus_csv.to_vec(),
        },
        RawFeedPayload {
            spec: make_feed_spec("threatfox", "c2", "threatfox_csv", 85),
            raw_bytes: threatfox_csv.to_vec(),
        },
        RawFeedPayload {
            spec: make_feed_spec("bazaar", "malware_hash", "bazaar_csv", 90),
            raw_bytes: bazaar_csv.to_vec(),
        },
        RawFeedPayload {
            spec: make_feed_spec("drop-v4", "hijacked_cidr", "spamhaus_drop_json", 95),
            raw_bytes: drop_json.to_vec(),
        },
        RawFeedPayload {
            spec: make_feed_spec("ipsum", "smtp_attack", "ips_txt", 78),
            raw_bytes: ipsum_txt.to_vec(),
        },
        RawFeedPayload {
            spec: make_feed_spec("cert-pl", "phishing", "domains_txt", 62),
            raw_bytes: phish_domains.to_vec(),
        },
        RawFeedPayload {
            spec: make_feed_spec("openphish", "phishing", "urls_txt", 65),
            raw_bytes: phish_urls.to_vec(),
        },
        RawFeedPayload {
            spec: make_feed_spec("disp", "disposable", "domains_txt", 85),
            raw_bytes: disposable_domains.to_vec(),
        },
        RawFeedPayload {
            spec: make_feed_spec("free", "free_provider", "free_csv", 90),
            raw_bytes: free_domains.to_vec(),
        },
        RawFeedPayload {
            spec: make_feed_spec("botvrij", "malware_hash", "sha256_txt", 82),
            raw_bytes: hashes.to_vec(),
        },
    ];

    let catalog = RuntimeCatalog {
        bootstrap_bundle_url: "https://example.org/bundle.tar.gz".to_string(),
        allowed_source_hosts: HashSet::new(),
        trusted_proxies: Vec::new(),
        rate_limit_per_minute: 240,
        swagger_enabled: true,
        retention_days: 7,
        version_prefix: "v".to_string(),
        release_title_template: "{version}".to_string(),
        abusech_auth_key: None,
        allowlist: default_allowlist_rules(),
        tld_risks: default_tld_risk_rules(),
    };

    let compiled = compile_threat_feeds(&payloads, &catalog).expect("Compilation must succeed");
    let fp1 = compute_compiled_fingerprint(&compiled);
    assert_eq!(fp1.len(), 64);

    // Verify allowlist & shared-hosting gates
    let find_dom = |name: &str| compiled.domains.iter().find(|r| r.domain == name);
    assert!(
        find_dom("google.com").is_none_or(|r| r.threat_category.is_none()),
        "google.com must never be marked as threat"
    );
    assert!(
        find_dom("chase.com").is_none_or(|r| r.threat_category.is_none()),
        "Tranco top-100K domain must never be marked as threat"
    );
    assert!(
        find_dom("pages.dev").is_none(),
        "Bare pages.dev shared-hosting root must never be domain-blocked"
    );
    assert!(
        find_dom("docs.google.com").is_none(),
        "Path-based docs.google.com must never be domain-blocked"
    );

    // Tenant subdomain on pages.dev & dedicated phishing domain MUST be blocked!
    let tenant = find_dom("evil-login.pages.dev").expect("Malicious pages.dev tenant must exist");
    assert_eq!(tenant.threat_category.as_deref(), Some("phishing"));
    assert_eq!(tenant.registered_domain, "evil-login.pages.dev");

    let phish = find_dom("evil-phish.top").expect("evil-phish.top must exist");
    assert_eq!(phish.threat_category.as_deref(), Some("phishing"));
    assert_eq!(phish.source_count, 2); // corroborated by cert-pl + openphish!
    assert!(phish.confidence >= 75);

    // gmail.com must stay free_provider/trusted, NEVER disposable
    let gmail = find_dom("gmail.com").expect("gmail.com in taxonomy");
    assert_ne!(gmail.email_kind.as_deref(), Some("disposable"));

    let mailinator = find_dom("mailinator.com").expect("mailinator.com in taxonomy");
    assert_eq!(mailinator.email_kind.as_deref(), Some("disposable"));

    // Exact phishing form URL on docs.google.com MUST be in URL table, while bare https://docs.google.com/ MUST NOT!
    assert!(compiled
        .urls
        .iter()
        .any(|u| u.canonical_url.contains("1FAIpQLSePhishForm")));
    assert!(!compiled
        .urls
        .iter()
        .any(|u| u.canonical_url == "https://docs.google.com/"));

    // URLhaus RPZ rules:
    // 1) compromised-bakery.org flagged abused_legit_malware -> URL blocked, domain NOT blocked!
    assert!(
        find_dom("compromised-bakery.org").is_none(),
        "abused_legit_malware host must never be promoted to domain RPZ"
    );
    assert!(compiled.urls.iter().any(|u| u
        .canonical_url
        .contains("compromised-bakery.org/wp-content/loader.exe")));
    // 2) dedicated-dropper.xyz (online + botnet_cc) -> domain IS promoted!
    assert!(find_dom("dedicated-dropper.xyz").is_some());
    // 3) offline-only-host.biz (offline in URLhaus CSV) -> URL recorded, domain NOT promoted!
    assert!(
        find_dom("offline-only-host.biz").is_none(),
        "Offline URLhaus CSV entry must not promote host to domain RPZ"
    );
    assert!(compiled
        .urls
        .iter()
        .any(|u| u.canonical_url.contains("offline-only-host.biz/old.exe")));

    // IP & CIDR compilation + MalwareBazaar hash check
    assert!(compiled
        .ips
        .iter()
        .any(|i| i.network == "185.220.101.0/24" && i.threat_category == "hijacked_cidr"));
    let bot_ip = compiled
        .ips
        .iter()
        .find(|i| i.network == "45.142.212.100/32")
        .expect("45.142.212.100/32 corroborated by threatfox + ipsum");
    assert_eq!(bot_ip.source_count, 2);
    assert!(!compiled
        .ips
        .iter()
        .any(|i| i.network.starts_with("1.1.1.1/")));
    assert!(compiled.hashes.iter().any(|h| {
        h.sha256 == "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            && h.malware_family == "Pikabot"
    }));

    // Package snapshot and verify all 9 artifacts + RPZ + DGMail ruleset + bundle round-trip
    let ts = Utc.with_ymd_and_hms(2026, 11, 3, 16, 0, 0).unwrap();
    assert_eq!(utc_timestamp_base_tag("v", ts), "v20261103.1600");
    assert_eq!(format_snapshot_version("v", ts, 0), "v20261103.1600");
    let ver = format_snapshot_version("v", ts, 1);
    assert_eq!(ver, "v20261103.1600.1");

    let packaged =
        package_snapshot(compiled, &ver, "{version}", ts).expect("Snapshot packaging must succeed");
    assert_eq!(packaged.release_title, "v20261103.1600.1");
    assert_eq!(format_release_title("", &ver, ts), "v20261103.1600.1");
    assert!(packaged
        .release_notes_md
        .starts_with("## DGSPAMGUARD Dataset Release `v20261103.1600.1`\n\n"));

    for &fname in &DATASET_FILENAMES {
        assert!(
            packaged.dataset_artifacts.contains_key(fname),
            "Missing canonical artifact {fname}"
        );
    }

    // Check RPZ zone syntax
    let (_, rpz_gz) = &packaged.dataset_artifacts["dgspamguard-threat-domains.rpz.gz"];
    let rpz_txt = String::from_utf8(gunzip_bounded(rpz_gz, 10 * 1024 * 1024).unwrap()).unwrap();
    assert!(rpz_txt.contains("$TTL 300"));
    assert!(rpz_txt.contains("evil-phish.top CNAME ."));
    assert!(rpz_txt.contains("*.evil-phish.top CNAME ."));
    assert!(!rpz_txt.contains("\npages.dev CNAME ."));

    // Check DGMail rules bundle (< 440 KB compressed, zero external URLs, HttpLookup empty)
    let (_, dgmail_gz) = &packaged.dataset_artifacts["dgmail-rules.json.gz"];
    assert!(
        dgmail_gz.len() <= 440 * 1024,
        "dgmail-rules.json.gz must stay strictly below DGMail's 500 KB fetch cap"
    );
    let dgmail_raw =
        String::from_utf8(gunzip_bounded(dgmail_gz, 16 * 1024 * 1024).unwrap()).unwrap();
    let dgmail_val: Value = serde_json::from_str(&dgmail_raw).unwrap();
    assert_eq!(
        dgmail_val
            .get("HttpLookup")
            .and_then(Value::as_array)
            .map(Vec::len),
        Some(0)
    );
    let dnsbls = dgmail_val
        .get("SpamDnsblServer")
        .and_then(Value::as_array)
        .unwrap();
    assert!(dnsbls
        .iter()
        .all(|d| d.get("enable").and_then(Value::as_bool) == Some(false)));
    assert!(dgmail_raw.contains("DGSPAMGUARD_SMTP_THREAT_IP"));
    assert!(dgmail_raw.contains("dgspamguard_smtp_threat_ips"));
    assert!(dgmail_raw.contains("45.142.212.100"));

    // Unpack bundle.tar.gz and verify SHA-256 integrity
    let unpacked = unpack_bootstrap_bundle(&packaged.bundle_bytes)
        .expect("Bootstrap bundle unpack must verify SHA256SUMS and succeed");
    assert_eq!(unpacked.version, "v20261103.1600.1");
    assert_eq!(compute_compiled_fingerprint(&unpacked.compiled), fp1);
}

#[test]
fn test_openapi_schema_parity_and_portal_rendering() {
    let schema = build_branded_openapi_schema();
    let paths = schema
        .get("paths")
        .and_then(Value::as_object)
        .expect("OpenAPI paths object must exist");

    for &(route, methods) in PUBLIC_OPENAPI_PATHS {
        let item = paths
            .get(route)
            .and_then(Value::as_object)
            .unwrap_or_else(|| panic!("OpenAPI missing route {route}"));
        for &m in methods {
            assert!(
                item.contains_key(m),
                "OpenAPI route {route} missing HTTP method {m}"
            );
        }
    }

    let html = build_branded_home_html("1.0.0", true);
    assert!(html.contains("01 / INDICATOR &amp; VERDICT"));
    assert!(html.contains("02 / THREAT &amp; CORROBORATION"));
    assert!(html.contains("03 / POSTURE &amp; MAIL SIGNALS"));
    assert!(html.contains("API Reference (/docs)"));
    assert!(html.contains("Snapshots (dgspamguard-data)"));
    assert!(html.contains("dgspamguard-color-scheme"));

    let swagger_html = build_branded_swagger_html(DEFAULT_SWAGGER_TITLE, "/openapi.json");
    assert!(swagger_html.contains("/docs/assets/logo-dark.svg"));
    assert!(swagger_html.contains("/docs/assets/logo.svg"));
    assert!(swagger_html.contains("/docs/assets/favicon.svg"));
    assert!(swagger_html.contains("Threat Inspector"));

    // Brand asset embedded fallback & traversal defense
    let dummy = std::path::Path::new("/nonexistent-dgspamguard-assets");
    for name in ["logo.svg", "logo-dark.svg", "favicon.svg"] {
        let (bytes, ct) = resolve_brand_asset(dummy, name).expect("Must resolve embedded asset");
        assert_eq!(ct, "image/svg+xml");
        assert!(std::str::from_utf8(&bytes).unwrap().contains("<svg"));
    }
    assert!(resolve_brand_asset(dummy, "../Cargo.toml").is_none());

    // CSP parity checks
    assert!(csp_for_path("/").contains("form-action 'self'"));
    assert!(csp_for_path("/docs/assets/logo.svg").contains("default-src 'none'"));
    assert!(csp_for_path("/docs").contains("https://cdn.jsdelivr.net"));
    assert_eq!(
        csp_for_path("/v1/domain/daviante.org"),
        "default-src 'none'; frame-ancestors 'none'"
    );
}

#[test]
fn test_rate_limiter_and_right_to_left_xff() {
    let limiter = SlidingWindowRateLimiter::new(2);
    assert!(limiter.check("203.0.113.5").allowed);
    assert!(limiter.check("203.0.113.5").allowed);
    let blocked = limiter.check("203.0.113.5");
    assert!(!blocked.allowed);
    assert!(blocked.retry_after_seconds.is_some());

    let trusted: Vec<IpNet> = vec!["10.0.0.0/8".parse().unwrap()];
    let peer: IpAddr = "10.0.0.2".parse().unwrap();
    // Spoofed 1.2.3.4 on left, real client 198.51.100.77 before trusted proxy 10.0.0.9
    let ip = extract_client_ip(&peer, Some("1.2.3.4, 198.51.100.77, 10.0.0.9"), &trusted);
    assert_eq!(ip, "198.51.100.77");

    // Untrusted peer cannot spoof X-Forwarded-For
    let untrusted_peer: IpAddr = "198.51.100.99".parse().unwrap();
    let ip2 = extract_client_ip(&untrusted_peer, Some("1.2.3.4"), &trusted);
    assert_eq!(ip2, "198.51.100.99");
}

#[test]
fn test_cli_subcommand_parsing() {
    let parsed =
        Cli::try_parse_from(["dgspamguard", "sync", "--force", "--export-dir", "/tmp/out"])
            .unwrap();
    match parsed.command {
        Commands::Sync { force, export_dir } => {
            assert!(force);
            assert_eq!(export_dir.unwrap().to_string_lossy(), "/tmp/out");
        }
        other => panic!("Unexpected command: {other:?}"),
    }

    let feed_ttl = Cli::try_parse_from([
        "dgspamguard",
        "feed",
        "set-ttl",
        "abusech-urlhaus-v1-urls",
        "900",
    ])
    .unwrap();
    match feed_ttl.command {
        Commands::Feed {
            action: FeedCommands::SetTtl { feed_key, seconds },
        } => {
            assert_eq!(feed_key, "abusech-urlhaus-v1-urls");
            assert_eq!(seconds, 900);
        }
        other => panic!("Unexpected command: {other:?}"),
    }
}

#[test]
fn test_per_feed_native_ttl_tiers_and_spamhaus_guardrail() {
    let feeds = build_default_feed_sources();
    assert_eq!(feeds.len(), 30);

    let ttl_of = |key: &str| -> i64 {
        feeds
            .iter()
            .find(|f| f.feed_key == key)
            .unwrap_or_else(|| panic!("Missing feed {key}"))
            .refresh_interval_seconds
    };

    // 15m real-time feeds
    assert_eq!(ttl_of("abusech-urlhaus-v1-urls"), 900);
    assert_eq!(ttl_of("abusech-urlhaus-v1-payloads"), 900);

    // 30m fast SMTP & CSIRT feeds
    assert_eq!(ttl_of("ip-blocklist-de-mail"), 1_800);
    assert_eq!(ttl_of("ip-blocklist-de-bots"), 1_800);
    assert_eq!(ttl_of("ip-feodo-tracker"), 1_800);
    assert_eq!(ttl_of("phish-cert-pl"), 1_800);
    assert_eq!(ttl_of("malware-urlhaus-online"), 1_800);

    // 1h active feeds
    assert_eq!(ttl_of("abusech-urlhaus-recent"), 3_600);
    assert_eq!(ttl_of("abusech-threatfox-recent"), 3_600);
    assert_eq!(ttl_of("abusech-bazaar-recent"), 3_600);
    assert_eq!(ttl_of("phish-openphish"), 3_600);
    assert_eq!(ttl_of("phish-phishunt"), 3_600);
    assert_eq!(ttl_of("phish-db-new-today"), 3_600);
    assert_eq!(ttl_of("hash-malicious-sha256"), 3_600);

    // 4h rate-limited feeds (Spamhaus DROP strictly >= 1h)
    assert!(ttl_of("ip-spamhaus-drop-v4") >= 3_600);
    assert!(ttl_of("ip-spamhaus-drop-v6") >= 3_600);
    assert_eq!(ttl_of("ip-spamhaus-drop-v4"), 14_400);
    assert_eq!(ttl_of("phish-army"), 14_400);
    assert_eq!(ttl_of("hash-botvrij-sha256"), 14_400);

    // 12h & 24h daily / structural feeds
    assert_eq!(ttl_of("phish-db-domains"), 43_200);
    assert_eq!(ttl_of("ip-ipsum-level3"), 43_200);
    assert_eq!(ttl_of("email-disposable-mx"), 43_200);
    assert_eq!(ttl_of("psl-mozilla"), 86_400);
    assert_eq!(ttl_of("allow-tranco-top"), 86_400);
}

#[test]
fn test_utc_wall_clock_snapshot_boundary_alignment() {
    let interval = 14_400u64; // 4 hours

    // Off-grid initial/manual snapshot at 17:30:34 UTC -> next scheduled boundary is 20:00:00 UTC
    let off_grid_snap = Utc.with_ymd_and_hms(2026, 11, 3, 17, 30, 34).unwrap();
    let mid_slot = Utc.with_ymd_and_hms(2026, 11, 3, 18, 45, 0).unwrap();
    let (due_mid, next_due) = evaluate_snapshot_boundary(mid_slot, off_grid_snap, interval);
    assert!(!due_mid);
    assert_eq!(
        next_due,
        Utc.with_ymd_and_hms(2026, 11, 3, 20, 0, 0).unwrap()
    );

    // Waking inside [20:00, 20:12) UTC triggers the 20:00 UTC boundary cut with clean vYYYYMMDD.2000 slot timestamp
    let at_boundary = Utc.with_ymd_and_hms(2026, 11, 3, 20, 0, 4).unwrap();
    let (due_2000, slot_2000) = evaluate_snapshot_boundary(at_boundary, off_grid_snap, interval);
    assert!(due_2000);
    assert_eq!(
        slot_2000,
        Utc.with_ymd_and_hms(2026, 11, 3, 20, 0, 0).unwrap()
    );
    assert_eq!(utc_timestamp_base_tag("v", slot_2000), "v20261103.2000");

    // Once packaged at 20:01:05 UTC, boundary is satisfied and next wakeup is 00:00:00 UTC next day
    let packaged_2000 = Utc.with_ymd_and_hms(2026, 11, 3, 20, 1, 5).unwrap();
    let check_after = Utc.with_ymd_and_hms(2026, 11, 3, 20, 1, 10).unwrap();
    let (due_after, next_midnight) =
        evaluate_snapshot_boundary(check_after, packaged_2000, interval);
    assert!(!due_after);
    assert_eq!(
        next_midnight,
        Utc.with_ymd_and_hms(2026, 11, 4, 0, 0, 0).unwrap()
    );

    // If 00:00..00:12 UTC passed with zero changes and a fast feed updates at 01:30 UTC,
    // live slot swaps immediately while snapshot packaging defers cleanly to 04:00:00 UTC
    let quiet_mid_slot = Utc.with_ymd_and_hms(2026, 11, 4, 1, 30, 0).unwrap();
    let (due_quiet, next_0400) =
        evaluate_snapshot_boundary(quiet_mid_slot, packaged_2000, interval);
    assert!(!due_quiet);
    assert_eq!(
        next_0400,
        Utc.with_ymd_and_hms(2026, 11, 4, 4, 0, 0).unwrap()
    );
    assert_eq!(
        floor_snapshot_utc_boundary(quiet_mid_slot, interval),
        Utc.with_ymd_and_hms(2026, 11, 4, 0, 0, 0).unwrap()
    );
}

#[tokio::test]
async fn test_cache_dir_eviction_and_orphan_tmp_cleanup() {
    let base = std::env::temp_dir().join(format!("dgspamguard-cache-test-{}", rand::random::<u64>()));
    let old_dir = base.join("v20261104.1600");
    let active_dir = base.join("v20261105.0800");
    tokio::fs::create_dir_all(&old_dir).await.unwrap();
    tokio::fs::create_dir_all(&active_dir).await.unwrap();

    tokio::fs::write(old_dir.join("bundle.tar.gz"), b"old-bundle")
        .await
        .unwrap();
    tokio::fs::write(active_dir.join("bundle.tar.gz"), b"active-bundle")
        .await
        .unwrap();
    tokio::fs::write(base.join(".orphan.tmp"), b"leaked-tmp")
        .await
        .unwrap();

    dgspamguard::db::purge_cache_dir_except(&base, Some("v20261105.0800")).await;

    assert!(!old_dir.exists(), "Old snapshot cache directory must be evicted");
    assert!(!base.join(".orphan.tmp").exists(), "Orphan top-level .tmp file must be deleted");
    assert!(
        active_dir.join("bundle.tar.gz").exists(),
        "Active snapshot cached file must remain intact"
    );

    let _ = tokio::fs::remove_dir_all(&base).await;
}
