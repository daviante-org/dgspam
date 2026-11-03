use crate::types::{
    AllowlistRule, CompiledDomainRow, CompiledIpRow, CompiledUrlRow, DgspamguardError,
    DgspamguardResult, FeedSourceSpec, TldRiskRule,
};
use serde_json::{json, Value};
use std::collections::BTreeSet;

/// Sanitized, zero-third-party DGMail spam-filter AST ruleset (`HttpLookup: []`, all external DNSBLs disabled).
pub const DGMAIL_BASE_SEED_JSON: &str = include_str!("../assets/dgmail-base-seed.json");

pub const DEFAULT_BOOTSTRAP_BUNDLE_URL: &str =
    "https://github.com/daviante-org/dgspamguard-data/releases/latest/download/bundle.tar.gz";

/// Placeholder token inside `dgspamguard_feed_sources.source_url` so raw Abuse.ch keys are never stored in feed URLs.
pub const ABUSECH_AUTH_KEY_PLACEHOLDER: &str = "{ABUSECH_AUTH_KEY}";

pub const DEFAULT_ALLOWED_HOSTS: &[&str] = &[
    "publicsuffix.org",
    "tranco-list.eu",
    "hole.cert.pl",
    "phishing.army",
    "raw.githubusercontent.com",
    "phishunt.io",
    "openphish.com",
    "malware-filter.gitlab.io",
    "www.botvrij.eu",
    "urlhaus-api.abuse.ch",
    "threatfox-api.abuse.ch",
    "mb-api.abuse.ch",
    "feodotracker.abuse.ch",
    "www.spamhaus.org",
    "lists.blocklist.de",
    "disposable.github.io",
    "github.com",
    "objects.githubusercontent.com",
    "release-assets.githubusercontent.com",
    "dgspamguard.daviante.org",
];

/// Built-in baseline free webmail providers so `dgspamguard` always classifies major providers even offline.
pub const FALLBACK_FREE_EMAIL_DOMAINS: &[&str] = &[
    "gmail.com",
    "googlemail.com",
    "outlook.com",
    "hotmail.com",
    "live.com",
    "msn.com",
    "yahoo.com",
    "yahoo.co.uk",
    "yahoo.co.in",
    "yahoo.co.jp",
    "yahoo.fr",
    "yahoo.de",
    "yahoo.ca",
    "yahoo.com.br",
    "ymail.com",
    "rocketmail.com",
    "icloud.com",
    "me.com",
    "mac.com",
    "aol.com",
    "proton.me",
    "protonmail.com",
    "protonmail.ch",
    "pm.me",
    "tuta.com",
    "tutanota.com",
    "tutamail.com",
    "zoho.com",
    "zohomail.com",
    "zohomail.in",
    "gmx.com",
    "gmx.de",
    "gmx.net",
    "web.de",
    "mail.com",
    "email.com",
    "fastmail.com",
    "fastmail.fm",
    "yandex.com",
    "yandex.ru",
    "mail.ru",
    "bk.ru",
    "inbox.ru",
    "list.ru",
    "163.com",
    "126.com",
    "qq.com",
    "sina.com",
    "naver.com",
    "daum.net",
    "hanmail.net",
    "rediffmail.com",
    "seznam.cz",
    "wp.pl",
    "onet.pl",
    "interia.pl",
    "o2.pl",
    "libero.it",
    "virgilio.it",
    "alice.it",
    "orange.fr",
    "laposte.net",
    "free.fr",
    "sfr.fr",
    "t-online.de",
    "freenet.de",
    "bluewin.ch",
    "uol.com.br",
    "bol.com.br",
    "terra.com.br",
];

pub fn build_default_feed_sources() -> Vec<FeedSourceSpec> {
    vec![
        // Layer 0: Public Suffix List & Top-Rank Allowlist Gate (24h TTL)
        FeedSourceSpec {
            feed_key: "psl-mozilla".to_string(),
            category: "psl".to_string(),
            parser_kind: "psl_dat".to_string(),
            source_url: "https://publicsuffix.org/list/public_suffix_list.dat".to_string(),
            refresh_interval_seconds: 86_400,
            min_records: 5_000,
            max_compressed_bytes: 8 * 1024 * 1024,
            max_uncompressed_bytes: 16 * 1024 * 1024,
            confidence_weight: 0,
            enabled: true,
            display_order: 1,
            etag: None,
            last_modified: None,
            last_fetched_at: None,
        },
        FeedSourceSpec {
            feed_key: "allow-tranco-top".to_string(),
            category: "allowlist".to_string(),
            parser_kind: "tranco_csv_zip".to_string(),
            source_url: "https://tranco-list.eu/top-1m.csv.zip".to_string(),
            refresh_interval_seconds: 86_400,
            min_records: 50_000,
            max_compressed_bytes: 32 * 1024 * 1024,
            max_uncompressed_bytes: 64 * 1024 * 1024,
            confidence_weight: 0,
            enabled: true,
            display_order: 2,
            etag: None,
            last_modified: None,
            last_fetched_at: None,
        },
        // Layer 1A: First-Party Authenticated Abuse.ch Intelligence (15m / 1h native TTL; gracefully skipped if DGSPAMGUARD_ABUSECH_AUTH_KEY is unset)
        FeedSourceSpec {
            feed_key: "abusech-urlhaus-v1-urls".to_string(),
            category: "malware".to_string(),
            parser_kind: "urlhaus_v1_urls_json".to_string(),
            source_url: "https://urlhaus-api.abuse.ch/v1/urls/recent/".to_string(),
            refresh_interval_seconds: 900,
            min_records: 10,
            max_compressed_bytes: 16 * 1024 * 1024,
            max_uncompressed_bytes: 32 * 1024 * 1024,
            confidence_weight: 86,
            enabled: true,
            display_order: 4,
            etag: None,
            last_modified: None,
            last_fetched_at: None,
        },
        FeedSourceSpec {
            feed_key: "abusech-urlhaus-recent".to_string(),
            category: "malware".to_string(),
            parser_kind: "urlhaus_csv".to_string(),
            source_url:
                "https://urlhaus-api.abuse.ch/v2/files/exports/{ABUSECH_AUTH_KEY}/recent.csv"
                    .to_string(),
            refresh_interval_seconds: 3_600,
            min_records: 100,
            max_compressed_bytes: 64 * 1024 * 1024,
            max_uncompressed_bytes: 128 * 1024 * 1024,
            confidence_weight: 84,
            enabled: true,
            display_order: 5,
            etag: None,
            last_modified: None,
            last_fetched_at: None,
        },
        FeedSourceSpec {
            feed_key: "abusech-threatfox-recent".to_string(),
            category: "c2".to_string(),
            parser_kind: "threatfox_csv".to_string(),
            source_url:
                "https://threatfox-api.abuse.ch/v2/files/exports/{ABUSECH_AUTH_KEY}/recent.csv"
                    .to_string(),
            refresh_interval_seconds: 3_600,
            min_records: 50,
            max_compressed_bytes: 32 * 1024 * 1024,
            max_uncompressed_bytes: 64 * 1024 * 1024,
            confidence_weight: 86,
            enabled: true,
            display_order: 6,
            etag: None,
            last_modified: None,
            last_fetched_at: None,
        },
        FeedSourceSpec {
            feed_key: "abusech-bazaar-recent".to_string(),
            category: "malware_hash".to_string(),
            parser_kind: "bazaar_csv".to_string(),
            source_url:
                "https://mb-api.abuse.ch/v2/files/exports/{ABUSECH_AUTH_KEY}/recent.csv"
                    .to_string(),
            refresh_interval_seconds: 3_600,
            min_records: 20,
            max_compressed_bytes: 16 * 1024 * 1024,
            max_uncompressed_bytes: 32 * 1024 * 1024,
            confidence_weight: 90,
            enabled: true,
            display_order: 7,
            etag: None,
            last_modified: None,
            last_fetched_at: None,
        },
        FeedSourceSpec {
            feed_key: "abusech-urlhaus-v1-payloads".to_string(),
            category: "malware_hash".to_string(),
            parser_kind: "urlhaus_v1_payloads_json".to_string(),
            source_url: "https://urlhaus-api.abuse.ch/v1/payloads/recent/".to_string(),
            refresh_interval_seconds: 900,
            min_records: 10,
            max_compressed_bytes: 16 * 1024 * 1024,
            max_uncompressed_bytes: 32 * 1024 * 1024,
            confidence_weight: 88,
            enabled: true,
            display_order: 8,
            etag: None,
            last_modified: None,
            last_fetched_at: None,
        },
        // Layer 1B: Active Phishing & Malware Domains / URLs (30m / 1h / 4h / 12h per-feed native TTLs)
        FeedSourceSpec {
            feed_key: "phish-cert-pl".to_string(),
            category: "phishing".to_string(),
            parser_kind: "domains_txt".to_string(),
            source_url: "https://hole.cert.pl/domains/v2/domains.txt".to_string(),
            refresh_interval_seconds: 1_800,
            min_records: 10_000,
            max_compressed_bytes: 32 * 1024 * 1024,
            max_uncompressed_bytes: 64 * 1024 * 1024,
            confidence_weight: 62,
            enabled: true,
            display_order: 10,
            etag: None,
            last_modified: None,
            last_fetched_at: None,
        },
        FeedSourceSpec {
            feed_key: "malware-urlhaus-online".to_string(),
            category: "malware".to_string(),
            parser_kind: "domains_txt".to_string(),
            source_url:
                "https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-domains-online.txt"
                    .to_string(),
            refresh_interval_seconds: 1_800,
            min_records: 100,
            max_compressed_bytes: 16 * 1024 * 1024,
            max_uncompressed_bytes: 32 * 1024 * 1024,
            confidence_weight: 68,
            enabled: true,
            display_order: 11,
            etag: None,
            last_modified: None,
            last_fetched_at: None,
        },
        FeedSourceSpec {
            feed_key: "phish-phishunt".to_string(),
            category: "phishing".to_string(),
            parser_kind: "urls_txt".to_string(),
            source_url: "https://phishunt.io/feed.txt".to_string(),
            refresh_interval_seconds: 3_600,
            min_records: 50,
            max_compressed_bytes: 16 * 1024 * 1024,
            max_uncompressed_bytes: 32 * 1024 * 1024,
            confidence_weight: 58,
            enabled: true,
            display_order: 12,
            etag: None,
            last_modified: None,
            last_fetched_at: None,
        },
        FeedSourceSpec {
            feed_key: "phish-openphish".to_string(),
            category: "phishing".to_string(),
            parser_kind: "urls_txt".to_string(),
            source_url: "https://openphish.com/feed.txt".to_string(),
            refresh_interval_seconds: 3_600,
            min_records: 50,
            max_compressed_bytes: 16 * 1024 * 1024,
            max_uncompressed_bytes: 32 * 1024 * 1024,
            confidence_weight: 65,
            enabled: true,
            display_order: 13,
            etag: None,
            last_modified: None,
            last_fetched_at: None,
        },
        FeedSourceSpec {
            feed_key: "phish-army".to_string(),
            category: "phishing".to_string(),
            parser_kind: "domains_txt".to_string(),
            source_url: "https://phishing.army/download/phishing_army_blocklist_extended.txt"
                .to_string(),
            refresh_interval_seconds: 14_400,
            min_records: 20_000,
            max_compressed_bytes: 32 * 1024 * 1024,
            max_uncompressed_bytes: 64 * 1024 * 1024,
            confidence_weight: 54,
            enabled: true,
            display_order: 14,
            etag: None,
            last_modified: None,
            last_fetched_at: None,
        },
        FeedSourceSpec {
            feed_key: "phish-malware-filter".to_string(),
            category: "phishing".to_string(),
            parser_kind: "domains_txt".to_string(),
            source_url: "https://malware-filter.gitlab.io/malware-filter/phishing-filter-domains.txt"
                .to_string(),
            refresh_interval_seconds: 14_400,
            min_records: 2_000,
            max_compressed_bytes: 32 * 1024 * 1024,
            max_uncompressed_bytes: 64 * 1024 * 1024,
            confidence_weight: 56,
            enabled: true,
            display_order: 15,
            etag: None,
            last_modified: None,
            last_fetched_at: None,
        },
        FeedSourceSpec {
            feed_key: "phish-db-domains".to_string(),
            category: "phishing".to_string(),
            parser_kind: "domains_txt".to_string(),
            source_url: "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-domains-ACTIVE.txt"
                .to_string(),
            refresh_interval_seconds: 43_200,
            min_records: 50_000,
            max_compressed_bytes: 64 * 1024 * 1024,
            max_uncompressed_bytes: 128 * 1024 * 1024,
            confidence_weight: 55,
            enabled: true,
            display_order: 16,
            etag: None,
            last_modified: None,
            last_fetched_at: None,
        },
        FeedSourceSpec {
            feed_key: "phish-db-urls".to_string(),
            category: "phishing".to_string(),
            parser_kind: "urls_txt".to_string(),
            source_url: "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-links-ACTIVE.txt"
                .to_string(),
            refresh_interval_seconds: 43_200,
            min_records: 50_000,
            max_compressed_bytes: 96 * 1024 * 1024,
            max_uncompressed_bytes: 160 * 1024 * 1024,
            confidence_weight: 58,
            enabled: true,
            display_order: 17,
            etag: None,
            last_modified: None,
            last_fetched_at: None,
        },
        FeedSourceSpec {
            feed_key: "phish-db-new-today".to_string(),
            category: "phishing".to_string(),
            parser_kind: "domains_txt".to_string(),
            source_url: "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-domains-NEW-today.txt"
                .to_string(),
            refresh_interval_seconds: 3_600,
            min_records: 0,
            max_compressed_bytes: 16 * 1024 * 1024,
            max_uncompressed_bytes: 32 * 1024 * 1024,
            confidence_weight: 60,
            enabled: true,
            display_order: 18,
            etag: None,
            last_modified: None,
            last_fetched_at: None,
        },
        // Layer 2: Malicious Sending IPs, Botnets & Hijacked Subnets — SMTP Connection Layer (30m / 4h / 12h TTLs)
        FeedSourceSpec {
            feed_key: "ip-spamhaus-drop-v4".to_string(),
            category: "hijacked_cidr".to_string(),
            parser_kind: "spamhaus_drop_json".to_string(),
            source_url: "https://www.spamhaus.org/drop/drop_v4.json".to_string(),
            refresh_interval_seconds: 14_400,
            min_records: 500,
            max_compressed_bytes: 16 * 1024 * 1024,
            max_uncompressed_bytes: 32 * 1024 * 1024,
            confidence_weight: 92,
            enabled: true,
            display_order: 19,
            etag: None,
            last_modified: None,
            last_fetched_at: None,
        },
        FeedSourceSpec {
            feed_key: "ip-spamhaus-drop-v6".to_string(),
            category: "hijacked_cidr".to_string(),
            parser_kind: "spamhaus_drop_json".to_string(),
            source_url: "https://www.spamhaus.org/drop/drop_v6.json".to_string(),
            refresh_interval_seconds: 14_400,
            min_records: 50,
            max_compressed_bytes: 16 * 1024 * 1024,
            max_uncompressed_bytes: 32 * 1024 * 1024,
            confidence_weight: 92,
            enabled: true,
            display_order: 20,
            etag: None,
            last_modified: None,
            last_fetched_at: None,
        },
        FeedSourceSpec {
            feed_key: "ip-blocklist-de-mail".to_string(),
            category: "smtp_attacker".to_string(),
            parser_kind: "ips_txt".to_string(),
            source_url: "https://lists.blocklist.de/lists/mail.txt".to_string(),
            refresh_interval_seconds: 1_800,
            min_records: 500,
            max_compressed_bytes: 16 * 1024 * 1024,
            max_uncompressed_bytes: 32 * 1024 * 1024,
            confidence_weight: 78,
            enabled: true,
            display_order: 21,
            etag: None,
            last_modified: None,
            last_fetched_at: None,
        },
        FeedSourceSpec {
            feed_key: "ip-blocklist-de-bots".to_string(),
            category: "botnet_ip".to_string(),
            parser_kind: "ips_txt".to_string(),
            source_url: "https://lists.blocklist.de/lists/bots.txt".to_string(),
            refresh_interval_seconds: 1_800,
            min_records: 500,
            max_compressed_bytes: 16 * 1024 * 1024,
            max_uncompressed_bytes: 32 * 1024 * 1024,
            confidence_weight: 76,
            enabled: true,
            display_order: 22,
            etag: None,
            last_modified: None,
            last_fetched_at: None,
        },
        FeedSourceSpec {
            feed_key: "ip-feodo-tracker".to_string(),
            category: "botnet_c2".to_string(),
            parser_kind: "ips_txt".to_string(),
            source_url: "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt"
                .to_string(),
            refresh_interval_seconds: 1_800,
            min_records: 0,
            max_compressed_bytes: 8 * 1024 * 1024,
            max_uncompressed_bytes: 16 * 1024 * 1024,
            confidence_weight: 94,
            enabled: true,
            display_order: 23,
            etag: None,
            last_modified: None,
            last_fetched_at: None,
        },
        FeedSourceSpec {
            feed_key: "ip-ipsum-level3".to_string(),
            category: "smtp_attacker".to_string(),
            parser_kind: "ips_txt".to_string(),
            source_url: "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt"
                .to_string(),
            refresh_interval_seconds: 43_200,
            min_records: 1_000,
            max_compressed_bytes: 16 * 1024 * 1024,
            max_uncompressed_bytes: 32 * 1024 * 1024,
            confidence_weight: 85,
            enabled: true,
            display_order: 24,
            etag: None,
            last_modified: None,
            last_fetched_at: None,
        },
        FeedSourceSpec {
            feed_key: "ip-phish-db-active".to_string(),
            category: "phishing_ip".to_string(),
            parser_kind: "ips_txt".to_string(),
            source_url: "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-IPs-ACTIVE.txt"
                .to_string(),
            refresh_interval_seconds: 43_200,
            min_records: 500,
            max_compressed_bytes: 16 * 1024 * 1024,
            max_uncompressed_bytes: 32 * 1024 * 1024,
            confidence_weight: 74,
            enabled: true,
            display_order: 25,
            etag: None,
            last_modified: None,
            last_fetched_at: None,
        },
        // Layer 3: Email Domain Taxonomy — MX-Validated Burner & Free Providers (12h / 24h TTL)
        FeedSourceSpec {
            feed_key: "email-disposable-mx".to_string(),
            category: "disposable".to_string(),
            parser_kind: "domains_txt".to_string(),
            source_url: "https://disposable.github.io/disposable-email-domains/domains_mx.txt"
                .to_string(),
            refresh_interval_seconds: 43_200,
            min_records: 5_000,
            max_compressed_bytes: 16 * 1024 * 1024,
            max_uncompressed_bytes: 32 * 1024 * 1024,
            confidence_weight: 90,
            enabled: true,
            display_order: 26,
            etag: None,
            last_modified: None,
            last_fetched_at: None,
        },
        FeedSourceSpec {
            feed_key: "email-disposable-blocklist".to_string(),
            category: "disposable".to_string(),
            parser_kind: "domains_txt".to_string(),
            source_url: "https://raw.githubusercontent.com/disposable-email-domains/disposable-email-domains/main/disposable_email_blocklist.conf"
                .to_string(),
            refresh_interval_seconds: 86_400,
            min_records: 2_000,
            max_compressed_bytes: 16 * 1024 * 1024,
            max_uncompressed_bytes: 32 * 1024 * 1024,
            confidence_weight: 85,
            enabled: true,
            display_order: 27,
            etag: None,
            last_modified: None,
            last_fetched_at: None,
        },
        FeedSourceSpec {
            feed_key: "email-burner-providers".to_string(),
            category: "disposable".to_string(),
            parser_kind: "domains_txt".to_string(),
            source_url: "https://raw.githubusercontent.com/wesbos/burner-email-providers/master/emails.txt"
                .to_string(),
            refresh_interval_seconds: 86_400,
            min_records: 5_000,
            max_compressed_bytes: 16 * 1024 * 1024,
            max_uncompressed_bytes: 32 * 1024 * 1024,
            confidence_weight: 80,
            enabled: true,
            display_order: 28,
            etag: None,
            last_modified: None,
            last_fetched_at: None,
        },
        FeedSourceSpec {
            feed_key: "email-mailchecker".to_string(),
            category: "disposable".to_string(),
            parser_kind: "domains_txt".to_string(),
            source_url: "https://raw.githubusercontent.com/FGRibreau/mailchecker/master/list.txt"
                .to_string(),
            refresh_interval_seconds: 86_400,
            min_records: 10_000,
            max_compressed_bytes: 16 * 1024 * 1024,
            max_uncompressed_bytes: 32 * 1024 * 1024,
            confidence_weight: 80,
            enabled: true,
            display_order: 29,
            etag: None,
            last_modified: None,
            last_fetched_at: None,
        },
        FeedSourceSpec {
            feed_key: "email-free-providers".to_string(),
            category: "free_provider".to_string(),
            parser_kind: "domains_txt".to_string(),
            source_url:
                "https://raw.githubusercontent.com/willwhite/freemail/master/data/free.txt"
                    .to_string(),
            refresh_interval_seconds: 86_400,
            min_records: 2_000,
            max_compressed_bytes: 16 * 1024 * 1024,
            max_uncompressed_bytes: 32 * 1024 * 1024,
            confidence_weight: 90,
            enabled: true,
            display_order: 30,
            etag: None,
            last_modified: None,
            last_fetched_at: None,
        },
        // Layer 4: Malware Attachment SHA-256 Hashes (1h / 4h TTL)
        FeedSourceSpec {
            feed_key: "hash-malicious-sha256".to_string(),
            category: "malware_hash".to_string(),
            parser_kind: "sha256_txt".to_string(),
            source_url:
                "https://raw.githubusercontent.com/romainmarcoux/malicious-hash/main/full-hash-sha256-aa.txt"
                    .to_string(),
            refresh_interval_seconds: 3_600,
            min_records: 10_000,
            max_compressed_bytes: 16 * 1024 * 1024,
            max_uncompressed_bytes: 32 * 1024 * 1024,
            confidence_weight: 86,
            enabled: true,
            display_order: 35,
            etag: None,
            last_modified: None,
            last_fetched_at: None,
        },
        FeedSourceSpec {
            feed_key: "hash-botvrij-sha256".to_string(),
            category: "malware_hash".to_string(),
            parser_kind: "sha256_txt".to_string(),
            source_url: "https://www.botvrij.eu/data/ioclist.sha256.raw".to_string(),
            refresh_interval_seconds: 14_400,
            min_records: 5,
            max_compressed_bytes: 16 * 1024 * 1024,
            max_uncompressed_bytes: 32 * 1024 * 1024,
            confidence_weight: 82,
            enabled: true,
            display_order: 36,
            etag: None,
            last_modified: None,
            last_fetched_at: None,
        },
    ]
}

pub fn default_allowlist_rules() -> Vec<AllowlistRule> {
    let trusted = [
        ("daviante.org", "Daviante core infrastructure"),
        ("dgroot.com", "Daviante hosting root"),
        ("google.com", "Global search & workspace provider"),
        ("gmail.com", "Google Mail"),
        ("youtube.com", "Google video platform"),
        ("microsoft.com", "Microsoft core domain"),
        ("office.com", "Microsoft 365"),
        ("outlook.com", "Microsoft Outlook"),
        ("live.com", "Microsoft Live"),
        ("apple.com", "Apple core domain"),
        ("icloud.com", "Apple iCloud"),
        ("amazon.com", "Amazon core domain"),
        ("aws.amazon.com", "Amazon Web Services"),
        ("cloudflare.com", "Cloudflare core domain"),
        ("one.one.one.one", "Cloudflare DNS"),
        ("github.com", "GitHub core domain"),
        ("gitlab.com", "GitLab core domain"),
        ("bitbucket.org", "Atlassian Bitbucket"),
        ("mozilla.org", "Mozilla Foundation"),
        ("wikipedia.org", "Wikimedia Foundation"),
        ("ietf.org", "Internet Engineering Task Force"),
        ("iana.org", "Internet Assigned Numbers Authority"),
        ("icann.org", "ICANN"),
        ("paypal.com", "PayPal financial services"),
        ("stripe.com", "Stripe payment infrastructure"),
        ("linkedin.com", "LinkedIn"),
        ("fastly.com", "Fastly CDN"),
        ("akamai.com", "Akamai CDN"),
        ("jsdelivr.net", "jsDelivr OSS CDN"),
        ("unpkg.com", "unpkg CDN"),
        ("crates.io", "Rust package registry"),
        ("rust-lang.org", "Rust project"),
        ("npmjs.com", "npm registry"),
        ("pypi.org", "Python Package Index"),
        ("docker.com", "Docker Hub"),
        ("docker.io", "Docker Registry"),
        ("quay.io", "Red Hat Quay"),
        ("redhat.com", "Red Hat"),
        ("ubuntu.com", "Canonical Ubuntu"),
        ("debian.org", "Debian Project"),
        ("alpine-linux.org", "Alpine Linux"),
        ("alpinelinux.org", "Alpine Linux"),
    ];

    let shared_hosting = [
        ("github.io", "GitHub Pages multi-tenant hosting"),
        ("githubusercontent.com", "GitHub user content"),
        ("gist.github.com", "GitHub Gist"),
        ("gitlab.io", "GitLab Pages multi-tenant hosting"),
        ("pages.dev", "Cloudflare Pages multi-tenant hosting"),
        ("workers.dev", "Cloudflare Workers multi-tenant hosting"),
        ("r2.dev", "Cloudflare R2 public buckets"),
        ("vercel.app", "Vercel multi-tenant hosting"),
        ("netlify.app", "Netlify multi-tenant hosting"),
        ("web.app", "Firebase Hosting"),
        ("firebaseapp.com", "Firebase Hosting"),
        ("googleapis.com", "Google Cloud APIs & storage"),
        ("googleusercontent.com", "Google user content"),
        ("docs.google.com", "Google Docs / Forms"),
        ("drive.google.com", "Google Drive"),
        ("sites.google.com", "Google Sites"),
        ("forms.gle", "Google Forms shortener"),
        ("onedrive.live.com", "Microsoft OneDrive"),
        ("1drv.ms", "Microsoft OneDrive shortener"),
        ("sharepoint.com", "Microsoft SharePoint tenants"),
        ("azurewebsites.net", "Azure App Service tenants"),
        ("blob.core.windows.net", "Azure Blob Storage"),
        ("web.core.windows.net", "Azure Static Websites"),
        ("amazonaws.com", "AWS multi-tenant endpoints"),
        ("cloudfront.net", "AWS CloudFront distributions"),
        ("herokuapp.com", "Heroku apps"),
        ("appspot.com", "Google App Engine"),
        ("run.app", "Google Cloud Run"),
        ("cloudfunctions.net", "Google Cloud Functions"),
        ("dropbox.com", "Dropbox shared links"),
        ("dl.dropboxusercontent.com", "Dropbox user content"),
        ("blogspot.com", "Blogger multi-tenant blogs"),
        ("wordpress.com", "WordPress.com multi-tenant blogs"),
        ("wixsite.com", "Wix multi-tenant sites"),
        ("weebly.com", "Weebly multi-tenant sites"),
        ("squarespace.com", "Squarespace multi-tenant sites"),
        ("myshopify.com", "Shopify storefronts"),
        ("canva.com", "Canva shared pages"),
        ("notion.site", "Notion public pages"),
        ("onrender.com", "Render multi-tenant apps"),
        ("fly.dev", "Fly.io multi-tenant apps"),
        ("railway.app", "Railway multi-tenant apps"),
        ("surge.sh", "Surge static sites"),
        ("duckdns.org", "DuckDNS dynamic DNS"),
        ("ddns.net", "No-IP dynamic DNS"),
        ("hopto.org", "No-IP dynamic DNS"),
        ("zapto.org", "No-IP dynamic DNS"),
        ("sytes.net", "No-IP dynamic DNS"),
        ("discord.com", "Discord CDN / webhooks"),
        ("discordapp.com", "Discord CDN"),
        ("t.me", "Telegram links"),
    ];

    let mut out = Vec::with_capacity(trusted.len() + shared_hosting.len());
    for (domain, notes) in trusted {
        out.push(AllowlistRule {
            domain: domain.to_string(),
            kind: "trusted".to_string(),
            notes: notes.to_string(),
        });
    }
    for (domain, notes) in shared_hosting {
        out.push(AllowlistRule {
            domain: domain.to_string(),
            kind: "shared_hosting".to_string(),
            notes: notes.to_string(),
        });
    }
    out
}

pub fn default_tld_risk_rules() -> Vec<TldRiskRule> {
    let entries: &[(&str, i16, &str, &str)] = &[
        (
            "top",
            38,
            "critical",
            "High-volume phishing & bulk credential abuse TLD",
        ),
        (
            "icu",
            36,
            "critical",
            "High-concentration ephemeral phishing & smishing TLD",
        ),
        (
            "cfd",
            36,
            "critical",
            "Frequent disposable phishing & brand-impersonation TLD",
        ),
        (
            "sbs",
            35,
            "critical",
            "High abuse-to-registration ratio in phishing feeds",
        ),
        (
            "cyou",
            35,
            "critical",
            "Frequent ephemeral C2 & credential harvesting TLD",
        ),
        (
            "tk",
            38,
            "critical",
            "Historically abused free registration ccTLD",
        ),
        (
            "gq",
            36,
            "critical",
            "Historically abused free registration ccTLD",
        ),
        (
            "ml",
            35,
            "critical",
            "Historically abused free registration ccTLD",
        ),
        (
            "cf",
            35,
            "critical",
            "Historically abused free registration ccTLD",
        ),
        (
            "ga",
            34,
            "critical",
            "Historically abused free registration ccTLD",
        ),
        (
            "buzz",
            30,
            "high",
            "Elevated bulk spam & phishing registration rate",
        ),
        (
            "rest",
            30,
            "high",
            "Elevated malware delivery & phishing domain rate",
        ),
        (
            "quest",
            28,
            "high",
            "Elevated credential phishing domain rate",
        ),
        (
            "zip",
            28,
            "high",
            "Filename-confusion phishing vector (.zip TLD)",
        ),
        (
            "mov",
            26,
            "high",
            "Filename-confusion phishing vector (.mov TLD)",
        ),
        ("click", 26, "high", "High-frequency redirect & lure TLD"),
        (
            "link",
            22,
            "elevated",
            "Elevated redirect & unsolicited mail lure TLD",
        ),
        (
            "xyz",
            22,
            "elevated",
            "Mixed general & bulk-registered ephemeral domains",
        ),
        (
            "shop",
            22,
            "elevated",
            "Frequent fake storefront & brand-spoof registrations",
        ),
        (
            "live",
            18,
            "elevated",
            "Elevated live-lure phishing registrations",
        ),
        (
            "online",
            18,
            "elevated",
            "Elevated low-cost bulk registrations",
        ),
        (
            "site",
            18,
            "elevated",
            "Elevated low-cost bulk registrations",
        ),
        ("fun", 20, "elevated", "Elevated bulk spam registrations"),
        ("space", 18, "elevated", "Elevated ephemeral registrations"),
        ("pw", 24, "high", "Elevated malware & spam domain ratio"),
        (
            "work",
            22,
            "elevated",
            "Elevated recruitment & invoice lure registrations",
        ),
        ("loan", 28, "high", "High unsolicited financial spam ratio"),
        ("date", 26, "high", "High unsolicited dating spam ratio"),
        ("men", 25, "high", "High bulk spam ratio"),
        ("win", 26, "high", "High prize/sweepstakes lure ratio"),
        ("bid", 25, "high", "High bulk spam ratio"),
        (
            "vip",
            18,
            "elevated",
            "Elevated scam & impersonation registrations",
        ),
        (
            "su",
            26,
            "high",
            "Elevated bulletproof & malware hosting prevalence",
        ),
        ("com", 5, "low", "Standard global commercial gTLD"),
        ("org", 5, "low", "Standard organization gTLD"),
        ("net", 6, "low", "Standard network infrastructure gTLD"),
        ("edu", 1, "low", "Verified academic institutions"),
        ("gov", 1, "low", "Verified government entities"),
        ("mil", 1, "low", "Verified military entities"),
        (
            "int",
            1,
            "low",
            "Verified international treaty organizations",
        ),
        ("io", 6, "low", "Technology & SaaS ccTLD"),
        ("dev", 6, "low", "HSTS-preloaded developer gTLD"),
        ("app", 6, "low", "HSTS-preloaded application gTLD"),
    ];

    entries
        .iter()
        .map(|&(tld, risk_score, risk_level, notes)| TldRiskRule {
            tld: tld.to_string(),
            risk_score,
            risk_level: risk_level.to_string(),
            notes: notes.to_string(),
        })
        .collect()
}

/// Extract the curated `trusted-domains` and `url-redirectors` domain sets from `DGMAIL_BASE_SEED_JSON`.
pub fn extract_seed_memory_sets() -> DgspamguardResult<(BTreeSet<String>, BTreeSet<String>)> {
    let parsed: Value = serde_json::from_str(DGMAIL_BASE_SEED_JSON)
        .map_err(|e| DgspamguardError::Compile(format!("Invalid dgmail-base-seed.json: {e}")))?;

    let mut trusted = BTreeSet::new();
    let mut redirectors = BTreeSet::new();

    if let Some(arr) = parsed.get("MemoryLookupKey").and_then(Value::as_array) {
        for item in arr {
            let ns = item.get("namespace").and_then(Value::as_str).unwrap_or("");
            let key = item
                .get("key")
                .and_then(Value::as_str)
                .unwrap_or("")
                .trim()
                .to_ascii_lowercase();
            if key.is_empty() {
                continue;
            }
            match ns {
                "trusted-domains" => {
                    trusted.insert(key);
                }
                "url-redirectors" => {
                    redirectors.insert(key);
                }
                _ => {}
            }
        }
    }

    Ok((trusted, redirectors))
}

/// Build the upgraded, zero-third-party `dgmail-rules.json` payload for DGMail's `spam_rules_url`.
/// Populates in-memory lookup namespaces (`dgm_free_domains`, `dgm_disposable_domains`,
/// `dgm_openphish`, `dgspamguard_threat_domains`, `dgspamguard_smtp_threat_ips`) while staying strictly under DGMail's 500 KB `.gz` fetch cap.
pub fn build_upgraded_dgmail_rules_json(
    domains: &[CompiledDomainRow],
    urls: &[CompiledUrlRow],
    ips: &[CompiledIpRow],
    max_disposable: usize,
    max_threat_domains: usize,
    max_phish_urls: usize,
    max_threat_ips: usize,
) -> DgspamguardResult<Vec<u8>> {
    let mut root: Value = serde_json::from_str(DGMAIL_BASE_SEED_JSON)
        .map_err(|e| DgspamguardError::Compile(format!("Failed to parse base DGMail seed: {e}")))?;

    // Ensure HttpLookup is strictly empty (zero outbound HTTP dependency)
    if let Some(obj) = root.as_object_mut() {
        obj.insert("HttpLookup".to_string(), json!([]));
    }

    // Add DGSPAMGUARD native rules to SpamRule
    if let Some(rules) = root.get_mut("SpamRule").and_then(Value::as_array_mut) {
        rules.push(json!({
            "@type": "Message",
            "name": "DGSPAMGUARD_SMTP_THREAT_IP",
            "enable": true,
            "priority": 18,
            "condition": {
                "else": "false",
                "match": {
                    "0": {
                        "if": "key_exists('dgspamguard_smtp_threat_ips', remote_ip)",
                        "then": "'DGSPAMGUARD_THREAT_IP'"
                    }
                }
            }
        }));
        rules.push(json!({
            "@type": "Url",
            "name": "DGSPAMGUARD_THREAT_URI_DOMAIN",
            "enable": true,
            "priority": 56,
            "condition": {
                "else": "false",
                "match": {
                    "0": {
                        "if": "key_exists('dgspamguard_threat_domains', host) || key_exists('dgspamguard_threat_domains', sld)",
                        "then": "'DGSPAMGUARD_THREAT_URI'"
                    }
                }
            }
        }));
        rules.push(json!({
            "@type": "Email",
            "name": "DGSPAMGUARD_THREAT_SENDER_DOMAIN",
            "enable": true,
            "priority": 64,
            "condition": {
                "else": "false",
                "match": {
                    "0": {
                        "if": "contains(['env_from', 'from', 'reply_to'], location) && (key_exists('dgspamguard_threat_domains', domain) || key_exists('dgspamguard_threat_domains', sld))",
                        "then": "'DGSPAMGUARD_THREAT_SENDER'"
                    }
                }
            }
        }));
        rules.push(json!({
            "@type": "Email",
            "name": "DGSPAMGUARD_ABUSED_TLD_SENDER",
            "enable": true,
            "priority": 65,
            "condition": {
                "else": "false",
                "match": {
                    "0": {
                        "if": "contains(['env_from', 'from', 'reply_to'], location) && (ends_with(domain, '.top') || ends_with(domain, '.icu') || ends_with(domain, '.cfd') || ends_with(domain, '.sbs') || ends_with(domain, '.cyou') || ends_with(domain, '.tk') || ends_with(domain, '.gq') || ends_with(domain, '.ml') || ends_with(domain, '.cf') || ends_with(domain, '.ga'))",
                        "then": "'DGSPAMGUARD_HIGH_RISK_TLD_FROM'"
                    }
                }
            }
        }));
        rules.push(json!({
            "@type": "Url",
            "name": "DGSPAMGUARD_ABUSED_TLD_URI",
            "enable": true,
            "priority": 57,
            "condition": {
                "else": "false",
                "match": {
                    "0": {
                        "if": "ends_with(host, '.top') || ends_with(host, '.icu') || ends_with(host, '.cfd') || ends_with(host, '.sbs') || ends_with(host, '.cyou') || ends_with(host, '.zip') || ends_with(host, '.mov')",
                        "then": "'DGSPAMGUARD_HIGH_RISK_TLD_URI'"
                    }
                }
            }
        }));
    }

    // Add corresponding scores to SpamTag
    if let Some(tags) = root.get_mut("SpamTag").and_then(Value::as_array_mut) {
        tags.push(json!({"@type": "Score", "score": 6.5, "tag": "DGSPAMGUARD_THREAT_IP"}));
        tags.push(json!({"@type": "Score", "score": 7.5, "tag": "DGSPAMGUARD_THREAT_URI"}));
        tags.push(json!({"@type": "Score", "score": 7.5, "tag": "DGSPAMGUARD_THREAT_SENDER"}));
        tags.push(json!({"@type": "Score", "score": 2.0, "tag": "DGSPAMGUARD_HIGH_RISK_TLD_FROM"}));
        tags.push(json!({"@type": "Score", "score": 1.5, "tag": "DGSPAMGUARD_HIGH_RISK_TLD_URI"}));
        // Give disposable sender a calibrated positive spam score
        for tag in tags.iter_mut() {
            if tag.get("tag").and_then(Value::as_str) == Some("DISPOSABLE_FROM")
                || tag.get("tag").and_then(Value::as_str) == Some("DISPOSABLE_ENV_FROM")
                || tag.get("tag").and_then(Value::as_str) == Some("DISPOSABLE_REPLY_TO")
            {
                if let Some(obj) = tag.as_object_mut() {
                    obj.insert("score".to_string(), json!(3.5));
                }
            }
        }
    }

    // Populate MemoryLookupKey namespaces sorted deterministically for high DEFLATE compression
    if let Some(mem_keys) = root
        .get_mut("MemoryLookupKey")
        .and_then(Value::as_array_mut)
    {
        let mut free_set: Vec<&str> = domains
            .iter()
            .filter(|r| r.email_kind.as_deref() == Some("free_provider"))
            .map(|r| r.domain.as_str())
            .collect();
        free_set.sort_unstable();
        for dom in free_set {
            mem_keys.push(json!({
                "key": dom,
                "namespace": "dgm_free_domains",
                "isGlobPattern": false
            }));
        }

        let mut disp_candidates: Vec<&CompiledDomainRow> = domains
            .iter()
            .filter(|r| r.email_kind.as_deref() == Some("disposable"))
            .collect();
        disp_candidates.sort_by(|a, b| {
            b.source_count
                .cmp(&a.source_count)
                .then_with(|| b.confidence.cmp(&a.confidence))
                .then_with(|| a.domain.cmp(&b.domain))
        });
        disp_candidates.truncate(max_disposable);
        disp_candidates.sort_by(|a, b| a.domain.cmp(&b.domain));
        for row in disp_candidates {
            mem_keys.push(json!({
                "key": row.domain,
                "namespace": "dgm_disposable_domains",
                "isGlobPattern": false
            }));
        }

        let mut threat_candidates: Vec<&CompiledDomainRow> = domains
            .iter()
            .filter(|r| r.threat_category.is_some())
            .collect();
        threat_candidates.sort_by(|a, b| {
            b.source_count
                .cmp(&a.source_count)
                .then_with(|| b.confidence.cmp(&a.confidence))
                .then_with(|| a.domain.cmp(&b.domain))
        });
        threat_candidates.truncate(max_threat_domains);
        threat_candidates.sort_by(|a, b| a.domain.cmp(&b.domain));
        for row in threat_candidates {
            mem_keys.push(json!({
                "key": row.domain,
                "namespace": "dgspamguard_threat_domains",
                "isGlobPattern": false
            }));
        }

        let mut url_candidates: Vec<&CompiledUrlRow> = urls.iter().collect();
        url_candidates.sort_by(|a, b| {
            b.source_count
                .cmp(&a.source_count)
                .then_with(|| b.confidence.cmp(&a.confidence))
                .then_with(|| a.canonical_url.cmp(&b.canonical_url))
        });
        url_candidates.truncate(max_phish_urls);
        url_candidates.sort_by(|a, b| a.canonical_url.cmp(&b.canonical_url));
        for row in url_candidates {
            mem_keys.push(json!({
                "key": row.canonical_url,
                "namespace": "dgm_openphish",
                "isGlobPattern": false
            }));
        }

        let mut ip_candidates: Vec<(&CompiledIpRow, &str)> = ips
            .iter()
            .filter_map(|r| {
                r.network
                    .strip_suffix("/32")
                    .or_else(|| r.network.strip_suffix("/128"))
                    .map(|bare_ip| (r, bare_ip))
            })
            .collect();
        ip_candidates.sort_by(|(a, a_ip), (b, b_ip)| {
            b.source_count
                .cmp(&a.source_count)
                .then_with(|| b.confidence.cmp(&a.confidence))
                .then_with(|| a_ip.cmp(b_ip))
        });
        ip_candidates.truncate(max_threat_ips);
        ip_candidates.sort_by_key(|(_, a_ip)| *a_ip);
        for (_, bare_ip) in ip_candidates {
            mem_keys.push(json!({
                "key": bare_ip,
                "namespace": "dgspamguard_smtp_threat_ips",
                "isGlobPattern": false
            }));
        }
    }

    serde_json::to_vec(&root).map_err(|e| {
        DgspamguardError::Compile(format!("Failed to serialize DGMail rules JSON: {e}"))
    })
}
