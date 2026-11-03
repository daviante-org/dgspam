use crate::types::{DgspamguardError, DgspamguardResult};
use flate2::read::{DeflateDecoder, GzDecoder};
use ipnet::IpNet;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::io::Read;
use std::net::IpAddr;
use url::{Host, Url};

const DEFAULT_ICANN_SUFFIXES: &[&str] = &[
    "co.uk", "org.uk", "gov.uk", "ac.uk", "me.uk", "net.uk", "com.au", "net.au", "org.au",
    "edu.au", "gov.au", "co.nz", "net.nz", "org.nz", "co.in", "net.in", "org.in", "gen.in",
    "firm.in", "ind.in", "gov.in", "ac.in", "edu.in", "res.in", "co.jp", "ne.jp", "or.jp", "ac.jp",
    "go.jp", "lg.jp", "com.br", "net.br", "org.br", "gov.br", "com.mx", "org.mx", "gob.mx",
    "com.cn", "net.cn", "org.cn", "gov.cn", "com.tw", "org.tw", "idv.tw", "com.hk", "org.hk",
    "edu.hk", "gov.hk", "com.sg", "org.sg", "edu.sg", "gov.sg", "co.za", "org.za", "net.za",
    "gov.za", "co.kr", "or.kr", "ne.kr", "go.kr", "co.il", "org.il", "net.il", "ac.il", "com.tr",
    "org.tr", "net.tr", "gov.tr", "com.ua", "org.ua", "net.ua", "com.pl", "net.pl", "org.pl",
    "com.ar", "org.ar", "gob.ar", "com.co", "org.co", "gov.co", "com.pe", "org.pe", "gob.pe",
    "com.my", "org.my", "net.my", "com.ph", "org.ph", "net.ph", "com.vn", "net.vn", "org.vn",
    "co.id", "or.id", "web.id", "co.th", "in.th", "or.th", "com.ng", "org.ng", "co.ke",
];

const DEFAULT_PRIVATE_SUFFIXES: &[&str] = &[
    "github.io",
    "githubusercontent.com",
    "gitlab.io",
    "pages.dev",
    "workers.dev",
    "r2.dev",
    "vercel.app",
    "netlify.app",
    "web.app",
    "firebaseapp.com",
    "herokuapp.com",
    "appspot.com",
    "cloudfunctions.net",
    "run.app",
    "azurewebsites.net",
    "blob.core.windows.net",
    "web.core.windows.net",
    "cloudfront.net",
    "s3.amazonaws.com",
    "elasticbeanstalk.com",
    "Execute-api.us-east-1.amazonaws.com",
    "blogspot.com",
    "wordpress.com",
    "myshopify.com",
    "wixsite.com",
    "weebly.com",
    "squarespace.com",
    "notion.site",
    "surge.sh",
    "onrender.com",
    "fly.dev",
    "railway.app",
    "duckdns.org",
    "ddns.net",
    "hopto.org",
    "zapto.org",
    "sytes.net",
    "no-ip.org",
    "no-ip.biz",
];

#[derive(Debug, Clone)]
pub struct PslMatcher {
    icann_exact: HashSet<String>,
    icann_wildcards: HashSet<String>,
    icann_exceptions: HashSet<String>,
    private_exact: HashSet<String>,
    private_wildcards: HashSet<String>,
    private_exceptions: HashSet<String>,
}

impl Default for PslMatcher {
    fn default() -> Self {
        let mut icann_exact = HashSet::with_capacity(DEFAULT_ICANN_SUFFIXES.len());
        for &s in DEFAULT_ICANN_SUFFIXES {
            icann_exact.insert(s.to_ascii_lowercase());
        }
        let mut private_exact = HashSet::with_capacity(DEFAULT_PRIVATE_SUFFIXES.len());
        for &s in DEFAULT_PRIVATE_SUFFIXES {
            private_exact.insert(s.to_ascii_lowercase());
        }
        Self {
            icann_exact,
            icann_wildcards: HashSet::new(),
            icann_exceptions: HashSet::new(),
            private_exact,
            private_wildcards: HashSet::new(),
            private_exceptions: HashSet::new(),
        }
    }
}

impl PslMatcher {
    /// Parse Mozilla's `public_suffix_list.dat`, preserving ICANN vs PRIVATE section boundaries.
    pub fn from_psl_dat(raw: &str) -> Self {
        let mut matcher = Self::default();
        let mut in_private = false;

        for line in raw.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            if trimmed.contains("===BEGIN PRIVATE DOMAINS===") {
                in_private = true;
                continue;
            }
            if trimmed.contains("===END PRIVATE DOMAINS===") {
                in_private = false;
                continue;
            }
            if trimmed.starts_with("//") {
                continue;
            }
            let rule_token = trimmed.split_whitespace().next().unwrap_or("");
            if rule_token.is_empty() {
                continue;
            }

            if let Some(rest) = rule_token.strip_prefix('!') {
                if let Ok(ascii) = idna::domain_to_ascii(rest) {
                    let clean = ascii.trim_matches('.').to_ascii_lowercase();
                    if !clean.is_empty() {
                        if in_private {
                            matcher.private_exceptions.insert(clean);
                        } else {
                            matcher.icann_exceptions.insert(clean);
                        }
                    }
                }
            } else if let Some(rest) = rule_token.strip_prefix("*.") {
                if let Ok(ascii) = idna::domain_to_ascii(rest) {
                    let clean = ascii.trim_matches('.').to_ascii_lowercase();
                    if !clean.is_empty() {
                        if in_private {
                            matcher.private_wildcards.insert(clean);
                        } else {
                            matcher.icann_wildcards.insert(clean);
                        }
                    }
                }
            } else if let Ok(ascii) = idna::domain_to_ascii(rule_token) {
                let clean = ascii.trim_matches('.').to_ascii_lowercase();
                if !clean.is_empty() {
                    if in_private {
                        matcher.private_exact.insert(clean);
                    } else {
                        matcher.icann_exact.insert(clean);
                    }
                }
            }
        }

        matcher
    }

    pub fn private_roots(&self) -> &HashSet<String> {
        &self.private_exact
    }

    /// Returns `(public_suffix, is_private_section)` using Mozilla PSL priority rules.
    pub fn resolve_suffix<'a>(&self, ascii_domain: &'a str) -> (&'a str, bool) {
        let mut suffixes: Vec<&'a str> = Vec::new();
        suffixes.push(ascii_domain);
        for (idx, ch) in ascii_domain.char_indices() {
            if ch == '.' && idx + 1 < ascii_domain.len() {
                suffixes.push(&ascii_domain[idx + 1..]);
            }
        }

        // Longest suffix is at index 0; evaluate longest-to-shortest for exceptions & wildcards/exact
        let mut best: Option<(&'a str, usize, bool, bool)> = None;
        // Tuple: (effective_suffix, rule_label_count, is_exception, is_private)

        for (i, &cand) in suffixes.iter().enumerate() {
            let label_count = suffixes.len() - i;
            if self.icann_exceptions.contains(cand) {
                let eff = suffixes.get(i + 1).copied().unwrap_or(cand);
                best = Some((eff, label_count, true, false));
                break;
            }
            if self.private_exceptions.contains(cand) {
                let eff = suffixes.get(i + 1).copied().unwrap_or(cand);
                best = Some((eff, label_count, true, true));
                break;
            }

            if let Some(&parent) = suffixes.get(i + 1) {
                if self.icann_wildcards.contains(parent) {
                    if best.is_none_or(|(_, prev_len, prev_exc, _)| {
                        !prev_exc && label_count > prev_len
                    }) {
                        best = Some((cand, label_count, false, false));
                    }
                } else if self.private_wildcards.contains(parent)
                    && best.is_none_or(|(_, prev_len, prev_exc, _)| {
                        !prev_exc && label_count > prev_len
                    })
                {
                    best = Some((cand, label_count, false, true));
                }
            }

            if self.icann_exact.contains(cand) {
                if best.is_none_or(|(_, prev_len, prev_exc, _)| !prev_exc && label_count > prev_len)
                {
                    best = Some((cand, label_count, false, false));
                }
            } else if self.private_exact.contains(cand)
                && best.is_none_or(|(_, prev_len, prev_exc, _)| !prev_exc && label_count > prev_len)
            {
                best = Some((cand, label_count, false, true));
            }
        }

        if let Some((eff, _, _, is_priv)) = best {
            (eff, is_priv)
        } else {
            let tld = suffixes.last().copied().unwrap_or(ascii_domain);
            (tld, false)
        }
    }

    /// Returns true if `ascii_domain` is itself a bare ICANN public suffix (e.g., `com`, `co.uk`).
    pub fn is_icann_public_suffix(&self, ascii_domain: &str) -> bool {
        let (suffix, is_priv) = self.resolve_suffix(ascii_domain);
        !is_priv && suffix == ascii_domain
    }

    /// Returns true if `ascii_domain` is itself a bare Private PSL root (e.g., `github.io`, `pages.dev`).
    pub fn is_private_public_suffix(&self, ascii_domain: &str) -> bool {
        let (suffix, is_priv) = self.resolve_suffix(ascii_domain);
        is_priv && suffix == ascii_domain
    }

    /// Compute `eTLD+1` (`registered_domain`). For bare Private PSL roots (`pages.dev`), falls back to ICANN `eTLD+1`.
    pub fn registered_domain(&self, ascii_domain: &str) -> String {
        let (suffix, is_priv) = self.resolve_suffix(ascii_domain);
        if suffix == ascii_domain {
            if is_priv {
                // e.g. bare `pages.dev` -> `pages.dev`, `s3.amazonaws.com` -> `amazonaws.com`
                return self.icann_registered_domain(ascii_domain);
            }
            return ascii_domain.to_string();
        }
        extract_etld_plus_one(ascii_domain, suffix)
    }

    /// Compute ICANN-only `eTLD+1` (ignoring private suffixes).
    pub fn icann_registered_domain(&self, ascii_domain: &str) -> String {
        let mut suffixes: Vec<&str> = Vec::new();
        suffixes.push(ascii_domain);
        for (idx, ch) in ascii_domain.char_indices() {
            if ch == '.' && idx + 1 < ascii_domain.len() {
                suffixes.push(&ascii_domain[idx + 1..]);
            }
        }
        let mut chosen = suffixes.last().copied().unwrap_or(ascii_domain);
        for (i, &cand) in suffixes.iter().enumerate() {
            if self.icann_exceptions.contains(cand) {
                chosen = suffixes.get(i + 1).copied().unwrap_or(cand);
                break;
            }
            if let Some(&parent) = suffixes.get(i + 1) {
                if self.icann_wildcards.contains(parent) {
                    chosen = cand;
                    break;
                }
            }
            if self.icann_exact.contains(cand) {
                chosen = cand;
                break;
            }
        }
        if chosen == ascii_domain {
            ascii_domain.to_string()
        } else {
            extract_etld_plus_one(ascii_domain, chosen)
        }
    }
}

fn extract_etld_plus_one(ascii_domain: &str, suffix: &str) -> String {
    if ascii_domain.len() <= suffix.len() + 1 {
        return ascii_domain.to_string();
    }
    let prefix_end = ascii_domain.len() - suffix.len() - 1;
    let prefix = &ascii_domain[..prefix_end];
    match prefix.rfind('.') {
        Some(dot_pos) => ascii_domain[dot_pos + 1..].to_string(),
        None => ascii_domain.to_string(),
    }
}

/// Extract the rightmost TLD label from an ASCII domain (`sub.example.co.uk` -> `uk`, `evil.top` -> `top`).
pub fn extract_tld(ascii_domain: &str) -> &str {
    ascii_domain.rsplit('.').next().unwrap_or(ascii_domain)
}

/// Normalize a raw domain string into `(ascii_punycode_lowercase, unicode_display)`.
/// Rejects single-label names, IPv4/IPv6 literals, invalid DNS labels, wildcards, and >253-char FQDNs.
pub fn normalize_domain(raw: &str) -> Option<(String, String)> {
    let mut s = raw.trim();
    if s.is_empty() {
        return None;
    }
    // Strip leading wildcard if present only when caller explicitly cleaned it beforehand; here reject wildcards
    s = s.trim_end_matches('.');
    if s.is_empty() || s.len() > 253 || s.contains('/') || s.contains(':') || s.contains('@') {
        return None;
    }
    if s.starts_with('.') || s.contains("..") || s.contains('*') || s.contains(' ') {
        return None;
    }
    if s.parse::<IpAddr>().is_ok() {
        return None;
    }

    let ascii = idna::domain_to_ascii_strict(s)
        .or_else(|_| idna::domain_to_ascii(s))
        .ok()?
        .to_ascii_lowercase();

    if ascii.len() > 253 || !ascii.contains('.') {
        return None;
    }
    if ascii.parse::<IpAddr>().is_ok() {
        return None;
    }

    let mut label_count = 0usize;
    for label in ascii.split('.') {
        label_count += 1;
        if label.is_empty() || label.len() > 63 {
            return None;
        }
        if label.starts_with('-') || label.ends_with('-') {
            return None;
        }
        if !label
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
        {
            return None;
        }
    }
    if label_count < 2 {
        return None;
    }
    // Rightmost TLD cannot be all-numeric (prevents malformed IPv4 fragments like `192.168.1.999` or `1.2`)
    let tld = extract_tld(&ascii);
    if tld.len() < 2 || tld.bytes().all(|b| b.is_ascii_digit()) || tld.contains('_') {
        return None;
    }

    let (unicode, _) = idna::domain_to_unicode(&ascii);
    let unicode_clean = if unicode.is_empty() {
        ascii.clone()
    } else {
        unicode
    };
    Some((ascii, unicode_clean))
}

/// Extract and normalize the domain part from an email address (`User@Sub.Example.COM` -> `sub.example.com`).
pub fn extract_email_domain(raw: &str) -> Option<(String, String)> {
    let trimmed = raw.trim().trim_matches('<').trim_matches('>');
    let (local, domain_part) = trimmed.rsplit_once('@')?;
    if local.trim().is_empty() || local.len() > 64 || local.contains(' ') {
        return None;
    }
    normalize_domain(domain_part)
}

/// Check whether an IPv4/IPv6 address is publicly routable and NOT a private/bogon/public-DNS address.
pub fn is_public_routable_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            if v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_documentation()
                || v4.is_unspecified()
                || v4.is_multicast()
            {
                return false;
            }
            let o = v4.octets();
            // RFC 6598 CGNAT 100.64.0.0/10, IETF 192.0.0.0/24, Benchmarking 198.18.0.0/15, Reserved 240/4
            if (o[0] == 100 && (o[1] & 0xc0) == 64)
                || (o[0] == 192 && o[1] == 0 && o[2] == 0)
                || (o[0] == 198 && (o[1] == 18 || o[1] == 19))
                || o[0] >= 240
            {
                return false;
            }
            // Protect major public DNS resolvers (Cloudflare, Google, Quad9, OpenDNS)
            if matches!(
                o,
                [1, 1, 1, 1]
                    | [1, 0, 0, 1]
                    | [8, 8, 8, 8]
                    | [8, 8, 4, 4]
                    | [9, 9, 9, 9]
                    | [149, 112, 112, 112]
                    | [208, 67, 222, 222]
                    | [208, 67, 220, 220]
            ) {
                return false;
            }
            true
        }
        IpAddr::V6(v6) => {
            if let Some(v4_mapped) = v6.to_ipv4_mapped() {
                return is_public_routable_ip(IpAddr::V4(v4_mapped));
            }
            if v6.is_loopback() || v6.is_unspecified() || v6.is_multicast() {
                return false;
            }
            let s = v6.segments();
            // Unique Local fc00::/7, Link-Local fe80::/10, Documentation 2001:db8::/32, Discard 100::/64
            if (s[0] & 0xfe00) == 0xfc00
                || (s[0] & 0xffc0) == 0xfe80
                || (s[0] == 0x2001 && s[1] == 0x0db8)
                || (s[0] == 0x0100 && s[1] == 0 && s[2] == 0 && s[3] == 0)
            {
                return false;
            }
            // Protect major IPv6 public DNS resolvers
            if (s[0] == 0x2606 && s[1] == 0x4700 && s[2] == 0x4700)
                || (s[0] == 0x2001 && s[1] == 0x4860 && s[2] == 0x4860)
                || (s[0] == 0x2620 && s[1] == 0x00fe)
            {
                return false;
            }
            true
        }
    }
}

/// Normalize a single IPv4 or IPv6 literal (unwrapping IPv4-mapped IPv6 `::ffff:a.b.c.d` and optional `:port`).
pub fn normalize_ip_literal(raw: &str) -> Option<IpAddr> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.len() > 64 {
        return None;
    }
    let parsed: IpAddr = if let Some(rest) = trimmed.strip_prefix('[') {
        let (inside, _) = rest.split_once(']')?;
        inside.parse().ok()?
    } else if let Ok(ip) = trimmed.parse::<IpAddr>() {
        ip
    } else if let Some((ip_part, port_part)) = trimmed.rsplit_once(':') {
        if !ip_part.contains(':') && port_part.bytes().all(|b| b.is_ascii_digit()) {
            ip_part.parse().ok()?
        } else {
            return None;
        }
    } else {
        return None;
    };

    match parsed {
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                Some(IpAddr::V4(v4))
            } else {
                Some(IpAddr::V6(v6))
            }
        }
        IpAddr::V4(v4) => Some(IpAddr::V4(v4)),
    }
}

/// Parse and validate a public routable IP or CIDR subnet for threat blocklisting.
/// Rejects bogons, private LANs, public DNS resolvers, and overly broad prefixes (`/<8` IPv4, `/<19` IPv6).
pub fn normalize_public_ip_or_cidr(raw: &str) -> Option<IpNet> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    if trimmed.contains('/') {
        let net = trimmed.parse::<IpNet>().ok()?.trunc();
        match net {
            IpNet::V4(v4n) => {
                if v4n.prefix_len() < 8 || !is_public_routable_ip(IpAddr::V4(v4n.addr())) {
                    return None;
                }
                Some(IpNet::V4(v4n))
            }
            IpNet::V6(v6n) => {
                if v6n.prefix_len() < 19 || !is_public_routable_ip(IpAddr::V6(v6n.addr())) {
                    return None;
                }
                Some(IpNet::V6(v6n))
            }
        }
    } else {
        let ip = normalize_ip_literal(trimmed)?;
        if !is_public_routable_ip(ip) {
            return None;
        }
        Some(IpNet::from(ip))
    }
}

/// Canonicalize an HTTP/HTTPS URL supporting both FQDN hosts AND public IPv4/IPv6 literal hosts.
/// Returns `(canonical_url, host_key, url_sha256_hex, optional_ip_host)`.
pub fn canonicalize_url_with_ip(raw: &str) -> Option<(String, String, String, Option<IpAddr>)> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.len() > 4096 {
        return None;
    }
    let mut parsed = Url::parse(trimmed).ok()?;
    let is_http = match parsed.scheme() {
        "http" => true,
        "https" => false,
        _ => return None,
    };
    parsed.set_fragment(None);
    let _ = parsed.set_username("");
    let _ = parsed.set_password(None);
    if (is_http && parsed.port() == Some(80)) || (!is_http && parsed.port() == Some(443)) {
        let _ = parsed.set_port(None);
    }

    let (host_key, ip_host) = match parsed.host()? {
        Host::Ipv4(v4) => {
            let ip = IpAddr::V4(v4);
            if !is_public_routable_ip(ip) {
                return None;
            }
            (v4.to_string(), Some(ip))
        }
        Host::Ipv6(v6) => {
            let ip = IpAddr::V6(v6);
            if !is_public_routable_ip(ip) {
                return None;
            }
            (v6.to_string(), Some(ip))
        }
        Host::Domain(d) => {
            let (ascii_domain, _) = normalize_domain(d)?;
            if parsed.set_host(Some(&ascii_domain)).is_err() {
                return None;
            }
            (ascii_domain, None)
        }
    };

    if parsed.path().is_empty() {
        parsed.set_path("/");
    }

    let canonical = parsed.to_string();
    let digest = sha256_hex(canonical.as_bytes());
    Some((canonical, host_key, digest, ip_host))
}

/// Canonicalize an HTTP/HTTPS URL into `(canonical_url, ascii_domain_or_ip, url_sha256_hex)`.
/// Lowercases scheme and Punycode host, strips default ports (`:80`/`:443`) and `#fragment`, preserves path & query.
pub fn canonicalize_url(raw: &str) -> Option<(String, String, String)> {
    let (canonical, host_key, digest, _) = canonicalize_url_with_ip(raw)?;
    Some((canonical, host_key, digest))
}

/// Validate and lowercase a 64-character hexadecimal SHA-256 digest.
pub fn normalize_sha256(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    let clean = trimmed
        .strip_prefix("sha256:")
        .or_else(|| trimmed.strip_prefix("SHA256:"))
        .unwrap_or(trimmed)
        .trim();
    if clean.len() != 64 || !clean.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    Some(clean.to_ascii_lowercase())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IndicatorInput {
    Sha256(String),
    Ip(IpAddr),
    Url {
        canonical_url: String,
        ascii_domain: String,
        url_sha256: String,
    },
    Email {
        ascii_domain: String,
        unicode_domain: String,
    },
    Domain {
        ascii_domain: String,
        unicode_domain: String,
    },
}

/// Auto-detect whether a raw indicator string is a SHA-256 hash, IPv4/IPv6 address, HTTP/HTTPS URL, Email address, or Domain.
pub fn classify_indicator(raw: &str) -> Result<IndicatorInput, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("Indicator must not be empty.".to_string());
    }
    if let Some(hash) = normalize_sha256(trimmed) {
        return Ok(IndicatorInput::Sha256(hash));
    }
    if trimmed.starts_with("http://")
        || trimmed.starts_with("https://")
        || trimmed.starts_with("HTTP://")
        || trimmed.starts_with("HTTPS://")
    {
        return canonicalize_url(trimmed)
            .map(
                |(canonical_url, ascii_domain, url_sha256)| IndicatorInput::Url {
                    canonical_url,
                    ascii_domain,
                    url_sha256,
                },
            )
            .ok_or_else(|| "Invalid HTTP/HTTPS URL or non-routable host.".to_string());
    }
    if let Some(ip) = normalize_ip_literal(trimmed) {
        return Ok(IndicatorInput::Ip(ip));
    }
    if trimmed.contains('@') && !trimmed.contains("://") {
        return extract_email_domain(trimmed)
            .map(|(ascii_domain, unicode_domain)| IndicatorInput::Email {
                ascii_domain,
                unicode_domain,
            })
            .ok_or_else(|| "Invalid email address domain.".to_string());
    }
    if trimmed.contains('/') {
        // Handle scheme-less URL like `evil-login.top/signin`
        let candidate = format!("https://{trimmed}");
        if let Some((canonical_url, ascii_domain, url_sha256)) = canonicalize_url(&candidate) {
            return Ok(IndicatorInput::Url {
                canonical_url,
                ascii_domain,
                url_sha256,
            });
        }
    }
    normalize_domain(trimmed)
        .map(|(ascii_domain, unicode_domain)| IndicatorInput::Domain {
            ascii_domain,
            unicode_domain,
        })
        .ok_or_else(|| "Invalid domain, URL, email address, or SHA-256 digest.".to_string())
}

/// Compute lowercase hex SHA-256 of arbitrary bytes.
pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

/// Decompress a GZIP byte buffer with a strict upper bound on uncompressed output bytes.
pub fn gunzip_bounded(bytes: &[u8], max_uncompressed: usize) -> DgspamguardResult<Vec<u8>> {
    let decoder = GzDecoder::new(bytes);
    let mut limited = decoder.take((max_uncompressed as u64).saturating_add(1));
    let mut out = Vec::new();
    limited
        .read_to_end(&mut out)
        .map_err(|e| DgspamguardError::Compile(format!("GZIP decompression failed: {e}")))?;
    if out.len() > max_uncompressed {
        return Err(DgspamguardError::Compile(format!(
            "Decompressed GZIP payload exceeded limit of {max_uncompressed} bytes."
        )));
    }
    Ok(out)
}

/// Pure-Rust single-entry ZIP extractor (`PK\x03\x04`, methods `0` Stored and `8` Deflate) with size cap.
pub fn extract_first_zip_entry(
    bytes: &[u8],
    max_uncompressed: usize,
) -> DgspamguardResult<Vec<u8>> {
    if bytes.len() < 30 || &bytes[0..4] != b"PK\x03\x04" {
        return Err(DgspamguardError::Compile(
            "Invalid ZIP archive: missing PK\\x03\\x04 local file header.".to_string(),
        ));
    }

    let flags = u16::from_le_bytes([bytes[6], bytes[7]]);
    let method = u16::from_le_bytes([bytes[8], bytes[9]]);
    let compressed_size = u32::from_le_bytes([bytes[18], bytes[19], bytes[20], bytes[21]]) as usize;
    let uncompressed_size =
        u32::from_le_bytes([bytes[22], bytes[23], bytes[24], bytes[25]]) as usize;
    let filename_len = u16::from_le_bytes([bytes[26], bytes[27]]) as usize;
    let extra_len = u16::from_le_bytes([bytes[28], bytes[29]]) as usize;

    if uncompressed_size > max_uncompressed {
        return Err(DgspamguardError::Compile(format!(
            "ZIP uncompressed size {uncompressed_size} exceeds limit {max_uncompressed}."
        )));
    }

    let data_offset = 30usize
        .checked_add(filename_len)
        .and_then(|v| v.checked_add(extra_len))
        .ok_or_else(|| DgspamguardError::Compile("ZIP header length overflow.".to_string()))?;

    if data_offset > bytes.len() {
        return Err(DgspamguardError::Compile(
            "Truncated ZIP local file header.".to_string(),
        ));
    }

    let has_data_descriptor = (flags & 0x0008) != 0;
    let slice = if !has_data_descriptor && compressed_size > 0 {
        let end = data_offset.checked_add(compressed_size).ok_or_else(|| {
            DgspamguardError::Compile("ZIP compressed size overflow.".to_string())
        })?;
        if end > bytes.len() {
            return Err(DgspamguardError::Compile(
                "Truncated ZIP compressed payload.".to_string(),
            ));
        }
        &bytes[data_offset..end]
    } else {
        &bytes[data_offset..]
    };

    match method {
        0 => {
            if has_data_descriptor && compressed_size == 0 {
                return Err(DgspamguardError::Compile(
                    "Stored ZIP entry with streaming data descriptor is unsupported.".to_string(),
                ));
            }
            if slice.len() > max_uncompressed {
                return Err(DgspamguardError::Compile(format!(
                    "Stored ZIP entry size {} exceeds limit {max_uncompressed}.",
                    slice.len()
                )));
            }
            Ok(slice.to_vec())
        }
        8 => {
            let decoder = DeflateDecoder::new(slice);
            let mut limited = decoder.take((max_uncompressed as u64).saturating_add(1));
            let mut out = Vec::with_capacity(uncompressed_size.min(16 * 1024 * 1024));
            limited.read_to_end(&mut out).map_err(|e| {
                DgspamguardError::Compile(format!("ZIP DEFLATE decode failed: {e}"))
            })?;
            if out.len() > max_uncompressed {
                return Err(DgspamguardError::Compile(format!(
                    "Decompressed ZIP entry exceeded limit of {max_uncompressed} bytes."
                )));
            }
            Ok(out)
        }
        other => Err(DgspamguardError::Compile(format!(
            "Unsupported ZIP compression method {other} (expected 0 or 8)."
        ))),
    }
}

/// Build non-empty parent suffix chain for domain lookup (`a.b.example.com` -> `["a.b.example.com", "b.example.com", "example.com"]`).
/// Stops at `registered_domain` so bare TLDs/ICANN public suffixes are never queried as threat matches.
pub fn domain_lookup_chain(ascii_domain: &str, registered_domain: &str) -> Vec<String> {
    let mut chain = Vec::new();
    let mut cur = ascii_domain;
    loop {
        chain.push(cur.to_string());
        if cur == registered_domain {
            break;
        }
        match cur.find('.') {
            Some(pos) if pos + 1 < cur.len() => {
                cur = &cur[pos + 1..];
            }
            _ => break,
        }
    }
    chain
}
