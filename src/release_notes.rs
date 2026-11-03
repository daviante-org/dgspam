use crate::types::{CompiledThreatSet, DatasetArtifactMeta};
use chrono::{DateTime, Utc};
use std::collections::BTreeMap;

/// Compute the compact UTC timestamp snapshot tag (`vYYYYMMDD.HHMM`) for 4-hour rolling releases.
pub fn utc_timestamp_base_tag(prefix: &str, ts: DateTime<Utc>) -> String {
    format!("{}{}", prefix, ts.format("%Y%m%d.%H%M"))
}

/// Format a compact UTC snapshot version (`v20261103.1600` for sequence `0`, `v20261103.1600.1` for `1`, etc.).
pub fn format_snapshot_version(prefix: &str, ts: DateTime<Utc>, seq_in_minute: u32) -> String {
    let base = utc_timestamp_base_tag(prefix, ts);
    if seq_in_minute == 0 {
        base
    } else {
        format!("{base}.{seq_in_minute}")
    }
}

/// Render the release title from a template (default `{version}`).
pub fn format_release_title(template: &str, version: &str, ts: DateTime<Utc>) -> String {
    let ts_str = ts.format("%Y-%m-%d %H:%M UTC").to_string();
    let rendered = template
        .replace("{version}", version)
        .replace("{date}", &ts.format("%Y-%m-%d").to_string())
        .replace("{timestamp}", &ts_str);
    let trimmed = rendered.trim();
    if trimmed.is_empty() {
        version.to_string()
    } else {
        trimmed.to_string()
    }
}

fn format_u64_commas(n: u64) -> String {
    let s = n.to_string();
    let bytes = s.as_bytes();
    let len = bytes.len();
    if len <= 3 {
        return s;
    }
    let mut out = String::with_capacity(len + len / 3);
    for (idx, &b) in bytes.iter().enumerate() {
        if idx > 0 && (len - idx) % 3 == 0 {
            out.push(',');
        }
        out.push(b as char);
    }
    out
}

fn format_i64_commas(n: i64) -> String {
    if n < 0 {
        format!("-{}", format_u64_commas(n.unsigned_abs()))
    } else {
        format_u64_commas(n as u64)
    }
}

fn human_bytes(num_bytes: usize) -> String {
    if num_bytes >= 1_048_576 {
        format!("{:.2} MB", (num_bytes as f64) / 1_048_576.0)
    } else if num_bytes >= 1024 {
        format!("{:.1} KB", (num_bytes as f64) / 1024.0)
    } else {
        format!("{num_bytes} B")
    }
}

/// Render Markdown release notes for `dgspamguard-data` rolling GitHub Releases and `/v1/snapshots/{version}`.
pub fn render_release_notes(
    version: &str,
    release_title: &str,
    generated_at: DateTime<Utc>,
    compiled: &CompiledThreatSet,
    artifacts: &BTreeMap<String, (DatasetArtifactMeta, Vec<u8>)>,
    bundle_sha256: &str,
    bundle_size_bytes: usize,
) -> String {
    let mut md = String::with_capacity(4096);
    if release_title.trim().is_empty() || release_title.trim() == version {
        md.push_str(&format!("## DGSPAMGUARD Dataset Release `{version}`\n\n"));
    } else {
        md.push_str(&format!("## {release_title}\n\n"));
    }
    md.push_str(
        "Automated 5-layer domain, URL, SMTP sending IP/subnet, email taxonomy, malware attachment hash, and mail rule intelligence snapshot compiled by **DGSPAMGUARD**.\n\n",
    );

    md.push_str("### Snapshot Summary\n\n");
    md.push_str("| Metric | Count |\n");
    md.push_str("| :--- | ---: |\n");
    md.push_str(&format!("| **Snapshot Version** | `{version}` |\n"));
    md.push_str(&format!(
        "| **Compiled At (UTC)** | `{}` |\n",
        generated_at.format("%Y-%m-%dT%H:%M:%SZ")
    ));
    md.push_str(&format!(
        "| **Active Threat Domains (RPZ / CSV / TXT)** | `{}` |\n",
        format_i64_commas(compiled.threat_domain_count)
    ));
    md.push_str(&format!(
        "| **Active Phishing & Malware URLs** | `{}` |\n",
        format_u64_commas(compiled.urls.len() as u64)
    ));
    md.push_str(&format!(
        "| **Malicious Sending IPs & Hijacked Subnets** | `{}` |\n",
        format_u64_commas(compiled.ips.len() as u64)
    ));
    md.push_str(&format!(
        "| **Disposable & Burner Email Domains** | `{}` |\n",
        format_i64_commas(compiled.disposable_domain_count)
    ));
    md.push_str(&format!(
        "| **Free Webmail Provider Domains** | `{}` |\n",
        format_i64_commas(compiled.free_domain_count)
    ));
    md.push_str(&format!(
        "| **URL Shortener & Redirector Domains** | `{}` |\n",
        format_i64_commas(compiled.redirector_domain_count)
    ));
    md.push_str(&format!(
        "| **Malware Attachment SHA-256 Hashes** | `{}` |\n",
        format_u64_commas(compiled.hashes.len() as u64)
    ));
    md.push_str(&format!(
        "| **Calibrated TLD Risk Profiles** | `{}` |\n\n",
        format_u64_commas(compiled.tld_risks.len() as u64)
    ));

    md.push_str("### Release Artifacts (`SHA-256`)\n\n");
    md.push_str("| Filename | Records | Size | SHA-256 |\n");
    md.push_str("| :--- | ---: | ---: | :--- |\n");
    md.push_str(&format!(
        "| `bundle.tar.gz` | All 9 datasets | {} | `{bundle_sha256}` |\n",
        human_bytes(bundle_size_bytes)
    ));
    for meta_tuple in artifacts.values() {
        let meta = &meta_tuple.0;
        let rec = meta
            .record_count
            .map(|c| format!("`{}`", format_i64_commas(c)))
            .unwrap_or_else(|| "-".to_string());
        md.push_str(&format!(
            "| `{}` | {} | {} | `{}` |\n",
            meta.filename,
            rec,
            human_bytes(meta.size_bytes.max(0) as usize),
            meta.sha256
        ));
    }

    md.push_str("\n### Verification\n\n");
    md.push_str("```bash\nsha256sum -c SHA256SUMS.txt\n```\n\n");
    md.push_str(
        "Rolling retention policy: snapshots are cut on fixed 4-hour UTC boundaries (`00:00`, `04:00`, `08:00`, `12:00`, `16:00`, `20:00` UTC) when upstream feeds change and retained for 7 days.\n",
    );
    md
}
