use crate::compiler::{
    compile_threat_feeds, compute_compiled_fingerprint, package_snapshot, unpack_bootstrap_bundle,
    RawFeedPayload,
};
use crate::config::Settings;
use crate::db::Database;
use crate::seed_data::ABUSECH_AUTH_KEY_PLACEHOLDER;
use crate::types::{
    DgspamguardError, DgspamguardResult, FeedSourceSpec, PackagedSnapshot, RuntimeCatalog,
    APP_VERSION,
};
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use flate2::write::GzEncoder;
use flate2::Compression;
use futures_util::StreamExt;
use reqwest::header::{ETAG, IF_MODIFIED_SINCE, IF_NONE_MATCH, LAST_MODIFIED, USER_AGENT};
use reqwest::redirect::Policy;
use reqwest::{Client, StatusCode};
use std::collections::HashSet;
use std::io::Write;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, error, info, warn};
use url::Url;

#[derive(Debug, Clone)]
pub struct SyncOutcome {
    pub changed: bool,
    pub snapshot_packaged: bool,
    pub version: String,
    pub fingerprint: String,
    pub threat_domains: i64,
    pub threat_urls: usize,
    pub threat_ips: usize,
    pub disposable_domains: i64,
    pub malware_hashes: usize,
}

/// Floor a UTC timestamp to the start of its `interval_seconds` wall-clock bucket
/// (e.g. `00:00`, `04:00`, `08:00`, `12:00`, `16:00`, `20:00` UTC when `interval_seconds = 14_400`).
pub fn floor_snapshot_utc_boundary(ts: DateTime<Utc>, interval_seconds: u64) -> DateTime<Utc> {
    let step = (interval_seconds as i64).max(300);
    let slot_epoch = ts.timestamp().div_euclid(step) * step;
    DateTime::<Utc>::from_timestamp(slot_epoch, 0).unwrap_or(ts)
}

/// Evaluate whether a scheduled UTC-aligned snapshot rollup is due at `now`,
/// and return `(is_due, target_boundary_utc)`.
///
/// For `14_400s` (4-hour) intervals, scheduled snapshots cut within `[B, B + 12m)` at
/// `00:00`, `04:00`, `08:00`, `12:00`, `16:00`, and `20:00` UTC so `dgspamguard-data`
/// (`15 */4 * * *` UTC) picks up freshly aligned `vYYYYMMDD.HH00` releases 15 minutes later.
pub fn evaluate_snapshot_boundary(
    now: DateTime<Utc>,
    last_snap_ts: DateTime<Utc>,
    interval_seconds: u64,
) -> (bool, DateTime<Utc>) {
    let step = (interval_seconds as i64).max(300);
    let grace_secs = (step / 12).clamp(60, 720);
    let current_slot = floor_snapshot_utc_boundary(now, interval_seconds);
    let next_slot = current_slot + ChronoDuration::seconds(step);

    if last_snap_ts < current_slot && now < current_slot + ChronoDuration::seconds(grace_secs) {
        (true, current_slot)
    } else {
        (false, next_slot)
    }
}

fn redact_secret(raw: &str, secret: Option<&str>) -> String {
    match secret.filter(|s| !s.is_empty()) {
        Some(sec) => raw.replace(sec, "{REDACTED}"),
        None => raw.to_string(),
    }
}

pub fn feed_requires_abusech_key(spec: &FeedSourceSpec) -> bool {
    spec.source_url.contains(ABUSECH_AUTH_KEY_PLACEHOLDER) || spec.feed_key.starts_with("abusech-")
}

fn validate_url_against_allowlist(
    raw_url: &str,
    allowed_hosts: &HashSet<String>,
) -> DgspamguardResult<Url> {
    let parsed = Url::parse(raw_url)
        .map_err(|e| DgspamguardError::Sync(format!("Invalid outbound URL '{raw_url}': {e}")))?;
    let host = parsed
        .host_str()
        .ok_or_else(|| DgspamguardError::Sync(format!("URL '{raw_url}' missing hostname.")))?
        .to_ascii_lowercase();

    let scheme = parsed.scheme();
    let is_local_test =
        (host == "127.0.0.1" || host == "localhost") && allowed_hosts.contains(&host);
    if scheme != "https" && !(scheme == "http" && is_local_test) {
        return Err(DgspamguardError::Sync(format!(
            "Outbound URL '{raw_url}' rejected: HTTPS is mandatory."
        )));
    }

    if !allowed_hosts.contains(&host) {
        return Err(DgspamguardError::Sync(format!(
            "Outbound host '{host}' is not in dgspamguard_allowed_hosts."
        )));
    }
    Ok(parsed)
}

fn build_http_client(
    timeout_secs: f64,
    allowed_hosts: HashSet<String>,
) -> DgspamguardResult<Client> {
    let hosts_arc = Arc::new(allowed_hosts);
    let redirect_policy = Policy::custom(move |attempt| {
        if attempt.previous().len() >= 5 {
            return attempt.error("Too many HTTP redirects (max 5).");
        }
        let next_url = attempt.url();
        let Some(host) = next_url.host_str().map(|s| s.to_ascii_lowercase()) else {
            return attempt.error("Redirect URL missing hostname.");
        };
        let is_local = (host == "127.0.0.1" || host == "localhost") && hosts_arc.contains(&host);
        if next_url.scheme() != "https" && !(next_url.scheme() == "http" && is_local) {
            return attempt.error("Redirect downgraded from HTTPS.");
        }
        if !hosts_arc.contains(&host) {
            return attempt.error(format!("Redirect target host '{host}' is not allowlisted."));
        }
        attempt.follow()
    });

    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let tls_cfg = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|e| DgspamguardError::Sync(format!("TLS config error: {e}")))?
    .with_root_certificates(root_store)
    .with_no_client_auth();

    Client::builder()
        .use_preconfigured_tls(tls_cfg)
        .redirect(redirect_policy)
        .timeout(Duration::from_secs_f64(timeout_secs.clamp(5.0, 600.0)))
        .connect_timeout(Duration::from_secs(20))
        .build()
        .map_err(|e| DgspamguardError::Sync(format!("HTTP client build error: {e}")))
}

fn compress_for_db_cache(raw: &[u8]) -> Vec<u8> {
    // Keep already-compressed GZIP or ZIP bytes as-is; GZIP plain text feeds to save ~80% DB space
    if (raw.len() >= 2 && raw[0] == 0x1f && raw[1] == 0x8b)
        || (raw.len() >= 4 && &raw[0..4] == b"PK\x03\x04")
    {
        return raw.to_vec();
    }
    let mut enc = GzEncoder::new(Vec::new(), Compression::fast());
    if enc.write_all(raw).is_ok() {
        if let Ok(compressed) = enc.finish() {
            return compressed;
        }
    }
    raw.to_vec()
}

async fn fetch_or_reuse_feed(
    db: &Database,
    client: &Client,
    catalog: &RuntimeCatalog,
    spec: &FeedSourceSpec,
    abusech_key: Option<&str>,
    force_refresh: bool,
) -> DgspamguardResult<(RawFeedPayload, bool)> {
    let now = Utc::now();
    let cached = db.get_cached_feed_payload(&spec.feed_key).await?;

    // Check per-feed native TTL before making any network request
    if !force_refresh {
        if let (Some(last_ts), Some(cached_bytes)) = (spec.last_fetched_at, cached.as_ref()) {
            let age_secs = (now - last_ts).num_seconds();
            if age_secs >= 0 && age_secs < spec.refresh_interval_seconds {
                debug!(
                    feed = %spec.feed_key,
                    age_seconds = age_secs,
                    ttl_seconds = spec.refresh_interval_seconds,
                    "Reusing fresh cached feed payload within TTL"
                );
                return Ok((
                    RawFeedPayload {
                        spec: spec.clone(),
                        raw_bytes: cached_bytes.clone(),
                    },
                    false,
                ));
            }
        }
    }

    let resolved_url = if spec.source_url.contains(ABUSECH_AUTH_KEY_PLACEHOLDER) {
        let key = abusech_key.ok_or_else(|| {
            DgspamguardError::Sync(format!(
                "Feed '{}' requires DGSPAMGUARD_ABUSECH_AUTH_KEY.",
                spec.feed_key
            ))
        })?;
        spec.source_url.replace(ABUSECH_AUTH_KEY_PLACEHOLDER, key)
    } else {
        spec.source_url.clone()
    };

    let url_checked = validate_url_against_allowlist(&resolved_url, &catalog.allowed_source_hosts)
        .map_err(|e| DgspamguardError::Sync(redact_secret(&e.to_string(), abusech_key)))?;
    let ua = format!("dgspamguard/{APP_VERSION} (+https://daviante.org)");
    let mut req = client.get(url_checked).header(USER_AGENT, ua);

    if feed_requires_abusech_key(spec) {
        if let Some(key) = abusech_key {
            req = req.header("Auth-Key", key);
        }
    }

    if !force_refresh && cached.is_some() {
        if let Some(etag) = &spec.etag {
            req = req.header(IF_NONE_MATCH, etag.as_str());
        }
        if let Some(lm) = &spec.last_modified {
            req = req.header(IF_MODIFIED_SINCE, lm.as_str());
        }
    }

    // 5-minute retry backoff timestamp if an upstream feed temporarily fails while we hold cached bytes
    let retry_backoff_ts =
        now - ChronoDuration::seconds((spec.refresh_interval_seconds - 300).max(0));

    let resp = match req.send().await {
        Ok(r) => r,
        Err(err) => {
            let safe_err = redact_secret(&err.to_string(), abusech_key);
            if let Some(fallback_bytes) = cached {
                let _ = db
                    .save_feed_fetch_state(
                        &spec.feed_key,
                        spec.etag.as_deref(),
                        spec.last_modified.as_deref(),
                        retry_backoff_ts,
                        None,
                    )
                    .await;
                warn!(
                    feed = %spec.feed_key,
                    error = %safe_err,
                    "Upstream feed request failed; backing off 5m and reusing cached DB payload"
                );
                return Ok((
                    RawFeedPayload {
                        spec: spec.clone(),
                        raw_bytes: fallback_bytes,
                    },
                    false,
                ));
            }
            return Err(DgspamguardError::Sync(format!(
                "Failed fetching feed '{}' ({}): {safe_err}",
                spec.feed_key, spec.source_url
            )));
        }
    };

    if resp.status() == StatusCode::NOT_MODIFIED {
        if let Some(cached_bytes) = cached {
            let new_etag = resp
                .headers()
                .get(ETAG)
                .and_then(|v| v.to_str().ok())
                .map(String::from)
                .or_else(|| spec.etag.clone());
            let new_lm = resp
                .headers()
                .get(LAST_MODIFIED)
                .and_then(|v| v.to_str().ok())
                .map(String::from)
                .or_else(|| spec.last_modified.clone());
            db.save_feed_fetch_state(
                &spec.feed_key,
                new_etag.as_deref(),
                new_lm.as_deref(),
                now,
                None,
            )
            .await?;
            info!(feed = %spec.feed_key, "Upstream returned 304 Not Modified; reusing cached payload");
            return Ok((
                RawFeedPayload {
                    spec: spec.clone(),
                    raw_bytes: cached_bytes,
                },
                false,
            ));
        }
    }

    if !resp.status().is_success() {
        let status = resp.status();
        if let Some(fallback_bytes) = cached {
            let _ = db
                .save_feed_fetch_state(
                    &spec.feed_key,
                    spec.etag.as_deref(),
                    spec.last_modified.as_deref(),
                    retry_backoff_ts,
                    None,
                )
                .await;
            warn!(
                feed = %spec.feed_key,
                status = %status,
                "Upstream feed returned non-200 status; backing off 5m and reusing cached DB payload"
            );
            return Ok((
                RawFeedPayload {
                    spec: spec.clone(),
                    raw_bytes: fallback_bytes,
                },
                false,
            ));
        }
        return Err(DgspamguardError::Sync(format!(
            "Feed '{}' returned HTTP {status}.",
            spec.feed_key
        )));
    }

    let new_etag = resp
        .headers()
        .get(ETAG)
        .and_then(|v| v.to_str().ok())
        .map(String::from);
    let new_lm = resp
        .headers()
        .get(LAST_MODIFIED)
        .and_then(|v| v.to_str().ok())
        .map(String::from);

    let max_bytes = spec.max_compressed_bytes.max(1024) as usize;
    let mut body = Vec::new();
    let mut stream = resp.bytes_stream();
    while let Some(chunk_res) = stream.next().await {
        let chunk = match chunk_res {
            Ok(c) => c,
            Err(err) => {
                let safe_err = redact_secret(&err.to_string(), abusech_key);
                if let Some(fallback_bytes) = cached {
                    let _ = db
                        .save_feed_fetch_state(
                            &spec.feed_key,
                            spec.etag.as_deref(),
                            spec.last_modified.as_deref(),
                            retry_backoff_ts,
                            None,
                        )
                        .await;
                    warn!(
                        feed = %spec.feed_key,
                        error = %safe_err,
                        "Stream interrupted on feed; backing off 5m and reusing cached DB payload"
                    );
                    return Ok((
                        RawFeedPayload {
                            spec: spec.clone(),
                            raw_bytes: fallback_bytes,
                        },
                        false,
                    ));
                }
                return Err(DgspamguardError::Sync(format!(
                    "Stream read failed on feed '{}': {safe_err}",
                    spec.feed_key
                )));
            }
        };
        if body.len().saturating_add(chunk.len()) > max_bytes {
            return Err(DgspamguardError::Sync(format!(
                "Feed '{}' exceeded download limit of {max_bytes} bytes.",
                spec.feed_key
            )));
        }
        body.extend_from_slice(&chunk);
    }

    let db_cached = compress_for_db_cache(&body);
    let payload_changed = cached.as_deref() != Some(db_cached.as_slice());

    db.save_feed_fetch_state(
        &spec.feed_key,
        new_etag.as_deref(),
        new_lm.as_deref(),
        now,
        if payload_changed {
            Some(&db_cached)
        } else {
            None
        },
    )
    .await?;

    if payload_changed {
        info!(
            feed = %spec.feed_key,
            downloaded_bytes = body.len(),
            stored_bytes = db_cached.len(),
            "Fetched updated upstream threat feed"
        );
    } else {
        info!(
            feed = %spec.feed_key,
            downloaded_bytes = body.len(),
            "Fetched upstream threat feed (payload identical to cached copy)"
        );
    }

    Ok((
        RawFeedPayload {
            spec: spec.clone(),
            raw_bytes: db_cached,
        },
        payload_changed,
    ))
}

pub async fn export_packaged_snapshot_to_dir(
    packaged: &PackagedSnapshot,
    export_dir: &Path,
) -> DgspamguardResult<()> {
    tokio::fs::create_dir_all(export_dir).await?;
    tokio::fs::write(export_dir.join("bundle.tar.gz"), &packaged.bundle_bytes).await?;
    tokio::fs::write(export_dir.join("manifest.json"), &packaged.manifest_json).await?;
    tokio::fs::write(export_dir.join("SHA256SUMS.txt"), &packaged.sha256sums_txt).await?;
    tokio::fs::write(
        export_dir.join("RELEASE_NOTES.md"),
        packaged.release_notes_md.as_bytes(),
    )
    .await?;
    tokio::fs::write(
        export_dir.join("VERSION.txt"),
        format!("{}\n", packaged.version).as_bytes(),
    )
    .await?;
    tokio::fs::write(
        export_dir.join("TITLE.txt"),
        format!("{}\n", packaged.release_title).as_bytes(),
    )
    .await?;
    for (fname, (_, bytes)) in &packaged.dataset_artifacts {
        tokio::fs::write(export_dir.join(fname), bytes).await?;
    }
    Ok(())
}

/// Execute a single serialized upstream sync + compilation + A/B slot activation cycle.
pub async fn sync_once(
    db: &Database,
    settings: &Settings,
    force_refresh: bool,
    export_dir: Option<&Path>,
) -> DgspamguardResult<SyncOutcome> {
    let mutex = db.sync_mutex();
    let _guard = mutex.lock().await;

    db.record_sync_attempt().await?;

    let result: DgspamguardResult<SyncOutcome> = async {
        let sync_started_at = Utc::now();
        let catalog = db.load_runtime_catalog().await?;
        let feeds = db.list_feed_sources().await?;
        let enabled_feeds: Vec<FeedSourceSpec> = feeds.into_iter().filter(|f| f.enabled).collect();
        if enabled_feeds.is_empty() {
            return Err(DgspamguardError::Sync(
                "No enabled feeds in dgspamguard_feed_sources.".to_string(),
            ));
        }

        let client = build_http_client(
            settings.sync_http_timeout_seconds,
            catalog.allowed_source_hosts.clone(),
        )?;

        let abusech_key = settings
            .abusech_auth_key_override
            .as_deref()
            .or(catalog.abusech_auth_key.as_deref())
            .map(str::trim)
            .filter(|s| !s.is_empty());

        let prev_state = db.get_state().await?;
        let active_snap = db.get_active_snapshot_meta().await?;

        let mut payloads = Vec::with_capacity(enabled_feeds.len());
        let mut non_structural_loaded = 0usize;
        let mut any_feed_changed = false;
        for spec in &enabled_feeds {
            if feed_requires_abusech_key(spec) && abusech_key.is_none() {
                debug!(
                    feed = %spec.feed_key,
                    "Skipping authenticated Abuse.ch feed (set DGSPAMGUARD_ABUSECH_AUTH_KEY to enable)"
                );
                continue;
            }
            let is_structural = spec.category == "psl" || spec.category == "allowlist";
            match fetch_or_reuse_feed(db, &client, &catalog, spec, abusech_key, force_refresh).await
            {
                Ok((payload, changed)) => {
                    if !is_structural {
                        non_structural_loaded += 1;
                    }
                    if changed {
                        any_feed_changed = true;
                    }
                    payloads.push(payload);
                }
                Err(err) if !is_structural => {
                    let safe_err = redact_secret(&err.to_string(), abusech_key);
                    warn!(
                        feed = %spec.feed_key,
                        error = %safe_err,
                        "Non-structural feed unavailable with no DB cache; continuing compilation with remaining feeds"
                    );
                }
                Err(err) => return Err(err),
            }
        }
        if non_structural_loaded == 0 {
            return Err(DgspamguardError::Sync(
                "Zero threat or taxonomy feeds succeeded; aborting compilation.".to_string(),
            ));
        }

        let (snap_boundary_due, snap_boundary_ts) = match &active_snap {
            Some((snap_ts, ..)) => evaluate_snapshot_boundary(
                sync_started_at,
                *snap_ts,
                settings.snapshot_interval_seconds,
            ),
            None => (true, sync_started_at),
        };
        let live_ahead_of_snap = match (prev_state.live_fingerprint.as_deref(), &active_snap) {
            (Some(lf), Some((_, sf, ..))) => lf != sf.as_str(),
            _ => true,
        };
        let pending_snapshot_due = force_refresh
            || export_dir.is_some()
            || !prev_state.initial_bootstrapped
            || active_snap.is_none()
            || (snap_boundary_due && live_ahead_of_snap);

        // Zero-CPU fast skip when due feed(s) returned 304 / identical bytes and no 4h snapshot is pending
        if !force_refresh
            && export_dir.is_none()
            && prev_state.initial_bootstrapped
            && !any_feed_changed
            && !pending_snapshot_due
        {
            db.record_sync_no_change().await?;
            db.refresh_in_memory_meta().await?;
            let ver = prev_state
                .active_version
                .unwrap_or_else(|| "unchanged".to_string());
            let (td, tu, ti, dd, mh) = active_snap
                .as_ref()
                .map(|(_, _, td, tu, ti, dd, mh)| {
                    (*td, *tu as usize, *ti as usize, *dd, *mh as usize)
                })
                .unwrap_or((0, 0, 0, 0, 0));
            info!(
                version = %ver,
                "All due feeds returned unchanged payloads; skipping compilation and slot swap"
            );
            return Ok(SyncOutcome {
                changed: false,
                snapshot_packaged: false,
                version: ver,
                fingerprint: prev_state.live_fingerprint.unwrap_or_default(),
                threat_domains: td,
                threat_urls: tu,
                threat_ips: ti,
                disposable_domains: dd,
                malware_hashes: mh,
            });
        }

        let compiled = compile_threat_feeds(&payloads, &catalog)?;
        let fingerprint = compute_compiled_fingerprint(&compiled);

        let differs_from_snap = active_snap
            .as_ref()
            .map(|(_, sf, ..)| sf.as_str() != fingerprint.as_str())
            .unwrap_or(true);
        let should_package_snapshot = force_refresh
            || export_dir.is_some()
            || !prev_state.initial_bootstrapped
            || active_snap.is_none()
            || (snap_boundary_due && differs_from_snap);

        if !should_package_snapshot {
            let ver = prev_state
                .active_version
                .unwrap_or_else(|| "unchanged".to_string());

            if prev_state.live_fingerprint.as_deref() == Some(fingerprint.as_str()) {
                db.record_sync_no_change().await?;
                db.refresh_in_memory_meta().await?;
                info!(version = %ver, "Compiled threat fingerprint unchanged; skipping slot swap");
                return Ok(SyncOutcome {
                    changed: false,
                    snapshot_packaged: false,
                    version: ver,
                    fingerprint,
                    threat_domains: compiled.threat_domain_count,
                    threat_urls: compiled.urls.len(),
                    threat_ips: compiled.ips.len(),
                    disposable_domains: compiled.disposable_domain_count,
                    malware_hashes: compiled.hashes.len(),
                });
            }

            db.activate_live_compiled_slot(&compiled, &fingerprint)
                .await?;
            info!(
                active_snapshot = %ver,
                threat_domains = compiled.threat_domain_count,
                threat_urls = compiled.urls.len(),
                threat_ips = compiled.ips.len(),
                disposable_domains = compiled.disposable_domain_count,
                malware_hashes = compiled.hashes.len(),
                "Swapped live A/B intelligence slot from fast feed refresh (next 4h UTC snapshot boundary deferred)"
            );
            return Ok(SyncOutcome {
                changed: true,
                snapshot_packaged: false,
                version: ver,
                fingerprint,
                threat_domains: compiled.threat_domain_count,
                threat_urls: compiled.urls.len(),
                threat_ips: compiled.ips.len(),
                disposable_domains: compiled.disposable_domain_count,
                malware_hashes: compiled.hashes.len(),
            });
        }

        let is_scheduled_boundary = !force_refresh
            && export_dir.is_none()
            && prev_state.initial_bootstrapped
            && active_snap.is_some()
            && snap_boundary_due;
        let version_ts = if is_scheduled_boundary {
            snap_boundary_ts
        } else {
            sync_started_at
        };
        let packaged_at = Utc::now().max(version_ts);
        let version = db
            .allocate_next_version(&catalog.version_prefix, version_ts)
            .await?;
        let packaged = package_snapshot(
            compiled,
            &version,
            &catalog.release_title_template,
            packaged_at,
        )?;

        if let Some(dir) = export_dir {
            export_packaged_snapshot_to_dir(&packaged, dir).await?;
        }

        let outcome = SyncOutcome {
            changed: true,
            snapshot_packaged: true,
            version: packaged.version.clone(),
            fingerprint: fingerprint.clone(),
            threat_domains: packaged.compiled.threat_domain_count,
            threat_urls: packaged.compiled.urls.len(),
            threat_ips: packaged.compiled.ips.len(),
            disposable_domains: packaged.compiled.disposable_domain_count,
            malware_hashes: packaged.compiled.hashes.len(),
        };

        db.activate_packaged_snapshot(&packaged, &fingerprint, catalog.retention_days)
            .await?;

        info!(
            version = %outcome.version,
            threat_domains = outcome.threat_domains,
            threat_urls = outcome.threat_urls,
            threat_ips = outcome.threat_ips,
            disposable_domains = outcome.disposable_domains,
            malware_hashes = outcome.malware_hashes,
            "Activated new DGSPAMGUARD threat intelligence snapshot"
        );
        Ok(outcome)
    }
    .await;

    if let Err(err) = &result {
        let safe = redact_secret(
            &err.to_string(),
            settings.abusech_auth_key_override.as_deref(),
        );
        let _ = db.record_sync_error(&safe).await;
    }
    result
}

/// Bootstrap PostgreSQL from a `bundle.tar.gz` release URL or `file://` path.
pub async fn bootstrap_from_bundle(
    db: &Database,
    settings: &Settings,
    bundle_source_override: Option<&str>,
) -> DgspamguardResult<String> {
    let mutex = db.sync_mutex();
    let _guard = mutex.lock().await;

    let catalog = db.load_runtime_catalog().await?;
    let source = bundle_source_override
        .map(String::from)
        .unwrap_or_else(|| catalog.bootstrap_bundle_url.clone());

    let bundle_bytes = if let Some(local_path) = source.strip_prefix("file://") {
        tokio::fs::read(local_path).await?
    } else if Path::new(&source).exists() {
        tokio::fs::read(&source).await?
    } else {
        let checked = validate_url_against_allowlist(&source, &catalog.allowed_source_hosts)?;
        let client = build_http_client(
            settings.sync_http_timeout_seconds,
            catalog.allowed_source_hosts.clone(),
        )?;
        let ua = format!("dgspamguard/{APP_VERSION} (+https://daviante.org)");
        let resp = client
            .get(checked)
            .header(USER_AGENT, ua)
            .send()
            .await
            .map_err(|e| DgspamguardError::Sync(format!("Bootstrap download failed: {e}")))?;
        if !resp.status().is_success() {
            return Err(DgspamguardError::Sync(format!(
                "Bootstrap bundle URL '{source}' returned HTTP {}.",
                resp.status()
            )));
        }
        let max_bundle = 192 * 1024 * 1024usize;
        let mut buf = Vec::new();
        let mut stream = resp.bytes_stream();
        while let Some(chunk_res) = stream.next().await {
            let chunk = chunk_res
                .map_err(|e| DgspamguardError::Sync(format!("Bootstrap stream read error: {e}")))?;
            if buf.len().saturating_add(chunk.len()) > max_bundle {
                return Err(DgspamguardError::Sync(
                    "Bootstrap bundle exceeded 192 MB download cap.".to_string(),
                ));
            }
            buf.extend_from_slice(&chunk);
        }
        buf
    };

    let packaged = unpack_bootstrap_bundle(&bundle_bytes)?;
    let fingerprint = compute_compiled_fingerprint(&packaged.compiled);
    let version = packaged.version.clone();
    db.activate_packaged_snapshot(&packaged, &fingerprint, catalog.retention_days)
        .await?;
    info!(version = %version, "Bootstrapped DGSPAMGUARD database from release bundle");
    Ok(version)
}

/// Ensure initial state is loaded on cold start: try `dgspamguard-data` release bundle first;
/// if unavailable (e.g. Day-1 empty data repo), seamlessly compile directly from upstream feeds.
pub async fn ensure_bootstrapped_on_startup(
    db: &Database,
    settings: &Settings,
) -> DgspamguardResult<()> {
    let st = db.get_state().await?;
    if st.initial_bootstrapped && (st.active_slot == "a" || st.active_slot == "b") {
        info!(
            slot = %st.active_slot,
            version = ?st.active_version,
            "Existing DGSPAMGUARD active dataset detected on startup"
        );
        return Ok(());
    }

    info!("Cold-start database detected; attempting fast bootstrap from release bundle...");
    match bootstrap_from_bundle(db, settings, None).await {
        Ok(ver) => {
            info!(version = %ver, "Cold-start bootstrap from bundle succeeded");
            Ok(())
        }
        Err(bundle_err) => {
            warn!(
                error = %bundle_err,
                "Release bundle unavailable; falling back to live upstream feed compilation"
            );
            let outcome = sync_once(db, settings, true, None).await?;
            info!(version = %outcome.version, "Cold-start live upstream compilation succeeded");
            Ok(())
        }
    }
}

/// Spawn the per-feed deadline scheduler.
/// Computes `min(last_fetched_at + refresh_interval_seconds)` across all enabled feeds (15m..24h),
/// wakes up with jitter as soon as the earliest feed or 4-hour snapshot rollup is due, and re-checks
/// PostgreSQL state at least every 60s so runtime CLI changes (`dgspamguard feed set-ttl`) take effect promptly.
pub fn spawn_sync_scheduler(db: Database, settings: Settings) {
    tokio::spawn(async move {
        // Brief startup settle so HTTP listener binds cleanly before first deadline evaluation
        tokio::time::sleep(Duration::from_secs(10)).await;

        loop {
            let _ = db.refresh_in_memory_meta().await;

            let check_res: DgspamguardResult<(Vec<String>, bool, Option<u64>)> = async {
                let catalog = db.load_runtime_catalog().await?;
                let feeds = db.list_feed_sources().await?;
                let state = db.get_state().await?;
                let active_snap = db.get_active_snapshot_meta().await?;

                let has_abusech_key = settings
                    .abusech_auth_key_override
                    .as_deref()
                    .or(catalog.abusech_auth_key.as_deref())
                    .map(str::trim)
                    .is_some_and(|s| !s.is_empty());

                let now = Utc::now();
                let mut due_feeds = Vec::new();
                let mut earliest_due: Option<chrono::DateTime<Utc>> = None;

                for f in feeds {
                    if !f.enabled || (feed_requires_abusech_key(&f) && !has_abusech_key) {
                        continue;
                    }
                    let ttl_secs = f.refresh_interval_seconds.max(60);
                    let due_at = match f.last_fetched_at {
                        Some(ts) => ts + ChronoDuration::seconds(ttl_secs),
                        None => now,
                    };
                    if due_at <= now {
                        due_feeds.push(f.feed_key);
                    } else {
                        earliest_due = Some(match earliest_due {
                            Some(cur) => cur.min(due_at),
                            None => due_at,
                        });
                    }
                }

                let mut snapshot_rollup_due = false;
                if state.initial_bootstrapped {
                    match (state.live_fingerprint.as_deref(), &active_snap) {
                        (Some(lf), Some((snap_ts, sf, ..))) if lf != sf.as_str() => {
                            let (is_due, snap_due_at) = evaluate_snapshot_boundary(
                                now,
                                *snap_ts,
                                settings.snapshot_interval_seconds,
                            );
                            if is_due {
                                snapshot_rollup_due = true;
                            } else {
                                earliest_due = Some(match earliest_due {
                                    Some(cur) => cur.min(snap_due_at),
                                    None => snap_due_at,
                                });
                            }
                        }
                        (_, None) => {
                            snapshot_rollup_due = true;
                        }
                        _ => {}
                    }
                }

                let secs_until_next =
                    earliest_due.map(|due| (due - now).num_seconds().max(1) as u64);

                Ok((due_feeds, snapshot_rollup_due, secs_until_next))
            }
            .await;

            match check_res {
                Ok((due_feeds, snapshot_rollup_due, secs_until_next)) => {
                    if !due_feeds.is_empty() || snapshot_rollup_due {
                        info!(
                            due_feed_count = due_feeds.len(),
                            due_feeds = %due_feeds.join(","),
                            snapshot_rollup_due = snapshot_rollup_due,
                            "Per-feed deadline scheduler running sync for due feeds"
                        );
                        if let Err(err) = sync_once(&db, &settings, false, None).await {
                            let safe_err = redact_secret(
                                &err.to_string(),
                                settings.abusech_auth_key_override.as_deref(),
                            );
                            error!(error = %safe_err, "Scheduled DGSPAMGUARD per-feed sync failed");
                            tokio::time::sleep(Duration::from_secs(30)).await;
                        } else {
                            tokio::time::sleep(Duration::from_secs(5)).await;
                        }
                    } else {
                        let jitter = (rand::random::<u64>() % 6) + 1;
                        let sleep_secs = secs_until_next
                            .map(|s| s.saturating_add(jitter))
                            .unwrap_or(60)
                            .min(60);
                        tokio::time::sleep(Duration::from_secs(sleep_secs)).await;
                    }
                }
                Err(err) => {
                    error!(error = %err, "Per-feed scheduler state check failed; retrying in 30s");
                    tokio::time::sleep(Duration::from_secs(30)).await;
                }
            }
        }
    });
}
