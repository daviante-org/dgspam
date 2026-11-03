use crate::config::Settings;
use crate::db::Database;
use crate::http::{build_router, AppState};
use crate::sync::{
    bootstrap_from_bundle, ensure_bootstrapped_on_startup, feed_requires_abusech_key,
    spawn_sync_scheduler, sync_once,
};
use crate::types::{DgspamguardResult, APP_VERSION};
use chrono::Utc;
use clap::{Parser, Subcommand};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;
use tokio::net::TcpListener;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(
    name = "dgspamguard",
    version = APP_VERSION,
    about = "Self-hosted domain, URL, email, file-hash threat intelligence & mail rule compiler engine by Daviante."
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Start the DGSPAMGUARD HTTP intelligence server and background sync scheduler
    Serve,
    /// Run a single upstream feed sync, compile datasets, and activate the new A/B slot
    Sync {
        /// Ignore per-feed TTLs and ETag caches; force re-fetch and snapshot generation
        #[arg(long)]
        force: bool,
        /// Optional directory to export bundle.tar.gz, manifest.json, SHA256SUMS.txt, and all 9 .gz artifacts
        #[arg(long)]
        export_dir: Option<PathBuf>,
    },
    /// Bootstrap PostgreSQL directly from a release bundle URL or local bundle.tar.gz path
    Bootstrap {
        /// Optional override URL or local path to bundle.tar.gz
        #[arg(long)]
        bundle: Option<String>,
    },
    /// Print current database slot, active snapshot version, and sync timestamps
    Status,
    /// Manage upstream threat intelligence feeds
    Feed {
        #[command(subcommand)]
        action: FeedCommands,
    },
    /// Manage domain allowlist and multi-tenant shared-hosting roots
    Allowlist {
        #[command(subcommand)]
        action: AllowlistCommands,
    },
    /// Inspect or update runtime configuration entries in PostgreSQL
    Config {
        #[command(subcommand)]
        action: ConfigCommands,
    },
    /// Container liveness probe (queries local /healthz/live)
    Healthcheck,
}

#[derive(Debug, Subcommand)]
pub enum FeedCommands {
    /// List all configured upstream feeds and their TTL/fetch status
    List,
    /// Enable a feed by key
    Enable { feed_key: String },
    /// Disable a feed by key
    Disable { feed_key: String },
    /// Update a feed's HTTPS URL (and allowlist its hostname)
    SetUrl { feed_key: String, url: String },
    /// Update a feed's independent refresh interval TTL in seconds (300..=604800)
    SetTtl { feed_key: String, seconds: i64 },
}

#[derive(Debug, Subcommand)]
pub enum AllowlistCommands {
    /// List all allowlisted trusted & shared-hosting domains
    List,
    /// Add or update an allowlist domain
    Add {
        domain: String,
        #[arg(long, default_value = "trusted")]
        kind: String,
        #[arg(long, default_value = "Added via CLI")]
        notes: String,
    },
    /// Remove a domain from the allowlist
    Remove { domain: String },
}

#[derive(Debug, Subcommand)]
pub enum ConfigCommands {
    /// Display all runtime configuration keys stored in PostgreSQL
    Show,
    /// Set a runtime configuration key to a JSON or string value
    Set { key: String, value: String },
}

fn init_tracing(default_level: &str) {
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_level));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .compact()
        .try_init();
}

pub async fn run_from_env() -> i32 {
    let cli = Cli::parse();
    match execute_cli(cli).await {
        Ok(()) => 0,
        Err(err) => {
            eprintln!("Error: {err}");
            1
        }
    }
}

pub async fn execute_cli(cli: Cli) -> DgspamguardResult<()> {
    if matches!(cli.command, Commands::Healthcheck) {
        let port = std::env::var("DGSPAMGUARD_PORT")
            .ok()
            .and_then(|v| v.parse::<u16>().ok())
            .unwrap_or(8091);
        let url = format!("http://127.0.0.1:{port}/healthz/live");
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(4))
            .build()
            .map_err(|e| crate::types::DgspamguardError::Sync(e.to_string()))?;
        let resp = client.get(&url).send().await.map_err(|e| {
            crate::types::DgspamguardError::Unavailable(format!("Healthcheck failed: {e}"))
        })?;
        if resp.status().is_success() {
            return Ok(());
        }
        return Err(crate::types::DgspamguardError::Unavailable(format!(
            "Healthcheck returned HTTP {}",
            resp.status()
        )));
    }

    let settings = Settings::from_env()?;
    init_tracing(&settings.log_level);
    let db = Database::connect(&settings).await?;

    match cli.command {
        Commands::Serve => {
            if settings.bootstrap_on_startup {
                let db_bg = db.clone();
                let settings_bg = settings.clone();
                // Run initial bootstrap asynchronously if DB isn't bootstrapped yet so /healthz/live responds immediately
                let st = db.get_state().await?;
                if st.initial_bootstrapped {
                    if settings.sync_scheduler_enabled {
                        spawn_sync_scheduler(db.clone(), settings.clone());
                    }
                } else {
                    tokio::spawn(async move {
                        if let Err(err) = ensure_bootstrapped_on_startup(&db_bg, &settings_bg).await
                        {
                            error!(error = %err, "Initial startup bootstrap failed");
                        }
                        if settings_bg.sync_scheduler_enabled {
                            spawn_sync_scheduler(db_bg, settings_bg);
                        }
                    });
                }
            } else if settings.sync_scheduler_enabled {
                spawn_sync_scheduler(db.clone(), settings.clone());
            }

            let catalog = db.load_runtime_catalog().await?;
            let state = AppState::new(db, settings.clone(), catalog.rate_limit_per_minute);
            let app = build_router(state);

            let bind_str = format!("{}:{}", settings.host, settings.port);
            let listener = TcpListener::bind(&bind_str).await?;
            info!(
                listen = %bind_str,
                version = APP_VERSION,
                "DGSPAMGUARD Threat & Mail Intelligence server listening"
            );

            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .with_graceful_shutdown(shutdown_signal())
            .await?;
        }
        Commands::Sync { force, export_dir } => {
            let outcome = sync_once(&db, &settings, force, export_dir.as_deref()).await?;
            println!(
                "version={} changed={} snapshot_packaged={} threat_domains={} threat_urls={} threat_ips={} disposable_domains={} malware_hashes={}",
                outcome.version,
                outcome.changed,
                outcome.snapshot_packaged,
                outcome.threat_domains,
                outcome.threat_urls,
                outcome.threat_ips,
                outcome.disposable_domains,
                outcome.malware_hashes
            );
        }
        Commands::Bootstrap { bundle } => {
            let ver = bootstrap_from_bundle(&db, &settings, bundle.as_deref()).await?;
            println!("Bootstrapped active snapshot: {ver}");
        }
        Commands::Status => {
            let st = db.get_state().await?;
            println!("Service Version      : {APP_VERSION}");
            println!("Initial Bootstrapped : {}", st.initial_bootstrapped);
            println!(
                "Active Slot          : {}",
                if st.active_slot.is_empty() {
                    "(none)"
                } else {
                    &st.active_slot
                }
            );
            println!(
                "Active Snapshot      : {}",
                st.active_version.as_deref().unwrap_or("(none)")
            );
            println!(
                "Live Updated At      : {}",
                st.live_updated_at
                    .map(|t| t.to_rfc3339())
                    .unwrap_or_else(|| "(never)".to_string())
            );
            println!(
                "Last Sync Success    : {}",
                st.last_sync_success_at
                    .map(|t| t.to_rfc3339())
                    .unwrap_or_else(|| "(never)".to_string())
            );
            if let Some(err) = st.last_sync_error {
                println!("Last Sync Error      : {err}");
            }
        }
        Commands::Feed { action } => match action {
            FeedCommands::List => {
                let catalog = db.load_runtime_catalog().await?;
                let has_abusech_key = settings
                    .abusech_auth_key_override
                    .as_deref()
                    .or(catalog.abusech_auth_key.as_deref())
                    .map(str::trim)
                    .is_some_and(|s| !s.is_empty());
                let feeds = db.list_feed_sources().await?;
                let now = Utc::now();
                println!(
                    "{:<28} {:<15} {:<8} {:<8} {:<20} NEXT_DUE",
                    "FEED_KEY", "CATEGORY", "TTL", "ENABLED", "LAST_FETCHED"
                );
                for f in feeds {
                    let ttl_str = format_human_ttl(f.refresh_interval_seconds);
                    let lf = f
                        .last_fetched_at
                        .map(|t| t.format("%Y-%m-%d %H:%M UTC").to_string())
                        .unwrap_or_else(|| "never".to_string());
                    let next_due = if !f.enabled {
                        "disabled".to_string()
                    } else if feed_requires_abusech_key(&f) && !has_abusech_key {
                        "skipped (no key)".to_string()
                    } else {
                        match f.last_fetched_at {
                            None => "due now".to_string(),
                            Some(ts) => {
                                let rem = (ts
                                    + chrono::Duration::seconds(f.refresh_interval_seconds)
                                    - now)
                                    .num_seconds();
                                if rem <= 0 {
                                    "due now".to_string()
                                } else {
                                    format!("in {}", format_human_ttl(rem))
                                }
                            }
                        }
                    };
                    println!(
                        "{:<28} {:<15} {:<8} {:<8} {:<20} {}",
                        f.feed_key, f.category, ttl_str, f.enabled, lf, next_due
                    );
                }
            }
            FeedCommands::Enable { feed_key } => {
                db.set_feed_enabled(&feed_key, true).await?;
                println!("Enabled feed '{feed_key}'.");
            }
            FeedCommands::Disable { feed_key } => {
                db.set_feed_enabled(&feed_key, false).await?;
                println!("Disabled feed '{feed_key}'.");
            }
            FeedCommands::SetUrl { feed_key, url } => {
                db.set_feed_url(&feed_key, &url).await?;
                println!("Updated feed '{feed_key}' URL to '{url}'.");
            }
            FeedCommands::SetTtl { feed_key, seconds } => {
                db.set_feed_ttl(&feed_key, seconds).await?;
                println!(
                    "Updated feed '{feed_key}' refresh TTL to {seconds}s ({}).",
                    format_human_ttl(seconds)
                );
            }
        },
        Commands::Allowlist { action } => match action {
            AllowlistCommands::List => {
                let cat = db.load_runtime_catalog().await?;
                println!("{:<34} {:<16} NOTES", "DOMAIN", "KIND");
                for r in cat.allowlist {
                    println!("{:<34} {:<16} {}", r.domain, r.kind, r.notes);
                }
            }
            AllowlistCommands::Add {
                domain,
                kind,
                notes,
            } => {
                let clean = db.upsert_allowlist(&domain, &kind, &notes).await?;
                println!("Upserted allowlist domain '{clean}' ({kind}).");
            }
            AllowlistCommands::Remove { domain } => {
                db.remove_allowlist(&domain).await?;
                println!("Removed '{domain}' from allowlist.");
            }
        },
        Commands::Config { action } => match action {
            ConfigCommands::Show => {
                let entries = db.list_config_entries().await?;
                for (k, v, desc) in entries {
                    let k_low = k.to_ascii_lowercase();
                    let display_val = if k_low.contains("key")
                        || k_low.contains("secret")
                        || k_low.contains("token")
                        || k_low.contains("password")
                    {
                        if v.is_null() || v.as_str().is_some_and(|s| s.trim().is_empty()) {
                            "null".to_string()
                        } else {
                            "\"***REDACTED***\"".to_string()
                        }
                    } else {
                        serde_json::to_string(&v).unwrap_or_default()
                    };
                    println!("{k} = {display_val}  # {desc}");
                }
            }
            ConfigCommands::Set { key, value } => {
                let stored = db.set_config_json(&key, &value).await?;
                let k_low = key.to_ascii_lowercase();
                let display_val = if k_low.contains("key")
                    || k_low.contains("secret")
                    || k_low.contains("token")
                    || k_low.contains("password")
                {
                    "\"***REDACTED***\"".to_string()
                } else {
                    serde_json::to_string(&stored).unwrap_or_default()
                };
                println!("Updated {key} = {display_val}");
            }
        },
        Commands::Healthcheck => unreachable!(),
    }

    Ok(())
}

fn format_human_ttl(secs: i64) -> String {
    if secs <= 0 {
        return "0s".to_string();
    }
    if secs % 86_400 == 0 {
        return format!("{}d", secs / 86_400);
    }
    if secs % 3_600 == 0 {
        return format!("{}h", secs / 3_600);
    }
    if secs % 60 == 0 {
        return format!("{}m", secs / 60);
    }
    let hours = secs / 3_600;
    let mins = (secs % 3_600) / 60;
    if hours > 0 {
        format!("{hours}h {mins}m")
    } else if mins > 0 {
        format!("{mins}m {}s", secs % 60)
    } else {
        format!("{secs}s")
    }
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    #[cfg(unix)]
    let terminate = async {
        if let Ok(mut sigterm) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            sigterm.recv().await;
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
    info!("Shutdown signal received; draining active HTTP connections");
}
