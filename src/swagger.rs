//! Daviante-branded Home Portal, Swagger UI v5 wrapper, brand assets, and OpenAPI 3.1 schema provider.

use crate::types::APP_VERSION;
use once_cell::sync::Lazy;
use serde_json::Value;
use std::path::Path;

pub const BRAND_ORG_NAME: &str = "Daviante";
pub const BRAND_ORG_URL: &str = "https://daviante.org";
pub const BRAND_CONTACT_EMAIL: &str = "code@daviante.org";
pub const BRAND_API_PRODUCTION_URL: &str = "https://dgspamguard.daviante.org";
pub const BRAND_REPO_URL: &str = "https://github.com/daviante-org/dgspamguard";
pub const BRAND_DATA_REPO_URL: &str = "https://github.com/daviante-org/dgspamguard-data";
pub const BRAND_TERMS_URL: &str =
    "https://github.com/daviante-org/dgspamguard-data/blob/main/docs/TERMS.md";
pub const BRAND_LICENSE_URL: &str = "https://www.apache.org/licenses/LICENSE-2.0";

pub const SWAGGER_UI_CSS_URL: &str =
    "https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui.css";
pub const SWAGGER_UI_JS_URL: &str =
    "https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui-bundle.js";

pub const DEFAULT_SWAGGER_TITLE: &str = "DGSPAMGUARD Threat & Mail Intelligence API — Daviante";
pub const DEFAULT_HOME_TITLE: &str =
    "DGSPAMGUARD — Domain, URL & Mail Threat Intelligence by Daviante";

pub const ALLOWED_BRAND_ASSETS: &[(&str, &str)] = &[
    ("logo.svg", "image/svg+xml"),
    ("logo-dark.svg", "image/svg+xml"),
    ("favicon.svg", "image/svg+xml"),
];

pub const PUBLIC_OPENAPI_PATHS: &[(&str, &[&str])] = &[
    ("/healthz/live", &["get"]),
    ("/healthz/ready", &["get"]),
    ("/v1/domain/{domain}", &["get"]),
    ("/v1/url/check", &["post"]),
    ("/v1/ip/{ip}", &["get"]),
    ("/v1/hash/{sha256}", &["get"]),
    ("/v1/check/batch", &["post"]),
    ("/v1/snapshots", &["get"]),
    ("/v1/snapshots/latest", &["get"]),
    ("/v1/snapshots/{version}", &["get"]),
    ("/v1/snapshots/{version}/bundle.tar.gz", &["get"]),
    ("/v1/snapshots/{version}/files/{filename}", &["get"]),
];

const EMBEDDED_LOGO_SVG: &[u8] = include_bytes!("../assets/logo.svg");
const EMBEDDED_LOGO_DARK_SVG: &[u8] = include_bytes!("../assets/logo-dark.svg");
const EMBEDDED_FAVICON_SVG: &[u8] = include_bytes!("../assets/favicon.svg");

const OPENAPI_YAML: &str = include_str!("../openapi.yaml");

const INLINE_FAVICON_DATA_URI: &str = concat!(
    "data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 64 64'%3E",
    "%3Cdefs%3E",
    "%3ClinearGradient id='fb' x1='0%25' y1='0%25' x2='100%25' y2='100%25'%3E",
    "%3Cstop offset='0%25' stop-color='%23F43F5E'/%3E",
    "%3Cstop offset='55%25' stop-color='%23E11D48'/%3E",
    "%3Cstop offset='100%25' stop-color='%239F1239'/%3E%3C/linearGradient%3E",
    "%3ClinearGradient id='fl' x1='0%25' y1='0%25' x2='100%25' y2='100%25'%3E",
    "%3Cstop offset='0%25' stop-color='%23FFFFFF'/%3E",
    "%3Cstop offset='100%25' stop-color='%23FFE4E6'/%3E%3C/linearGradient%3E",
    "%3ClinearGradient id='fr' x1='0%25' y1='0%25' x2='100%25' y2='100%25'%3E",
    "%3Cstop offset='0%25' stop-color='%23FECDD3'/%3E",
    "%3Cstop offset='100%25' stop-color='%23FDA4AF'/%3E%3C/linearGradient%3E",
    "%3C/defs%3E",
    "%3Crect width='64' height='64' rx='16' fill='url(%23fb)'/%3E",
    "%3Ccircle cx='32' cy='29' r='22.5' fill='none' stroke='%23FDA4AF' stroke-opacity='.35' stroke-width='1.8' stroke-dasharray='6 3'/%3E",
    "%3Cpath d='M11 14L32 14L32 54L26.8 50.2L26.8 34L11 17.8Z' fill='url(%23fl)'/%3E",
    "%3Cpath d='M53 14L32 14L32 54L37.2 50.2L37.2 34L53 17.8Z' fill='url(%23fr)'/%3E",
    "%3Cpath d='M18.5 18.5L45.5 18.5L35 29.5L29 29.5Z' fill='%23881337'/%3E",
    "%3Cline x1='9' y1='23.5' x2='55' y2='23.5' stroke='%23FFFFFF' stroke-width='2.4' stroke-linecap='round' stroke-opacity='.92'/%3E",
    "%3Ccircle cx='32' cy='23.5' r='3.4' fill='%23FFFFFF'/%3E",
    "%3Ccircle cx='32' cy='45.5' r='2' fill='%23881337'/%3E%3C/svg%3E"
);

static OPENAPI_SCHEMA: Lazy<Value> = Lazy::new(|| {
    let raw_yaml = std::fs::read_to_string("/app/openapi.yaml")
        .ok()
        .unwrap_or_else(|| OPENAPI_YAML.to_string());
    let mut val: Value = serde_saphyr::from_str(&raw_yaml)
        .expect("Embedded openapi.yaml must be valid OpenAPI 3.1 YAML");
    if let Some(info) = val.get_mut("info").and_then(Value::as_object_mut) {
        info.insert(
            "version".to_string(),
            Value::String(APP_VERSION.to_string()),
        );
    }
    val
});

fn escape_html(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for ch in raw.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            _ => out.push(ch),
        }
    }
    out
}

/// Resolve a whitelisted brand SVG asset from `assets_dir` on disk, falling back to embedded SVG bytes.
pub fn resolve_brand_asset(assets_dir: &Path, asset_name: &str) -> Option<(Vec<u8>, &'static str)> {
    let &(_, content_type) = ALLOWED_BRAND_ASSETS
        .iter()
        .find(|&&(name, _)| name == asset_name)?;

    if let Ok(base_dir) = assets_dir.canonicalize() {
        let candidate = base_dir.join(asset_name);
        if let Ok(resolved) = candidate.canonicalize() {
            if resolved.parent() == Some(base_dir.as_path()) && resolved.is_file() {
                if let Ok(bytes) = std::fs::read(&resolved) {
                    return Some((bytes, content_type));
                }
            }
        }
    }

    let embedded = match asset_name {
        "logo.svg" => EMBEDDED_LOGO_SVG,
        "logo-dark.svg" => EMBEDDED_LOGO_DARK_SVG,
        "favicon.svg" => EMBEDDED_FAVICON_SVG,
        _ => return None,
    };
    Some((embedded.to_vec(), content_type))
}

/// Return the Daviante-branded OpenAPI 3.1 specification as a JSON `Value`.
pub fn build_branded_openapi_schema() -> Value {
    OPENAPI_SCHEMA.clone()
}

/// Render a Daviante-branded HTML document hosting Swagger UI v5 (`GET /docs`).
pub fn build_branded_swagger_html(title: &str, openapi_url: &str) -> String {
    let escaped_title = escape_html(title);
    let escaped_ver = escape_html(APP_VERSION);
    let openapi_url_json =
        serde_json::to_string(openapi_url).unwrap_or_else(|_| "\"/openapi.json\"".to_string());

    SWAGGER_HTML_TEMPLATE
        .replace("__ESCAPED_TITLE__", &escaped_title)
        .replace("__SWAGGER_UI_CSS_URL__", SWAGGER_UI_CSS_URL)
        .replace("__ESCAPED_VER__", &escaped_ver)
        .replace("__BRAND_ORG_URL__", BRAND_ORG_URL)
        .replace("__BRAND_DATA_REPO_URL__", BRAND_DATA_REPO_URL)
        .replace("__BRAND_REPO_URL__", BRAND_REPO_URL)
        .replace("__BRAND_CONTACT_EMAIL__", BRAND_CONTACT_EMAIL)
        .replace("__BRAND_ORG_NAME__", BRAND_ORG_NAME)
        .replace("__SWAGGER_UI_JS_URL__", SWAGGER_UI_JS_URL)
        .replace("__OPENAPI_URL_JSON__", &openapi_url_json)
}

/// Render a zero-CDN, CSP-strict interactive 5-layer threat & mail intelligence portal at `GET /`.
pub fn build_branded_home_html(version: &str, swagger_enabled: bool) -> String {
    let escaped_title = escape_html(DEFAULT_HOME_TITLE);
    let escaped_ver = escape_html(version);

    let docs_nav_links = if swagger_enabled {
        concat!(
            r#"<a href="/docs">API Reference (/docs)</a>"#,
            r#"<a href="/openapi.json" target="_blank" rel="noopener noreferrer">openapi.json</a>"#
        )
    } else {
        ""
    };

    HOME_HTML_TEMPLATE
        .replace("__ESCAPED_TITLE__", &escaped_title)
        .replace("__INLINE_FAVICON_DATA_URI__", INLINE_FAVICON_DATA_URI)
        .replace("__ESCAPED_VER__", &escaped_ver)
        .replace("__DOCS_NAV_LINKS__", docs_nav_links)
        .replace("__BRAND_DATA_REPO_URL__", BRAND_DATA_REPO_URL)
        .replace("__BRAND_REPO_URL__", BRAND_REPO_URL)
        .replace("__BRAND_ORG_URL__", BRAND_ORG_URL)
        .replace("__BRAND_ORG_NAME__", BRAND_ORG_NAME)
        .replace("__BRAND_CONTACT_EMAIL__", BRAND_CONTACT_EMAIL)
}

const SWAGGER_HTML_TEMPLATE: &str = r#####"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <!-- Declare light and dark theme support early to prevent FOUC on branded chrome -->
  <meta name="color-scheme" content="light dark">
  <script>
    try {
      var savedScheme = localStorage.getItem("dgspamguard-color-scheme");
      if (savedScheme === "light" || savedScheme === "dark") {
        document.querySelector('meta[name="color-scheme"]').content = savedScheme;
      }
    } catch (_e) {}
  </script>
  <title>__ESCAPED_TITLE__</title>
  <link rel="icon" type="image/svg+xml" href="/docs/assets/favicon.svg">
  <link rel="stylesheet" href="__SWAGGER_UI_CSS_URL__">
  <style>
    :root {
      /* Daviante Light & Dark Brand Tokens */
      --dg-surface-light: #f6f8fa;
      --dg-surface-dark: #0d1117;
      --dg-header-light: #ffffff;
      --dg-header-dark: #161b22;
      --dg-border-light: #d0d7de;
      --dg-border-dark: #30363d;
      --dg-text-light: #0f172a;
      --dg-text-dark: #f0f6fc;
      --dg-muted-light: #475569;
      --dg-muted-dark: #8b949e;
      --dg-accent-light: #be123c;
      --dg-accent-dark: #fb7185;

      --dg-surface: var(--dg-surface-light);
      --dg-header: var(--dg-header-light);
      --dg-border: var(--dg-border-light);
      --dg-text: var(--dg-text-light);
      --dg-muted: var(--dg-muted-light);
      --dg-accent: var(--dg-accent-light);

      color-scheme: light dark;
      accent-color: var(--dg-accent);
    }

    @media (prefers-color-scheme: dark) {
      :root {
        --dg-surface: var(--dg-surface-dark);
        --dg-header: var(--dg-header-dark);
        --dg-border: var(--dg-border-dark);
        --dg-text: var(--dg-text-dark);
        --dg-muted: var(--dg-muted-dark);
        --dg-accent: var(--dg-accent-dark);
      }
    }

    :root:has(> head > meta[name="color-scheme"][content="dark"]) {
      color-scheme: dark;
      --dg-surface: var(--dg-surface-dark);
      --dg-header: var(--dg-header-dark);
      --dg-border: var(--dg-border-dark);
      --dg-text: var(--dg-text-dark);
      --dg-muted: var(--dg-muted-dark);
      --dg-accent: var(--dg-accent-dark);
    }

    :root:has(> head > meta[name="color-scheme"][content="light"]) {
      color-scheme: light;
      --dg-surface: var(--dg-surface-light);
      --dg-header: var(--dg-header-light);
      --dg-border: var(--dg-border-light);
      --dg-text: var(--dg-text-light);
      --dg-muted: var(--dg-muted-light);
      --dg-accent: var(--dg-accent-light);
    }

    @supports (color: light-dark(white, black)) {
      :root {
        --dg-surface: light-dark(var(--dg-surface-light), var(--dg-surface-dark));
        --dg-header: light-dark(var(--dg-header-light), var(--dg-header-dark));
        --dg-border: light-dark(var(--dg-border-light), var(--dg-border-dark));
        --dg-text: light-dark(var(--dg-text-light), var(--dg-text-dark));
        --dg-muted: light-dark(var(--dg-muted-light), var(--dg-muted-dark));
        --dg-accent: light-dark(var(--dg-accent-light), var(--dg-accent-dark));
      }
    }

    * {
      box-sizing: border-box;
    }

    body {
      margin: 0;
      padding: 0;
      background-color: var(--dg-surface);
      color: var(--dg-text);
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
    }

    /* Daviante Top Navigation & Brand Bar */
    .dg-topbar {
      background-color: var(--dg-header);
      border-bottom: 1px solid var(--dg-border);
      padding: 12px 24px;
      position: sticky;
      top: 0;
      z-index: 100;
    }

    .dg-topbar-inner {
      max-width: 1420px;
      margin: 0 auto;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 16px;
      flex-wrap: wrap;
    }

    .dg-brand {
      display: flex;
      align-items: center;
      gap: 14px;
      text-decoration: none;
      color: var(--dg-text);
    }

    .dg-brand picture,
    .dg-brand img {
      display: block;
      height: 32px;
      width: auto;
    }

    .dg-sep {
      width: 1px;
      height: 16px;
      background-color: var(--dg-border);
    }

    .dg-meta-label {
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      font-size: 12px;
      color: var(--dg-muted);
    }

    .dg-nav {
      display: flex;
      align-items: center;
      gap: 18px;
      flex-wrap: wrap;
      font-size: 13px;
      font-weight: 500;
    }

    .dg-nav a {
      color: var(--dg-muted);
      text-decoration: none;
      transition: color 0.15s ease;
    }

    .dg-nav a:hover {
      color: var(--dg-text);
      text-decoration: underline;
      text-underline-offset: 3px;
    }

    /* Swagger UI container explicitly scoped to light color-scheme with solid background
       so Swagger UI v5's light-only styles and native form inputs remain high-contrast. */
    .dg-swagger-surface {
      color-scheme: only light;
      accent-color: #e11d48;
      background-color: #ffffff;
      color: #0f172a;
      min-height: calc(100vh - 124px);
      padding: 8px 0 36px;
    }

    /* Hide default upstream Swagger topbar if rendered and apply Daviante Crimson accents */
    .swagger-ui .topbar {
      display: none;
    }

    .swagger-ui .info .title small.version-stamp {
      background-color: #e11d48;
    }

    .swagger-ui .btn.authorize {
      color: #be123c;
      border-color: #e11d48;
    }

    .swagger-ui .btn.authorize svg {
      fill: #be123c;
    }

    .swagger-ui .opblock.opblock-post .opblock-summary-method {
      background: #0f766e;
    }

    /* Daviante Footer */
    .dg-footer {
      background-color: var(--dg-header);
      border-top: 1px solid var(--dg-border);
      padding: 14px 24px;
      font-size: 12.5px;
      color: var(--dg-muted);
    }

    .dg-footer-inner {
      max-width: 1420px;
      margin: 0 auto;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
      flex-wrap: wrap;
    }

    .dg-footer a {
      color: var(--dg-accent);
      text-decoration: none;
    }

    .dg-footer a:hover {
      text-decoration: underline;
    }
  </style>
</head>
<body>
  <header class="dg-topbar">
    <div class="dg-topbar-inner">
      <a class="dg-brand" href="/">
        <picture id="dg-swagger-logo">
          <source media="(prefers-color-scheme: dark)" srcset="/docs/assets/logo-dark.svg">
          <source media="(prefers-color-scheme: light)" srcset="/docs/assets/logo.svg">
          <img src="/docs/assets/logo.svg" alt="dgspamguard" width="160" height="32">
        </picture>
        <span class="dg-sep" aria-hidden="true"></span>
        <span class="dg-meta-label">v__ESCAPED_VER__ &middot; OpenAPI 3.1 Reference</span>
      </a>
      <nav class="dg-nav" aria-label="Daviante documentation links">
        <a href="/">Threat Inspector</a>
        <a href="/openapi.json" target="_blank" rel="noopener noreferrer">openapi.json</a>
        <a href="__BRAND_DATA_REPO_URL__" target="_blank" rel="noopener noreferrer">Snapshots (dgspamguard-data)</a>
        <a href="__BRAND_REPO_URL__" target="_blank" rel="noopener noreferrer">GitHub</a>
        <a href="__BRAND_ORG_URL__" target="_blank" rel="noopener noreferrer">Daviante</a>
      </nav>
    </div>
  </header>

  <main class="dg-swagger-surface">
    <div id="swagger-ui"></div>
  </main>

  <footer class="dg-footer">
    <div class="dg-footer-inner">
      <span>Maintained by <a href="__BRAND_ORG_URL__" target="_blank" rel="noopener noreferrer">__BRAND_ORG_NAME__</a> &mdash; Compiled from abuse.ch, Spamhaus DROP, Phishing.Database, Tranco &amp; Open Mail Intelligence Feeds.</span>
      <span>Apache-2.0 License &middot; <a href="mailto:__BRAND_CONTACT_EMAIL__">__BRAND_CONTACT_EMAIL__</a></span>
    </div>
  </footer>

  <script src="__SWAGGER_UI_JS_URL__" crossorigin="anonymous"></script>
  <script>
    window.addEventListener("DOMContentLoaded", function () {
      try {
        var pref = localStorage.getItem("dgspamguard-color-scheme");
        if (pref === "dark" || pref === "light") {
          var pic = document.getElementById("dg-swagger-logo");
          if (pic) {
            var targetSrc = pref === "dark" ? "/docs/assets/logo-dark.svg" : "/docs/assets/logo.svg";
            pic.querySelectorAll("source").forEach(function (s) { s.srcset = targetSrc; });
            var img = pic.querySelector("img");
            if (img) img.src = targetSrc;
          }
        }
      } catch (_e) {}

      window.ui = SwaggerUIBundle({
        url: __OPENAPI_URL_JSON__,
        dom_id: "#swagger-ui",
        deepLinking: true,
        displayRequestDuration: true,
        filter: true,
        persistAuthorization: true,
        tryItOutEnabled: true,
        presets: [
          SwaggerUIBundle.presets.apis,
          SwaggerUIBundle.SwaggerUIStandalonePreset
        ].filter(Boolean),
        layout: "BaseLayout"
      });
    });
  </script>
</body>
</html>
"#####;

const HOME_HTML_TEMPLATE: &str = r#####"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <!-- Declare light and dark theme support early and restore user override before first paint -->
  <meta name="color-scheme" content="light dark">
  <script>
    try {
      var savedScheme = localStorage.getItem("dgspamguard-color-scheme");
      if (savedScheme === "light" || savedScheme === "dark") {
        document.querySelector('meta[name="color-scheme"]').content = savedScheme;
      }
    } catch (_e) {}
  </script>
  <title>__ESCAPED_TITLE__</title>
  <link rel="icon" type="image/svg+xml" href="__INLINE_FAVICON_DATA_URI__">
  <style>
    :root {
      /* Calibrated Light & Dark Architectural Slate Tokens (matched to Daviante logo.svg / logo-dark.svg) */
      --dg-bg-light: #f6f8fa;
      --dg-bg-dark: #0d1117;
      --dg-paper-light: #ffffff;
      --dg-paper-dark: #161b22;
      --dg-subtle-light: #f0f3f6;
      --dg-subtle-dark: #1c2128;
      --dg-border-light: #d0d7de;
      --dg-border-dark: #30363d;
      --dg-border-strong-light: #8c959f;
      --dg-border-strong-dark: #6e7681;
      --dg-text-light: #0f172a;
      --dg-text-dark: #f0f6fc;
      --dg-muted-light: #475569;
      --dg-muted-dark: #8b949e;
      --dg-logo-sub-light: #334155;
      --dg-logo-sub-dark: #cbd5e1;
      --dg-dot-light: #e11d48;
      --dg-dot-dark: #fb7185;
      --dg-accent-light: #be123c;
      --dg-accent-dark: #fb7185;
      --dg-btn-bg: #e11d48;
      --dg-btn-bg-hover: #be123c;

      /* 4-Tier Semantic Status Palette:
         1. ok   (Emerald)    -> Clean indicator, Trusted Apex Allowlist
         2. info (Steel Blue) -> Free Webmail Provider, Multi-Tenant Shared Host
         3. warn (Amber)      -> Disposable MX, URL Shortener/Redirector, Elevated TLD
         4. err  (Crimson)    -> Phishing, Malware, Botnet C2, Hijacked CIDR, Validation Error */
      --dg-ok-light: #047857;
      --dg-ok-dark: #3fb950;
      --dg-ok-bg-light: #ecfdf5;
      --dg-ok-bg-dark: rgba(46, 160, 67, 0.14);
      --dg-ok-border-light: #6ee7b7;
      --dg-ok-border-dark: rgba(63, 185, 80, 0.40);

      --dg-info-light: #0369a1;
      --dg-info-dark: #58a6ff;
      --dg-info-bg-light: #f0f9ff;
      --dg-info-bg-dark: rgba(56, 139, 253, 0.14);
      --dg-info-border-light: #7dd3fc;
      --dg-info-border-dark: rgba(88, 166, 255, 0.40);

      --dg-warn-light: #b45309;
      --dg-warn-dark: #d29922;
      --dg-warn-bg-light: #fffbeb;
      --dg-warn-bg-dark: rgba(187, 128, 9, 0.15);
      --dg-warn-border-light: #fcd34d;
      --dg-warn-border-dark: rgba(210, 153, 34, 0.42);

      --dg-err-light: #be123c;
      --dg-err-dark: #f85149;
      --dg-err-bg-light: #fff1f2;
      --dg-err-bg-dark: rgba(248, 81, 73, 0.15);
      --dg-err-border-light: #fda4af;
      --dg-err-border-dark: rgba(248, 81, 73, 0.45);

      /* Pre-light-dark() fallback defaults */
      --dg-bg: var(--dg-bg-light);
      --dg-paper: var(--dg-paper-light);
      --dg-subtle: var(--dg-subtle-light);
      --dg-border: var(--dg-border-light);
      --dg-border-strong: var(--dg-border-strong-light);
      --dg-text: var(--dg-text-light);
      --dg-muted: var(--dg-muted-light);
      --dg-logo-sub: var(--dg-logo-sub-light);
      --dg-dot: var(--dg-dot-light);
      --dg-accent: var(--dg-accent-light);
      --dg-ok: var(--dg-ok-light);
      --dg-ok-bg: var(--dg-ok-bg-light);
      --dg-ok-border: var(--dg-ok-border-light);
      --dg-info: var(--dg-info-light);
      --dg-info-bg: var(--dg-info-bg-light);
      --dg-info-border: var(--dg-info-border-light);
      --dg-warn: var(--dg-warn-light);
      --dg-warn-bg: var(--dg-warn-bg-light);
      --dg-warn-border: var(--dg-warn-border-light);
      --dg-err: var(--dg-err-light);
      --dg-err-bg: var(--dg-err-bg-light);
      --dg-err-border: var(--dg-err-border-light);

      color-scheme: light dark;
      accent-color: var(--dg-accent);
    }

    @media (prefers-color-scheme: dark) {
      :root {
        --dg-bg: var(--dg-bg-dark);
        --dg-paper: var(--dg-paper-dark);
        --dg-subtle: var(--dg-subtle-dark);
        --dg-border: var(--dg-border-dark);
        --dg-border-strong: var(--dg-border-strong-dark);
        --dg-text: var(--dg-text-dark);
        --dg-muted: var(--dg-muted-dark);
        --dg-logo-sub: var(--dg-logo-sub-dark);
        --dg-dot: var(--dg-dot-dark);
        --dg-accent: var(--dg-accent-dark);
        --dg-ok: var(--dg-ok-dark);
        --dg-ok-bg: var(--dg-ok-bg-dark);
        --dg-ok-border: var(--dg-ok-border-dark);
        --dg-info: var(--dg-info-dark);
        --dg-info-bg: var(--dg-info-bg-dark);
        --dg-info-border: var(--dg-info-border-dark);
        --dg-warn: var(--dg-warn-dark);
        --dg-warn-bg: var(--dg-warn-bg-dark);
        --dg-warn-border: var(--dg-warn-border-dark);
        --dg-err: var(--dg-err-dark);
        --dg-err-bg: var(--dg-err-bg-dark);
        --dg-err-border: var(--dg-err-border-dark);
      }
    }

    :root:has(> head > meta[name="color-scheme"][content="dark"]) {
      color-scheme: dark;
      --dg-bg: var(--dg-bg-dark);
      --dg-paper: var(--dg-paper-dark);
      --dg-subtle: var(--dg-subtle-dark);
      --dg-border: var(--dg-border-dark);
      --dg-border-strong: var(--dg-border-strong-dark);
      --dg-text: var(--dg-text-dark);
      --dg-muted: var(--dg-muted-dark);
      --dg-logo-sub: var(--dg-logo-sub-dark);
      --dg-dot: var(--dg-dot-dark);
      --dg-accent: var(--dg-accent-dark);
      --dg-ok: var(--dg-ok-dark);
      --dg-ok-bg: var(--dg-ok-bg-dark);
      --dg-ok-border: var(--dg-ok-border-dark);
      --dg-info: var(--dg-info-dark);
      --dg-info-bg: var(--dg-info-bg-dark);
      --dg-info-border: var(--dg-info-border-dark);
      --dg-warn: var(--dg-warn-dark);
      --dg-warn-bg: var(--dg-warn-bg-dark);
      --dg-warn-border: var(--dg-warn-border-dark);
      --dg-err: var(--dg-err-dark);
      --dg-err-bg: var(--dg-err-bg-dark);
      --dg-err-border: var(--dg-err-border-dark);
    }

    :root:has(> head > meta[name="color-scheme"][content="light"]) {
      color-scheme: light;
      --dg-bg: var(--dg-bg-light);
      --dg-paper: var(--dg-paper-light);
      --dg-subtle: var(--dg-subtle-light);
      --dg-border: var(--dg-border-light);
      --dg-border-strong: var(--dg-border-strong-light);
      --dg-text: var(--dg-text-light);
      --dg-muted: var(--dg-muted-light);
      --dg-logo-sub: var(--dg-logo-sub-light);
      --dg-dot: var(--dg-dot-light);
      --dg-accent: var(--dg-accent-light);
      --dg-ok: var(--dg-ok-light);
      --dg-ok-bg: var(--dg-ok-bg-light);
      --dg-ok-border: var(--dg-ok-border-light);
      --dg-info: var(--dg-info-light);
      --dg-info-bg: var(--dg-info-bg-light);
      --dg-info-border: var(--dg-info-border-light);
      --dg-warn: var(--dg-warn-light);
      --dg-warn-bg: var(--dg-warn-bg-light);
      --dg-warn-border: var(--dg-warn-border-light);
      --dg-err: var(--dg-err-light);
      --dg-err-bg: var(--dg-err-bg-light);
      --dg-err-border: var(--dg-err-border-light);
    }

    @supports (color: light-dark(white, black)) {
      :root {
        --dg-bg: light-dark(var(--dg-bg-light), var(--dg-bg-dark));
        --dg-paper: light-dark(var(--dg-paper-light), var(--dg-paper-dark));
        --dg-subtle: light-dark(var(--dg-subtle-light), var(--dg-subtle-dark));
        --dg-border: light-dark(var(--dg-border-light), var(--dg-border-dark));
        --dg-border-strong: light-dark(var(--dg-border-strong-light), var(--dg-border-strong-dark));
        --dg-text: light-dark(var(--dg-text-light), var(--dg-text-dark));
        --dg-muted: light-dark(var(--dg-muted-light), var(--dg-muted-dark));
        --dg-logo-sub: light-dark(var(--dg-logo-sub-light), var(--dg-logo-sub-dark));
        --dg-dot: light-dark(var(--dg-dot-light), var(--dg-dot-dark));
        --dg-accent: light-dark(var(--dg-accent-light), var(--dg-accent-dark));
        --dg-ok: light-dark(var(--dg-ok-light), var(--dg-ok-dark));
        --dg-ok-bg: light-dark(var(--dg-ok-bg-light), var(--dg-ok-bg-dark));
        --dg-ok-border: light-dark(var(--dg-ok-border-light), var(--dg-ok-border-dark));
        --dg-info: light-dark(var(--dg-info-light), var(--dg-info-dark));
        --dg-info-bg: light-dark(var(--dg-info-bg-light), var(--dg-info-bg-dark));
        --dg-info-border: light-dark(var(--dg-info-border-light), var(--dg-info-border-dark));
        --dg-warn: light-dark(var(--dg-warn-light), var(--dg-warn-dark));
        --dg-warn-bg: light-dark(var(--dg-warn-bg-light), var(--dg-warn-bg-dark));
        --dg-warn-border: light-dark(var(--dg-warn-border-light), var(--dg-warn-border-dark));
        --dg-err: light-dark(var(--dg-err-light), var(--dg-err-dark));
        --dg-err-bg: light-dark(var(--dg-err-bg-light), var(--dg-err-bg-dark));
        --dg-err-border: light-dark(var(--dg-err-border-light), var(--dg-err-border-dark));
      }
    }

    @media (forced-colors: active) {
      :root {
        --dg-border: CanvasText;
        --dg-border-strong: CanvasText;
      }
    }

    * {
      box-sizing: border-box;
    }

    body {
      margin: 0;
      min-block-size: 100dvh;
      display: flex;
      flex-direction: column;
      background-color: var(--dg-bg);
      color: var(--dg-text);
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      line-height: 1.5;
    }

    .dg-mono {
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      font-variant-numeric: tabular-nums;
    }

    a:focus-visible,
    button:focus-visible,
    input:focus-visible {
      outline: 2px solid var(--dg-accent);
      outline-offset: 2px;
    }

    /* Top Utility Bar */
    .dg-topbar {
      background-color: var(--dg-paper);
      border-block-end: 1px solid var(--dg-border);
      padding: 0.75rem 1.5rem;
      position: sticky;
      inset-block-start: 0;
      z-index: 50;
    }

    .dg-container {
      max-inline-size: 1140px;
      margin-inline: auto;
      inline-size: 100%;
    }

    .dg-topbar-inner {
      display: flex;
      align-items: safe center;
      justify-content: space-between;
      gap: 1rem;
      flex-wrap: wrap;
    }

    .dg-brand-group {
      display: flex;
      align-items: center;
      gap: 0.875rem;
      flex-wrap: wrap;
    }

    .dg-brand {
      display: inline-flex;
      align-items: center;
      text-decoration: none;
      color: var(--dg-text);
    }

    .dg-brand svg {
      block-size: 32px;
      inline-size: auto;
      display: block;
    }

    .dg-sep {
      inline-size: 1px;
      block-size: 16px;
      background-color: var(--dg-border);
    }

    .dg-brand-subtitle {
      font-size: 0.75rem;
      color: var(--dg-muted);
    }

    .dg-nav {
      display: flex;
      align-items: safe center;
      gap: 1.125rem;
      flex-wrap: wrap;
      font-size: 0.8125rem;
      font-weight: 500;
    }

    .dg-nav a {
      color: var(--dg-muted);
      text-decoration: none;
    }

    .dg-nav a:hover {
      color: var(--dg-text);
      text-decoration: underline;
      text-underline-offset: 3px;
    }

    .dg-theme-btn {
      display: inline-flex;
      align-items: center;
      gap: 0.375rem;
      background-color: var(--dg-subtle);
      color: var(--dg-text);
      border: 1px solid var(--dg-border);
      border-radius: 4px;
      padding: 0.25rem 0.6rem;
      font-size: 0.75rem;
      font-weight: 600;
      cursor: pointer;
    }

    .dg-theme-btn:hover {
      border-color: var(--dg-border-strong);
    }

    .dg-theme-btn svg {
      inline-size: 14px;
      block-size: 14px;
      display: block;
    }

    /* Main Workspace */
    main {
      flex: 1;
      padding: 1.5rem 1.5rem 2.25rem;
    }

    /* Command-Bar Query Form */
    .dg-query-header {
      display: flex;
      align-items: baseline;
      justify-content: space-between;
      flex-wrap: wrap;
      gap: 0.5rem;
      margin-block-end: 0.375rem;
    }

    .dg-field-label {
      font-size: 0.8125rem;
      font-weight: 600;
      color: var(--dg-text);
    }

    .dg-hint {
      font-size: 0.75rem;
      color: var(--dg-muted);
    }

    .dg-command-row {
      display: flex;
      flex-wrap: wrap;
      gap: 0.5rem;
      align-items: flex-start;
    }

    .dg-input-col {
      flex: 1 1 300px;
      min-inline-size: 0;
    }

    .dg-input-shell {
      display: flex;
      align-items: center;
      background-color: var(--dg-paper);
      border: 1px solid var(--dg-border-strong);
      border-radius: 4px;
      padding-inline: 0.75rem;
      min-block-size: 42px;
      transition: border-color 0.12s ease;
    }

    .dg-input-shell:focus-within {
      border-color: var(--dg-accent);
      outline: 1px solid var(--dg-accent);
    }

    .dg-prompt-prefix {
      font-size: 0.75rem;
      font-weight: 600;
      color: var(--dg-muted);
      margin-inline-end: 0.625rem;
      user-select: none;
      white-space: nowrap;
    }

    .dg-q-input {
      flex: 1;
      min-inline-size: 0;
      background: transparent;
      border: none;
      color: var(--dg-text);
      font-size: 0.9375rem;
      padding-block: 0.5rem;
    }

    .dg-q-input:focus {
      outline: none;
    }

    .dg-kbd {
      font-size: 0.75rem;
      line-height: 1.2;
      color: var(--dg-muted);
      border: 1px solid var(--dg-border);
      background-color: var(--dg-subtle);
      padding: 0.1rem 0.4rem;
      border-radius: 3px;
      margin-inline-start: 0.5rem;
      user-select: none;
    }

    /* Post-interaction validation states */
    .dg-input-shell:has(.dg-q-input:user-invalid),
    .dg-input-shell:has(.dg-q-input.user-invalid-fallback) {
      border-color: var(--dg-err);
      background-color: var(--dg-err-bg);
    }

    .dg-input-shell:has(.dg-q-input:user-valid),
    .dg-input-shell:has(.dg-q-input.user-valid-fallback) {
      border-color: var(--dg-ok);
    }

    .dg-error-msg {
      display: none;
      margin-block-start: 0.375rem;
      font-size: 0.78rem;
      font-weight: 500;
      color: var(--dg-err);
    }

    .dg-input-col:has(.dg-q-input:user-invalid) .dg-error-msg,
    .dg-input-col:has(.dg-q-input.user-invalid-fallback) .dg-error-msg {
      display: block;
    }

    .dg-btn {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      min-block-size: 42px;
      padding: 0 1.1rem;
      border-radius: 4px;
      font-size: 0.8125rem;
      font-weight: 600;
      cursor: pointer;
      border: 1px solid transparent;
      white-space: nowrap;
    }

    .dg-btn-primary {
      background-color: var(--dg-btn-bg);
      color: #ffffff;
    }

    .dg-btn-primary:hover {
      background-color: var(--dg-btn-bg-hover);
    }

    .dg-btn-primary:disabled {
      opacity: 0.65;
      cursor: wait;
    }

    .dg-btn-secondary {
      background-color: var(--dg-paper);
      color: var(--dg-text);
      border-color: var(--dg-border-strong);
    }

    .dg-btn-secondary:hover {
      background-color: var(--dg-subtle);
    }

    @media (pointer: coarse) {
      .dg-input-shell,
      .dg-btn {
        min-block-size: 48px;
      }
    }

    /* Quiet Monospace Presets */
    .dg-presets {
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      gap: 0.875rem;
      margin-block: 0.625rem 1.25rem;
      font-size: 0.75rem;
      color: var(--dg-muted);
    }

    .dg-preset-btn {
      background: none;
      border: none;
      padding: 0;
      color: var(--dg-text);
      font-family: inherit;
      font-size: inherit;
      text-decoration: underline;
      text-decoration-color: var(--dg-border-strong);
      text-underline-offset: 3px;
      cursor: pointer;
    }

    .dg-preset-btn:hover {
      color: var(--dg-accent);
      text-decoration-color: var(--dg-accent);
    }

    /* Square Technical Tags (Zero Rounded Pill Soup) */
    .dg-tag {
      display: inline-flex;
      align-items: center;
      gap: 0.35rem;
      font-size: 0.75rem;
      font-weight: 600;
      line-height: 1.3;
      padding: 0.15rem 0.5rem;
      border-radius: 3px;
      border: 1px solid var(--dg-border);
      background-color: var(--dg-subtle);
      color: var(--dg-text);
      white-space: nowrap;
    }

    .dg-tag-ok {
      background-color: var(--dg-ok-bg);
      border-color: var(--dg-ok-border);
      color: var(--dg-ok);
    }

    .dg-tag-info {
      background-color: var(--dg-info-bg);
      border-color: var(--dg-info-border);
      color: var(--dg-info);
    }

    .dg-tag-warn {
      background-color: var(--dg-warn-bg);
      border-color: var(--dg-warn-border);
      color: var(--dg-warn);
    }

    .dg-tag-err {
      background-color: var(--dg-err-bg);
      border-color: var(--dg-err-border);
      color: var(--dg-err);
    }

    /* Unified Registry Ledger Sheet */
    .dg-ledger {
      background-color: var(--dg-paper);
      border: 1px solid var(--dg-border);
      border-radius: 4px;
      overflow: clip;
    }

    .dg-ledger-head {
      padding: 1rem 1.25rem;
      background-color: var(--dg-subtle);
      display: flex;
      flex-wrap: wrap;
      align-items: baseline;
      justify-content: space-between;
      gap: 0.75rem;
    }

    .dg-headline-left {
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      gap: 0.75rem;
      min-inline-size: 0;
    }

    .dg-subject-title {
      font-size: clamp(1.2rem, 2.2vw, 1.45rem);
      font-weight: 700;
      letter-spacing: -0.02em;
      word-break: break-all;
    }

    .dg-summary-line {
      font-size: 0.84375rem;
      color: var(--dg-muted);
    }

    .dg-headline-right {
      font-size: 0.75rem;
      color: var(--dg-muted);
      display: flex;
      align-items: center;
      gap: 0.625rem;
    }

    .dg-latency {
      color: var(--dg-text);
      font-weight: 600;
    }

    /* 3-Column Specification Hairline Grid */
    .dg-ledger-cols {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(290px, 1fr));
    }

    .dg-ledger-col {
      padding: 1.125rem 1.25rem;
      border-block-start: 1px solid var(--dg-border);
      min-inline-size: 0;
    }

    @media (min-width: 960px) {
      .dg-ledger-cols {
        grid-template-columns: repeat(3, minmax(0, 1fr));
      }
      .dg-ledger-col + .dg-ledger-col {
        border-inline-start: 1px solid var(--dg-border);
      }
    }

    .dg-col-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 0.5rem;
      margin-block-end: 0.875rem;
    }

    .dg-col-index {
      font-size: 0.75rem;
      font-weight: 700;
      letter-spacing: 0.03em;
      color: var(--dg-muted);
    }

    .dg-kv {
      display: grid;
      grid-template-columns: 112px minmax(0, 1fr);
      row-gap: 0.55rem;
      column-gap: 0.75rem;
      font-size: 0.84375rem;
      margin: 0;
    }

    .dg-kv dt {
      color: var(--dg-muted);
      font-weight: 400;
    }

    .dg-kv dd {
      margin: 0;
      font-weight: 500;
      min-inline-size: 0;
      overflow-wrap: anywhere;
    }

    /* 6-Cell Posture & Mail Signal Matrix */
    .dg-signal-matrix {
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 0.375rem;
      margin-block-end: 0.875rem;
    }

    .dg-sig-cell {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 0.4rem;
      padding: 0.3rem 0.5rem;
      border: 1px solid var(--dg-border);
      border-radius: 3px;
      font-size: 0.75rem;
      color: var(--dg-muted);
      background: transparent;
    }

    .dg-sig-label {
      display: inline-flex;
      align-items: center;
      gap: 0.4rem;
      white-space: nowrap;
    }

    .dg-sig-dot {
      inline-size: 7px;
      block-size: 7px;
      border-radius: 1px;
      border: 1px solid var(--dg-border-strong);
      background-color: transparent;
      flex-shrink: 0;
    }

    .dg-sig-state {
      font-weight: 600;
    }

    .dg-sig-cell.is-ok {
      background-color: var(--dg-ok-bg);
      border-color: var(--dg-ok-border);
      color: var(--dg-text);
    }
    .dg-sig-cell.is-ok .dg-sig-dot {
      background-color: var(--dg-ok);
      border-color: var(--dg-ok);
    }
    .dg-sig-cell.is-ok .dg-sig-state {
      color: var(--dg-ok);
    }

    .dg-sig-cell.is-info {
      background-color: var(--dg-info-bg);
      border-color: var(--dg-info-border);
      color: var(--dg-text);
    }
    .dg-sig-cell.is-info .dg-sig-dot {
      background-color: var(--dg-info);
      border-color: var(--dg-info);
    }
    .dg-sig-cell.is-info .dg-sig-state {
      color: var(--dg-info);
    }

    .dg-sig-cell.is-warn {
      background-color: var(--dg-warn-bg);
      border-color: var(--dg-warn-border);
      color: var(--dg-text);
    }
    .dg-sig-cell.is-warn .dg-sig-dot {
      background-color: var(--dg-warn);
      border-color: var(--dg-warn);
    }
    .dg-sig-cell.is-warn .dg-sig-state {
      color: var(--dg-warn);
    }

    .dg-sig-cell.is-err {
      background-color: var(--dg-err-bg);
      border-color: var(--dg-err-border);
      color: var(--dg-text);
    }
    .dg-sig-cell.is-err .dg-sig-dot {
      background-color: var(--dg-err);
      border-color: var(--dg-err);
    }
    .dg-sig-cell.is-err .dg-sig-state {
      color: var(--dg-err);
    }

    /* Integrated Wire Drawer */
    .dg-drawer {
      border-block-start: 1px solid var(--dg-border);
    }

    .dg-drawer-bar {
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      justify-content: space-between;
      gap: 0.5rem;
      padding: 0.5rem 1rem;
      background-color: var(--dg-subtle);
      border-block-end: 1px solid var(--dg-border);
    }

    .dg-tabs {
      display: flex;
      flex-wrap: wrap;
      gap: 0.25rem;
    }

    .dg-tab {
      background: transparent;
      border: 1px solid transparent;
      color: var(--dg-muted);
      padding: 0.25rem 0.65rem;
      border-radius: 3px;
      font-size: 0.75rem;
      font-weight: 600;
      cursor: pointer;
    }

    .dg-tab:hover {
      color: var(--dg-text);
    }

    .dg-tab[aria-selected="true"] {
      background-color: var(--dg-paper);
      border-color: var(--dg-border-strong);
      color: var(--dg-text);
    }

    .dg-copy-btn {
      background-color: var(--dg-paper);
      color: var(--dg-text);
      border: 1px solid var(--dg-border);
      border-radius: 3px;
      padding: 0.25rem 0.65rem;
      font-size: 0.75rem;
      font-weight: 600;
      cursor: pointer;
    }

    .dg-copy-btn:hover {
      border-color: var(--dg-border-strong);
    }

    /* Adaptive IDE Wire Output — crisp #ffffff in Light Mode, #0b0e14 in Dark Mode */
    pre.dg-pre {
      background-color: #ffffff;
      color: var(--dg-text);
      margin: 0;
      padding: 0.9rem 1.25rem;
      font-size: 0.8125rem;
      line-height: 1.55;
      overflow-x: auto;
      max-block-size: 300px;
      overflow-y: auto;
      scrollbar-gutter: stable;
    }

    /* IDE Syntax Highlighting — CSS Custom Highlight API (zero DOM overhead) + fallback tokens */
    ::highlight(dg-hl-key) { color: #0550ae; }
    ::highlight(dg-hl-str) { color: #116329; }
    ::highlight(dg-hl-num) { color: #953800; }
    ::highlight(dg-hl-kw) { color: #8250df; }
    ::highlight(dg-hl-flag) { color: #cf222e; }
    ::highlight(dg-hl-url) { color: #0969da; text-decoration: underline; text-decoration-color: rgba(9, 105, 218, 0.35); }
    ::highlight(dg-hl-punc) { color: #57606a; }
    ::highlight(dg-hl-comment) { color: #57606a; }

    .dg-tok-key { color: #0550ae; }
    .dg-tok-str { color: #116329; }
    .dg-tok-num { color: #953800; }
    .dg-tok-kw { color: #8250df; }
    .dg-tok-flag { color: #cf222e; }
    .dg-tok-url { color: #0969da; text-decoration: underline; text-decoration-color: rgba(9, 105, 218, 0.35); }
    .dg-tok-punc { color: #57606a; }
    .dg-tok-comment { color: #57606a; font-style: italic; }

    @media (prefers-color-scheme: dark) {
      pre.dg-pre { background-color: #0b0e14; }
      ::highlight(dg-hl-key) { color: #79c0ff; }
      ::highlight(dg-hl-str) { color: #7ee787; }
      ::highlight(dg-hl-num) { color: #ffa657; }
      ::highlight(dg-hl-kw) { color: #d2a8ff; }
      ::highlight(dg-hl-flag) { color: #ff7b72; }
      ::highlight(dg-hl-url) { color: #a5d6ff; text-decoration-color: rgba(165, 214, 255, 0.35); }
      ::highlight(dg-hl-punc) { color: #8b949e; }
      ::highlight(dg-hl-comment) { color: #8b949e; }
      .dg-tok-key { color: #79c0ff; }
      .dg-tok-str { color: #7ee787; }
      .dg-tok-num { color: #ffa657; }
      .dg-tok-kw { color: #d2a8ff; }
      .dg-tok-flag { color: #ff7b72; }
      .dg-tok-url { color: #a5d6ff; text-decoration-color: rgba(165, 214, 255, 0.35); }
      .dg-tok-punc { color: #8b949e; }
      .dg-tok-comment { color: #8b949e; }
    }

    :root:has(> head > meta[name="color-scheme"][content="dark"]) pre.dg-pre { background-color: #0b0e14; }
    :root:has(> head > meta[name="color-scheme"][content="dark"]) ::highlight(dg-hl-key) { color: #79c0ff; }
    :root:has(> head > meta[name="color-scheme"][content="dark"]) ::highlight(dg-hl-str) { color: #7ee787; }
    :root:has(> head > meta[name="color-scheme"][content="dark"]) ::highlight(dg-hl-num) { color: #ffa657; }
    :root:has(> head > meta[name="color-scheme"][content="dark"]) ::highlight(dg-hl-kw) { color: #d2a8ff; }
    :root:has(> head > meta[name="color-scheme"][content="dark"]) ::highlight(dg-hl-flag) { color: #ff7b72; }
    :root:has(> head > meta[name="color-scheme"][content="dark"]) ::highlight(dg-hl-url) { color: #a5d6ff; text-decoration-color: rgba(165, 214, 255, 0.35); }
    :root:has(> head > meta[name="color-scheme"][content="dark"]) ::highlight(dg-hl-punc) { color: #8b949e; }
    :root:has(> head > meta[name="color-scheme"][content="dark"]) ::highlight(dg-hl-comment) { color: #8b949e; }
    :root:has(> head > meta[name="color-scheme"][content="dark"]) .dg-tok-key { color: #79c0ff; }
    :root:has(> head > meta[name="color-scheme"][content="dark"]) .dg-tok-str { color: #7ee787; }
    :root:has(> head > meta[name="color-scheme"][content="dark"]) .dg-tok-num { color: #ffa657; }
    :root:has(> head > meta[name="color-scheme"][content="dark"]) .dg-tok-kw { color: #d2a8ff; }
    :root:has(> head > meta[name="color-scheme"][content="dark"]) .dg-tok-flag { color: #ff7b72; }
    :root:has(> head > meta[name="color-scheme"][content="dark"]) .dg-tok-url { color: #a5d6ff; text-decoration-color: rgba(165, 214, 255, 0.35); }
    :root:has(> head > meta[name="color-scheme"][content="dark"]) .dg-tok-punc { color: #8b949e; }
    :root:has(> head > meta[name="color-scheme"][content="dark"]) .dg-tok-comment { color: #8b949e; }

    :root:has(> head > meta[name="color-scheme"][content="light"]) pre.dg-pre { background-color: #ffffff; }
    :root:has(> head > meta[name="color-scheme"][content="light"]) ::highlight(dg-hl-key) { color: #0550ae; }
    :root:has(> head > meta[name="color-scheme"][content="light"]) ::highlight(dg-hl-str) { color: #116329; }
    :root:has(> head > meta[name="color-scheme"][content="light"]) ::highlight(dg-hl-num) { color: #953800; }
    :root:has(> head > meta[name="color-scheme"][content="light"]) ::highlight(dg-hl-kw) { color: #8250df; }
    :root:has(> head > meta[name="color-scheme"][content="light"]) ::highlight(dg-hl-flag) { color: #cf222e; }
    :root:has(> head > meta[name="color-scheme"][content="light"]) ::highlight(dg-hl-url) { color: #0969da; text-decoration-color: rgba(9, 105, 218, 0.35); }
    :root:has(> head > meta[name="color-scheme"][content="light"]) ::highlight(dg-hl-punc) { color: #57606a; }
    :root:has(> head > meta[name="color-scheme"][content="light"]) ::highlight(dg-hl-comment) { color: #57606a; }
    :root:has(> head > meta[name="color-scheme"][content="light"]) .dg-tok-key { color: #0550ae; }
    :root:has(> head > meta[name="color-scheme"][content="light"]) .dg-tok-str { color: #116329; }
    :root:has(> head > meta[name="color-scheme"][content="light"]) .dg-tok-num { color: #953800; }
    :root:has(> head > meta[name="color-scheme"][content="light"]) .dg-tok-kw { color: #8250df; }
    :root:has(> head > meta[name="color-scheme"][content="light"]) .dg-tok-flag { color: #cf222e; }
    :root:has(> head > meta[name="color-scheme"][content="light"]) .dg-tok-url { color: #0969da; text-decoration-color: rgba(9, 105, 218, 0.35); }
    :root:has(> head > meta[name="color-scheme"][content="light"]) .dg-tok-punc { color: #57606a; }
    :root:has(> head > meta[name="color-scheme"][content="light"]) .dg-tok-comment { color: #57606a; }

    @supports (color: light-dark(white, black)) {
      pre.dg-pre { background-color: light-dark(#ffffff, #0b0e14); }
      ::highlight(dg-hl-key) { color: light-dark(#0550ae, #79c0ff); }
      ::highlight(dg-hl-str) { color: light-dark(#116329, #7ee787); }
      ::highlight(dg-hl-num) { color: light-dark(#953800, #ffa657); }
      ::highlight(dg-hl-kw) { color: light-dark(#8250df, #d2a8ff); }
      ::highlight(dg-hl-flag) { color: light-dark(#cf222e, #ff7b72); }
      ::highlight(dg-hl-url) { color: light-dark(#0969da, #a5d6ff); text-decoration-color: light-dark(rgba(9, 105, 218, 0.35), rgba(165, 214, 255, 0.35)); }
      ::highlight(dg-hl-punc) { color: light-dark(#57606a, #8b949e); }
      ::highlight(dg-hl-comment) { color: light-dark(#57606a, #8b949e); }
      .dg-tok-key { color: light-dark(#0550ae, #79c0ff); }
      .dg-tok-str { color: light-dark(#116329, #7ee787); }
      .dg-tok-num { color: light-dark(#953800, #ffa657); }
      .dg-tok-kw { color: light-dark(#8250df, #d2a8ff); }
      .dg-tok-flag { color: light-dark(#cf222e, #ff7b72); }
      .dg-tok-url { color: light-dark(#0969da, #a5d6ff); text-decoration-color: light-dark(rgba(9, 105, 218, 0.35), rgba(165, 214, 255, 0.35)); }
      .dg-tok-punc { color: light-dark(#57606a, #8b949e); }
      .dg-tok-comment { color: light-dark(#57606a, #8b949e); }
    }

    /* Quiet Technical Snapshot & Footer Strip */
    .dg-meta-strip {
      margin-block-start: 0.875rem;
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      justify-content: space-between;
      gap: 0.75rem;
      font-size: 0.78rem;
      color: var(--dg-muted);
    }

    .dg-meta-strip a,
    .dg-footer a {
      color: var(--dg-accent);
      text-decoration: none;
    }

    .dg-meta-strip a:hover,
    .dg-footer a:hover {
      text-decoration: underline;
      text-underline-offset: 3px;
    }

    .dg-footer {
      border-block-start: 1px solid var(--dg-border);
      background-color: var(--dg-paper);
      padding: 0.875rem 1.5rem;
      font-size: 0.78rem;
      color: var(--dg-muted);
    }

    .dg-footer-inner {
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      justify-content: space-between;
      gap: 0.75rem;
    }
  </style>
</head>
<body>
  <header class="dg-topbar">
    <div class="dg-container dg-topbar-inner">
      <div class="dg-brand-group">
        <a class="dg-brand" href="/">
          <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 280 56" width="160" height="32" role="img" aria-label="dgspamguard by Daviante">
            <defs>
              <linearGradient id="dg-mark-bg" x1="0%" y1="0%" x2="100%" y2="100%">
                <stop offset="0%" stop-color="#F43F5E"/>
                <stop offset="50%" stop-color="#E11D48"/>
                <stop offset="100%" stop-color="#9F1239"/>
              </linearGradient>
              <linearGradient id="dg-mark-border" x1="0%" y1="0%" x2="0%" y2="100%">
                <stop offset="0%" stop-color="#FFFFFF" stop-opacity="0.35"/>
                <stop offset="100%" stop-color="#FFFFFF" stop-opacity="0.0"/>
              </linearGradient>
              <linearGradient id="dg-sieve-l" x1="0%" y1="0%" x2="100%" y2="100%">
                <stop offset="0%" stop-color="#FFFFFF"/>
                <stop offset="100%" stop-color="#FFE4E6"/>
              </linearGradient>
              <linearGradient id="dg-sieve-r" x1="0%" y1="0%" x2="100%" y2="100%">
                <stop offset="0%" stop-color="#FECDD3"/>
                <stop offset="100%" stop-color="#FDA4AF"/>
              </linearGradient>
            </defs>
            <g transform="translate(6, 6)">
              <rect width="44" height="44" rx="12" fill="url(#dg-mark-bg)"/>
              <rect x="0.5" y="0.5" width="43" height="43" rx="11.5" fill="none" stroke="url(#dg-mark-border)" stroke-width="1"/>
              <circle cx="22" cy="20" r="15.5" fill="none" stroke="#FFFFFF" stroke-opacity="0.15" stroke-width="1" stroke-dasharray="4 2"/>
              <path d="M 8,10 L 22,10 L 22,37 L 18.5,34.5 L 18.5,23.5 L 8,12.5 Z" fill="url(#dg-sieve-l)"/>
              <path d="M 36,10 L 22,10 L 22,37 L 25.5,34.5 L 25.5,23.5 L 36,12.5 Z" fill="url(#dg-sieve-r)"/>
              <path d="M 13,13 L 31,13 L 24,20.5 L 20,20.5 Z" fill="#9F1239"/>
              <line x1="6.5" y1="16.2" x2="37.5" y2="16.2" stroke="#FFFFFF" stroke-width="1.4" stroke-linecap="round" stroke-opacity="0.9"/>
              <circle cx="22" cy="16.2" r="2.2" fill="#FFFFFF"/>
              <circle cx="22" cy="31.5" r="1.3" fill="#9F1239"/>
            </g>
            <g transform="translate(64, 38)">
              <text font-size="30" letter-spacing="-0.8">
                <tspan fill="var(--dg-text)" font-weight="700">dg</tspan><tspan fill="var(--dg-logo-sub)" font-weight="600">spamguard</tspan><tspan fill="var(--dg-dot)" font-weight="900">.</tspan>
              </text>
            </g>
          </svg>
        </a>
        <span class="dg-sep" aria-hidden="true"></span>
        <span class="dg-brand-subtitle dg-mono">v__ESCAPED_VER__ &middot; Threat &amp; Mail Intelligence</span>
      </div>

      <nav class="dg-nav" aria-label="Primary navigation">
        __DOCS_NAV_LINKS__
        <a href="__BRAND_DATA_REPO_URL__" target="_blank" rel="noopener noreferrer">Snapshots (dgspamguard-data)</a>
        <a href="__BRAND_REPO_URL__" target="_blank" rel="noopener noreferrer">GitHub</a>
        <a href="__BRAND_ORG_URL__" target="_blank" rel="noopener noreferrer">Daviante</a>
        <button type="button" id="dg-theme-toggle" class="dg-theme-btn" aria-label="Switch color theme">
          <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" aria-hidden="true">
            <circle cx="8" cy="8" r="3.25"/>
            <path d="M8 1.5v1.75M8 12.75v1.75M1.5 8h1.75M12.75 8h1.75M3.4 3.4l1.25 1.25M11.35 11.35l1.25 1.25M12.6 3.4l-1.25 1.25M4.65 11.35L3.4 12.6"/>
          </svg>
          <span id="dg-theme-label" class="dg-mono">Theme</span>
        </button>
      </nav>
    </div>
  </header>

  <main>
    <div class="dg-container">
      <!-- Command-Bar Search -->
      <section aria-labelledby="dg-lookup-label">
        <form id="dg-lookup-form" action="/" method="GET">
          <div class="dg-query-header">
            <label id="dg-lookup-label" for="dg-q-input" class="dg-field-label">Indicator Query</label>
            <span id="dg-q-hint" class="dg-hint dg-mono">Domain, URL, IPv4/IPv6, Email, or SHA-256 &middot; press / to focus</span>
          </div>
          <div class="dg-command-row">
            <div class="dg-input-col">
              <div class="dg-input-shell">
                <span class="dg-prompt-prefix dg-mono" aria-hidden="true">CHECK &gt;</span>
                <input
                  type="text"
                  id="dg-q-input"
                  name="q"
                  class="dg-q-input dg-mono"
                  required
                  minlength="3"
                  maxlength="2048"
                  pattern="\s*\S{3,2048}\s*"
                  placeholder="e.g. daviante.org, mailinator.com, 1.1.1.1, user@gmail.com, or https://..."
                  autocorrect="off"
                  autocapitalize="off"
                  spellcheck="false"
                  enterkeyhint="search"
                  aria-describedby="dg-q-hint"
                  aria-errormessage="dg-q-error"
                >
                <kbd class="dg-kbd dg-mono" aria-hidden="true">/</kbd>
              </div>
              <div id="dg-q-error" class="dg-error-msg" role="alert">
                <span aria-hidden="true">&#10005; </span>Enter a valid domain, URL, IPv4/IPv6 literal, email address, or 64-hex SHA-256 digest (no spaces).
              </div>
            </div>
            <button type="submit" id="dg-submit-btn" class="dg-btn dg-btn-primary">Query</button>
          </div>

          <div class="dg-presets dg-mono" aria-label="Sample indicators">
            <span>Examples:</span>
            <button type="button" class="dg-preset-btn" data-sample="daviante.org">daviante.org (Trusted)</button>
            <button type="button" class="dg-preset-btn" data-sample="mailinator.com">mailinator.com (Disposable)</button>
            <button type="button" class="dg-preset-btn" data-sample="user@gmail.com">user@gmail.com (Freemail)</button>
            <button type="button" class="dg-preset-btn" data-sample="1.1.1.1">1.1.1.1 (Clean IP)</button>
            <button type="button" class="dg-preset-btn" data-sample="https://tinyurl.com/demo">https://tinyurl.com/demo (Shortener)</button>
            <button type="button" class="dg-preset-btn" data-sample="github.io">github.io (Shared Host)</button>
          </div>
        </form>
      </section>

      <!-- Single Unified Registry Ledger -->
      <section class="dg-ledger" aria-live="polite" id="dg-result-region">
        <!-- Record Headline Strip -->
        <div class="dg-ledger-head">
          <div class="dg-headline-left">
            <span class="dg-subject-title dg-mono" id="res-subject">Querying&hellip;</span>
            <span class="dg-tag dg-mono" id="res-status-tag">RESOLVING</span>
            <span class="dg-summary-line" id="res-summary-line">Fetching active record from /v1/domain/daviante.org</span>
          </div>
          <div class="dg-headline-right dg-mono">
            <span id="res-endpoint-label">GET /v1/domain/daviante.org</span>
            <span>&middot;</span>
            <span class="dg-latency" id="res-latency">&mdash; ms</span>
          </div>
        </div>

        <!-- 3-Column Specification Grid -->
        <div class="dg-ledger-cols">
          <!-- Column 01: Indicator & Verdict -->
          <div class="dg-ledger-col">
            <div class="dg-col-header">
              <span class="dg-col-index dg-mono">01 / INDICATOR &amp; VERDICT</span>
              <span class="dg-tag dg-mono" id="res-risk-tag">RISK &mdash;</span>
            </div>
            <dl class="dg-kv">
              <dt>Type</dt>
              <dd id="res-kind" class="dg-mono">&mdash;</dd>
              <dt>Normalized</dt>
              <dd id="res-normalized" class="dg-mono">&mdash;</dd>
              <dt>Registered Root</dt>
              <dd id="res-root" class="dg-mono">&mdash;</dd>
              <dt>Policy Action</dt>
              <dd id="res-action" class="dg-mono">&mdash;</dd>
              <dt>TLD Profile</dt>
              <dd id="res-tld" class="dg-mono">&mdash;</dd>
            </dl>
          </div>

          <!-- Column 02: Threat & Corroboration -->
          <div class="dg-ledger-col">
            <div class="dg-col-header">
              <span class="dg-col-index dg-mono">02 / THREAT &amp; CORROBORATION</span>
              <span class="dg-tag dg-mono" id="res-cat-tag">THREAT &mdash;</span>
            </div>
            <dl class="dg-kv">
              <dt>Classification</dt>
              <dd id="res-category" class="dg-mono">&mdash;</dd>
              <dt>Confidence</dt>
              <dd id="res-confidence" class="dg-mono">&mdash;</dd>
              <dt>Match Scope</dt>
              <dd id="res-scope" class="dg-mono">&mdash;</dd>
              <dt>Source Count</dt>
              <dd id="res-src-count" class="dg-mono">&mdash;</dd>
              <dt>Matched Feeds</dt>
              <dd id="res-sources" class="dg-mono">&mdash;</dd>
            </dl>
          </div>

          <!-- Column 03: Posture & Mail Signals -->
          <div class="dg-ledger-col">
            <div class="dg-col-header">
              <span class="dg-col-index dg-mono">03 / POSTURE &amp; MAIL SIGNALS</span>
              <span class="dg-tag dg-mono" id="res-posture-tag">DIRECT / CLEAN</span>
            </div>
            <div class="dg-signal-matrix dg-mono" id="res-sec-matrix">
              <div class="dg-sig-cell"><span class="dg-sig-label"><span class="dg-sig-dot"></span>THREAT FEED</span><span class="dg-sig-state">&mdash;</span></div>
              <div class="dg-sig-cell"><span class="dg-sig-label"><span class="dg-sig-dot"></span>DISPOSABLE MX</span><span class="dg-sig-state">&mdash;</span></div>
              <div class="dg-sig-cell"><span class="dg-sig-label"><span class="dg-sig-dot"></span>FREE WEBMAIL</span><span class="dg-sig-state">&mdash;</span></div>
              <div class="dg-sig-cell"><span class="dg-sig-label"><span class="dg-sig-dot"></span>URL SHORTENER</span><span class="dg-sig-state">&mdash;</span></div>
              <div class="dg-sig-cell"><span class="dg-sig-label"><span class="dg-sig-dot"></span>SHARED HOST</span><span class="dg-sig-state">&mdash;</span></div>
              <div class="dg-sig-cell"><span class="dg-sig-label"><span class="dg-sig-dot"></span>TRUSTED ALLOW</span><span class="dg-sig-state">&mdash;</span></div>
            </div>
            <dl class="dg-kv">
              <dt>Matched Target</dt>
              <dd id="res-matched-target" class="dg-mono">&mdash;</dd>
              <dt>Snapshot</dt>
              <dd id="res-snap-ver" class="dg-mono">&mdash;</dd>
            </dl>
          </div>
        </div>

        <!-- Integrated Wire Drawer -->
        <div class="dg-drawer">
          <div class="dg-drawer-bar">
            <div class="dg-tabs dg-mono" role="tablist" aria-label="API wire representations">
              <button type="button" role="tab" aria-selected="true" class="dg-tab" data-wire-tab="json">JSON Payload</button>
              <button type="button" role="tab" aria-selected="false" class="dg-tab" data-wire-tab="curl">cURL</button>
              <button type="button" role="tab" aria-selected="false" class="dg-tab" data-wire-tab="batch">Batch POST</button>
            </div>
            <button type="button" id="dg-copy-wire-btn" class="dg-copy-btn dg-mono">Copy</button>
          </div>
          <pre class="dg-pre dg-mono"><code id="res-wire-code">// Querying DGSPAMGUARD API...</code></pre>
        </div>
      </section>

      <!-- Snapshot Metadata Line -->
      <section class="dg-meta-strip dg-mono" aria-label="Dataset snapshot status">
        <div>
          Snapshot <strong id="snap-version" style="color:var(--dg-text);">checking&hellip;</strong><span id="snap-details"></span>
        </div>
        <div>
          <a href="__BRAND_DATA_REPO_URL__/releases/latest" target="_blank" rel="noopener noreferrer">
            Download DNS RPZ / DGMail Rules / CSV Releases &rarr;
          </a>
        </div>
      </section>
    </div>
  </main>

  <footer class="dg-footer">
    <div class="dg-container dg-footer-inner">
      <span>Maintained by <a href="__BRAND_ORG_URL__" target="_blank" rel="noopener noreferrer">__BRAND_ORG_NAME__</a> &mdash; Compiled from abuse.ch, Spamhaus DROP, Phishing.Database, Tranco &amp; Open Mail Intelligence Feeds.</span>
      <span class="dg-mono">Apache-2.0 &middot; <a href="mailto:__BRAND_CONTACT_EMAIL__">__BRAND_CONTACT_EMAIL__</a></span>
    </div>
  </footer>

  <script>
    (function () {
      "use strict";

      const metaScheme = document.querySelector('meta[name="color-scheme"]');
      const themeBtn = document.getElementById("dg-theme-toggle");
      const themeLabel = document.getElementById("dg-theme-label");
      const mqDark = window.matchMedia ? window.matchMedia("(prefers-color-scheme: dark)") : null;

      function currentRenderedScheme() {
        const c = metaScheme ? metaScheme.content : "light dark";
        if (c === "dark" || c === "light") return c;
        return (mqDark && mqDark.matches) ? "dark" : "light";
      }

      function syncThemeButton() {
        if (!themeLabel) return;
        const active = currentRenderedScheme();
        themeLabel.textContent = active === "dark" ? "Dark" : "Light";
      }

      if (themeBtn && metaScheme) {
        themeBtn.addEventListener("click", function () {
          const next = currentRenderedScheme() === "dark" ? "light" : "dark";
          const sys = (mqDark && mqDark.matches) ? "dark" : "light";
          if (next === sys) {
            metaScheme.content = "light dark";
            try { localStorage.removeItem("dgspamguard-color-scheme"); } catch (_e) {}
          } else {
            metaScheme.content = next;
            try { localStorage.setItem("dgspamguard-color-scheme", next); } catch (_e) {}
          }
          syncThemeButton();
        });
      }
      if (mqDark && mqDark.addEventListener) {
        mqDark.addEventListener("change", syncThemeButton);
      }
      window.addEventListener("storage", function (ev) {
        if (ev.key === "dgspamguard-color-scheme" && metaScheme) {
          metaScheme.content = (ev.newValue === "light" || ev.newValue === "dark") ? ev.newValue : "light dark";
          syncThemeButton();
        }
      });
      syncThemeButton();

      const form = document.getElementById("dg-lookup-form");
      const qInput = document.getElementById("dg-q-input");
      const submitBtn = document.getElementById("dg-submit-btn");
      const copyWireBtn = document.getElementById("dg-copy-wire-btn");

      // Keyboard '/' shortcut to focus query input
      document.addEventListener("keydown", function (e) {
        if (e.key === "/" && !e.ctrlKey && !e.metaKey && !e.altKey) {
          const active = document.activeElement;
          const tag = active ? active.tagName : "";
          if (tag !== "INPUT" && tag !== "TEXTAREA" && !(active && active.isContentEditable)) {
            e.preventDefault();
            qInput.focus();
            qInput.select();
          }
        }
      });

      // Post-interaction validation fallback & ARIA sync
      if (window.CSS && CSS.supports && CSS.supports("selector(:user-invalid)")) {
        const syncAria = function (el) {
          if (el && el.matches) {
            el.setAttribute("aria-invalid", el.matches(":user-invalid") ? "true" : "false");
          }
        };
        form.addEventListener("blur", function (e) { syncAria(e.target); }, true);
        form.addEventListener("input", function (e) {
          if (e.target && e.target.hasAttribute("aria-invalid")) {
            syncAria(e.target);
          }
        });
      } else {
        const dirtyState = new WeakMap();
        const updateFallback = function (el) {
          if (!el || !el.checkValidity) return;
          const ok = el.checkValidity();
          el.classList.toggle("user-invalid-fallback", !ok);
          el.classList.toggle("user-valid-fallback", ok);
          if (!ok) {
            el.setAttribute("aria-invalid", "true");
          } else {
            el.removeAttribute("aria-invalid");
          }
        };
        form.addEventListener("blur", function (e) {
          const st = dirtyState.get(e.target) || { interacted: false, blurred: false };
          st.blurred = true;
          dirtyState.set(e.target, st);
          if (st.interacted) updateFallback(e.target);
        }, true);
        form.addEventListener("input", function (e) {
          const st = dirtyState.get(e.target) || { interacted: false, blurred: false };
          st.interacted = true;
          dirtyState.set(e.target, st);
          if (st.blurred) updateFallback(e.target);
        });
      }

      let activeWireTab = "json";
      const wireSnippets = {
        json: "// Querying DGSPAMGUARD API...",
        curl: "",
        batch: ""
      };
      const HL_BUCKETS = ["key", "str", "num", "kw", "flag", "url", "punc", "comment"];

      function tokenizeJson(text, baseOffset, buckets) {
        if (!text) return;
        const cmt = text.match(/^\s*\/\/[^\n]*/);
        if (cmt) {
          buckets.comment.push([baseOffset, baseOffset + cmt[0].length]);
          return;
        }
        const trimmed = text.trim();
        if (!trimmed.startsWith("{") && !trimmed.startsWith("[")) {
          return;
        }
        const re = /("(?:\\.|[^"\\])*")(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?|[{}\[\]:,]/g;
        let m;
        while ((m = re.exec(text)) !== null) {
          const s = baseOffset + m.index;
          const e = s + m[0].length;
          if (m[1] !== undefined) {
            const strEnd = s + m[1].length;
            if (m[2] !== undefined) {
              buckets.key.push([s, strEnd]);
              buckets.punc.push([strEnd, e]);
            } else {
              buckets.str.push([s, strEnd]);
            }
          } else if (m[3] !== undefined) {
            buckets.kw.push([s, e]);
          } else if (m[0].length === 1 && "{}[]:,".indexOf(m[0]) !== -1) {
            buckets.punc.push([s, e]);
          } else {
            buckets.num.push([s, e]);
          }
        }
      }

      function tokenizeShell(text, buckets) {
        if (!text) return;
        const re = /('[\s\S]*?')|("(?:\\.|[^"\\])*")|(https?:\/\/[^\s'"\\]+)|(\s-[A-Za-z]+)|\b(curl)\b|\b(GET|POST|PUT|DELETE|HEAD)\b|(\\)$/gm;
        let m;
        while ((m = re.exec(text)) !== null) {
          const s = m.index;
          const e = s + m[0].length;
          if (m[1] !== undefined) {
            const inner = m[1].slice(1, -1);
            const t = inner.trim();
            if (t.startsWith("{") || t.startsWith("[")) {
              buckets.punc.push([s, s + 1]);
              tokenizeJson(inner, s + 1, buckets);
              buckets.punc.push([e - 1, e]);
            } else {
              buckets.str.push([s, e]);
            }
          } else if (m[2] !== undefined) {
            buckets.str.push([s, e]);
          } else if (m[3] !== undefined) {
            buckets.url.push([s, e]);
          } else if (m[4] !== undefined) {
            buckets.flag.push([s + 1, e]);
          } else if (m[5] !== undefined) {
            buckets.key.push([s, e]);
          } else if (m[6] !== undefined) {
            buckets.kw.push([s, e]);
          } else if (m[7] !== undefined) {
            buckets.flag.push([s, e]);
          }
        }
      }

      function refreshWireView() {
        const codeEl = document.getElementById("res-wire-code");
        if (!codeEl) return;
        const rawText = wireSnippets[activeWireTab] || "";
        const buckets = { key: [], str: [], num: [], kw: [], flag: [], url: [], punc: [], comment: [] };

        if (activeWireTab === "json") {
          tokenizeJson(rawText, 0, buckets);
        } else {
          tokenizeShell(rawText, buckets);
        }

        if (window.CSS && CSS.highlights && typeof Highlight !== "undefined") {
          HL_BUCKETS.forEach(function (k) { CSS.highlights.delete("dg-hl-" + k); });
          codeEl.textContent = rawText;
          const walker = document.createTreeWalker(codeEl, NodeFilter.SHOW_TEXT);
          const textNode = walker.nextNode();
          if (!textNode) return;
          HL_BUCKETS.forEach(function (k) {
            const spans = buckets[k];
            if (!spans || !spans.length) return;
            const ranges = spans.map(function (pair) {
              const r = new Range();
              r.setStart(textNode, pair[0]);
              r.setEnd(textNode, pair[1]);
              return r;
            });
            CSS.highlights.set("dg-hl-" + k, new Highlight(...ranges));
          });
        } else {
          const flat = [];
          HL_BUCKETS.forEach(function (k) {
            buckets[k].forEach(function (pair) { flat.push([pair[0], pair[1], k]); });
          });
          flat.sort(function (a, b) { return a[0] - b[0]; });
          const frag = document.createDocumentFragment();
          let cursor = 0;
          for (let i = 0; i < flat.length; i++) {
            const s = flat[i][0];
            const e = flat[i][1];
            const k = flat[i][2];
            if (s < cursor) continue;
            if (s > cursor) frag.append(rawText.slice(cursor, s));
            const sp = document.createElement("span");
            sp.className = "dg-tok-" + k;
            sp.textContent = rawText.slice(s, e);
            frag.append(sp);
            cursor = e;
          }
          if (cursor < rawText.length) frag.append(rawText.slice(cursor));
          codeEl.replaceChildren(frag);
        }
      }

      document.querySelectorAll("[data-wire-tab]").forEach(function (tabBtn) {
        tabBtn.addEventListener("click", function () {
          activeWireTab = tabBtn.getAttribute("data-wire-tab") || "json";
          document.querySelectorAll("[data-wire-tab]").forEach(function (b) {
            b.setAttribute("aria-selected", b === tabBtn ? "true" : "false");
          });
          refreshWireView();
        });
      });

      function setText(id, val) {
        const el = document.getElementById(id);
        if (el) el.textContent = val;
      }

      function setTag(id, text, tone) {
        const el = document.getElementById(id);
        if (!el) return;
        el.textContent = text;
        el.className = "dg-tag dg-mono" + (tone ? " dg-tag-" + tone : "");
      }

      function detectMode(raw) {
        const s = (raw || "").trim();
        const cleanHash = s.replace(/^sha256:/i, "").trim();
        if (/^[0-9a-fA-F]{64}$/.test(cleanHash)) {
          return { kind: "hash", value: cleanHash, raw: s };
        }
        if (/^https?:\/\//i.test(s)) {
          return { kind: "url", value: s, raw: s };
        }
        if (s.indexOf("@") !== -1 && s.indexOf("://") === -1) {
          const parts = s.split("@");
          return { kind: "email", value: parts[parts.length - 1], raw: s };
        }
        const unwrappedIp = s.replace(/^\[|\]$/g, "");
        if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(unwrappedIp) || (unwrappedIp.indexOf(":") !== -1 && unwrappedIp.indexOf("/") === -1)) {
          return { kind: "ip", value: unwrappedIp, raw: s };
        }
        if (s.indexOf("/") !== -1) {
          return { kind: "url", value: "https://" + s, raw: s };
        }
        return { kind: "domain", value: s, raw: s };
      }

      function toneForVerdict(verdict) {
        const v = (verdict || "clean").toLowerCase();
        if (v === "malicious") return "err";
        if (v === "suspicious" || v === "elevated") return "warn";
        return "ok";
      }

      function actionForVerdict(verdict, isThreat) {
        const v = (verdict || "clean").toLowerCase();
        if (v === "malicious" || isThreat) return "reject / quarantine";
        if (v === "suspicious") return "flag / challenge";
        if (v === "elevated") return "elevated scrutiny";
        return "allow";
      }

      function renderSignalMatrix(flags) {
        const matrix = document.getElementById("res-sec-matrix");
        if (!matrix) return;
        while (matrix.firstChild) matrix.removeChild(matrix.firstChild);

        const defs = [
          ["THREAT FEED", !!flags.threat, "err"],
          ["DISPOSABLE MX", !!flags.disposable, "warn"],
          ["FREE WEBMAIL", !!flags.free, "info"],
          ["URL SHORTENER", !!flags.redirector, "warn"],
          ["SHARED HOST", !!flags.shared, "info"],
          ["TRUSTED ALLOW", !!flags.trusted, "ok"]
        ];

        defs.forEach(function (item) {
          const label = item[0];
          const active = item[1];
          const tone = item[2];

          const cell = document.createElement("div");
          cell.className = "dg-sig-cell" + (active ? " is-" + tone : "");

          const left = document.createElement("span");
          left.className = "dg-sig-label";
          const dot = document.createElement("span");
          dot.className = "dg-sig-dot";
          dot.setAttribute("aria-hidden", "true");
          left.appendChild(dot);
          left.appendChild(document.createTextNode(label));

          const right = document.createElement("span");
          right.className = "dg-sig-state";
          right.textContent = active ? "TRUE" : "—";

          cell.appendChild(left);
          cell.appendChild(right);
          matrix.appendChild(cell);
        });

        if (flags.threat) {
          setTag("res-posture-tag", "✕ THREAT LISTED", "err");
        } else if (flags.disposable) {
          setTag("res-posture-tag", "DISPOSABLE MX", "warn");
        } else if (flags.redirector) {
          setTag("res-posture-tag", "URL SHORTENER", "warn");
        } else if (flags.trusted) {
          setTag("res-posture-tag", "✓ TRUSTED ALLOW", "ok");
        } else if (flags.free) {
          setTag("res-posture-tag", "FREE WEBMAIL", "info");
        } else if (flags.shared) {
          setTag("res-posture-tag", "SHARED HOST", "info");
        } else {
          setTag("res-posture-tag", "DIRECT / CLEAN", "");
        }
      }

      function renderPayload(mode, data, elapsedMs, endpointLabel, curlCmd) {
        setText("res-latency", elapsedMs.toFixed(1) + " ms");
        setText("res-endpoint-label", endpointLabel);

        const verdict = (data.verdict || "clean").toLowerCase();
        const vTone = toneForVerdict(verdict);
        const vPrefix = verdict === "malicious" ? "✕ " : (verdict === "clean" ? "✓ " : "");

        if (mode.kind === "hash") {
          const score = data.found ? Math.max(85, data.confidence || 0) : 0;
          const srcs = data.sources || [];
          setText("res-subject", data.sha256 || mode.value);
          setTag("res-status-tag", vPrefix + verdict.toUpperCase() + " · SHA-256", vTone);
          setText(
            "res-summary-line",
            data.found
              ? ("Known attachment malware payload (" + (data.malware_family || "malware") + ")")
              : "No cryptographic SHA-256 malware IOC matched"
          );

          setTag("res-risk-tag", "RISK " + score + " / 100", vTone);
          setText("res-kind", "SHA-256 Digest");
          setText("res-normalized", (data.sha256 || "").slice(0, 24) + "…");
          setText("res-root", "n/a");
          setText("res-action", actionForVerdict(verdict, !!data.found));
          setText("res-tld", "n/a");

          setTag("res-cat-tag", data.found ? ("✕ " + (data.malware_family || "MALWARE").toUpperCase()) : "✓ NO IOC", data.found ? "err" : "ok");
          setText("res-category", data.found ? (data.malware_family || "malware") : "none");
          setText("res-confidence", (data.confidence || 0) + "%");
          setText("res-scope", data.found ? "exact_sha256" : "—");
          setText("res-src-count", srcs.length + " feed(s)");
          setText("res-sources", srcs.length ? srcs.join(", ") : "0 matched");

          renderSignalMatrix({ threat: !!data.found });
          setText("res-matched-target", data.found ? data.sha256 : "—");
          setText("res-snap-ver", data.snapshot_version || "—");
        } else if (mode.kind === "ip") {
          const srcs = data.sources || [];
          const verStr = "IPv" + (data.ip_version || 4);
          setText("res-subject", data.ip || mode.value);
          setTag("res-status-tag", vPrefix + verdict.toUpperCase() + " · " + verStr, vTone);
          setText(
            "res-summary-line",
            data.is_threat
              ? ("Matched " + (data.matched_network || data.ip) + " (" + (data.category || "smtp_threat") + ")")
              : (data.is_public_routable ? "Public routable host — not listed in SMTP or CIDR threat feeds" : "Non-routable private or special-purpose IP address")
          );

          setTag("res-risk-tag", "RISK " + (data.risk_score || 0) + " / 100", vTone);
          setText("res-kind", verStr + " Host");
          setText("res-normalized", data.ip || "—");
          setText("res-root", data.is_public_routable ? "public_inet" : "special_purpose");
          setText("res-action", actionForVerdict(verdict, !!data.is_threat));
          setText("res-tld", "n/a");

          setTag("res-cat-tag", data.is_threat ? ("✕ " + (data.category || "THREAT").toUpperCase()) : "✓ NO THREAT", data.is_threat ? "err" : "ok");
          setText("res-category", data.is_threat ? (data.category || "smtp_threat") : "none");
          setText("res-confidence", (data.confidence || 0) + "%");
          setText("res-scope", data.match_scope || "—");
          setText("res-src-count", (data.source_count || srcs.length) + " feed(s)");
          setText("res-sources", srcs.length ? srcs.join(", ") : "0 matched");

          renderSignalMatrix({ threat: !!data.is_threat });
          setText("res-matched-target", data.matched_network || "—");
          setText("res-snap-ver", data.snapshot_version || "—");
        } else if (mode.kind === "url") {
          const srcs = data.sources || [];
          const tax = data.taxonomy || {};
          const tld = data.tld || {};
          setText("res-subject", data.canonical_url || mode.value);
          setTag("res-status-tag", vPrefix + verdict.toUpperCase() + " · URL", vTone);
          setText(
            "res-summary-line",
            "Host " + (data.domain || "—") + " · eTLD+1 " + (data.registered_domain || "—") + " · SHA-256 " + (data.url_sha256 || "").slice(0, 12) + "…"
          );

          setTag("res-risk-tag", "RISK " + (data.risk_score || 0) + " / 100", vTone);
          setText("res-kind", "HTTP/HTTPS URL");
          setText("res-normalized", data.domain || "—");
          setText("res-root", data.registered_domain || "—");
          setText("res-action", actionForVerdict(verdict, !!data.is_threat));
          setText("res-tld", tld.tld ? ("." + tld.tld + " (" + tld.risk_level + " · " + tld.risk_score + ")") : "—");

          setTag("res-cat-tag", data.is_threat ? ("✕ " + (data.category || "THREAT").toUpperCase()) : "✓ NO THREAT", data.is_threat ? "err" : "ok");
          setText("res-category", data.is_threat ? (data.category || "threat") : "none");
          setText("res-confidence", (data.confidence || 0) + "%");
          setText("res-scope", data.match_scope || "—");
          setText("res-src-count", srcs.length + " feed(s)");
          setText("res-sources", srcs.length ? srcs.join(", ") : "0 matched");

          renderSignalMatrix({
            threat: !!data.is_threat,
            disposable: !!tax.is_disposable_email,
            free: !!tax.is_free_email,
            redirector: !!tax.is_url_redirector,
            shared: !!tax.is_shared_hosting,
            trusted: !!tax.is_trusted
          });
          setText("res-matched-target", data.is_threat ? (data.match_scope === "exact_url" ? (data.url_sha256 || "").slice(0, 16) + "…" : (data.domain || "—")) : "—");
          setText("res-snap-ver", data.snapshot_version || "—");
        } else {
          const thr = data.threat || {};
          const tax = data.taxonomy || {};
          const tld = data.tld || {};
          const srcs = thr.sources || [];
          const isEmail = mode.kind === "email";
          setText("res-subject", isEmail ? (mode.raw + " → " + data.domain) : (data.domain || mode.value));
          setTag("res-status-tag", vPrefix + verdict.toUpperCase() + (isEmail ? " · EMAIL" : " · DOMAIN"), vTone);

          const taxNotes = [];
          if (tax.is_trusted) taxNotes.push("Trusted allowlist root");
          if (tax.is_disposable_email) taxNotes.push("Disposable / burner MX provider");
          if (tax.is_free_email) taxNotes.push("Consumer free webmail provider");
          if (tax.is_url_redirector) taxNotes.push("URL shortener / redirector");
          if (tax.is_shared_hosting) taxNotes.push("Multi-tenant shared hosting");
          const summaryTail = thr.is_threat
            ? ("Matched threat feed (" + (thr.category || "threat") + ")")
            : (taxNotes.length ? taxNotes.join(" · ") : "Standard domain — no active threat indicators");
          setText("res-summary-line", "eTLD+1 " + (data.registered_domain || "—") + " — " + summaryTail);

          setTag("res-risk-tag", "RISK " + (data.risk_score || 0) + " / 100", vTone);
          setText("res-kind", isEmail ? "Email Sender Domain" : "DNS Domain");
          setText("res-normalized", data.unicode_domain && data.unicode_domain !== data.domain ? (data.domain + " (" + data.unicode_domain + ")") : (data.domain || "—"));
          setText("res-root", data.registered_domain || "—");
          setText("res-action", actionForVerdict(verdict, !!thr.is_threat));
          setText("res-tld", tld.tld ? ("." + tld.tld + " (" + tld.risk_level + " · " + tld.risk_score + ")") : "—");

          setTag("res-cat-tag", thr.is_threat ? ("✕ " + (thr.category || "THREAT").toUpperCase()) : "✓ NO THREAT", thr.is_threat ? "err" : "ok");
          setText("res-category", thr.is_threat ? (thr.category || "threat") : "none");
          setText("res-confidence", (thr.confidence || 0) + "%");
          setText("res-scope", thr.matched_domain ? (thr.matched_domain === data.domain ? "exact_domain" : "parent_domain") : "—");
          setText("res-src-count", (thr.source_count || 0) + " feed(s)");
          setText("res-sources", srcs.length ? srcs.join(", ") : "0 matched");

          renderSignalMatrix({
            threat: !!thr.is_threat,
            disposable: !!tax.is_disposable_email,
            free: !!tax.is_free_email,
            redirector: !!tax.is_url_redirector,
            shared: !!tax.is_shared_hosting,
            trusted: !!tax.is_trusted
          });
          setText("res-matched-target", thr.matched_domain || "—");
          setText("res-snap-ver", data.snapshot_version || "—");
        }

        const origin = window.location.origin;
        const batchBody = JSON.stringify(
          { items: [mode.raw || "daviante.org", "user@mailinator.com", "1.1.1.1", "https://tinyurl.com/demo"] },
          null,
          2
        ).replace(/'/g, "'\\''");
        wireSnippets.json = JSON.stringify(data, null, 2);
        wireSnippets.curl = curlCmd;
        wireSnippets.batch =
          "curl -fsSL -X POST " + origin + "/v1/check/batch \\\n" +
          "  -H \"Content-Type: application/json\" \\\n" +
          "  -d '" + batchBody + "'";
        refreshWireView();
      }

      async function runLookup(targetRaw) {
        const trimmed = (targetRaw || "").trim() || "daviante.org";
        const mode = detectMode(trimmed);
        const origin = window.location.origin;

        let url = "";
        let opts = { method: "GET", headers: { "Accept": "application/json" } };
        let endpointLabel = "";
        let curlCmd = "";

        if (mode.kind === "hash") {
          url = "/v1/hash/" + encodeURIComponent(mode.value);
          endpointLabel = "GET " + url;
          curlCmd = "curl -fsSL " + origin + url;
        } else if (mode.kind === "ip") {
          url = "/v1/ip/" + encodeURIComponent(mode.value);
          endpointLabel = "GET " + url;
          curlCmd = "curl -fsSL " + origin + url;
        } else if (mode.kind === "url") {
          url = "/v1/url/check";
          const payloadStr = JSON.stringify({ url: mode.value });
          const prettyPayload = JSON.stringify({ url: mode.value }, null, 2).replace(/'/g, "'\\''");
          opts = {
            method: "POST",
            headers: { "Accept": "application/json", "Content-Type": "application/json" },
            body: payloadStr
          };
          endpointLabel = "POST " + url;
          curlCmd = "curl -fsSL -X POST " + origin + url + " \\\n  -H \"Content-Type: application/json\" \\\n  -d '" + prettyPayload + "'";
        } else {
          url = "/v1/domain/" + encodeURIComponent(mode.value);
          endpointLabel = "GET " + url;
          curlCmd = "curl -fsSL " + origin + url;
        }

        submitBtn.disabled = true;
        setTag("res-status-tag", "QUERYING", "");
        setText("res-endpoint-label", endpointLabel);
        const t0 = performance.now();
        try {
          const resp = await fetch(url, opts);
          const elapsed = performance.now() - t0;
          const body = await resp.json();
          if (!resp.ok) {
            setText("res-subject", trimmed);
            setTag("res-status-tag", "✕ HTTP " + resp.status, "err");
            setText("res-summary-line", (body && (body.detail || body.title)) ? (body.detail || body.title) : "Request rejected");
            wireSnippets.json = JSON.stringify(body, null, 2);
            wireSnippets.curl = curlCmd;
            refreshWireView();
            return;
          }
          renderPayload(mode, body, elapsed, endpointLabel, curlCmd);
        } catch (err) {
          setTag("res-status-tag", "✕ NETWORK ERROR", "err");
          setText("res-summary-line", "Unable to reach DGSPAMGUARD HTTP endpoint");
          wireSnippets.json = String(err);
          refreshWireView();
        } finally {
          submitBtn.disabled = false;
        }
      }

      form.addEventListener("submit", function (e) {
        e.preventDefault();
        if (!form.checkValidity()) {
          form.reportValidity();
          return;
        }
        const q = qInput.value.trim();
        const nextUrl = q && q !== "daviante.org" ? ("/?q=" + encodeURIComponent(q)) : "/";
        window.history.replaceState(null, "", nextUrl);
        runLookup(q);
      });

      document.querySelectorAll("[data-sample]").forEach(function (btn) {
        btn.addEventListener("click", function () {
          const sample = btn.getAttribute("data-sample") || "";
          qInput.value = sample;
          qInput.removeAttribute("aria-invalid");
          qInput.classList.remove("user-invalid-fallback");
          const nextUrl = sample && sample !== "daviante.org" ? ("/?q=" + encodeURIComponent(sample)) : "/";
          window.history.replaceState(null, "", nextUrl);
          runLookup(sample);
        });
      });

      copyWireBtn.addEventListener("click", function () {
        const text = wireSnippets[activeWireTab] || "";
        if (!text || !navigator.clipboard) return;
        navigator.clipboard.writeText(text).then(function () {
          copyWireBtn.textContent = "Copied";
          setTimeout(function () { copyWireBtn.textContent = "Copy"; }, 1400);
        });
      });

      async function loadSnapshotBanner() {
        try {
          const r = await fetch("/v1/snapshots/latest", { headers: { "Accept": "application/json" } });
          if (r.ok) {
            const meta = await r.json();
            setText("snap-version", meta.version || "ready");
            const total =
              (Number(meta.threat_domains) || 0) +
              (Number(meta.threat_urls) || 0) +
              (Number(meta.threat_ips) || 0) +
              (Number(meta.disposable_domains) || 0) +
              (Number(meta.free_domains) || 0) +
              (Number(meta.redirector_domains) || 0) +
              (Number(meta.malware_hashes) || 0);
            setText("snap-details", total > 0 ? (" · " + total.toLocaleString() + " indicators · 30 authoritative feeds") : "");
            return;
          }
          const ready = await fetch("/healthz/ready", { headers: { "Accept": "application/json" } });
          if (ready.ok) {
            const st = await ready.json();
            setText("snap-version", st.active_version || "live");
          } else {
            setText("snap-version", "initializing");
          }
        } catch (_e) {
          setText("snap-version", "offline");
        }
      }

      const initialQ = new URLSearchParams(window.location.search).get("q") || "daviante.org";
      qInput.value = initialQ;
      refreshWireView();
      runLookup(initialQ);
      loadSnapshotBanner();
    })();
  </script>
</body>
</html>
"#####;
