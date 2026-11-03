<div align="left">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="./assets/logo-dark.svg">
    <source media="(prefers-color-scheme: light)" srcset="./assets/logo.svg">
    <img alt="dgspamguard" src="./assets/logo.svg" width="280" height="56">
  </picture>
</div>

<br>

**Self-Hosted Domain, URL, SMTP IP, Email Taxonomy, File-Hash Threat Intelligence, Protective DNS RPZ & Mail Rule Compiler Engine**

`dgspamguard` is the self-hosted domain, URL, SMTP IP/CIDR, email, and attachment threat intelligence service maintained by [Daviante](https://daviante.org) (`https://dgspamguard.daviante.org`). It compiles **5 layers of open Internet security & mail intelligence** across **30 authoritative feeds** (25 keyless public CSIRT/OSINT feeds plus 5 optional authenticated Abuse.ch v1/v2 feeds); serves sub-5ms **read-only** REST lookups from PostgreSQL Blue/Green indexes (including GiST `inet_ops` longest-prefix CIDR matching); provides the `dgspamguard` operational CLI; and produces 4-hour rolling multi-format dataset releases (including RFC DNS Response Policy Zones, SMTP IP/CIDR blocklists, and DGMail's self-hosted `dgmail-rules.json.gz`) published in [`daviante-org/dgspamguard-data`](https://github.com/daviante-org/dgspamguard-data).

---

## Key Capabilities

- **5-Layer Open Threat & Mail Intelligence (30 Authoritative Feeds, Zero Commercial Lock-In & Zero Telemetry)**:
  1. **Layer 0 — Canonical Boundaries & False-Positive Allowlist Gates**: **Mozilla Public Suffix List (ICANN vs Private sections)** + **Tranco Top 1M** research ranking (Top-100K domain shield + Top-10K enterprise root shield) + built-in trusted apex & multi-tenant shared-hosting subtraction gates (`pages.dev`, `github.io`, `vercel.app` subdomain isolation vs `docs.google.com`, `drive.google.com`, `dropbox.com` path-only isolation).
  2. **Layer 1 — Active Phishing, Malware Distribution & Botnet C2 Domains/URLs**: **CERT Polska (`CERT.PL`)**, **OpenPhish Community**, **Abuse.ch URLhaus** (keyless `text_online` + optional v1 JSON & v2 CSV with `abused_legit_*` and `online`-only RPZ safeguards), **Abuse.ch ThreatFox**, **Phishunt**, **Phishing Army Extended**, **`Phishing.Database`** (`ACTIVE` domains, `NEW-today` domains, and `ACTIVE` full links), and **`malware-filter` Phishing** — scored by multi-source corroboration confidence (`0`–`100`).
  3. **Layer 2 — Malicious Sending IPs, Botnets & Hijacked Subnets (SMTP Connection Layer)**: **Spamhaus DROP** (`drop_v4.json` + `drop_v6.json`), **IPsum Level 3+** (`stamparm/ipsum` corroborated across 3+ lists), **Blocklist.de** (`mail.txt` Postfix/SMTP attackers + `bots.txt`), **Abuse.ch Feodo Tracker** (Dridex, Emotet, QakBot, Pikabot C2 IPs), and **`Phishing.Database` Active IPs**, with automatic bogon/private/public-DNS-resolver protection (`1.1.1.1`, `8.8.8.8`, `9.9.9.9`, `208.67.222.222`).
  4. **Layer 3 — Email Provider Taxonomy & TLD Risk (`From` / `Reply-To`)**: **MX-Validated Disposable Email Domains** (`disposable.github.io/disposable-email-domains/domains_mx.txt` + `disposable_email_blocklist.conf`, `FGRibreau/mailchecker`, `wesbos` burner providers), **Free Mailbox Providers** (`willwhite/freemail` + curated fallback), and **High-Abuse TLD Multipliers** (`RFC 2606` reserved TLDs + abused gTLDs/ccTLDs).
  5. **Layer 4 — Malware Attachment `SHA-256` Hashes**: **Abuse.ch MalwareBazaar** + **URLhaus Payloads** + **`romainmarcoux/malicious-hash`** (`80K+` hourly-updated malware `SHA-256` hashes) + **Botvrij.eu** (`CIRCL` / `MISP` OSINT) cryptographic `SHA-256` payload indicators.
- **100% Read-Only HTTP Surface + Built-In `dgspamguard` CLI**: Exposes zero administrative or mutating HTTP endpoints to the network. Operational tasks (`dgspamguard status`, `dgspamguard sync`, `dgspamguard bootstrap`, `dgspamguard feed`, `dgspamguard allowlist`, `dgspamguard config`) run locally inside the container via `/usr/local/bin/dgspamguard`.
- **Per-Feed Native Deadline Scheduler & Decoupled 4h Snapshots**: Each of the 30 feeds refreshes independently on its provider's real publication cadence (`15m` URLhaus v1 JSON APIs, `30m` Blocklist.de SMTP/bots, Feodo Tracker, CERT.PL & URLhaus online, `1h` URLhaus/ThreatFox/MalwareBazaar v2 CSVs, OpenPhish, Phishunt, `Phishing.Database NEW-today` & `malicious-hash`, `4h` Spamhaus DROP v4/v6, Phishing Army & Botvrij, `12h` `Phishing.Database` active corpora, IPsum L3+ & MX-validated burner domains, `24h` Mozilla PSL, Tranco Top 1M & email taxonomies). High-frequency updates swap live Blue/Green query tables (`*_a` / `*_b`) immediately with zero downtime, while heavy `~115 MB` snapshot tarballs (`DGSPAMGUARD_SNAPSHOT_INTERVAL_SECONDS=14400`) are packaged on fixed **4-hour UTC boundaries** (`00:00`, `04:00`, `08:00`, `12:00`, `16:00`, `20:00` UTC) with **7-day rolling retention**.
- **9 Open-Standard Artifacts per Snapshot (`vYYYYMMDD.HHMM`)**:
  - `dgspamguard-threat-domains.csv.gz` · `dgspamguard-threat-domains.txt.gz` · `dgspamguard-threat-urls.csv.gz` · `dgspamguard-smtp-ips.csv.gz` · `dgspamguard-email-domains.csv.gz` · `dgspamguard-malware-hashes.csv.gz` · `dgspamguard-tld-risk.csv.gz`
  - **`dgspamguard-threat-domains.rpz.gz`**: Standard **DNS Response Policy Zone (RPZ)** (`CNAME .` NXDOMAIN actions) ready for **`daviante-doh`**, Unbound, PowerDNS Recursor, Knot Resolver, and BIND 9.
  - **`dgmail-rules.json.gz`**: Self-hosted **DGMail** spam-classifier ruleset (`<= 440 KB` compressed, zero third-party `HttpLookup` URLs, all external DNSBL calls disabled, pre-populated in-RAM `dgm_free_domains`, `dgm_disposable_domains`, `dgm_openphish`, `dgspamguard_threat_domains`, and `dgspamguard_smtp_threat_ips` connection-layer `remote_ip` lookup maps).
- **Ultra-Light `FROM scratch` Rust Runtime**: Single static `musl` Rust binary (`~10 MB` image, `~3–8 MB` idle RAM, zero C/OpenSSL dependencies, zero shell or OS packages, `0` Trivy image CVEs) running unprivileged (`UID 10001:0`, `chmod -R g=u`, `--read-only` rootfs, `cap_drop: [ALL]`) across **Docker**, **Podman**, **Kubernetes** (`restricted` PSS), and **Red Hat OpenShift** (`restricted-v2` SCC + native Edge-TLS `Route`).

---

## Quick Start

### Docker or Podman Compose
```bash
cp .env.example .env
docker compose up -d          # or: podman compose up -d
docker compose exec dgspamguard dgspamguard status
```

### Kubernetes (Official GitHub OCI Helm v3 Chart)
```bash
helm install dgspamguard oci://ghcr.io/daviante-org/charts/dgspamguard -n dgspamguard --create-namespace
kubectl -n dgspamguard exec deploy/dgspamguard -- dgspamguard status
```

### Red Hat OpenShift (`restricted-v2` SCC + Native Route)
```bash
oc new-project dgspamguard
helm install dgspamguard oci://ghcr.io/daviante-org/charts/dgspamguard -n dgspamguard \
  --set openshift.enabled=true \
  --set openshift.route.enabled=true
```

---

## HTTP API, DGMail & Protective DNS Integration

A zero-CDN interactive **Registry Ledger** inspection portal (auto-detecting domains, URLs, email addresses, and `SHA-256` hashes with light/dark theme support) is served at `GET /` (`https://dgspamguard.daviante.org`), and Swagger UI is served at `GET /docs` (OpenAPI 3.1 contract: [`openapi.yaml`](./openapi.yaml); disable Swagger anytime via `DGSPAMGUARD_SWAGGER_ENABLED=false`). Compatible with **PostgreSQL 14+** (default Compose/Helm image uses `postgres:18.6-alpine`).

### Read-Only HTTP Endpoints
| Method & Path | Description |
| :--- | :--- |
| `GET /healthz/live` · `GET /healthz/ready` | Container liveness and PostgreSQL + active Blue/Green slot readiness probes. |
| `GET /v1/domain/{domain}` | Domain / hostname / email-domain lookup (Punycode/IDNA normalized, PSL `registered_domain`, verdict, score, categories, email taxonomy, RPZ status, and TLD risk). |
| `POST /v1/url/check` | Exact canonical URL (`SHA-256`) + hostname/IP hierarchy + TLD risk evaluation (`{"url": "https://..."}`). |
| `GET /v1/ip/{ip}` | Longest-prefix IPv4/IPv6 CIDR lookup across hijacked netblocks, botnet C2 IPs, and SMTP attackers. |
| `GET /v1/hash/{sha256}` | Malware attachment `SHA-256` cryptographic hash lookup. |
| `POST /v1/check/batch` | Bulk mixed indicator evaluation (up to `250` domains, URLs, IPv4/IPv6 addresses, emails, or `SHA-256` hashes in a single request). |
| `GET /v1/snapshots` · `GET /v1/snapshots/latest` | Rolling 7-day snapshot history, SHA-256 manifest, and `?current_version=` update check. |
| `GET /v1/snapshots/{version}/bundle.tar.gz` | Complete snapshot `tar.gz` bundle (`ETag` / `304` & `X-Checksum-Sha256`). |
| `GET /v1/snapshots/{version}/files/{filename}` | Individual `.csv.gz`, `.txt.gz`, `dgspamguard-threat-domains.rpz.gz`, `dgmail-rules.json.gz`, `manifest.json`, or `SHA256SUMS.txt`. |

### Self-Hosted DGMail Integration
Point DGMail's spam classifier updater directly at your `dgspamguard` instance or [`daviante-org/dgspamguard-data`](https://github.com/daviante-org/dgspamguard-data):
```toml
[spam-filter.updates]
url = "https://github.com/daviante-org/dgspamguard-data/releases/latest/download/dgmail-rules.json.gz"
# Or direct local/cluster service URL:
# url = "http://dgspamguard.dgspamguard.svc.cluster.local:8091/v1/snapshots/latest/files/dgmail-rules.json.gz"
```

### Protective DNS RPZ Integration (`daviante-doh`, Unbound, Knot, PowerDNS)
Download `dgspamguard-threat-domains.rpz.gz` (`gunzip -c`) to enforce NXDOMAIN protective blocking on verified phishing, malware, and C2 domains with zero collateral blocking of Tranco Top 10K or shared hosting roots:
```yaml
# Unbound example:
rpz:
  name: "rpz.dgspamguard.daviante.org"
  zonefile: "/var/lib/unbound/dgspamguard-threat-domains.rpz"
  rpz-log: yes
```

### `dgspamguard` Operational CLI (`/usr/local/bin/dgspamguard`)
```bash
dgspamguard status                                             # Inspect active slot, snapshot version & sync health
dgspamguard sync [--force] [--export-dir <dir>]                # Refresh inactive slot from upstream feeds & cut snapshot
dgspamguard bootstrap [--bundle <url-or-path>]                 # Bootstrap PostgreSQL from a bundle.tar.gz archive
dgspamguard feed {list | enable <k> | disable <k> | set-url | set-ttl} # Manage upstream feeds & per-feed TTLs
dgspamguard allowlist {list | add <domain> | remove <domain>}  # Manage trusted & shared-hosting allowlists
dgspamguard config {show | set <key> <value>}                  # Inspect or update PostgreSQL runtime parameters
dgspamguard healthcheck                                        # Local container liveness probe
```

---

## Documentation Index

| Document | Contents |
| :--- | :--- |
| **[`docs/ARCHITECTURE.md`](./docs/ARCHITECTURE.md)** | System topology, 5-layer compiler pipeline, Blue/Green PostgreSQL schema, shared-hosting isolation, and memory profile. |
| **[`docs/DATA_POLICY.md`](./docs/DATA_POLICY.md)** | All 30 upstream feeds, tiered refresh TTLs, confidence scoring, false-positive guardrails, and operator allowlist policy. |
| **[`docs/DEPLOYMENT.md`](./docs/DEPLOYMENT.md)** | Docker, Podman, Reverse Proxy TLS, Kubernetes OCI Helm chart, Red Hat OpenShift `restricted-v2`, and air-gapped bootstrap. |
| **[`docs/DEVELOPMENT.md`](./docs/DEVELOPMENT.md)** | Building from source, running Clippy and integration tests, offline bundle export, and OpenAPI contract verification. |
| **[`docs/SECURITY.md`](./docs/SECURITY.md)** | Vulnerability reporting (`code@daviante.org`), read-only HTTP threat model, SSRF/tarbomb defenses, and SLSA provenance. |
| **[`CREDITS.md`](./CREDITS.md)** · **[`NOTICE`](./NOTICE)** | Complete third-party data ownership, copyright, academic citations, MIT/MPL/CC0 notices, and trademark disclaimers across all 30 feeds and baseline rule assets. |
| **[`openapi.yaml`](./openapi.yaml)** | Canonical OpenAPI 3.1 HTTP specification (verified against Axum routes in CI). |
| **[`charts/dgspamguard/`](./charts/dgspamguard/Chart.yaml)** · **[`deploy/`](./deploy/kubernetes/dgspamguard.yaml)** | Official Helm v3 chart and standalone Kubernetes / Red Hat OpenShift manifests. |

---

## Upstream Intelligence Attribution

| Category | Feeds & Providers | Format | License / Attribution |
| :--- | :--- | :--- | :--- |
| **Allowlist & Domain Boundaries** | `Mozilla Public Suffix List`, `Tranco Top 1M` (`https://tranco-list.eu`) | `.dat`, `.csv.zip` | MPL-2.0 / Open Research |
| **Phishing Domains & URLs** | `CERT Polska (CERT.PL)`, `OpenPhish Community`, `Phishunt`, `Phishing Army`, `Phishing.Database`, `malware-filter` | `.txt` | Open CSIRT / MIT / CC-BY 4.0 |
| **Malware URLs, C2 & Payloads** | `abuse.ch URLhaus`, `abuse.ch ThreatFox`, `abuse.ch MalwareBazaar`, `abuse.ch Feodo Tracker` | `.json`, `.csv`, `.txt` | CC0 1.0 Public Domain |
| **Bad Subnets & SMTP Attack IPs** | `Spamhaus DROP` (IPv4 & IPv6), `IPsum` (`stamparm`), `Blocklist.de` (`mail` & `bots`), `Phishing.Database` IPs | `.json`, `.txt` | Free w/ Attribution / Unlicense / MIT |
| **Disposable & Free Email Senders** | `disposable-email-domains` (`domains_mx`), `FGRibreau/mailchecker`, `wesbos/burner-email-providers`, `willwhite/freemail` | `.txt`, `.conf` | CC0 1.0 / MIT |
| **Malware Attachment Hashes** | `romainmarcoux/malicious-hash`, `Botvrij.eu / CIRCL OSINT` | `.txt` | MIT / Open OSINT |

---

## License & Upstream Data Attribution

Software, schemas, and documentation in this repository are licensed under the [Apache License, Version 2.0](./LICENSE) (see [`NOTICE`](./NOTICE)). Daviante claims no ownership over third-party CSIRT, OSINT, domain-boundary, or email-taxonomy data and does not transfer or sublicense rights belonging to upstream providers; all upstream owners, licenses, and citations are credited in [`CREDITS.md`](./CREDITS.md) and [`docs/DATA_POLICY.md`](./docs/DATA_POLICY.md).

Maintained by **Daviante** (`https://daviante.org`) — Contact: `code@daviante.org`.
