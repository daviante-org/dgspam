# Deployment Guide

`dgspamguard` ships as a rootless, read-only `FROM scratch` OCI image (`ghcr.io/daviante-org/dgspamguard:<semver>`) supporting `linux/amd64` and `linux/arm64`.

> **Tagging Policy**: Daviante never publishes mutable `:latest` container tags. Always pin an explicit SemVer tag such as `1.0.0`.

---

## 1. Sizing & Network Requirements

| Resource | Minimum | Recommended | Notes |
| :--- | :--- | :--- | :--- |
| **CPU** | `0.25 vCPU` | `1 vCPU` | Sub-millisecond steady-state CPU; spikes briefly when due feeds update (15m/30m/1h live swaps; 4h GZIP/RPZ snapshots). |
| **Container RAM** | `256 MiB` | `512 MiB` | Idle HTTP RSS is `~3–8 MiB`; compilation peak is `~180–280 MiB`. |
| **PostgreSQL Disk** | `2 GiB` | `5 GiB` | Holds active + standby Blue/Green slots plus 7 days of rolling snapshot tarballs (`~42` snapshots max). |
| **Outbound Egress** | TCP `443` | TCP `443` | Required only to hostnames in `dgspamguard_allowed_hosts` (or `github.com` / `objects.githubusercontent.com` for air-gapped/mirror bundle bootstrap). |

---

## 2. Docker & Podman Compose

```bash
cp .env.example .env
# Edit POSTGRES_PASSWORD and DGSPAMGUARD_DATABASE_URL in .env
podman compose up -d          # or: docker compose up -d
podman compose logs -f dgspamguard
```

Verify readiness:
```bash
curl -fsS http://127.0.0.1:8091/healthz/ready | jq .
```

---

## 3. Kubernetes (OCI Helm Chart)

```bash
helm install dgspamguard oci://ghcr.io/daviante-org/charts/dgspamguard \
  --version 1.0.0 \
  --namespace dgspamguard \
  --create-namespace \
  --set database.internal.password="replace-with-strong-password"
```

To use an external managed PostgreSQL cluster instead of the bundled `postgres:18.6-alpine` StatefulSet:
```bash
helm install dgspamguard oci://ghcr.io/daviante-org/charts/dgspamguard \
  --version 1.0.0 \
  --namespace dgspamguard \
  --create-namespace \
  --set database.internal.enabled=false \
  --set database.external.url="postgresql://dgspamguard:STRONG_PASS@pg.internal:5432/dgspamguard?sslmode=require"
```

Standalone manifest alternative: [`deploy/kubernetes/dgspamguard.yaml`](../deploy/kubernetes/dgspamguard.yaml).

---

## 4. Red Hat OpenShift (`restricted-v2` SCC)

Both the `Dockerfile` (`USER 10001:0`, `chmod -R g=u`) and Helm templates omit hardcoded `runAsUser` when `openshift.enabled=true` so OpenShift's dynamic namespace UID range works out of the box under `restricted-v2`:

```bash
oc new-project dgspamguard
helm install dgspamguard oci://ghcr.io/daviante-org/charts/dgspamguard \
  --version 1.0.0 \
  --namespace dgspamguard \
  --set openshift.enabled=true \
  --set openshift.route.enabled=true \
  --set openshift.route.host=dgspamguard.apps.example.com
```

Standalone OpenShift manifest: [`deploy/openshift/dgspamguard.yaml`](../deploy/openshift/dgspamguard.yaml).

---

## 5. Reverse Proxy & Client Rate Limiting

When running behind Traefik, NGINX, Envoy, or Cloudflare, configure `DGSPAMGUARD_TRUSTED_PROXIES` so `X-Forwarded-For` is honored only from trusted proxy CIDRs:

```bash
DGSPAMGUARD_TRUSTED_PROXIES="10.0.0.0/8,172.16.0.0/12,192.168.0.0/16"
DGSPAMGUARD_RATE_LIMIT_PER_MINUTE="600"
```

---

## 6. Environment Variables Reference

| Variable | Default | Description |
| :--- | :--- | :--- |
| `DGSPAMGUARD_DATABASE_URL` | `postgresql://dgspamguard:dgspamguard@127.0.0.1:5432/dgspamguard` | PostgreSQL connection URI. |
| `DGSPAMGUARD_DB_POOL_MIN_SIZE` | `2` | Minimum warm connections in `deadpool-postgres`. |
| `DGSPAMGUARD_DB_POOL_MAX_SIZE` | `16` | Maximum connections in `deadpool-postgres`. |
| `DGSPAMGUARD_HOST` | `0.0.0.0` | Bind address for HTTP server. |
| `DGSPAMGUARD_PORT` | `8091` | Bind TCP port for HTTP server. |
| `DGSPAMGUARD_SWAGGER_ENABLED` | `true` | Serve interactive Swagger UI at `GET /docs`. |
| `DGSPAMGUARD_ASSETS_DIR` | `assets` | Directory containing `dgmail-base-seed.json` & SVG brand assets. |
| `DGSPAMGUARD_CACHE_DIR` | `/tmp/dgspamguard-cache` | Ephemeral streaming cache directory (mount `emptyDir` / `tmpfs` when `--read-only`). |
| `DGSPAMGUARD_BOOTSTRAP_ON_STARTUP` | `true` | Automatically bootstrap from `dgspamguard-data` (or upstream sync on Day 1) when DB is empty. |
| `DGSPAMGUARD_BOOTSTRAP_BUNDLE_URL` | *(latest `dgspamguard-data` release)* | Custom HTTPS URL or local path to `bundle.tar.gz` for air-gapped bootstrap. |
| `DGSPAMGUARD_SYNC_SCHEDULER_ENABLED` | `true` | Enable per-feed deadline refresh & snapshot scheduler. |
| `DGSPAMGUARD_SYNC_INTERVAL_SECONDS` | `60` (`1m`) | Max scheduler deadline check interval (`15`–`604800`); each feed refreshes on its own TTL (`15m`–`24h`). |
| `DGSPAMGUARD_SNAPSHOT_INTERVAL_SECONDS` | `14400` (`4h`) | Rolling `bundle.tar.gz` snapshot packaging cadence (`300`–`604800`); live A/B slot swaps remain immediate. |
| `DGSPAMGUARD_SYNC_HTTP_TIMEOUT_SECONDS` | `90.0` | Per-feed HTTPS download timeout in seconds. |
| `DGSPAMGUARD_RETENTION_DAYS` | `7` | Rolling retention window in days for stored snapshots (`1`–`90`). |
| `DGSPAMGUARD_ABUSECH_AUTH_KEY` | *(empty)* | Optional Abuse.ch `Auth-Key` (`https://auth.abuse.ch/`) unlocking URLhaus v1/v2, ThreatFox & MalwareBazaar exports. |
| `DGSPAMGUARD_RATE_LIMIT_PER_MINUTE` | `600` | Per-IP sliding-window HTTP rate limit per minute. |
| `DGSPAMGUARD_TRUSTED_PROXIES` | *(empty)* | Comma-separated CIDRs trusted to supply `X-Forwarded-For` / `X-Real-IP`. |
| `DGSPAMGUARD_LOG_LEVEL` | `info` | `tracing` filter (`error`, `warn`, `info`, `debug`). |
