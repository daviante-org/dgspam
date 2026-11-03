# Upstream Data Sources & Compilation Policy

`dgspamguard` aggregates **30 authoritative Internet security & mail intelligence feeds** across **5 layers**: 25 keyless public registries/CSIRTs/OSINT trackers plus 5 optional authenticated Abuse.ch v1/v2 feeds (unlocked when a free `DGSPAMGUARD_ABUSECH_AUTH_KEY` from `https://auth.abuse.ch/` is configured; gracefully skipped otherwise). Zero user telemetry or runtime third-party lookup calls are ever emitted.

---

## 1. Configured Upstream Feeds (30 Total Across 5 Layers)

### Layer 0 — Canonical Domain Boundaries & False-Positive Allowlist Gates
| Feed Key | Upstream Maintainer | Default TTL | Min Records | Weight | Purpose |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `psl-mozilla` | Mozilla Foundation (`publicsuffix.org`) | `24h` (`86400s`) | `5,000` | `0` | ICANN & Private (`// ===BEGIN PRIVATE DOMAINS===`) registrable domain boundaries |
| `allow-tranco-top` | Tranco Research List (`tranco-list.eu`) | `24h` (`86400s`) | `50,000` | `0` | Top-100K exact domain shield & Top-10K enterprise root false-positive gate |

### Layer 1 — Active Phishing, Malware Distribution & Botnet C2 Domains/URLs
| Feed Key | Auth | Upstream Maintainer | Default TTL | Min Records | Weight | Purpose |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `abusech-urlhaus-v1-urls` | `Auth-Key` | Abuse.ch URLhaus v1 JSON | `15m` (`900s`) | `10` | `86` | Real-time recent malware URLs + `spamhaus_dbl` (`abused_legit_*` RPZ protection) |
| `abusech-urlhaus-recent` | `Auth-Key` | Abuse.ch URLhaus v2 CSV | `1h` (`3600s`) | `100` | `84` | Recent malware URLs (`url_status == "online"` promotes dedicated hosts/IPs) |
| `abusech-threatfox-recent` | `Auth-Key` | Abuse.ch ThreatFox v2 CSV | `1h` (`3600s`) | `50` | `86` | Active C2 & phishing domains, URLs, `ip:port` endpoints, and hashes |
| `phish-cert-pl` | Keyless | CERT Polska / NASK (`hole.cert.pl`) | `30m` (`1800s`) | `10,000` | `62` | Verified active phishing & fraud domains |
| `malware-urlhaus-online` | Keyless | Abuse.ch URLhaus (`text_online`) | `30m` (`1800s`) | `100` | `68` | Currently online malware distribution payload domains |
| `phish-phishunt` | Keyless | Phishunt (`phishunt.io`) | `1h` (`3600s`) | `50` | `58` | Verified active phishing URLs & hostnames |
| `phish-openphish` | Keyless | OpenPhish Community (`openphish.com`) | `1h` (`3600s`) | `50` | `65` | Active credential-phishing URLs & hostnames |
| `phish-db-new-today` | Keyless | `Phishing.Database` (`NEW-today`) | `1h` (`3600s`) | `0` | `60` | Newly observed active phishing domains today (`PyFunceble`-tested) |
| `phish-army` | Keyless | Phishing Army Extended (`phishing.army`) | `4h` (`14400s`) | `20,000` | `54` | Normalized multi-tenant-safe phishing domain blocklist |
| `phish-malware-filter` | Keyless | `malware-filter` Phishing Domains | `4h` (`14400s`) | `2,000` | `56` | Curated active phishing domain blocklist |
| `phish-db-domains` | Keyless | `Phishing.Database` (`ACTIVE` domains) | `12h` (`43200s`) | `50,000` | `55` | Active `PyFunceble`-validated phishing domains corpus |
| `phish-db-urls` | Keyless | `Phishing.Database` (`ACTIVE` links) | `12h` (`43200s`) | `50,000` | `58` | Active `PyFunceble`-validated phishing full links corpus |

### Layer 2 — Malicious Sending IPs, Botnets & Hijacked Subnets (SMTP Connection Layer)
| Feed Key | Upstream Maintainer | Default TTL | Min Records | Weight | Purpose |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `ip-spamhaus-drop-v4` | Spamhaus Project (`drop_v4.json`) | `4h` (`14400s`) | `500` | `92` | "Don't Route Or Peer" hijacked & cybercrime IPv4 CIDR netblocks |
| `ip-spamhaus-drop-v6` | Spamhaus Project (`drop_v6.json`) | `4h` (`14400s`) | `50` | `92` | "Don't Route Or Peer" hijacked & cybercrime IPv6 CIDR netblocks |
| `ip-blocklist-de-mail` | Blocklist.de (`lists/mail.txt`) | `30m` (`1800s`) | `500` | `78` | IPs attacking Postfix/SMTP/Mail servers in the last 48 hours |
| `ip-blocklist-de-bots` | Blocklist.de (`lists/bots.txt`) | `30m` (`1800s`) | `500` | `76` | Active botnet & brute-force attacker IPs |
| `ip-feodo-tracker` | Abuse.ch Feodo Tracker (`CC0`) | `30m` (`1800s`) | `0` | `94` | Active Dridex, Emotet, QakBot & Pikabot botnet C2 IPs |
| `ip-ipsum-level3` | IPsum by `stamparm` (`levels/3.txt`) | `12h` (`43200s`) | `1,000` | `85` | High-confidence bad IPs corroborated across 3+ independent blocklists |
| `ip-phish-db-active` | `Phishing.Database` (`phishing-IPs-ACTIVE`) | `12h` (`43200s`) | `500` | `74` | Active `PyFunceble`-verified phishing infrastructure IPs |

### Layer 3 — Disposable, Burner & Free Email Providers (`From` / `Reply-To`)
| Feed Key | Upstream Maintainer | Default TTL | Min Records | Weight | Purpose |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `email-disposable-mx` | `disposable-email-domains` (`domains_mx.txt`) | `12h` (`43200s`) | `5,000` | `90` | Daily DNS/MX-validated active disposable email domains |
| `email-disposable-blocklist` | `disposable-email-domains` (`CC0`) | `24h` (`86400s`) | `2,000` | `85` | Primary disposable/throwaway email provider registry |
| `email-burner-providers` | `wesbos/burner-email-providers` (`MIT`) | `24h` (`86400s`) | `5,000` | `80` | Temporary/burner inbox domains |
| `email-mailchecker` | `FGRibreau/mailchecker` (`MIT`) | `24h` (`86400s`) | `10,000` | `80` | Extended international disposable email domains |
| `email-free-providers` | `willwhite/freemail` (`MIT`) | `24h` (`86400s`) | `2,000` | `90` | Consumer free mailbox providers (`is_free_email = true`) |

### Layer 4 — Malware Attachment `SHA-256` Hashes
| Feed Key | Auth | Upstream Maintainer | Default TTL | Min Records | Weight | Purpose |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `abusech-bazaar-recent` | `Auth-Key` | Abuse.ch MalwareBazaar v2 CSV | `1h` (`3600s`) | `20` | `90` | Recent malware sample `SHA-256` hashes & signature families |
| `abusech-urlhaus-v1-payloads` | `Auth-Key` | Abuse.ch URLhaus v1 Payloads JSON | `15m` (`900s`) | `10` | `88` | Real-time malware payload `SHA-256` digests distributed via URLhaus |
| `hash-malicious-sha256` | Keyless | `romainmarcoux/malicious-hash` (`MIT`) | `1h` (`3600s`) | `10,000` | `86` | Hourly-updated malware binary `SHA-256` indicators (`80K+` hashes) |
| `hash-botvrij-sha256` | Keyless | Botvrij.eu / CIRCL OSINT | `4h` (`14400s`) | `5` | `82` | Cryptographic `SHA-256` hashes of malware attachments |

All 30 feeds are seeded into `dgspamguard_feed_sources` and controllable at runtime via `dgspamguard feed {list | enable | disable | set-url | set-ttl}` (with a hard `>= 3600s` floor enforced on Spamhaus DROP feeds to guarantee fair-use compliance).

---

## 2. False-Positive Prevention Policy

1. **Sanity Record Minimums**: If an upstream feed returns an empty or truncated file below its `min_records` threshold, `dgspamguard` rejects the fresh response and falls back cleanly.
2. **Tranco Top-100K & Top-10K Shields**: Exact domains ranked `1..=100,000` and enterprise roots ranked `1..=10,000` in the Tranco research list (`https://tranco-list.eu`) are protected from domain-level `malicious` verdicts and RPZ NXDOMAIN rules.
3. **URLhaus RPZ Safeguards**: Per Abuse.ch's official guidance (`https://urlhaus.abuse.ch/api/`), offline URLs in `recent.csv` and compromised legitimate hosts marked `abused_legit_*` in `spamhaus_dbl` are matched strictly at exact-URL granularity (`POST /v1/url/check`), never promoted to whole-domain RPZ blocks.
4. **Shared-Hosting Isolation**:
   - **Subdomain-isolated platforms** (Mozilla Private PSL entries + `shared_hosting` allowlist entries like `github.io`, `pages.dev`, `vercel.app`) never have their bare root blocked, while dedicated malicious tenant subdomains (`login-secure.pages.dev`) are blocked.
   - **Path-isolated platforms** (`docs.google.com`, `drive.google.com`, `dropbox.com`, `onedrive.live.com`, `raw.githubusercontent.com`, `discord.com`, `t.me`) never have their hostname blocked; only exact canonical URLs (`SHA-256`) are flagged.
5. **Bogon & Public DNS Resolver IP Shield**: Loopback, RFC 1918 private networks, CGNAT, multicast, overly broad prefixes (`< /8` IPv4, `< /19` IPv6), and major public DNS resolvers (`1.1.1.1`, `8.8.8.8`, `9.9.9.9`, `208.67.222.222` and IPv6 equivalents) can never be ingested into `dgspamguard_ips`.

---

## 3. Operator Overrides & Delisting

```bash
# Permanently trust an apex domain and all of its subdomains:
dgspamguard allowlist add example-partner.com --kind trusted --notes "Verified B2B partner"

# Register an internal or regional multi-tenant platform root:
dgspamguard allowlist add apps.internal-cloud.net --kind shared_hosting --notes "Tenant subdomain platform"

# Recompile and flip the active slot immediately:
dgspamguard sync --force
```

For false-positive reports on `https://dgspamguard.daviante.org` or [`daviante-org/dgspamguard-data`](https://github.com/daviante-org/dgspamguard-data), contact `code@daviante.org`.
