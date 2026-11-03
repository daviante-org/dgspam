# Data Sources, Ownership, Credits & Legal Attribution

**Project:** `daviante-org/dgspamguard` (`https://dgspamguard.daviante.org`)  
**Maintainer:** Daviante (`https://daviante.org`)  
**Legal, False-Positive & Provenance Contact:** `code@daviante.org`

---

## 1. Ownership Statement & Scope of License

1. **Software Ownership (`Apache-2.0`)**: Daviante owns and licenses solely the **DGSPAMGUARD** Rust compiler, normalization/subtraction engine, HTTP lookup server, CLI, container/Helm deployment manifests, and documentation in this repository under the [Apache License, Version 2.0](./LICENSE).
2. **No Claim of Ownership Over Third-Party Data**: **Daviante does not claim copyright, sui generis database ownership, or proprietary title over any third-party threat intelligence feeds, CSIRT warning lists, domain suffix registries, popularity rankings, SMTP IP blocklists, email taxonomies, or malware hash corpora** ingested by `dgspamguard` or compiled into [`daviante-org/dgspamguard-data`](https://github.com/daviante-org/dgspamguard-data). All rights in upstream data remain with their respective authors, CSIRTs, universities, and maintainers credited below.
3. **No Sublicensing of Upstream Rights**: Daviante's license applies strictly to its own software and compilation pipeline and **does not grant, transfer, or sublicense any proprietary rights belonging to upstream data providers**. Organizations, ISPs, managed security providers, or commercial vendors consuming compiled feeds remain solely responsible for reviewing and complying with the terms of each underlying upstream source (and can enable/disable any individual feed at runtime via `dgspamguard feed disable <feed_key>`).
4. **Nominative Attribution & Non-Endorsement**: All third-party names, marks, and domains cited in this repository belong to their respective owners and are referenced strictly for transparent data-provenance attribution, with zero implied affiliation, sponsorship, or endorsement.

---

## 2. Complete Upstream Data Inventory & Credits (30 Feeds Across 5 Layers)

### 2.1 Layer 0 — Domain Boundaries & False-Positive Subtraction Gates

| Feed Key | Upstream Owner / Authors | Canonical URL / Repository | License & Usage Scope |
| :--- | :--- | :--- | :--- |
| `psl-mozilla` | **Mozilla Foundation** & Public Suffix List contributors | `https://publicsuffix.org/list/public_suffix_list.dat` | **MPL-2.0** ([Mozilla Public License 2.0](https://mozilla.org/MPL/2.0/)) — used to compute ICANN & Private multi-tenant registrable boundaries. |
| `allow-tranco-top` | **Tranco Research Project** (Victor Le Pochat, Tom Van Goethem, Samaneh Tajalizadehkhoob, Maciej Korczyński, Wouter Joosen — KU Leuven / UGA) | `https://tranco-list.eu/top-1m.csv.zip` | **Academic Research Ranking** ([`tranco-list.eu`](https://tranco-list.eu/)). Used **solely internally during compilation** as a false-positive subtraction shield (`Top-100K` / `Top-10K`); **Tranco rankings are never exported or redistributed** in `dgspamguard-data` artifacts. |

**Academic Citation for Tranco:**
> Victor Le Pochat, Tom Van Goethem, Samaneh Tajalizadehkhoob, Maciej Korczyński, and Wouter Joosen. *"Tranco: A Research-Oriented Top Sites Ranking Hardened Against Manipulation."* Proceedings of the 26th Annual Network and Distributed System Security Symposium (NDSS), 2019. `https://doi.org/10.14722/ndss.2019.23386`

### 2.2 Layer 1 — Phishing, Malware Distribution & Botnet C2 Domains/URLs

| Feed Key | Upstream Owner / Maintainer | Canonical URL / Repository | License / Terms |
| :--- | :--- | :--- | :--- |
| `abusech-urlhaus-v1-urls` · `abusech-urlhaus-recent` | **abuse.ch — URLhaus** (Institute for Cybersecurity and Engineering ICE, Bern University of Applied Sciences) | `https://urlhaus.abuse.ch/` (`urlhaus-api.abuse.ch`) | **CC0 1.0 Universal (Public Domain)** ([URLhaus API Terms](https://urlhaus.abuse.ch/api/) — `abused_legit_*` & `online`-only RPZ safeguards enforced) |
| `abusech-threatfox-recent` | **abuse.ch — ThreatFox** (ICE, Bern University of Applied Sciences) | `https://threatfox.abuse.ch/` (`threatfox-api.abuse.ch`) | **CC0 1.0 Universal (Public Domain)** |
| `phish-cert-pl` | **CERT Polska / NASK** (National Research Institute, Poland) | `https://hole.cert.pl/domains/v2/domains.txt` | **Public CSIRT Warning Feed** ([CERT Polska Warning List](https://cert.pl/posts/2020/03/ostrzezenia_phishing/)) |
| `malware-urlhaus-online` · `phish-malware-filter` | **curben & `malware-filter` contributors** | `https://gitlab.com/malware-filter` (`malware-filter.gitlab.io`) | **MIT License / CC0 1.0** |
| `phish-openphish` | **OpenPhish** | `https://openphish.com/feed.txt` | **OpenPhish Community Feed** (subject to [OpenPhish Terms of Use](https://openphish.com/terms.html); commercial resale requires direct OpenPhish licensing) |
| `phish-phishunt` | **Phishunt** | `https://phishunt.io/feed.txt` | **Public Community Phishing Feed** ([`phishunt.io`](https://phishunt.io/)) |
| `phish-army` | **Andrea Draghetti — Phishing Army** | `https://phishing.army/download/phishing_army_blocklist_extended.txt` | **Free Public Blocklist** ([Phishing Army License](https://phishing.army/) — generator GPLv3; aggregated feed provided "AS IS" without transferring upstream rights) |
| `phish-db-domains` · `phish-db-urls` · `phish-db-new-today` | **Mitchell Krog, Nissar Chababy (`@funilrys`), Funceble & `Phishing.Database` contributors** | `https://github.com/Phishing-Database/Phishing.Database` | **MIT License** |

### 2.3 Layer 2 — Malicious Sending IPs, Botnets & Hijacked Subnets (SMTP Connection Layer)

| Feed Key | Upstream Owner / Maintainer | Canonical URL / Repository | License / Attribution Requirements |
| :--- | :--- | :--- | :--- |
| `ip-spamhaus-drop-v4` · `ip-spamhaus-drop-v6` | **The Spamhaus Project** (`© The Spamhaus Project`) | `https://www.spamhaus.org/drop/drop_v4.json` · `drop_v6.json` | **Free with Attribution**: Provided free of charge by **The Spamhaus Project** ([Spamhaus DROP](https://www.spamhaus.org/drop/)). Underlying copyright and database rights remain with The Spamhaus Project; `>= 1h` (`4h` default) polling floor enforced in code. |
| `ip-feodo-tracker` | **abuse.ch — Feodo Tracker** (ICE, Bern University of Applied Sciences) | `https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt` | **CC0 1.0 Universal (Public Domain)** |
| `ip-ipsum-level3` | **Miroslav Stampar (`@stamparm`) — IPsum** | `https://github.com/stamparm/ipsum` (`levels/3.txt`) | **The Unlicense (Public Domain)** |
| `ip-blocklist-de-mail` · `ip-blocklist-de-bots` | **Martin Schurig & Blocklist.de contributors** | `https://lists.blocklist.de/lists/mail.txt` · `bots.txt` | **Free Community Abuse Feed** ([`www.blocklist.de`](https://www.blocklist.de/)) |
| `ip-phish-db-active` | **Mitchell Krog, Nissar Chababy (`@funilrys`) & `Phishing.Database` contributors** | `https://github.com/Phishing-Database/Phishing.Database` (`phishing-IPs-ACTIVE.txt`) | **MIT License** |

### 2.4 Layer 3 — Disposable, Burner & Free Email Provider Taxonomies

| Feed Key | Upstream Owner / Maintainer | Canonical URL / Repository | License |
| :--- | :--- | :--- | :--- |
| `email-disposable-mx` | **`disposable` contributors** | `https://github.com/disposable/disposable-email-domains` (`domains_mx.txt`) | **CC0 1.0 / Open Domain List** |
| `email-disposable-blocklist` | **Martenson & `disposable-email-domains` contributors** | `https://github.com/disposable-email-domains/disposable-email-domains` | **CC0 1.0 Universal (Public Domain)** |
| `email-burner-providers` | **Wes Bos (`@wesbos`) & contributors** | `https://github.com/wesbos/burner-email-providers` | **MIT License** |
| `email-mailchecker` | **Francois-Guillaume Ribreau (`@FGRibreau`) & contributors** | `https://github.com/FGRibreau/mailchecker` | **MIT License** |
| `email-free-providers` | **Will White (`@willwhite`) & contributors** | `https://github.com/willwhite/freemail` | **MIT License** |

### 2.5 Layer 4 — Malware Attachment `SHA-256` Hashes & Baseline Mail Rule Grammar

| Feed Key / Asset | Upstream Owner / Maintainer | Canonical URL / Repository | License |
| :--- | :--- | :--- | :--- |
| `abusech-bazaar-recent` | **abuse.ch — MalwareBazaar** (ICE, Bern University of Applied Sciences) | `https://bazaar.abuse.ch/` (`mb-api.abuse.ch`) | **CC0 1.0 Universal (Public Domain)** |
| `abusech-urlhaus-v1-payloads` | **abuse.ch — URLhaus Payloads** (ICE, Bern University of Applied Sciences) | `https://urlhaus.abuse.ch/` (`urlhaus-api.abuse.ch`) | **CC0 1.0 Universal (Public Domain)** |
| `hash-malicious-sha256` | **Romain Marcoux (`@romainmarcoux`) — `malicious-hash`** | `https://github.com/romainmarcoux/malicious-hash` | **MIT License** |
| `hash-botvrij-sha256` | **Botvrij.eu / CIRCL OSINT** | `https://www.botvrij.eu/data/ioclist.sha256.raw` | **Open OSINT Indicator Feed** ([`botvrij.eu`](https://www.botvrij.eu/)) |
| `assets/dgmail-base-seed.json` | **Stalwart Labs LLC** (adapted by Daviante) | `https://github.com/stalwartlabs/spam-filter` | **Apache-2.0 OR MIT** (sanitized by Daviante to remove all external runtime `HttpLookup` and live third-party DNSBL queries, replacing them with self-hosted `dgspamguard` lookup maps) |

---

## 3. Rights-Holder, Attribution & False-Positive Contact

We are grateful to every CSIRT, university research group, registry, and open-source maintainer listed above for defending the open Internet.
- **Upstream Maintainers & Rights Holders**: To request an attribution update, polling rate change, or removal of a feed from default configuration, email **`code@daviante.org`**.
- **Domain / IP Delisting & False-Positive Review**: Include the exact indicator and snapshot version tag (`vYYYYMMDD.HHMM`) and email **`code@daviante.org`**.
