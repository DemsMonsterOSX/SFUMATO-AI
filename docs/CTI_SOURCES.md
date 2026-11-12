# Cyber threat intelligence sources

All integrations are **read-only lookups**. Each adapter (`backend/app/cti/`) separates `fetch_raw` (network) from `parse`
(pure normalisation); demonstration fixtures go through the very same `parse` code as live responses.

| Provider | Access | Indicators | Auth | Status of the integration |
|---|---|---|---|---|
| **CISA KEV** | JSON feed `known_exploited_vulnerabilities.json` | CVE | none | **Verified live** (CVE-2023-4966 and CVE-2024-4577 returned from the real catalogue) |
| **ThreatFox** (abuse.ch) | `POST https://threatfox-api.abuse.ch/api/v1/` (`search_ioc`, `search_hash`) | IP, domain, URL, MD5, SHA-256 | free `Auth-Key` header | Written against the documented API; **not run against the live service** (no key available) |
| **URLhaus** (abuse.ch) | `POST https://urlhaus-api.abuse.ch/v1/{url,host,payload}/` | IP, domain, URL, hashes | same `Auth-Key` | Same: documented format only |
| **AlienVault OTX** | `GET /api/v1/indicators/{type}/{value}/general` | IP, domain, URL, hashes, CVE | free `X-OTX-API-KEY` | Same: documented format only |
| **OpenCTI** | GraphQL (`stixCyberObservables`, `indicators`) | all types, including internal ones | token | Same; FULL mode compose file provided, never started here |
| MITRE ATT&CK | OpenCTI connector (FULL) + a curated local technique table (`services/mitre.py`) used to validate the agent's technique IDs | — | — | Local table used in LITE |

Terms of use and fair-use limits change: check https://abuse.ch (free API subject to fair use; commercial use may need a
subscription), https://otx.alienvault.com and https://www.cisa.gov before relying on them. Rate limits are handled as
`rate_limited` provider statuses (HTTP 429 is retried with backoff, then reported).

Not integrated (documented as future work): public STIX/TAXII feeds, other free feeds.

## Enrichment workflow

1. **Extract** indicators from the declared list and from the alert fields (network, process, file, authentication,
   alert description, and the *decoded* PowerShell payload). Text only: nothing is executed.
2. **Normalise and de-duplicate** (refang `hxxp`/`[.]`, lowercase, canonical URL), reject malformed values (reported).
3. **Classify scope**: `public`, `private`, `loopback`, `link_local`, `documentation` (RFC 5737/3849/2606), `multicast`,
   `reserved`, `internal` (internal suffixes, single-label hosts, the organisation's own domains).
4. **Privacy filter** (`cti/engine.py::_eligible`): only `public` indicators may reach public providers. Private,
   internal and personal data (e-mails) are never sent; documentation values are never sent live; only the
   self-hosted OpenCTI may receive internal indicators.
5. **Query** eligible providers concurrently (timeout `CTI_TIMEOUT_SECONDS`, retries, cache).
6. **Store** every normalised result and the raw response (`cti_queries`).
7. **Correlate** into evidence: malicious/suspicious/allow-listed evidence is weighted by provider count, confidence and
   freshness (> 180 days is discounted). **An indicator no provider knows produces neutral evidence — unknown is never benign.**

Per result the UI shows provider, indicator, query time, status, verdict, threat type, malware, actors, confidence,
first/last seen, freshness, references, duration, HTTP status, API error and the **data origin**.

## Demo vs live

* **Reproducible demo mode**: answers come from `examples/fixtures/cti/*.json`, clearly marked `DEMO FIXTURE` everywhere.
  They use documentation addresses (`203.0.113.0/24`, `*.test`, `*.example`), so no real infrastructure is accused.
  The CISA KEV fixture is a snapshot of the public entry for CVE-2024-4577. Works with no network.
* **Live intelligence mode**: real calls to every *configured* provider. Documentation addresses are not routable and
  are therefore never sent, so the bundled scenarios mostly produce `not_found` live — use real public indicators or
  CVEs to see live hits.
