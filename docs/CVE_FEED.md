# CVE feed into the bucket

Free public vulnerability data, collected into the project's Cloud Storage bucket and shown in the web app (**CVE Feed** page)
and by Da Vinci AI.

| Source | What | Access |
|---|---|---|
| CISA KEV | CVEs known to be exploited (due dates, ransomware use) | Free JSON file, no key |
| NIST NVD API 2.0 | Recent CVEs, CVSS scores, CWE | Free; an API key is optional and only raises the rate limit |
| FIRST EPSS API | Probability that a CVE is exploited in the next 30 days | Free |

## Run

```powershell
gcloud auth login ; gcloud config set project <PROJECT_ID>
python bigdata/cve_ingest.py --bucket <bucket> --days 30         # fetch and upload
python bigdata/cve_ingest.py --dry-run --days 3                  # fetch and summarise only, nothing uploaded
$env:NVD_API_KEY = "<free key>"                                  # optional: faster NVD paging (never commit it)
```

Without a key the script pauses 6.5 s between NVD pages (about 9 pages for 30 days: roughly a minute) and then looks up EPSS
scores in batches of 80 (a few minutes). The NVD window is split into chunks of at most 100 days (the API accepts 120).

## Outputs

`gs://<bucket>/cve/<YYYY-MM-DD>/` and `gs://<bucket>/cve/latest/`:

| File | Content |
|---|---|
| `kev.json` | Raw CISA KEV catalogue |
| `nvd_recent.jsonl.gz` | One compact line per CVE of the window (id, dates, status, description, best CVSS, CWE, KEV flag) |
| `summary.json` | Figures used by the web app: KEV totals and recent additions, NVD counts by severity and by day, top CVSS, top EPSS |
| `manifest.json` | Generation time, counts and sha256 of every file |

A copy of `summary.json` is also written to `ml/cve/summary.json` and ships with the web app as a fallback.

## How the web app reads it

`backend/app/services/cve.py` first reads `cve/latest/summary.json` from the bucket with the VM's own identity (metadata
server token, read-only scope), cached for 10 minutes: **a new ingestion shows up without redeploying**. If the bucket is not
reachable (local development), it falls back to the file in the package. API: `GET /api/v1/cves/summary`, `GET /api/v1/cves/search?q=`.

## Scheduling (not set up)

Today the ingestion is run by hand from a machine with `gcloud` (the VM's service account is read-only on purpose). Options for
a daily run, none of which is deployed here:

* Windows Task Scheduler on your PC running the command above;
* a Cloud Run job triggered by Cloud Scheduler (needs a container image and a service account with write access to the bucket);
* a scheduled GitHub Action (needs a bucket credential stored as a repository secret: weigh that risk).

## Limits

* Many CVEs have **no CVSS score during their first days** (the NVD marks them as awaiting analysis): severity counts are incomplete
  for the most recent days, and the page says so.
* EPSS is fetched only for KEV entries and for CVEs scored 7.0 or higher; very new CVEs have no EPSS value yet.
* Only CVEs *published* in the window are kept; older CVEs and later changes are not tracked.
* The search covers the lists held in `summary.json` (KEV additions, top CVSS, top EPSS), not the whole NVD.
* Third-party data: respect the terms of use of CISA, NIST and FIRST when you publish results.
