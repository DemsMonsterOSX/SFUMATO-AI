# API documentation

Interactive OpenAPI docs: `http://localhost:8000/docs` (FastAPI). Base path `/api/v1`.

**Authentication**: header `X-API-Key: <key>` (keys in `API_KEYS`). Only `GET /api/v1/health` is public.
**Limits**: request body ≤ 256 KiB (`413`), 120 requests/min per key (`429`, `Retry-After: 60`; SSE streams are exempt).

| Status | Meaning |
|---|---|
| 202 | Incident accepted |
| 401 | Missing/invalid API key |
| 409 | Incident ID already exists (use `?resubmit=true`), or report requested before the investigation finished |
| 413 / 422 / 429 | Too large / schema validation failed (field-level `errors`) / rate limited |

## Submit an incident

```bash
curl -X POST "http://localhost:8000/api/v1/incidents?cti_mode=demo&resubmit=true" \
  -H "X-API-Key: $KEY" -H "Content-Type: application/json" \
  --data @examples/incidents/02_suspicious_powershell.json
# {"incident_id":"SFUMATO-2026-0102-R2","status":"queued","message":"Incident accepted for investigation"}
```

Query parameters: `cti_mode=demo|live` (default `CTI_MODE`), `resubmit=true` (store a new run as `<id>-R<n>`),
`via=api|simulator`.

### Incident schema

`GET /api/v1/schema/incident` returns the JSON Schema. Required: `incident_id` (`[A-Za-z0-9._:-]{3,128}`), `timestamp`
(timezone-aware ISO 8601), `source`, `severity` (`informational|low|medium|high|critical`), `alert{name,description?,category?}`.
Optional blocks: `asset`, `user`, `process`, `network`, `authentication`, `file`, `indicators[]`
(`ipv4|ipv6|domain|hostname|url|md5|sha1|sha256|email|cve`), `metadata` (detection_rule, confidence 0-100, tags,
change_ticket, maintenance_window, plus ≤ 32 scalar extra keys). Unknown top-level keys are rejected.

## Endpoints

| Method & path | Description |
|---|---|
| `GET /health` | Liveness + component health (public) |
| `GET /status` | SOAR, ML, AI and CTI subsystem status |
| `GET /stats` | Command-center statistics (counts, verdicts, 24 h timeline by alert time, recent alerts) |
| `GET /incidents` | List (`limit`, `offset`, `status`, `verdict`, `q`) |
| `GET /incidents/{id}` | Detail: raw + normalized JSON, report, playbook runs with task logs |
| `GET /incidents/{id}/report` | Final report (`409` until finished) |
| `GET /incidents/{id}/events` | Stored event history (`after=<seq>`) |
| `GET /incidents/{id}/events/stream` | Server-Sent Events (`event: investigation`, final `event: end`) |
| `GET /incidents/{id}/soar` | Playbook runs, task states, durations, logs |
| `GET /incidents/{id}/cti` | CTI queries with raw provider responses (`include_raw=false` to omit) |
| `GET /cti/status` | Providers: configuration, per-provider health, last errors, data origin |
| `GET /cti/indicators`, `GET /cti/graph` | Aggregated indicators; relationship graph from real provider data |
| `GET /soar/playbooks`, `GET /soar/runs` | Playbook definitions + statistics; recent executions |
| `GET /ml/model`, `POST /ml/reload` | Triage model, metrics; reload/retrain |
| `GET /ml/guide`, `POST /ml/guide/sync` | GUIDE reference model from the bucket |
| `GET /knowledge/status`, `POST /knowledge/sync`, `GET /knowledge/search?q=` | Knowledge base |
| `GET /ai/status` | AI provider selection and why |
| `GET /observatory/recent` | Recent ML/AI outputs |
| `GET /scenarios`, `GET /scenarios/{key}` | Bundled demo scenarios |
| `GET /settings`, `PUT /settings/credentials`, `GET /audit` | Effective config (no secrets), write-only credentials, audit log |

## Report structure (abridged)

```jsonc
{
  "incident_id": "...", "cti_mode": "demo",
  "indicators": [{"type":"ipv4","value":"...","scope":"documentation","shareable":false,"origins":["network.destination_ip"]}],
  "cti": {"results": [{"provider":"threatfox","verdict":"malicious","data_origin":"demo_fixture","duration_ms":3, ...}], "skipped": [...]},
  "evidence": [{"id":"EV-BEH-001","polarity":"malicious","weight":22,"title":"...","mitre":["T1059.001"]}],
  "ml": {"status":"classified","label":"true_positive","probabilities":{...},"reference":{"status":"...","p_threat":0.9}},
  "knowledge": {"passages":[{"evidence_id":"EV-KB-001","title":"...","score":0.71}]},
  "ai": {"provider":"ollama","mode":"llm","summary":"...","recommended_verdict":"TRUE_POSITIVE","knowledge_guidance":[...]},
  "decision": {"verdict":"TRUE_POSITIVE","threat_score":94,"confidence":95,"human_review_required":false,"rationale":[...]},
  "recommendations": [{"priority":"P1","action":"...","display_only":true,"automated":false}],
  "mitre": [{"id":"T1059.001","name":"...","evidence_ids":["EV-BEH-001"]}]
}
```

`data_origin` is `live`, `cache` or `demo_fixture`: demonstration data is never presented as live intelligence.

## SSE example

```bash
curl -N -H "X-API-Key: $KEY" http://localhost:8000/api/v1/incidents/SFUMATO-2026-0102/events/stream
```
Each event carries `seq`, `ts`, `type` (`incident|playbook|task|log|cti_result|milestone`), `stage`, `status`, `message`, `data`.
Pass `?after=<seq>` to resume after the last event you received (the stream replays from the database).

The dashboard calls the API through its own server-side proxy (`/api/backend/...`), which adds the key; the key is never
sent to the browser.
