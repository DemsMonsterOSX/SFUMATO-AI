# Troubleshooting

First look: `docker compose ps`, `docker compose logs api worker --tail 100`, `GET /api/v1/health`, `GET /api/v1/status`.

| Symptom | Cause / fix |
|---|---|
| `start.ps1` cannot be run | `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`, then re-run |
| "Docker daemon is not running" | Start Docker Desktop (Windows: WSL 2 must be installed: `wsl --install`, then reboot) |
| Port 3000/8000 already in use | Stop the other program, or change the published ports in `docker-compose.yml` |
| Dashboard shows "Backend unavailable"/502 | The `api` container is not healthy yet (first start ≈ 1-2 min: migrations + model training). Check `docker compose logs api` |
| `401 Missing or invalid API key` | Use the key printed by the start script (`API_KEYS` in `.env`). The dashboard proxy reads the same value: restart the `frontend` after changing it |
| `409 already exists` | Add `?resubmit=true` (a new run is stored as `<id>-R2`) |
| `422` on submit | The response lists each failing field; compare with `GET /api/v1/schema/incident` (timestamps need a timezone, e.g. `Z`) |
| AI shows `deterministic` | Ollama not reachable/model missing. `ollama pull qwen2.5:7b-instruct`; in Docker the host is `host.docker.internal:11434`. `GET /api/v1/ai/status` states the exact reason |
| AI report takes long | First call loads the model; parallel incidents queue (one generation at a time). Use `AI_PROVIDER=deterministic` for instant reports |
| Live CTI shows `not configured` | ThreatFox/URLhaus need `ABUSECH_AUTH_KEY`, OTX needs `OTX_API_KEY` (free). Enter them in **Settings** |
| Live CTI shows `unauthorized` | Key rejected: check it (abuse.ch keys come from https://auth.abuse.ch/) |
| Live CTI `rate_limited`/`timeout` | The provider throttled/was slow: it is retried, then reported; results are cached for an hour |
| Live mode finds nothing for the demo incidents | Their indicators are documentation addresses, never sent live. Use real public indicators or a CVE |
| ML `abstained` | Expected when telemetry is thin or the case is atypical: see `reason` on the ML tab |
| "model trained with scikit-learn X, runtime is Y" | Delete `ml/models/triage_model.joblib` (retrains automatically) or `POST /api/v1/ml/reload`. For the GUIDE model, retrain with the same scikit-learn version |
| Knowledge base `not_configured` | Set `KB_ARTIFACT_URI` or `KB_HF_REPO` (+ `HF_TOKEN`), then `POST /api/v1/knowledge/sync` |
| Knowledge base / model `Invalid signature` | `ARTIFACT_SIGNING_KEY` differs from the one used to publish. This is the protection working; use the same value on both sides |
| `Checksum mismatch` | The bucket content changed after publishing: republish from the notebook |
| GCS errors (403/404) | Reader service account needs `roles/storage.objectViewer` on the bucket; `GOOGLE_APPLICATION_CREDENTIALS` must be the in-container path (`/run/secrets/…`, file in `./secrets`) |
| `pgvector unavailable` in logs | The database is not a pgvector image: the knowledge base falls back to memory (fine locally). In Docker use `pgvector/pgvector:pg16` |
| Postgres won't start after switching the image | The old `pgdata` volume came from `postgres:16-alpine` (different libc). `docker compose down -v` (deletes data) |
| `database is locked` (local SQLite) | Several processes write at once; use Docker/PostgreSQL for concurrent loads |
| Pipeline stuck on a stage | The incident is requeued automatically after `JOB_STALE_AFTER_SECONDS` (300 s) without heartbeat; check the worker logs |
| Live view lags in a background tab | Browsers throttle timers in hidden tabs; events are all stored and appear when you return |
| Elasticsearch exits (FULL mode) | Raise `vm.max_map_count` to 262144 and give Docker ≥ 12 GB RAM |
| Kaggle notebook cannot reach Hugging Face/GCS | Internet must be on (requires a verified phone number) |

Logs: API/worker log to stdout (`docker compose logs`). Investigation events are in the database and under *Timeline* in the UI.
