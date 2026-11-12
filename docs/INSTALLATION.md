# Installation

## Option A — Docker (recommended)

Prerequisites: Docker Desktop (Windows 11, with WSL 2) or Docker Engine + Compose v2. ~6 GB free disk. Nothing else.

```bash
./start.sh            # Linux / macOS
.\start.ps1           # Windows PowerShell
# or simply:  docker compose up -d --build
```

The script creates `.env` from `.env.example`, generates the secrets (`API_KEYS`, `SECRET_KEY`, `POSTGRES_PASSWORD`,
`ARTIFACT_SIGNING_KEY`), builds the images, waits for the health checks and prints the URLs and the API key.

| URL | What |
|---|---|
| http://localhost:3000 | Dashboard |
| http://localhost:8000/docs | OpenAPI documentation |
| http://localhost:8000/api/v1/health | Health (no authentication) |

Options: `--full` / `-Full` (OpenCTI), `--llm` / `-Llm` (Ollama container with NVIDIA GPU), `--stop` / `-Stop`.
On Windows, if scripts are blocked: `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`.

On first start the platform automatically: runs the database migrations, trains the ML model if no compatible
artifact exists (≈1 minute), seeds three demonstration incidents (demo CTI fixtures) and investigates them.

### Local LLM (Ollama)

* Easiest: install Ollama on the host and `ollama pull qwen2.5:7b-instruct` (≈4.7 GB; fits an 8 GB GPU). The
  containers reach it through `host.docker.internal:11434` (the default `OLLAMA_URL`).
* Or `./start.sh --llm` to run Ollama in Docker (requires the NVIDIA container toolkit).
* No LLM at all? The platform falls back to a deterministic, evidence-based report. Set `AI_PROVIDER=deterministic`
  for instant, reproducible reports.

### FULL mode (OpenCTI)

`./start.sh --full` generates the extra secrets and starts OpenCTI 6.9.9 (+ Elasticsearch, storage, RabbitMQ, workers,
MITRE ATT&CK and CISA KEV connectors). Allow 5-10 minutes on first start and ~12-16 GB of free RAM. OpenCTI UI:
http://localhost:8080 (admin e-mail and password are in `.env`). Elasticsearch may need `vm.max_map_count=262144` on Linux
(on Docker Desktop/WSL: `wsl -d docker-desktop sysctl -w vm.max_map_count=262144`).

## Option B — local development (no Docker)

Prerequisites: Python 3.12+ (3.13 works), Node 22, optionally Ollama.

```bash
python -m venv .venv
.venv/Scripts/pip install -r backend/requirements-dev.txt       # Linux/macOS: .venv/bin/pip
cd backend && ../.venv/Scripts/python -m uvicorn app.main:app --port 8000   # SQLite + embedded worker
cd frontend && npm install && npm run dev                                    # http://localhost:3000
cd backend && ../.venv/Scripts/python -m pytest                              # test suite
```

`backend/.env` (git-ignored) overrides the repository `.env` for local runs, e.g. `OLLAMA_URL=http://127.0.0.1:11434`.
Retrain the triage model: `cd backend && python -m app.ml.train`.

## Configuration

Everything is in `.env` (see `.env.example`, every variable is commented). Key settings:

| Variable | Default | Meaning |
|---|---|---|
| `CTI_MODE` | `demo` | `demo` = labelled local fixtures (offline) · `live` = real providers (per-incident override in the simulator/API) |
| `API_KEYS` | generated | Comma-separated keys for the `X-API-Key` header |
| `AI_PROVIDER` | `auto` | `auto` (local Ollama first; external only if `AI_ALLOW_EXTERNAL=true`) · `ollama` · `anthropic` · `openai` · `deterministic` |
| `OLLAMA_URL` / `OLLAMA_MODEL` | host Ollama / `qwen2.5:7b-instruct` | Local LLM |
| `ABUSECH_AUTH_KEY` | empty | Free key from https://auth.abuse.ch/ (ThreatFox + URLhaus) |
| `OTX_API_KEY` | empty | Free AlienVault OTX key |
| `OPENCTI_URL` / `OPENCTI_TOKEN` | empty (auto in FULL) | OpenCTI |
| `ML_ARTIFACT_URI`, `KB_ARTIFACT_URI`, `ARTIFACT_SIGNING_KEY`, `GOOGLE_APPLICATION_CREDENTIALS` | empty | Cloud bucket (see `ml/guide/README.md`) |

### What needs credentials (no hidden magic)

* **Demo mode works with none.** CISA KEV needs no key. ThreatFox/URLhaus (abuse.ch) and OTX need **free** keys:
  enter them once on the **Settings** page (stored encrypted, write-only) or in `.env`. Without them, live mode simply
  skips those providers and says so.
* External LLM keys are optional and ignored unless explicitly enabled.
* The Hugging Face dataset used for the knowledge base is gated: it needs your account and token.

## Data and persistence

Docker volumes: `pgdata` (database), `redisdata`, `kbdata` (downloaded knowledge base), `ollama` (with `--llm`).
`docker compose down` keeps them; `docker compose down -v` deletes everything.
