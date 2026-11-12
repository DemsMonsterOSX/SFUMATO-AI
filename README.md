# Sfumato Autonomous SOC

Autonomous security-incident investigation platform. It takes in a JSON incident and runs it through a real SOAR playbook, then shows an explainable verdict in a web dashboard. The playbook:

- extracts and classifies the indicators;
- enriches them with CTI (OpenCTI, ThreatFox, URLhaus, AlienVault OTX, CISA KEV);
- analyses process, network and authentication behaviour;
- runs an ML triage model that can abstain;
- runs an AI investigator (Ollama, Anthropic or OpenAI-compatible, or a deterministic fallback);
- applies a transparent decision engine.

Created by **Florian Payet, Damien Leclercq and Adrien Scazzola**.

This is an original creation of **Florian Payet** ([@DemsMonsterOSX](https://github.com/DemsMonsterOSX)). © 2026 Florian Payet. All rights reserved: no licence is granted unless a `LICENSE` file says so.

> Response actions are **display-only**. Sfumato never blocks, isolates, disables or modifies anything.

## Start

```bash
./start.sh            # Linux/macOS  (or: docker compose up -d --build)
.\start.ps1           # Windows
```

Open http://localhost:3000. The API docs are at http://localhost:8000/docs, and the key is printed by the script (header `X-API-Key`).

| Option | Effect |
|---|---|
| `--full` / `-Full` | FULL mode: also deploys OpenCTI 6.9.9 with the MITRE and CISA KEV connectors (≈12–16 GB RAM free) |
| `--llm` / `-Llm` | Ollama in a container with an NVIDIA GPU (otherwise an Ollama installed on the host is used if it is running) |
| `--stop` / `-Stop` | Stops everything; data volumes are kept |

## Modes

- **REPRODUCIBLE DEMO (default)**: CTI answers come from local fixtures, clearly labelled `DEMO FIXTURE`, using only RFC 5737 / RFC 2606 documentation values. Works offline.
- **LIVE INTELLIGENCE**: real queries to the configured providers. Choose it per incident in the simulator, or set `CTI_MODE=live`. ThreatFox and URLhaus need a free key from https://auth.abuse.ch/, OTX needs a free key, CISA KEV needs none. Keys are entered in **Settings** (stored encrypted, write-only) or in `.env`.

## Cloud bucket, GUIDE model and knowledge base (optional)

Heavy computation happens on a free Kaggle notebook; a Google Cloud Storage bucket carries the small, **signed**
artifacts to Sfumato, which then runs offline.

- **Reference model** trained on Microsoft GUIDE (real true / false / benign-positive labels): second opinion
  capped at 10 points, abstains when unsure, never decides alone.
- **Knowledge base (RAG)** built from the Hugging Face dataset `Vyber07/cyber-security`: defensive guidance cited in
  the AI report, never counted as evidence.
- Remote artifacts are pickles, so they are only loaded if their HMAC signature and checksums verify
  (`ARTIFACT_SIGNING_KEY`). Sfumato's bucket credentials are read-only.

Step-by-step (20 € budget alert, bucket, service accounts, Kaggle): [ml/guide/README.md](ml/guide/README.md).
Settings: `ML_ARTIFACT_URI`, `KB_ARTIFACT_URI`, `ARTIFACT_SIGNING_KEY`, `GOOGLE_APPLICATION_CREDENTIALS` in `.env`.

## Submit an incident through the API

```bash
curl -X POST "http://localhost:8000/api/v1/incidents?resubmit=true" -H "X-API-Key: <key>" \
     -H "Content-Type: application/json" --data @examples/incidents/02_suspicious_powershell.json
```

## Development without Docker

```bash
python -m venv .venv && .venv/Scripts/pip install -r backend/requirements-dev.txt
cd backend && ../.venv/Scripts/python -m uvicorn app.main:app --port 8000   # SQLite + embedded worker
cd frontend && npm install && npm run dev                                    # http://localhost:3000
cd backend && ../.venv/Scripts/python -m pytest                              # 64 tests
```

## Documentation

[INSTALLATION](docs/INSTALLATION.md) · [DEMO_GUIDE](docs/DEMO_GUIDE.md) (5-10 min live demo) · [ARCHITECTURE](docs/ARCHITECTURE.md) ·
[API_DOCUMENTATION](docs/API_DOCUMENTATION.md) · [CTI_SOURCES](docs/CTI_SOURCES.md) · [MACHINE_LEARNING](docs/MACHINE_LEARNING.md) ·
[AI_AGENT](docs/AI_AGENT.md) · [SECURITY](docs/SECURITY.md) · [TROUBLESHOOTING](docs/TROUBLESHOOTING.md) ·
[GCP_DEPLOYMENT](docs/GCP_DEPLOYMENT.md) (free-tier VM, HTTPS, team login) ·
[Cloud bucket + GUIDE](ml/guide/README.md)

## Layout

`backend/app` contains the API, SOAR engine (`soar/`), CTI adapters (`cti/`), ML (`ml/`), AI agent (`agents/`), decision engine (`decision/`) and worker. `playbooks/` holds the executable YAML playbook, `config/organization.yml` the organisation context (change register, approved software…), `examples/` the scenarios and CTI fixtures, `ml/` the dataset, model and metrics, and `frontend/` the Next.js dashboard.
