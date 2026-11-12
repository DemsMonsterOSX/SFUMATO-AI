#!/usr/bin/env bash
# Sfumato Autonomous SOC — one-command start.
#   ./start.sh            LITE mode (default, ~2-3 GB RAM)
#   ./start.sh --full     FULL mode with OpenCTI (needs ~12-16 GB RAM free)
#   ./start.sh --llm      also start a containerised Ollama with GPU (NVIDIA)
#   ./start.sh --stop     stop everything (data volumes are kept)
set -euo pipefail
cd "$(dirname "$0")"

FULL=0; LLM=0
for arg in "$@"; do
  case "$arg" in
    --full) FULL=1 ;;
    --llm) LLM=1 ;;
    --stop) docker compose -f docker-compose.yml -f docker-compose.full.yml --profile llm down; exit 0 ;;
    -h|--help) sed -n '2,7p' "$0"; exit 0 ;;
    *) echo "Unknown option: $arg"; exit 1 ;;
  esac
done

command -v docker >/dev/null 2>&1 || { echo "Docker is required: https://docs.docker.com/get-docker/"; exit 1; }
docker compose version >/dev/null 2>&1 || { echo "Docker Compose v2 is required (docker compose ...)."; exit 1; }
docker info >/dev/null 2>&1 || { echo "The Docker daemon is not running. Start Docker Desktop / dockerd and retry."; exit 1; }

rand() { LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c "${1:-32}"; }
uuid() { cat /proc/sys/kernel/random/uuid 2>/dev/null || python3 -c 'import uuid;print(uuid.uuid4())'; }
set_env() {  # set_env KEY VALUE — only if the key is empty or still the placeholder
  local key="$1" val="$2" cur
  cur=$(grep -E "^${key}=" .env | head -1 | cut -d= -f2- || true)
  if [ -z "$cur" ] || [[ "$cur" == *change-me* ]] || [[ "$cur" == change-this* ]] || [ "$cur" = "sfumato-db-password" ]; then
    if grep -qE "^${key}=" .env; then sed -i.bak "s|^${key}=.*|${key}=${val}|" .env && rm -f .env.bak; else echo "${key}=${val}" >> .env; fi
  fi
}

if [ ! -f .env ]; then
  cp .env.example .env
  echo "Created .env from .env.example"
fi
set_env API_KEYS "sfumato-$(rand 32)"
set_env SECRET_KEY "$(rand 48)"
set_env POSTGRES_PASSWORD "$(rand 24)"
set_env ARTIFACT_SIGNING_KEY "$(rand 48)"

FILES=(-f docker-compose.yml)
if [ "$FULL" = 1 ]; then
  set_env OPENCTI_ADMIN_PASSWORD "$(rand 20)"
  set_env OPENCTI_ADMIN_TOKEN "$(uuid)"
  set_env OPENCTI_ENCRYPTION_KEY "$(head -c 32 /dev/urandom | base64)"
  set_env OPENCTI_HEALTH_KEY "$(uuid)"
  set_env MINIO_ROOT_PASSWORD "$(rand 24)"
  set_env RABBITMQ_DEFAULT_PASS "$(rand 24)"
  set_env CONNECTOR_MITRE_ID "$(uuid)"
  set_env CONNECTOR_CISA_KEV_ID "$(uuid)"
  FILES+=(-f docker-compose.full.yml)
  echo "FULL mode: OpenCTI will be available at http://localhost:8080 (first start can take 5-10 minutes)."
fi
PROFILE=()
if [ "$LLM" = 1 ]; then
  PROFILE=(--profile llm)
  grep -q "^OLLAMA_URL=http://ollama:11434" .env || sed -i.bak "s|^OLLAMA_URL=.*|OLLAMA_URL=http://ollama:11434|" .env && rm -f .env.bak
fi

docker compose "${FILES[@]}" "${PROFILE[@]}" up -d --build

echo -n "Waiting for the API to become healthy"
for _ in $(seq 1 90); do
  if curl -fsS http://localhost:8000/api/v1/health >/dev/null 2>&1; then echo " ok"; break; fi
  echo -n "."; sleep 2
done
echo -n "Waiting for the dashboard"
for _ in $(seq 1 60); do
  if curl -fsS http://localhost:3000/ >/dev/null 2>&1; then echo " ok"; break; fi
  echo -n "."; sleep 2
done

KEY=$(grep -E '^API_KEYS=' .env | cut -d= -f2- | cut -d, -f1)
cat <<EOF

  Sfumato Autonomous SOC is running
  ─────────────────────────────────
  Dashboard     http://localhost:3000
  API docs      http://localhost:8000/docs
  API key       ${KEY}   (header X-API-Key)

  Try:  curl -X POST http://localhost:8000/api/v1/incidents -H "X-API-Key: ${KEY}" \\
          -H "Content-Type: application/json" --data @examples/incidents/02_suspicious_powershell.json

EOF
