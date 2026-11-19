#!/usr/bin/env bash
# Sfumato internal LLM bootstrap: Ollama serving a Qwen model on a CPU VM (GCE startup script, runs as root at EVERY boot, idempotent).
# Metadata: ollama-version, ollama-sha256, qwen-model. Serial markers: QWEN_READY, QWEN_SPEED, QWEN_FAILED.
# SECURITY: Ollama has no authentication. It listens on all interfaces but no firewall rule opens port 11434 to the Internet:
# only VMs of the project's internal network can reach it. The VM has no service account (no access to the project's data).
set -uo pipefail
exec > >(tee -a /var/log/sfumato-qwen-startup.log) 2>&1
echo "== qwen startup $(date -u +%FT%TZ)"
MD=http://metadata.google.internal/computeMetadata/v1/instance/attributes
attr() { curl -fsS -H 'Metadata-Flavor: Google' "$MD/$1" 2>/dev/null || true; }
fail() { echo "QWEN_FAILED: $*"; exit 1; }
VER=$(attr ollama-version); SHA=$(attr ollama-sha256); MODEL=$(attr qwen-model)
[ -n "$VER" ] && [ -n "$SHA" ] && [ -n "$MODEL" ] || fail "missing metadata"

if [ ! -f /opt/.sfumato-qwen-packages ]; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y && apt-get install -y --no-install-recommends zstd curl ca-certificates || fail "apt install failed"
  touch /opt/.sfumato-qwen-packages
fi

if [ ! -x /usr/local/bin/ollama ] || [ "$(cat /opt/.ollama-version 2>/dev/null)" != "$VER" ]; then
  curl -fsSL --max-time 1800 "https://github.com/ollama/ollama/releases/download/v$VER/ollama-linux-amd64.tar.zst" -o /tmp/ollama.tar.zst || fail "ollama download failed"
  echo "$SHA  /tmp/ollama.tar.zst" | sha256sum -c - || fail "ollama sha256 mismatch (refusing to run it)"
  zstd -d -c /tmp/ollama.tar.zst | tar -x -C /usr/local || fail "ollama unpack failed"
  rm -f /tmp/ollama.tar.zst
  echo "$VER" > /opt/.ollama-version
fi
id ollama >/dev/null 2>&1 || useradd --system --home /var/lib/ollama --shell /usr/sbin/nologin ollama
mkdir -p /var/lib/ollama/models && chown -R ollama:ollama /var/lib/ollama

cat > /etc/systemd/system/ollama.service <<'UNIT'
[Unit]
Description=Ollama (internal Qwen)
After=network-online.target
Wants=network-online.target
[Service]
User=ollama
Environment=OLLAMA_HOST=0.0.0.0:11434
Environment=OLLAMA_MODELS=/var/lib/ollama/models
Environment=OLLAMA_KEEP_ALIVE=30m
Environment=OLLAMA_NUM_PARALLEL=1
Environment=HOME=/var/lib/ollama
ExecStart=/usr/local/bin/ollama serve
Restart=always
RestartSec=5
[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable ollama >/dev/null 2>&1
systemctl restart ollama
for i in $(seq 1 60); do curl -fsS http://127.0.0.1:11434/api/version >/dev/null 2>&1 && break; sleep 2; done
curl -fsS http://127.0.0.1:11434/api/version >/dev/null 2>&1 || { journalctl -u ollama -n 20 --no-pager; fail "ollama did not start"; }

if ! sudo -u ollama env HOME=/var/lib/ollama OLLAMA_MODELS=/var/lib/ollama/models /usr/local/bin/ollama list | grep -q "^$MODEL"; then
  sudo -u ollama env HOME=/var/lib/ollama OLLAMA_MODELS=/var/lib/ollama/models /usr/local/bin/ollama pull "$MODEL" || fail "model pull failed"
fi
echo "QWEN_READY model=$MODEL ollama=$VER"

# warm-up and speed measurement (short fixed prompt; eval_count / eval_duration is the generation speed in tokens per second)
R=$(curl -fsS http://127.0.0.1:11434/api/generate -d "{\"model\":\"$MODEL\",\"prompt\":\"In two sentences, what is a SOC analyst?\",\"stream\":false,\"options\":{\"num_predict\":80,\"temperature\":0}}" || true)
echo "$R" | python3 -c '
import sys, json
try:
    d = json.load(sys.stdin)
    print("QWEN_SPEED tokens=%d generation_tokens_per_s=%.2f load_s=%.1f total_s=%.1f" % (d["eval_count"], d["eval_count"] / (d["eval_duration"] / 1e9), d.get("load_duration", 0) / 1e9, d["total_duration"] / 1e9))
except Exception as e:
    print("QWEN_SPEED unavailable", e)
'
