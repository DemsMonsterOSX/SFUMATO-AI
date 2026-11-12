#!/usr/bin/env bash
# Sfumato VM bootstrap. Runs as root at EVERY boot (GCE startup-script); idempotent.
# Inputs come from instance metadata: sfumato-bucket, sfumato-package, sfumato-package-sha256, sfumato-env, sfumato-team.
# Log: /var/log/sfumato-startup.log and the serial console (markers SFUMATO_READY / SFUMATO_FAILED).
set -uo pipefail
exec > >(tee -a /var/log/sfumato-startup.log) 2>&1
echo "== sfumato startup $(date -u +%FT%TZ)"
MD=http://metadata.google.internal/computeMetadata/v1
mdv() { curl -fsS -H 'Metadata-Flavor: Google' "$MD/$1" 2>/dev/null || true; }
attr() { mdv "instance/attributes/$1"; }
REV=$(attr sfumato-rev)   # set by the deploy script; lets it tell this boot's markers from an older boot's
fail() { echo "SFUMATO_FAILED REV=$REV: $*"; exit 1; }

BUCKET=$(attr sfumato-bucket); PKG=$(attr sfumato-package); SHA=$(attr sfumato-package-sha256)
[ -n "$BUCKET" ] && [ -n "$PKG" ] && [ -n "$SHA" ] || fail "missing package metadata"
APP=/opt/sfumato; DATA=/var/lib/sfumato

# --- swap (the free e2-micro has 1 GB of RAM) -------------------------------------------------
if ! swapon --show | grep -q /swapfile; then
  [ -f /swapfile ] || { fallocate -l 2G /swapfile && chmod 600 /swapfile && mkswap /swapfile; }
  swapon /swapfile || echo "warning: swap not enabled"
  grep -q /swapfile /etc/fstab || echo '/swapfile none swap sw 0 0' >> /etc/fstab
fi

# --- system packages (first boot only) ---------------------------------------------------------
if [ ! -f $APP/.packages-ok ]; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y && apt-get install -y --no-install-recommends python3 python3-venv python3-pip nodejs caddy libgomp1 curl ca-certificates \
    || fail "apt install failed"
  mkdir -p $APP && touch $APP/.packages-ok
fi
id sfumato >/dev/null 2>&1 || useradd --system --home $DATA --shell /usr/sbin/nologin sfumato
mkdir -p $APP/releases $DATA/ml/models $DATA/ml/evaluation $DATA/kb $DATA/fastembed

# --- package: download from the (private) bucket with the VM's own identity, verify sha256 ------
if [ ! -d "$APP/releases/$SHA" ]; then
  TOKEN=$(mdv instance/service-accounts/default/token | python3 -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')
  OBJ=$(python3 -c 'import sys,urllib.parse;print(urllib.parse.quote(sys.argv[1],safe=""))' "$PKG")
  curl -fsS -H "Authorization: Bearer $TOKEN" "https://storage.googleapis.com/storage/v1/b/$BUCKET/o/$OBJ?alt=media" -o /tmp/pkg.tgz \
    || fail "package download failed"
  [ "$(sha256sum /tmp/pkg.tgz | cut -d' ' -f1)" = "$SHA" ] || fail "package sha256 mismatch (refusing to run it)"
  mkdir -p "$APP/releases/$SHA.tmp" && tar -xzf /tmp/pkg.tgz -C "$APP/releases/$SHA.tmp" && mv "$APP/releases/$SHA.tmp" "$APP/releases/$SHA"
  rm -f /tmp/pkg.tgz
fi
ln -sfn "$APP/releases/$SHA" $APP/current
ls -1dt $APP/releases/*/ | grep -v "/$SHA/" | tail -n +2 | xargs -r rm -rf   # keep current + 1 previous release

# --- python environment (reinstalled only when requirements change) ----------------------------
REQ=$APP/current/backend/requirements.txt
if [ ! -x $APP/venv/bin/python ] || [ "$(sha256sum $REQ | cut -d' ' -f1)" != "$(cat $APP/venv/.req-sha 2>/dev/null)" ]; then
  python3 -m venv $APP/venv && $APP/venv/bin/pip install --no-cache-dir -r $REQ || fail "pip install failed"
  sha256sum $REQ | cut -d' ' -f1 > $APP/venv/.req-sha
fi
cp -f $APP/current/ml/models/* $DATA/ml/models/ 2>/dev/null || true
cp -f $APP/current/ml/evaluation/* $DATA/ml/evaluation/ 2>/dev/null || true
chown -R sfumato:sfumato $DATA

# --- configuration (secrets live only in instance metadata, never in the bucket) ---------------
mkdir -p /etc/sfumato
attr sfumato-env > /etc/sfumato/env
cat >> /etc/sfumato/env <<PATHS
REPO_DIR=$APP/current
DATABASE_URL=sqlite:////var/lib/sfumato/sfumato.db
ML_MODEL_DIR=$DATA/ml/models
ML_EVAL_DIR=$DATA/ml/evaluation
KB_DIR=$DATA/kb
KB_MODEL_CACHE=$DATA/fastembed
PATHS
chmod 640 /etc/sfumato/env && chgrp sfumato /etc/sfumato/env

cat > /etc/systemd/system/sfumato-api.service <<UNIT
[Unit]
Description=Sfumato API (FastAPI + embedded SOAR worker)
After=network-online.target
Wants=network-online.target
[Service]
User=sfumato
WorkingDirectory=$APP/current/backend
EnvironmentFile=/etc/sfumato/env
ExecStart=$APP/venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8000 --proxy-headers --forwarded-allow-ips 127.0.0.1
Restart=always
RestartSec=5
NoNewPrivileges=true
ProtectSystem=full
ProtectHome=true
[Install]
WantedBy=multi-user.target
UNIT
cat > /etc/systemd/system/sfumato-web.service <<UNIT
[Unit]
Description=Sfumato dashboard (Next.js standalone)
After=sfumato-api.service
[Service]
User=sfumato
WorkingDirectory=$APP/current/web
EnvironmentFile=/etc/sfumato/env
Environment=NODE_ENV=production PORT=3000 HOSTNAME=127.0.0.1 BACKEND_URL=http://127.0.0.1:8000 NEXT_TELEMETRY_DISABLED=1 NODE_OPTIONS=--max-old-space-size=160
ExecStart=/usr/bin/node server.js
Restart=always
RestartSec=5
NoNewPrivileges=true
ProtectSystem=full
ProtectHome=true
[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable sfumato-api sfumato-web >/dev/null 2>&1
systemctl restart sfumato-api sfumato-web

# --- HTTPS + team login (Caddy). Hostname = <ip>.sslip.io, so no domain is needed ---------------
IP=$(mdv instance/network-interfaces/0/access-configs/0/external-ip)
[ -n "$IP" ] || fail "no external IP"
HOST="${IP//./-}.sslip.io"
TEAM=$(attr sfumato-team | grep -E '^[A-Za-z0-9._-]+ \$2[aby]\$' || true)
[ -n "$TEAM" ] || fail "no team account: refusing to publish the dashboard without a login"
{
  echo "$HOST {"
  echo "  basicauth {"
  echo "$TEAM" | sed 's/^/    /'
  echo "  }"
  echo "  header Strict-Transport-Security \"max-age=31536000\""
  echo "  reverse_proxy 127.0.0.1:3000 {"
  echo "    flush_interval -1"
  echo "  }"
  echo "}"
} > /etc/caddy/Caddyfile
caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile >/dev/null 2>&1 || { caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile 2>&1 | tail -5; fail "invalid Caddyfile"; }
systemctl enable caddy >/dev/null 2>&1
systemctl restart caddy
sleep 3
systemctl is-active --quiet caddy || { journalctl -u caddy -n 20 --no-pager; fail "caddy is not running"; }

# --- wait for the API ---------------------------------------------------------------------------
for i in $(seq 1 120); do
  curl -fsS http://127.0.0.1:8000/api/v1/health >/dev/null 2>&1 && break
  sleep 5
done
curl -fsS http://127.0.0.1:8000/api/v1/health >/dev/null 2>&1 || { journalctl -u sfumato-api -n 30 --no-pager; fail "API did not become healthy"; }
curl -fsS -o /dev/null http://127.0.0.1:3000/ || { journalctl -u sfumato-web -n 30 --no-pager; fail "dashboard did not start"; }
echo "SFUMATO_READY REV=$REV https://$HOST"
