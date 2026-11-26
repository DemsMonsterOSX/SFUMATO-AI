#!/usr/bin/env bash
# Sfumato SOAR VM bootstrap: Shuffle (open-source SOAR, https://github.com/Shuffle/Shuffle) with Docker Compose.
# GCE startup script, runs as root at EVERY boot, idempotent. Workflows and the OpenSearch data live on the VM disk.
# Metadata: shuffle-password, shuffle-apikey, shuffle-secret. Markers: SOAR_READY, SOAR_FAILED.
# SECURITY: the UI (HTTPS 3443, self-signed certificate) is opened by a firewall rule only to the address given at creation;
# the backend (5001) and OpenSearch (9200) are reachable only from the project's internal network, or not at all.
set -uo pipefail
exec > >(tee -a /var/log/sfumato-soar-startup.log) 2>&1
echo "== soar startup $(date -u +%FT%TZ)"
MD=http://metadata.google.internal/computeMetadata/v1/instance/attributes
attr() { curl -fsS -H 'Metadata-Flavor: Google' "$MD/$1" 2>/dev/null || true; }
fail() { echo "SOAR_FAILED: $*"; exit 1; }
SPW=$(attr shuffle-password); SKEY=$(attr shuffle-apikey); SSEC=$(attr shuffle-secret)
[ -n "$SPW" ] && [ -n "$SKEY" ] && [ -n "$SSEC" ] || fail "missing metadata"
VERSION=v2.3.0

if ! swapon --show | grep -q /swapfile; then
  [ -f /swapfile ] || { fallocate -l 4G /swapfile && chmod 600 /swapfile && mkswap /swapfile; }
  swapon /swapfile || echo "warning: swap not enabled"
  grep -q /swapfile /etc/fstab || echo '/swapfile none swap sw 0 0' >> /etc/fstab
fi
sysctl -w vm.max_map_count=262144 >/dev/null
echo 'vm.max_map_count=262144' > /etc/sysctl.d/99-opensearch.conf

if [ ! -f /opt/.sfumato-soar-installed ]; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y && apt-get install -y --no-install-recommends curl ca-certificates gnupg git python3 || fail "base packages failed"
  curl -fsSL https://download.docker.com/linux/debian/gpg -o /tmp/docker.key || fail "docker key download failed"
  FP=$(gpg --show-keys --with-colons /tmp/docker.key | awk -F: '/^fpr:/{print $10; exit}')
  [ "$FP" = "9DC858229FC7DD38854AE2D88D81803C0EBFCD88" ] || fail "Docker signing key fingerprint mismatch ($FP)"
  install -m 0755 -d /etc/apt/keyrings
  gpg --dearmor < /tmp/docker.key > /etc/apt/keyrings/docker.gpg
  echo "deb [signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian bookworm stable" > /etc/apt/sources.list.d/docker.list
  apt-get update -y && apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin || fail "docker packages failed"
  git clone --depth 1 --branch "$VERSION" https://github.com/Shuffle/Shuffle.git /opt/Shuffle || fail "git clone failed"
  touch /opt/.sfumato-soar-installed
fi
systemctl enable --now docker >/dev/null 2>&1

cd /opt/Shuffle || fail "no Shuffle directory"
setenv() { if grep -q "^$1=" .env; then sed -i "s|^$1=.*|$1=$2|" .env; else echo "$1=$2" >> .env; fi; }
setenv SHUFFLE_DEFAULT_USERNAME admin
setenv SHUFFLE_DEFAULT_PASSWORD "$SPW"
setenv SHUFFLE_DEFAULT_APIKEY "$SKEY"
setenv SHUFFLE_ENCRYPTION_MODIFIER "$SSEC"
setenv TZ UTC
chmod 600 .env
mkdir -p shuffle-database shuffle-apps shuffle-files
chown -R 1000:1000 shuffle-database
docker compose up -d || fail "docker compose up failed"

for i in $(seq 1 120); do
  curl -ks -o /dev/null -w '%{http_code}' https://127.0.0.1:3443/ 2>/dev/null | grep -q '^200$' && curl -fs http://127.0.0.1:5001/api/v1/_ah/health >/dev/null 2>&1 && break
  sleep 5
done
curl -ks -o /dev/null -w '%{http_code}' https://127.0.0.1:3443/ 2>/dev/null | grep -q '^200$' || { docker compose ps; docker compose logs --tail 20; fail "shuffle frontend did not answer"; }
echo "SOAR_READY shuffle=$VERSION containers=$(docker ps -q | wc -l)"
