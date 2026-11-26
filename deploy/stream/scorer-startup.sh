#!/usr/bin/env bash
# Sfumato scorer worker bootstrap (GCE startup script, runs as root at EVERY boot, idempotent).
# An autoscaled worker: no Kafka broker, only the streaming application (scorer role). The streaming controller on kafka-1 starts
# the VM when the consumer lag stays high and stops it when the lag stays low (see streaming/autoscaler.py).
# The application sync below is the same as on the Kafka VMs (kafka-startup.sh): the code, models and roles come from the bucket
# and the instance metadata (stream-bucket, stream-roles, stream-env, kafka-voters). Marker: SCORER_WORKER_READY.
set -uo pipefail
exec > >(tee -a /var/log/sfumato-scorer-startup.log) 2>&1
echo "== scorer worker startup $(date -u +%FT%TZ)"
if [ ! -f /opt/.sfumato-packages-ok ]; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y && apt-get install -y --no-install-recommends python3 python3-venv python3-pip curl ca-certificates \
    || { echo "SCORER_WORKER_FAILED: apt install failed"; exit 1; }
  touch /opt/.sfumato-packages-ok
fi

# ---- application sync: code, models and roles come from the bucket / instance metadata (no SSH needed) ----------------------------
# The sync timer polls gs://BUCKET/stream/code/manifest.json every 30 s. When the sha256 of app.tgz changes it installs the new
# code and restarts the services; the roles of this VM (scorer, producer, cve-bridge, cve-consumer) and the scenario variables
# are read from the metadata keys stream-roles and stream-env, so changing them takes effect within a minute without a reboot.
cat > /usr/local/bin/sfumato-stream-sync.sh <<'EOS'
#!/usr/bin/env bash
set -uo pipefail
MD=http://metadata.google.internal/computeMetadata/v1
attr() { curl -fsS -H 'Metadata-Flavor: Google' "$MD/instance/attributes/$1" 2>/dev/null || true; }
BUCKET=$(attr stream-bucket); ROLES=$(attr stream-roles); ENVV=$(attr stream-env); VOTERS=$(attr kafka-voters); BOOTMD=$(attr kafka-bootstrap)
[ -n "$BUCKET" ] || exit 0
TOKEN=$(curl -fsS -H 'Metadata-Flavor: Google' "$MD/instance/service-accounts/default/token" | python3 -c 'import sys,json;print(json.load(sys.stdin)["access_token"])') || exit 0
get() { # object dest
  local o; o=$(python3 -c 'import sys,urllib.parse;print(urllib.parse.quote(sys.argv[1],safe=""))' "$1")
  curl -fsS -H "Authorization: Bearer $TOKEN" "https://storage.googleapis.com/storage/v1/b/$BUCKET/o/$o?alt=media" -o "$2"
}
APP=/opt/sfumato-stream; mkdir -p $APP
id sfstream >/dev/null 2>&1 || useradd --system --home $APP --shell /usr/sbin/nologin sfstream
BOOT=${BOOTMD:-$(echo "$VOTERS" | tr ',' '\n' | sed -E 's/^[0-9]+@//; s/:9093$/:9092/' | paste -sd, -)}
NEWENV=$(printf 'BOOTSTRAP=%s\nBUCKET=%s\n%s\n' "$BOOT" "$BUCKET" "$ENVV")
CHANGED=0
if [ "$NEWENV" != "$(cat /etc/sfumato-stream.env 2>/dev/null)" ]; then echo "$NEWENV" > /etc/sfumato-stream.env; chmod 640 /etc/sfumato-stream.env; chgrp sfstream /etc/sfumato-stream.env; CHANGED=1; fi
if get stream/code/manifest.json /tmp/stream-manifest.json 2>/dev/null; then
  SHA=$(python3 -c 'import json;print(json.load(open("/tmp/stream-manifest.json"))["sha256"])')
  REQ=$(python3 -c 'import json;print(json.load(open("/tmp/stream-manifest.json"))["requirements_sha256"])')
  if [ "$SHA" != "$(cat $APP/.sha 2>/dev/null)" ]; then
    get stream/code/app.tgz /tmp/stream-app.tgz && [ "$(sha256sum /tmp/stream-app.tgz | cut -d' ' -f1)" = "$SHA" ] || { echo "app sha mismatch"; exit 1; }
    rm -rf $APP/app && mkdir -p $APP/app && tar -xzf /tmp/stream-app.tgz -C $APP/app && echo "$SHA" > $APP/.sha
    if [ "$REQ" != "$(cat $APP/.req 2>/dev/null)" ] || [ ! -x $APP/venv/bin/python ]; then
      python3 -m venv $APP/venv && $APP/venv/bin/pip install --no-cache-dir -q -r $APP/app/requirements.txt && echo "$REQ" > $APP/.req || { echo "pip failed"; exit 1; }
    fi
    chown -R sfstream:sfstream $APP; CHANGED=1
  fi
fi
for role in scorer producer cve-bridge cve-consumer controller; do
  script=${role//-/_}; unit=sfumato-$role.service
  if [ ! -f /etc/systemd/system/$unit ]; then
    cat > /etc/systemd/system/$unit <<UNIT
[Unit]
Description=Sfumato streaming: $role
After=network-online.target kafka.service
[Service]
User=sfstream
EnvironmentFile=/etc/sfumato-stream.env
WorkingDirectory=$APP/app
ExecStart=$APP/venv/bin/python -u $APP/app/$script.py
Restart=always
RestartSec=5
[Install]
WantedBy=multi-user.target
UNIT
    systemctl daemon-reload
  fi
  if echo ",$ROLES," | grep -q ",$role,"; then
    [ -x $APP/venv/bin/python ] || continue
    systemctl is-active --quiet $unit || { systemctl enable --now $unit >/dev/null 2>&1; continue; }
    [ "$CHANGED" = 1 ] && systemctl restart $unit
  else
    systemctl is-enabled --quiet $unit 2>/dev/null && systemctl disable --now $unit >/dev/null 2>&1
  fi
done
exit 0
EOS
chmod +x /usr/local/bin/sfumato-stream-sync.sh
cat > /etc/systemd/system/sfumato-stream-sync.service <<UNIT
[Unit]
Description=Sfumato streaming application sync
[Service]
Type=oneshot
ExecStart=/usr/local/bin/sfumato-stream-sync.sh
UNIT
cat > /etc/systemd/system/sfumato-stream-sync.timer <<UNIT
[Unit]
Description=Run the Sfumato streaming sync every 30 seconds
[Timer]
OnBootSec=45
OnUnitActiveSec=30
AccuracySec=5
[Install]
WantedBy=timers.target
UNIT
systemctl daemon-reload
systemctl enable --now sfumato-stream-sync.timer >/dev/null 2>&1
echo "SYNC_TIMER_ENABLED"
echo "SCORER_WORKER_READY"
