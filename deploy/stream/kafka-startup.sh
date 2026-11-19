#!/usr/bin/env bash
# Sfumato Kafka broker bootstrap (GCE startup script, runs as root at EVERY boot, idempotent).
# One VM = one KRaft node that is both broker and controller; three VMs form the cluster (replication factor 3, min ISR 2).
# Inputs come from instance metadata: kafka-node-id, kafka-cluster-id, kafka-voters, kafka-version, kafka-sha512, kafka-heap.
# Markers on the serial console: KAFKA_READY (broker listening), TOPICS_READY (node 1 only, after topic creation).
# SECURITY: PLAINTEXT listeners, no authentication. Acceptable only because the brokers are reachable from the project's
# internal network only (no firewall rule opens 9092/9093 to the Internet). Do not expose these ports.
set -uo pipefail
exec > >(tee -a /var/log/sfumato-kafka-startup.log) 2>&1
echo "== kafka startup $(date -u +%FT%TZ)"
MD=http://metadata.google.internal/computeMetadata/v1/instance/attributes
attr() { curl -fsS -H 'Metadata-Flavor: Google' "$MD/$1" 2>/dev/null || true; }
fail() { echo "KAFKA_FAILED: $*"; exit 1; }

ID=$(attr kafka-node-id); CID=$(attr kafka-cluster-id); VOTERS=$(attr kafka-voters)
VER=$(attr kafka-version); SHA=$(attr kafka-sha512); HEAP=$(attr kafka-heap)
[ -n "$ID" ] && [ -n "$CID" ] && [ -n "$VOTERS" ] && [ -n "$VER" ] && [ -n "$SHA" ] || fail "missing metadata"
HEAP=${HEAP:-700m}
FQDN=$(hostname -f)

# swap: the e2-small has 2 GB of RAM
if ! swapon --show | grep -q /swapfile; then
  [ -f /swapfile ] || { fallocate -l 1G /swapfile && chmod 600 /swapfile && mkswap /swapfile; }
  swapon /swapfile || echo "warning: swap not enabled"
  grep -q /swapfile /etc/fstab || echo '/swapfile none swap sw 0 0' >> /etc/fstab
fi

# packages (first boot)
if [ ! -f /opt/.sfumato-packages-ok ]; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y && apt-get install -y --no-install-recommends openjdk-17-jre-headless python3 python3-venv python3-pip curl ca-certificates \
    || fail "apt install failed"
  touch /opt/.sfumato-packages-ok
fi

# Kafka: download (CDN first, then the main mirror, then the throttled archive) and verify the published SHA-512 before unpacking
if [ ! -d "/opt/kafka_2.13-$VER" ]; then
  ok=0
  for base in "https://dlcdn.apache.org/kafka" "https://downloads.apache.org/kafka" "https://archive.apache.org/dist/kafka"; do
    if curl -fsSL --max-time 900 "$base/$VER/kafka_2.13-$VER.tgz" -o /tmp/kafka.tgz; then ok=1; echo "downloaded from $base"; break; fi
  done
  [ "$ok" = 1 ] || fail "kafka download failed"
  echo "$SHA  /tmp/kafka.tgz" | sha512sum -c - || fail "kafka sha512 mismatch (refusing to run it)"
  tar -xzf /tmp/kafka.tgz -C /opt && rm -f /tmp/kafka.tgz
fi
ln -sfn "/opt/kafka_2.13-$VER" /opt/kafka
id kafka >/dev/null 2>&1 || useradd --system --home /var/lib/kafka --shell /usr/sbin/nologin kafka
mkdir -p /var/lib/kafka-logs /etc/kafka /var/lib/kafka /var/log/kafka
chown -R kafka:kafka /var/lib/kafka-logs /var/lib/kafka /var/log/kafka

cat > /etc/kafka/server.properties <<CFG
process.roles=broker,controller
node.id=$ID
controller.quorum.voters=$VOTERS
listeners=PLAINTEXT://0.0.0.0:9092,CONTROLLER://0.0.0.0:9093
advertised.listeners=PLAINTEXT://$FQDN:9092
controller.listener.names=CONTROLLER
inter.broker.listener.name=PLAINTEXT
listener.security.protocol.map=CONTROLLER:PLAINTEXT,PLAINTEXT:PLAINTEXT
log.dirs=/var/lib/kafka-logs
num.partitions=3
default.replication.factor=3
min.insync.replicas=2
offsets.topic.replication.factor=3
transaction.state.log.replication.factor=3
transaction.state.log.min.isr=2
auto.create.topics.enable=false
log.retention.hours=24
log.retention.bytes=536870912
log.segment.bytes=134217728
group.initial.rebalance.delay.ms=3000
CFG
chown kafka:kafka /etc/kafka/server.properties

if [ ! -f /var/lib/kafka-logs/meta.properties ]; then
  sudo -u kafka /opt/kafka/bin/kafka-storage.sh format -t "$CID" -c /etc/kafka/server.properties || fail "kafka-storage format failed"
fi

cat > /etc/systemd/system/kafka.service <<UNIT
[Unit]
Description=Apache Kafka (KRaft broker+controller)
After=network-online.target
Wants=network-online.target
[Service]
User=kafka
Environment="KAFKA_HEAP_OPTS=-Xmx$HEAP -Xms$HEAP"
Environment=LOG_DIR=/var/log/kafka
ExecStart=/opt/kafka/bin/kafka-server-start.sh /etc/kafka/server.properties
Restart=always
RestartSec=5
LimitNOFILE=100000
[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable kafka >/dev/null 2>&1
systemctl restart kafka

for i in $(seq 1 60); do
  (echo > /dev/tcp/127.0.0.1/9092) >/dev/null 2>&1 && break
  sleep 5
done
(echo > /dev/tcp/127.0.0.1/9092) >/dev/null 2>&1 || { journalctl -u kafka -n 30 --no-pager; fail "broker not listening"; }
echo "KAFKA_READY node=$ID $FQDN"

# node 1 creates the topics once the three brokers are in the quorum (idempotent)
if [ "$ID" = "1" ]; then
  B=localhost:9092
  for i in $(seq 1 40); do
    n=$(/opt/kafka/bin/kafka-broker-api-versions.sh --bootstrap-server $B 2>/dev/null | grep -c 'id: ')
    [ "$n" -ge 3 ] && break
    sleep 10
  done
  mk() { /opt/kafka/bin/kafka-topics.sh --bootstrap-server $B --create --if-not-exists --topic "$1" --partitions "$2" --replication-factor 3 --config min.insync.replicas=2 --config retention.ms="$3"; }
  mk network-flows 6 86400000
  mk network-flows-dlq 1 604800000
  mk alerts 3 86400000
  mk cve-events 3 604800000
  /opt/kafka/bin/kafka-topics.sh --bootstrap-server $B --describe
  echo "TOPICS_READY brokers=$n"
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
BUCKET=$(attr stream-bucket); ROLES=$(attr stream-roles); ENVV=$(attr stream-env); VOTERS=$(attr kafka-voters)
[ -n "$BUCKET" ] || exit 0
TOKEN=$(curl -fsS -H 'Metadata-Flavor: Google' "$MD/instance/service-accounts/default/token" | python3 -c 'import sys,json;print(json.load(sys.stdin)["access_token"])') || exit 0
get() { # object dest
  local o; o=$(python3 -c 'import sys,urllib.parse;print(urllib.parse.quote(sys.argv[1],safe=""))' "$1")
  curl -fsS -H "Authorization: Bearer $TOKEN" "https://storage.googleapis.com/storage/v1/b/$BUCKET/o/$o?alt=media" -o "$2"
}
APP=/opt/sfumato-stream; mkdir -p $APP
id sfstream >/dev/null 2>&1 || useradd --system --home $APP --shell /usr/sbin/nologin sfstream
BOOT=$(echo "$VOTERS" | tr ',' '\n' | sed -E 's/^[0-9]+@//; s/:9093$/:9092/' | paste -sd, -)
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
