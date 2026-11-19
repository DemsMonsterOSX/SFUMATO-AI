#!/usr/bin/env bash
# Sfumato Flink VM bootstrap (GCE startup script, runs as root at EVERY boot, idempotent).
# Standalone Flink (one JobManager + one TaskManager with 2 slots) running a Flink SQL job on the Kafka topic network-flows, and
# a small Python reader that publishes the job's results to the bucket for the web app.
# Metadata: flink-version, flink-sha512, kafka-connector-version, kafka-connector-sha1, kafka-bootstrap, stream-bucket, flink-sql.
# Markers: FLINK_READY, FLINK_JOB_SUBMITTED, FLINK_FAILED.
# SECURITY: the Flink web UI (port 8081) has no authentication: it listens on the internal network only and no firewall rule
# opens it to the Internet. The VM runs as the sfumato-stream service account (read/write on the bucket objects only).
set -uo pipefail
exec > >(tee -a /var/log/sfumato-flink-startup.log) 2>&1
echo "== flink startup $(date -u +%FT%TZ)"
MD=http://metadata.google.internal/computeMetadata/v1
attr() { curl -fsS -H 'Metadata-Flavor: Google' "$MD/instance/attributes/$1" 2>/dev/null || true; }
fail() { echo "FLINK_FAILED: $*"; exit 1; }
FV=$(attr flink-version); FSHA=$(attr flink-sha512); CV=$(attr kafka-connector-version); CSHA=$(attr kafka-connector-sha1)
BOOT=$(attr kafka-bootstrap); BUCKET=$(attr stream-bucket)
[ -n "$FV" ] && [ -n "$FSHA" ] && [ -n "$CV" ] && [ -n "$CSHA" ] && [ -n "$BOOT" ] && [ -n "$BUCKET" ] || fail "missing metadata"

if ! swapon --show | grep -q /swapfile; then
  [ -f /swapfile ] || { fallocate -l 2G /swapfile && chmod 600 /swapfile && mkswap /swapfile; }
  swapon /swapfile || echo "warning: swap not enabled"
  grep -q /swapfile /etc/fstab || echo '/swapfile none swap sw 0 0' >> /etc/fstab
fi
if [ ! -f /opt/.sfumato-flink-packages ]; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y && apt-get install -y --no-install-recommends openjdk-17-jre-headless python3 python3-venv python3-pip curl ca-certificates \
    || fail "apt install failed"
  touch /opt/.sfumato-flink-packages
fi
id flink >/dev/null 2>&1 || useradd --system --home /opt/flink --shell /usr/sbin/nologin flink

if [ ! -d "/opt/flink-$FV" ]; then
  ok=0
  for base in "https://dlcdn.apache.org/flink" "https://downloads.apache.org/flink" "https://archive.apache.org/dist/flink"; do
    if curl -fsSL --max-time 1200 "$base/flink-$FV/flink-$FV-bin-scala_2.12.tgz" -o /tmp/flink.tgz; then ok=1; echo "downloaded from $base"; break; fi
  done
  [ "$ok" = 1 ] || fail "flink download failed"
  echo "$FSHA  /tmp/flink.tgz" | sha512sum -c - || fail "flink sha512 mismatch (refusing to run it)"
  tar -xzf /tmp/flink.tgz -C /opt && rm -f /tmp/flink.tgz
fi
ln -sfn "/opt/flink-$FV" /opt/flink
JAR="flink-sql-connector-kafka-$CV.jar"
if [ ! -f "/opt/flink/lib/$JAR" ]; then
  curl -fsSL "https://repo1.maven.org/maven2/org/apache/flink/flink-sql-connector-kafka/$CV/$JAR" -o "/tmp/$JAR" || fail "connector download failed"
  echo "$CSHA  /tmp/$JAR" | sha1sum -c - || fail "connector sha1 mismatch"
  mv "/tmp/$JAR" /opt/flink/lib/
fi

# memory for an e2-medium (4 GB): JobManager 1 GB, TaskManager 1.6 GB, the rest for the OS and the reader
FC=/opt/flink/conf/config.yaml
[ -f "$FC" ] || FC=/opt/flink/conf/flink-conf.yaml
python3 - "$FC" <<'PY'
import re, sys
p = sys.argv[1]
want = {"jobmanager.memory.process.size": "1024m", "taskmanager.memory.process.size": "1700m", "taskmanager.numberOfTaskSlots": "2",
        "parallelism.default": "2", "rest.address": "0.0.0.0", "rest.bind-address": "0.0.0.0", "jobmanager.rpc.address": "localhost"}
txt = open(p).read()
if p.endswith("config.yaml"):   # Flink 1.19+: flat keys are accepted in config.yaml
    for k, v in want.items():
        txt = re.sub(rf"^\s*{re.escape(k)}\s*:.*\n", "", txt, flags=re.M)
        txt += f"{k}: {v}\n"
else:
    for k, v in want.items():
        txt = re.sub(rf"^{re.escape(k)}:.*\n", "", txt, flags=re.M)
        txt += f"{k}: {v}\n"
open(p, "w").write(txt)
PY
chown -R flink:flink "/opt/flink-$FV"
mkdir -p /opt/flink-job && chown flink:flink /opt/flink-job

mkunit() { # name, exec
cat > /etc/systemd/system/$1.service <<UNIT
[Unit]
Description=$1
After=network-online.target
[Service]
User=flink
Environment=JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64
ExecStart=$2
Restart=always
RestartSec=5
[Install]
WantedBy=multi-user.target
UNIT
}
mkunit flink-jobmanager "/opt/flink/bin/jobmanager.sh start-foreground"
mkunit flink-taskmanager "/opt/flink/bin/taskmanager.sh start-foreground"
systemctl daemon-reload
systemctl enable flink-jobmanager flink-taskmanager >/dev/null 2>&1
systemctl restart flink-jobmanager
sleep 8
systemctl restart flink-taskmanager
for i in $(seq 1 60); do
  n=$(curl -fsS http://127.0.0.1:8081/overview 2>/dev/null | python3 -c 'import sys,json;print(json.load(sys.stdin)["taskmanagers"])' 2>/dev/null || echo 0)
  [ "$n" -ge 1 ] 2>/dev/null && break
  sleep 5
done
[ "${n:-0}" -ge 1 ] 2>/dev/null || { journalctl -u flink-jobmanager -n 20 --no-pager; fail "no TaskManager registered"; }
echo "FLINK_READY version=$FV taskmanagers=$n"

# the SQL job (submitted once: skipped when a job with this name is already running)
attr flink-sql | sed "s#@BOOTSTRAP@#$BOOT#g" > /opt/flink-job/job.sql
chown flink:flink /opt/flink-job/job.sql
if curl -fsS http://127.0.0.1:8081/jobs/overview | grep -q '"name":"sfumato-flow-analytics"'; then
  echo "job already running"
else
  sudo -u flink env JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64 /opt/flink/bin/sql-client.sh -f /opt/flink-job/job.sql > /var/log/flink-sql-submit.log 2>&1 \
    && echo "FLINK_JOB_SUBMITTED" || { tail -20 /var/log/flink-sql-submit.log; fail "SQL job submission failed"; }
fi
sleep 15
NJOBS=$(curl -fsS http://127.0.0.1:8081/jobs/overview | python3 -c 'import sys,json;print(sum(1 for j in json.load(sys.stdin)["jobs"] if j["state"]=="RUNNING"))' 2>/dev/null || echo 0)
echo "FLINK_RUNNING_JOBS $NJOBS"
if [ "$NJOBS" -lt 2 ] 2>/dev/null; then
  echo "FLINK_SQL_LOG_BEGIN"; tail -40 /var/log/flink-sql-submit.log; echo "FLINK_SQL_LOG_END"
fi

# results reader (Python): code from the bucket (the same app.tgz as the Kafka VMs), published every 8 seconds
TOKEN=$(curl -fsS -H 'Metadata-Flavor: Google' "$MD/instance/service-accounts/default/token" | python3 -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')
get() { local o; o=$(python3 -c 'import sys,urllib.parse;print(urllib.parse.quote(sys.argv[1],safe=""))' "$1"); curl -fsS -H "Authorization: Bearer $TOKEN" "https://storage.googleapis.com/storage/v1/b/$BUCKET/o/$o?alt=media" -o "$2"; }
APP=/opt/sfumato-flink-reader; mkdir -p $APP
if get stream/code/manifest.json /tmp/m.json && get stream/code/app.tgz /tmp/app.tgz; then
  want=$(python3 -c 'import json;print(json.load(open("/tmp/m.json"))["sha256"])')
  [ "$(sha256sum /tmp/app.tgz | cut -d' ' -f1)" = "$want" ] || fail "app sha mismatch"
  rm -rf $APP/app && mkdir -p $APP/app && tar -xzf /tmp/app.tgz -C $APP/app
  [ -x $APP/venv/bin/python ] || { python3 -m venv $APP/venv && $APP/venv/bin/pip install --no-cache-dir -q confluent-kafka==2.6.1 google-cloud-storage==2.18.2 || fail "pip failed"; }
  cat > /etc/systemd/system/sfumato-flink-reader.service <<UNIT
[Unit]
Description=Sfumato Flink results reader
After=network-online.target flink-jobmanager.service
[Service]
Environment=BOOTSTRAP=$BOOT
Environment=BUCKET=$BUCKET
WorkingDirectory=$APP/app
ExecStart=$APP/venv/bin/python -u $APP/app/flink_state.py
Restart=always
RestartSec=5
[Install]
WantedBy=multi-user.target
UNIT
  systemctl daemon-reload
  systemctl enable sfumato-flink-reader >/dev/null 2>&1
  systemctl restart sfumato-flink-reader
  echo "READER_STARTED"
else
  echo "warning: application code not found in the bucket (run scripts/gcp_stream.ps1 deploy-app), reader not started"
fi
# diagnostics: records read and written by each operator of each job, 100 seconds after the submission
sleep 100
for j in $(curl -fsS http://127.0.0.1:8081/jobs/overview | python3 -c 'import sys,json;[print(x["jid"]) for x in json.load(sys.stdin)["jobs"]]'); do
  curl -fsS http://127.0.0.1:8081/jobs/$j | python3 -c '
import sys, json
d = json.load(sys.stdin)
print("FLINK_DIAG job", d["name"], d["state"])
for v in d["vertices"]:
    print("FLINK_DIAG   vertex", v["name"][:100], v["status"], "read", v["metrics"]["read-records"], "write", v["metrics"]["write-records"])
'
done
echo "FLINK_ALL_DONE"
