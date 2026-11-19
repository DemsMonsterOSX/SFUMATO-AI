#!/usr/bin/env bash
# Sfumato log VM bootstrap: Elasticsearch 8.x + Logstash (GCE startup script, runs as root at EVERY boot, idempotent).
# Logs are pushed by the applications over HTTP to Logstash (port 8080, basic auth), parsed, and indexed in Elasticsearch
# (index sfumato-logs-YYYY.MM.dd, deleted after 14 days). The web app's Logs tab queries Elasticsearch (port 9200, basic auth).
# Metadata: elastic-password, logship-token. Markers: ELK_READY, ELK_FAILED.
# SECURITY: no firewall rule opens 9200 or 8080 to the Internet: only VMs of the project's internal network can reach them, and both
# require a password. TLS is not enabled (plain HTTP inside the project network). Kibana is not installed.
set -uo pipefail
exec > >(tee -a /var/log/sfumato-elk-startup.log) 2>&1
echo "== elk startup $(date -u +%FT%TZ)"
MD=http://metadata.google.internal/computeMetadata/v1/instance/attributes
attr() { curl -fsS -H 'Metadata-Flavor: Google' "$MD/$1" 2>/dev/null || true; }
fail() { echo "ELK_FAILED: $*"; exit 1; }
EPW=$(attr elastic-password); TOK=$(attr logship-token)
[ -n "$EPW" ] && [ -n "$TOK" ] || fail "missing metadata"

if ! swapon --show | grep -q /swapfile; then
  [ -f /swapfile ] || { fallocate -l 2G /swapfile && chmod 600 /swapfile && mkswap /swapfile; }
  swapon /swapfile || echo "warning: swap not enabled"
  grep -q /swapfile /etc/fstab || echo '/swapfile none swap sw 0 0' >> /etc/fstab
fi
sysctl -w vm.max_map_count=262144 >/dev/null
echo 'vm.max_map_count=262144' > /etc/sysctl.d/99-elasticsearch.conf

if [ ! -f /opt/.sfumato-elk-installed ]; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y && apt-get install -y --no-install-recommends curl ca-certificates gnupg apt-transport-https python3 || fail "base packages failed"
  curl -fsSL https://artifacts.elastic.co/GPG-KEY-elasticsearch -o /tmp/elastic.key || fail "key download failed"
  FP=$(gpg --show-keys --with-colons /tmp/elastic.key | awk -F: '/^fpr:/{print $10; exit}')
  [ "$FP" = "46095ACC8548582C1A2699A9D27D666CD88E42B4" ] || fail "Elastic signing key fingerprint mismatch ($FP)"
  gpg --dearmor < /tmp/elastic.key > /usr/share/keyrings/elastic.gpg
  echo "deb [signed-by=/usr/share/keyrings/elastic.gpg] https://artifacts.elastic.co/packages/8.x/apt stable main" > /etc/apt/sources.list.d/elastic-8.x.list
  apt-get update -y && apt-get install -y elasticsearch logstash || fail "elastic packages failed"
  touch /opt/.sfumato-elk-installed
fi

# heap sizes for an 8 GB VM
mkdir -p /etc/elasticsearch/jvm.options.d /etc/logstash/jvm.options.d 2>/dev/null
printf -- '-Xms2g\n-Xmx2g\n' > /etc/elasticsearch/jvm.options.d/heap.options
cat > /etc/elasticsearch/elasticsearch.yml <<'YML'
cluster.name: sfumato-logs
node.name: elk-1
path.data: /var/lib/elasticsearch
path.logs: /var/log/elasticsearch
network.host: 0.0.0.0
discovery.type: single-node
xpack.security.enabled: true
xpack.security.http.ssl.enabled: false
xpack.security.transport.ssl.enabled: false
YML
/usr/share/elasticsearch/bin/elasticsearch-keystore list 2>/dev/null | grep -q '^bootstrap.password$' || true
printf '%s' "$EPW" | /usr/share/elasticsearch/bin/elasticsearch-keystore add -x -f bootstrap.password >/dev/null 2>&1 || fail "keystore password failed"
systemctl daemon-reload
systemctl enable elasticsearch >/dev/null 2>&1
systemctl restart elasticsearch
for i in $(seq 1 90); do
  curl -fsS -u "elastic:$EPW" http://127.0.0.1:9200/_cluster/health >/dev/null 2>&1 && break
  sleep 5
done
curl -fsS -u "elastic:$EPW" http://127.0.0.1:9200/_cluster/health >/dev/null 2>&1 || { journalctl -u elasticsearch -n 25 --no-pager; fail "elasticsearch did not start"; }

# 14-day retention and an index template for the log fields
curl -fsS -u "elastic:$EPW" -X PUT http://127.0.0.1:9200/_ilm/policy/sfumato-logs -H 'Content-Type: application/json' \
  -d '{"policy":{"phases":{"hot":{"actions":{}},"delete":{"min_age":"14d","actions":{"delete":{}}}}}}' >/dev/null || echo "warning: ilm policy not created"
curl -fsS -u "elastic:$EPW" -X PUT http://127.0.0.1:9200/_index_template/sfumato-logs -H 'Content-Type: application/json' -d '{
  "index_patterns":["sfumato-logs-*"],
  "template":{"settings":{"number_of_shards":1,"number_of_replicas":0,"index.lifecycle.name":"sfumato-logs"},
    "mappings":{"properties":{"@timestamp":{"type":"date"},"service":{"type":"keyword"},"level":{"type":"keyword"},"route":{"type":"keyword"},
      "method":{"type":"keyword"},"status":{"type":"integer"},"ms":{"type":"float"},"host":{"type":"keyword"},"message":{"type":"text"}}}}}' >/dev/null || echo "warning: template not created"

# Logstash: HTTP input with basic auth -> light parsing -> Elasticsearch
printf -- '-Xms768m\n-Xmx768m\n' > /etc/logstash/jvm.options.d/heap.options
cat > /etc/logstash/conf.d/sfumato.conf <<CONF
input {
  http {
    port => 8080
    host => "0.0.0.0"
    user => "logship"
    password => "$TOK"
    codec => "json"
  }
}
filter {
  # the applications send a UNIX time in "ts" (seconds); keep the event time rather than the arrival time
  if [ts] {
    date { match => ["ts", "UNIX"] target => "@timestamp" }
    mutate { remove_field => ["ts"] }
  }
  if ![level] { mutate { add_field => { "level" => "INFO" } } }
  mutate { uppercase => ["level"] remove_field => ["headers", "event", "url", "http", "user_agent"] }
}
output {
  elasticsearch {
    hosts => ["http://127.0.0.1:9200"]
    user => "elastic"
    password => "$EPW"
    index => "sfumato-logs-%{+YYYY.MM.dd}"
  }
}
CONF
chown root:logstash /etc/logstash/conf.d/sfumato.conf; chmod 640 /etc/logstash/conf.d/sfumato.conf
systemctl enable logstash >/dev/null 2>&1
systemctl restart logstash
for i in $(seq 1 90); do
  curl -s -o /dev/null -w '%{http_code}' -u "logship:$TOK" -H 'Content-Type: application/json' -d '{"service":"elk","level":"INFO","message":"logstash ready probe"}' http://127.0.0.1:8080 2>/dev/null | grep -q '^200$' && break
  sleep 5
done
curl -s -o /dev/null -w '%{http_code}' -u "logship:$TOK" -H 'Content-Type: application/json' -d '{"service":"elk","level":"INFO","message":"logstash ready probe"}' http://127.0.0.1:8080 2>/dev/null | grep -q '^200$' || { journalctl -u logstash -n 25 --no-pager; fail "logstash did not accept events"; }
echo "ELK_READY elasticsearch=$(curl -fsS -u "elastic:$EPW" http://127.0.0.1:9200 | python3 -c 'import sys,json;print(json.load(sys.stdin)["version"]["number"])') logstash=$(/usr/share/logstash/bin/logstash --version 2>/dev/null | tail -1)"
