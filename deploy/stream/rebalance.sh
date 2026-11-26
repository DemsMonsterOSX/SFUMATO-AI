#!/usr/bin/env bash
# Spread the partitions of the streaming topics over the given brokers (run on sfumato-kafka-1 as root).
# Usage: rebalance.sh 1,2,3,4      (add-brokers)      rebalance.sh 1,2      (drop-brokers, before stopping brokers 3 and 4)
# Keeps the replication factor of each partition (2). A throttle protects the running flow while the replicas move; it is removed at the end.
set -uo pipefail
BROKERS=${1:?broker list, e.g. 1,2,3,4}
B=localhost:9092; K=/opt/kafka/bin
cat > /tmp/topics.json <<'JSON'
{"version":1,"topics":[{"topic":"network-flows"},{"topic":"network-flows-dlq"},{"topic":"alerts"},{"topic":"flow-aggregates"},{"topic":"rule-alerts"},{"topic":"cve-events"}]}
JSON
$K/kafka-reassign-partitions.sh --bootstrap-server $B --topics-to-move-json-file /tmp/topics.json --broker-list "$BROKERS" --generate > /tmp/gen.txt 2>&1 || { cat /tmp/gen.txt; echo "REBALANCE_FAILED generate"; exit 1; }
awk '/Proposed partition reassignment configuration/{getline; print}' /tmp/gen.txt > /tmp/plan.json
[ -s /tmp/plan.json ] || { cat /tmp/gen.txt; echo "REBALANCE_FAILED empty plan"; exit 1; }
$K/kafka-reassign-partitions.sh --bootstrap-server $B --reassignment-json-file /tmp/plan.json --execute --throttle 200000000 > /tmp/exec.txt 2>&1 || { cat /tmp/exec.txt; echo "REBALANCE_FAILED execute"; exit 1; }
for i in $(seq 1 120); do
  $K/kafka-reassign-partitions.sh --bootstrap-server $B --reassignment-json-file /tmp/plan.json --verify > /tmp/ver.txt 2>&1
  grep -q "still in progress" /tmp/ver.txt || break
  sleep 5
done
grep -q "still in progress" /tmp/ver.txt && { echo "REBALANCE_FAILED timeout"; exit 1; }
$K/kafka-topics.sh --bootstrap-server $B --describe --topic network-flows | head -8
echo "REBALANCE_DONE brokers=$BROKERS"
