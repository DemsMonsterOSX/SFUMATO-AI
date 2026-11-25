#!/usr/bin/env bash
# Throughput of the per-source Flink job at one parallelism, on the backlog already stored in the topic conn-events.
#   sudo bash scale-run.sh <parallelism> <records in the topic> [output json]
# Cancels the running jobs, submits /opt/flink-job/template.sql with the given parallelism (it reads the topic from the earliest offset),
# samples the number of records read by the source every 5 s, and stops when all records have been read or progress stops for 90 s.
# Result: records, seconds from the first record to the last, average and peak records per second, the samples.
set -uo pipefail
P=${1:?parallelism}; N=${2:?records}; OUT=${3:-/tmp/scale-$P.json}
R=http://127.0.0.1:8081
ids() { curl -fsS $R/jobs/overview | python3 -c 'import sys,json;[print(j["jid"]) for j in json.load(sys.stdin)["jobs"] if j["state"]=="RUNNING"]'; }
for j in $(ids); do curl -fsS -X PATCH "$R/jobs/$j?mode=cancel" >/dev/null; done
sleep 8
sed -E "s#('parallelism.default' = )'[0-9]+'#\1'$P'#" /opt/flink-job/template.sql > /opt/flink-job/job-p$P.sql
chown flink:flink /opt/flink-job/job-p$P.sql
sudo -u flink env JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64 /opt/flink/bin/sql-client.sh -f /opt/flink-job/job-p$P.sql > /var/log/flink-scale-$P.log 2>&1 || { tail -20 /var/log/flink-scale-$P.log; echo SUBMIT_FAILED; exit 1; }
sleep 10
JID=$(ids | head -1); [ -n "$JID" ] || { echo NO_JOB; tail -20 /var/log/flink-scale-$P.log; exit 1; }
python3 - "$R" "$JID" "$N" "$P" "$OUT" <<'PY'
import json, sys, time, urllib.request
R, JID, N, P, OUT = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4]), sys.argv[5]
def read():
    d = json.load(urllib.request.urlopen(f"{R}/jobs/{JID}", timeout=10))
    v = d["vertices"][0]
    m = json.load(urllib.request.urlopen(f"{R}/jobs/{JID}/vertices/{v['id']}/subtasks/metrics?get=Source__conns%5B1%5D.numRecordsOut&agg=sum", timeout=10))
    return d["state"], int(m[0]["sum"]) if m else 0
samples, t_first, last_change, prev = [], None, time.time(), -1
while True:
    time.sleep(5)
    try:
        state, n = read()
    except Exception:
        continue
    now = time.time()
    if n > 0 and t_first is None:
        t_first = now
    samples.append((round(now - (t_first or now), 1), n))
    if n != prev:
        last_change, prev = now, n
    if n >= N or now - last_change > 90 or state not in ("RUNNING", "CREATED"):
        break
secs = samples[-1][0]
rates = [(b[1] - a[1]) / (b[0] - a[0]) for a, b in zip(samples, samples[1:]) if b[0] > a[0]]
res = {"parallelism": P, "records_expected": N, "records_read": samples[-1][1], "seconds": secs,
       "avg_records_per_s": round(samples[-1][1] / secs) if secs else None, "peak_records_per_s": round(max(rates)) if rates else None, "samples": samples[::3]}
json.dump(res, open(OUT, "w"))
print(json.dumps({k: v for k, v in res.items() if k != "samples"}))
PY
