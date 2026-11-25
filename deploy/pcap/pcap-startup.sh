#!/usr/bin/env bash
# PCAP -> Zeek -> Parquet, for ONE day of CSE-CIC-IDS2018 (GCE startup script, runs at every boot, resumable).
# Inputs (instance metadata): pcap-url, pcap-bucket, pcap-prefix, pcap-max-hours, pcap-workers.
# Markers on the serial console and in /var/lib/pcap/log.txt: PCAP_STAGE <name>, PCAP_DONE, PCAP_FAILED <why>, PCAP_DEADLINE.
# Safety: a hard deadline powers the VM off after pcap-max-hours from the FIRST boot (the disk is then kept until the VM is deleted).
set -uo pipefail
MD=http://metadata.google.internal/computeMetadata/v1
attr() { curl -fsS -H 'Metadata-Flavor: Google' "$MD/instance/attributes/$1" 2>/dev/null || true; }
URL=$(attr pcap-url); BUCKET=$(attr pcap-bucket); PREFIX=$(attr pcap-prefix); MAXH=$(attr pcap-max-hours); WORKERS=$(attr pcap-workers)
MAXH=${MAXH:-8}; WORKERS=${WORKERS:-6}
S=/var/lib/pcap; W=/var/lib/pcap/work; mkdir -p $S $W
LOG=$S/log.txt
say() { echo "$(date -u +%FT%TZ) $*" | tee -a $LOG | tee /dev/ttyS0 >/dev/null 2>&1 || true; }
fail() { say "PCAP_FAILED $*"; exit 1; }
[ -n "$URL" ] && [ -n "$BUCKET" ] && [ -n "$PREFIX" ] || fail "missing metadata"
[ -f $S/done ] && { say "PCAP_DONE (already)"; sleep 20; /sbin/poweroff; exit 0; }

# hard deadline: every boot gets its own window of pcap-max-hours (so a resumed run is bounded too)
echo $(( $(date +%s) + MAXH * 3600 )) > $S/deadline
LEFT=$(( $(cat $S/deadline) - $(date +%s) ))
if [ $LEFT -le 60 ]; then say "PCAP_DEADLINE reached, powering off"; /sbin/poweroff; exit 0; fi
systemctl is-active --quiet pcap-deadline.timer || systemd-run --unit=pcap-deadline --on-active=${LEFT}s /sbin/poweroff >/dev/null 2>&1

stage() { say "PCAP_STAGE $1"; }
stage packages
if ! command -v docker >/dev/null || ! command -v unzip >/dev/null || ! command -v bsdtar >/dev/null; then
  apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq docker.io unzip curl python3-venv libarchive-tools >/dev/null || fail "apt"
fi
[ -x $S/venv/bin/python ] || { python3 -m venv $S/venv && $S/venv/bin/pip install -q pyarrow pandas || fail "pip"; }

stage download
ARCH=$W/archive.${URL##*.}
if [ ! -f $W/pcap.ok ] && [ ! -d $W/pcap ]; then
  SIZE=$(curl -fsSIL "$URL" | tr -d '\r' | awk 'tolower($1)=="content-length:"{s=$2} END{print s}')
  [ -n "$SIZE" ] || fail "no content-length"
  curl -fL -C - --retry 30 --retry-delay 15 --retry-all-errors -o $ARCH "$URL" || fail "download"
  [ "$(stat -c %s $ARCH)" = "$SIZE" ] || fail "size mismatch ($(stat -c %s $ARCH) vs $SIZE)"
  say "downloaded $SIZE bytes"
fi

stage unzip
if [ ! -d $W/pcap ]; then
  mkdir -p $W/pcap.tmp
  case "$ARCH" in
    *.rar) bsdtar -xf $ARCH -C $W/pcap.tmp || fail "unrar" ;;
    *) unzip -q -o $ARCH -d $W/pcap.tmp || fail "unzip" ;;
  esac
  mv $W/pcap.tmp $W/pcap && rm -f $ARCH
fi
df -h $W | tail -1 | tee -a $LOG >/dev/null
find $W/pcap -type f | head -50 > $S/files-sample.txt
find $W/pcap -type f | wc -l > $S/files-count.txt

stage zeek-image
docker image inspect zeek/zeek:lts >/dev/null 2>&1 || docker pull zeek/zeek:lts >/dev/null || fail "docker pull"

stage zeek
mkdir -p $W/zeek
# a pcap is recognised by its magic number (classic pcap, either byte order, or pcapng)
find $W/pcap -type f -size +1M | while read -r f; do
  m=$(head -c4 "$f" | od -An -tx1 | tr -d ' \n')
  case "$m" in d4c3b2a1|a1b2c3d4|0a0d0d0a|4d3cb2a1|a1b23c4d) echo "$f";; esac
done > $S/pcaps.txt
N=$(wc -l < $S/pcaps.txt); say "pcap files: $N"
[ "$N" -gt 0 ] || fail "no pcap found in the archive (see files-sample.txt)"
run_one() {
  f="$1"; id=$(echo "$f" | md5sum | cut -c1-12); out=/var/lib/pcap/work/zeek/$id
  [ -f $out/.done ] && return 0
  rm -rf $out; mkdir -p $out; echo "$f" > $out/source.txt
  docker run --rm -v /var/lib/pcap/work:/var/lib/pcap/work -w $out zeek/zeek:lts zeek -C -r "$f" LogAscii::use_json=T >/dev/null 2>$out/zeek.err && touch $out/.done
}
export -f run_one
xargs -a $S/pcaps.txt -P "$WORKERS" -I{} bash -c 'run_one "$@"' _ {}
DONE=$(find $W/zeek -name .done | wc -l); say "zeek finished $DONE / $N"
[ "$DONE" -gt 0 ] || fail "zeek produced nothing"

stage parquet
cat > $S/to_parquet.py <<'PY'
import glob, json, os, sys
import pandas as pd
W = "/var/lib/pcap/work"; OUT = "/var/lib/pcap/out"; os.makedirs(OUT, exist_ok=True)
COLS = ["ts","uid","id.orig_h","id.orig_p","id.resp_h","id.resp_p","proto","service","duration","orig_bytes","resp_bytes","conn_state","history","orig_pkts","orig_ip_bytes","resp_pkts","resp_ip_bytes"]
n = 0
for d in sorted(glob.glob(W + "/zeek/*")):
    f = d + "/conn.log"
    if not os.path.exists(f):
        continue
    src = open(d + "/source.txt").read().strip()
    rows = []
    for line in open(f):
        try:
            r = json.loads(line)
        except ValueError:
            continue
        rows.append({c: r.get(c) for c in COLS})
        if len(rows) >= 500000:
            pd.DataFrame(rows).assign(source=src).to_parquet(f"{OUT}/conn-{n:05d}.parquet", index=False); n += 1; rows = []
    if rows:
        pd.DataFrame(rows).assign(source=src).to_parquet(f"{OUT}/conn-{n:05d}.parquet", index=False); n += 1
print("parquet parts", n)
PY
$S/venv/bin/python $S/to_parquet.py | tee -a $LOG >/dev/null || fail "parquet"

stage upload
gcloud storage cp -r $S/out "gs://$BUCKET/$PREFIX/conn/" --quiet >/dev/null 2>&1 || fail "upload conn"
gcloud storage cp $S/files-sample.txt $S/files-count.txt $S/pcaps.txt $LOG "gs://$BUCKET/$PREFIX/meta/" --quiet >/dev/null 2>&1 || true
touch $S/done
say "PCAP_DONE parts=$(ls $S/out | wc -l)"
sleep 20; /sbin/poweroff
exit 0
