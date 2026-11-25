"""Turn the Zeek conn logs of one or several days into labelled per-source windows (60 s).

  python bigdata/pcap_windows.py --day 2018-02-14 --input <folder of conn-*.parquet> --output windows_2018-02-14.parquet

A window is an attack when its source is one of the day's attacker addresses (bigdata/pcap_labels.json, from the dataset's page) and the
window lies inside that attack's printed time slot (converted to UTC, plus a margin). Everything else is "benign", which includes
internet scanners and the attackers' idle time: false-positive counts are therefore an upper bound.
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import sys
from datetime import datetime, timedelta, timezone

import pandas as pd

sys.path.insert(0, os.path.dirname(__file__))
import pcap_features as pf  # noqa: E402

COLS = ["ts", "uid", "id.orig_h", "id.resp_h", "id.resp_p", "proto", "duration", "orig_bytes", "resp_bytes", "conn_state"]


def label_windows(w: pd.DataFrame, day: str, cfg: dict) -> pd.DataFrame:
    off, margin = timedelta(hours=cfg["utc_offset_hours"]), timedelta(minutes=cfg["margin_minutes"])
    w["family"] = "benign"
    for att in cfg["days"][day]["attacks"]:
        d = datetime.strptime(day, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        h0, m0 = map(int, att["start"].split(":")); h1, m1 = map(int, att["end"].split(":"))
        t0 = (d + timedelta(hours=h0, minutes=m0) + off - margin).timestamp()
        t1 = (d + timedelta(hours=h1, minutes=m1) + off + margin).timestamp()
        m = w["src"].isin(att["ips"]) & (w["t"] >= t0) & (w["t"] <= t1)
        w.loc[m, "family"] = att["family"]
    w["day"] = day
    return w


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--day", required=True)
    ap.add_argument("--input", required=True)
    ap.add_argument("--output", required=True)
    ap.add_argument("--labels", default=os.path.join(os.path.dirname(__file__), "pcap_labels.json"))
    a = ap.parse_args()
    cfg = json.load(open(a.labels, encoding="utf-8"))
    files = sorted(glob.glob(a.input.rstrip("/\\") + "/*.parquet"))
    df = pd.concat([pd.read_parquet(f, columns=COLS) for f in files], ignore_index=True)
    w = label_windows(pf.windows(df), a.day, cfg)
    w.to_parquet(a.output, index=False)
    print(a.day, "connections", len(df), "windows", len(w), w["family"].value_counts().to_dict())


if __name__ == "__main__":
    main()
