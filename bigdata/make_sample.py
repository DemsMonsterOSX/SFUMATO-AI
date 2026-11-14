"""Tiny fake CSE-CIC-IDS2018-shaped CSVs for a local smoke test of spark_pipeline.py (NOT real data).
  python bigdata/make_sample.py bigdata/_sample"""
import csv
import random
import sys
from pathlib import Path

out = Path(sys.argv[1])
out.mkdir(parents=True, exist_ok=True)
random.seed(1)
BASE = ["Dst Port", "Protocol", "Timestamp", "Flow Duration", "Tot Fwd Pkts", "Tot Bwd Pkts", "TotLen Fwd Pkts", "Pkt Len Mean", "Flow Byts/s"]
for i, (day, extra) in enumerate([("14/02/2018", False), ("15/02/2018", False), ("20/02/2018", True), ("21/02/2018", False)]):
    cols = (["Flow ID", "Src IP", "Src Port", "Dst IP"] if extra else []) + BASE + ["Label"]
    with open(out / f"day{i}.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(cols)
        for n in range(3000):
            atk = random.random() < 0.3
            dur = random.randint(1, 200) if atk else random.randint(1000, 900000)
            fwd = random.randint(50, 500) if atk else random.randint(1, 20)
            row = [80 if atk else random.choice([443, 53, 22]), 6, f"{day} {random.randint(0, 23):02d}:{random.randint(0, 59):02d}:00",
                   dur, fwd, random.randint(0, 5), fwd * random.randint(40, 90), random.uniform(30, 600),
                   "Infinity" if n % 500 == 0 else random.uniform(10, 1e6)]
            if extra:
                row = ["x", "1.2.3.4", 1234, "5.6.7.8"] + row
            w.writerow(row + ["DoS attacks-Hulk" if atk else "Benign"])
        if i == 0:
            w.writerow(cols)   # an embedded repeated header, as in the real files
print("sample written to", out)
