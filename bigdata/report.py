"""Phase 5: turn results.json (written by spark_pipeline.py) into one self-contained HTML dashboard.
  python bigdata/report.py bigdata/report/results.json bigdata/report/index.html
Charts: Chart.js 4.4.1 from cdnjs. Every number comes from results.json; nothing is hard-coded."""
import html
import json
import sys
from pathlib import Path

src, dst = Path(sys.argv[1]), Path(sys.argv[2])
raw = src.read_text(encoding="utf-8").strip().splitlines()
r = json.loads(raw[0] if len(raw) == 1 else "\n".join(raw))
eda, ml = r["eda"], r.get("ml", {})
labels = sorted(eda["label_counts"].items(), key=lambda kv: -kv[1])
hours = [eda["attacks_by_hour"].get(str(h), 0) for h in range(24)]


def metric_row(name: str, m: dict) -> str:
    c = m["confusion"]
    return (f"<tr><td>{html.escape(name)}</td><td>{m['auc_roc']:.4f}</td><td>{m['auc_pr']:.4f}</td><td>{m['precision']:.4f}</td>"
            f"<td>{m['recall']:.4f}</td><td>{m['f1']:.4f}</td><td>{m['test_rows']:,}</td>"
            f"<td>TP {c['tp']:,} / FP {c['fp']:,} / FN {c['fn']:,} / TN {c['tn']:,}</td></tr>")


rows = ""
if "random_split" in ml:
    rows += metric_row("Random 80/20 split", ml["random_split"])
if "time_holdout" in ml:
    rows += metric_row(f"Time hold-out (test from {ml['time_holdout']['cutoff_day']})", ml["time_holdout"])
data = {
    "labels": [k for k, _ in labels], "counts": [v for _, v in labels],
    "days": [d["day"] for d in eda["per_day"]], "flows": [d["flows"] for d in eda["per_day"]], "attacks": [d["attacks"] for d in eda["per_day"]],
    "hours": hours,
    "fi": [f["feature"] for f in ml.get("feature_importances", [])], "fiv": [f["importance"] for f in ml.get("feature_importances", [])],
}
page = f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sfumato Big Data results</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.min.js"></script>
<style>body{{font:15px/1.5 system-ui,sans-serif;max-width:1000px;margin:24px auto;padding:0 16px;color:#1a1a1a}}
h1{{font-size:24px}}h2{{font-size:18px;margin-top:32px}}.k{{display:flex;gap:12px;flex-wrap:wrap}}
.k div{{border:1px solid #ddd;border-radius:8px;padding:10px 16px}}.k b{{display:block;font-size:22px}}
table{{border-collapse:collapse;width:100%;font-size:13px}}td,th{{border:1px solid #ddd;padding:6px 8px;text-align:left}}
canvas{{max-height:340px}}</style></head><body>
<h1>Sfumato: network intrusion detection on 6.9 GB (CSE-CIC-IDS2018)</h1>
<div class="k"><div><b>{r['raw_rows']:,}</b>raw flows</div><div><b>{r['clean_rows']:,}</b>after cleaning</div>
<div><b>{r['dropped_rows']:,}</b>dropped (headers, NaN, Infinity)</div><div><b>{r['total_seconds']//60} min</b>Spark total</div></div>
<h2>Traffic classes (log scale)</h2><canvas id="c1"></canvas>
<h2>Flows and attacks per day</h2><canvas id="c2"></canvas>
<h2>Malicious flows by hour of day</h2><canvas id="c3"></canvas>
<h2>Random Forest: attack vs benign</h2>
<table><tr><th>Evaluation</th><th>AUC-ROC</th><th>AUC-PR</th><th>Precision</th><th>Recall</th><th>F1</th><th>Test rows</th><th>Confusion</th></tr>{rows}</table>
<h2>Top feature importances</h2><canvas id="c4"></canvas>
<script>const D={json.dumps(data)};
new Chart(c1,{{type:'bar',data:{{labels:D.labels,datasets:[{{label:'flows',data:D.counts,backgroundColor:'#3b6fb6'}}]}},options:{{scales:{{y:{{type:'logarithmic'}}}}}}}});
new Chart(c2,{{type:'bar',data:{{labels:D.days,datasets:[{{label:'flows',data:D.flows,backgroundColor:'#3b6fb6'}},{{label:'attacks',data:D.attacks,backgroundColor:'#c0392b'}}]}}}});
new Chart(c3,{{type:'bar',data:{{labels:[...Array(24).keys()],datasets:[{{label:'malicious flows',data:D.hours,backgroundColor:'#c0392b'}}]}}}});
new Chart(c4,{{type:'bar',data:{{labels:D.fi,datasets:[{{label:'importance',data:D.fiv,backgroundColor:'#2e8b57'}}]}},options:{{indexAxis:'y'}}}});
</script></body></html>"""
dst.write_text(page, encoding="utf-8")
print("report written to", dst)
