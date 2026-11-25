"""Compare the two Flink rules on the alerts they published (source-alerts, naive-alerts), de-duplicated by (src, window_start).

  python streaming/eval_alerts.py source-alerts.jsonl naive-alerts.jsonl [out.json]

A window counts as an attack window when at least half of its connections carry a family label (the label is attached by conn_replay.py
and never read by the rules). The same window can be published several times because the job was run at parallelism 1, 2 and 4 on the
same backlog; the duplicates are dropped.
"""
import json
import sys


def load(path):
    out = {}
    for line in open(path, encoding="utf-8"):
        try:
            d = json.loads(line)
        except ValueError:
            continue
        out[(d["src"], d["window_start"])] = d
    return out


def stats(alerts):
    att = sum(1 for d in alerts.values() if d["attack_conns"] * 2 >= d["conns"])
    srcs = {d["src"] for d in alerts.values()}
    att_srcs = {d["src"] for d in alerts.values() if d["attack_conns"] * 2 >= d["conns"]}
    return {"alert_windows": len(alerts), "attack_windows": att, "benign_windows": len(alerts) - att,
            "precision": round(att / len(alerts), 4) if alerts else None, "distinct_sources": len(srcs), "attack_sources": len(att_srcs)}


if __name__ == "__main__":
    s, n = load(sys.argv[1]), load(sys.argv[2])
    res = {"concentrated_source": stats(s), "volume_only": stats(n)}
    res["attack_windows_missed_by_concentrated"] = len({k for k, d in n.items() if d["attack_conns"] * 2 >= d["conns"]} - {k for k, d in s.items() if d["attack_conns"] * 2 >= d["conns"]})
    print(json.dumps(res, indent=1))
    if len(sys.argv) > 3:
        json.dump(res, open(sys.argv[3], "w"), indent=1)
