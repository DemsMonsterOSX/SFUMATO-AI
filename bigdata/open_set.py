"""A detector that knows what it does not know: abstention and escalation, evaluated one attack family at a time (leave-one-family-out).

  python bigdata/open_set.py --windows w_2018-02-14.parquet w_2018-02-15.parquet ... --output ml/bigdata/open_set.json

Input: labelled per-source 60 s windows (bigdata/pcap_windows.py). For each attack family F, everything is trained WITHOUT F and then tested
on F plus held-out benign windows (the later 40 % of each day's benign windows). Three policies are compared on the same models:

  plain      attack if the mean score of the ensemble is >= 0.5
  abstain    attack if score >= HI and members agree; benign if score <= LO and the window looks like the benign training data;
             anything else is UNKNOWN (no automatic verdict)
  escalate   UNKNOWN windows go to stage 2: the concentration rule (many connections, at most 2 hosts, one dominant port) confirms an
             attack; what no stage confirms goes to a human queue

Thresholds are fixed in advance (HI 0.9, LO 0.1, disagreement 0.15, novelty = 99.5th percentile of the benign training windows), not tuned on
the held-out family. Reported per family: recall, benign false positives, share of benign windows sent to humans, and the average number of
windows sent to humans per hour of capture. The families come from a handful of attacker hosts: windows of one family are not independent.
"""
from __future__ import annotations

import argparse
import json

import numpy as np
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier, IsolationForest

import pcap_features as pf

HI, LO, STD_MAX, K = 0.9, 0.1, 0.15, 5
FEATURES = pf.FEATURES


def concentration_rule(d: pd.DataFrame) -> np.ndarray:
    return ((d["n"] >= 200) & (d["n_dst"] <= 2) & (d["top_port_share"] >= 0.9)).to_numpy()


def train(tr: pd.DataFrame, seed: int = 0):
    rng = np.random.default_rng(seed)
    models = []
    for k in range(K):
        idx = rng.choice(len(tr), size=len(tr), replace=True)   # bootstrap: members disagree where the data does not decide
        b = tr.iloc[idx]
        w = np.where(b["y"] == 1, (b["y"] == 0).sum() / max(1, (b["y"] == 1).sum()), 1.0)
        models.append(HistGradientBoostingClassifier(max_iter=120, random_state=k).fit(b[FEATURES], b["y"], sample_weight=w))
    benign = tr[tr["y"] == 0]
    iso = IsolationForest(n_estimators=100, random_state=0, n_jobs=-1).fit(benign[FEATURES].sample(min(len(benign), 100_000), random_state=0))
    cutoff = float(np.quantile(-iso.score_samples(benign[FEATURES].sample(min(len(benign), 50_000), random_state=1)), 0.995))
    return models, iso, cutoff


def decide(models, iso, cutoff, d: pd.DataFrame) -> pd.DataFrame:
    P = np.vstack([m.predict_proba(d[FEATURES])[:, 1] for m in models])
    mean, sd = P.mean(0), P.std(0)
    novel = (-iso.score_samples(d[FEATURES])) > cutoff
    plain = mean >= 0.5
    attack = (mean >= HI) & (sd <= STD_MAX)
    benign = (mean <= LO) & ~novel
    unknown = ~attack & ~benign
    rule = concentration_rule(d)
    confirmed = unknown & rule
    human = unknown & ~rule
    return pd.DataFrame({"plain": plain, "auto_attack": attack, "auto_benign": benign, "unknown": unknown, "rule_confirmed": confirmed, "human": human}, index=d.index)


def summarise(out: pd.DataFrame, y: np.ndarray, hours: float) -> dict:
    a, b = y == 1, y == 0
    n_a, n_b = int(a.sum()), int(b.sum())
    r = lambda m: round(float(m[a].sum()) / max(1, n_a), 4)   # noqa: E731
    return {
        "attack_windows": n_a, "benign_windows": n_b,
        "plain": {"recall": r(out["plain"].to_numpy()), "false_positives": int(out["plain"].to_numpy()[b].sum())},
        "abstain": {"recall_auto": r(out["auto_attack"].to_numpy()), "unknown_attack_share": r(out["unknown"].to_numpy()),
                    "missed_as_benign": r(out["auto_benign"].to_numpy()), "false_positives": int(out["auto_attack"].to_numpy()[b].sum()),
                    "benign_unknown_share": round(float(out["unknown"].to_numpy()[b].sum()) / max(1, n_b), 5)},
        "escalate": {"recall_total": r((out["auto_attack"] | out["rule_confirmed"]).to_numpy()),
                     "attack_sent_to_human": r(out["human"].to_numpy()),
                     "false_positives": int((out["auto_attack"] | out["rule_confirmed"]).to_numpy()[b].sum()),
                     "benign_to_human": int(out["human"].to_numpy()[b].sum()),
                     "human_windows_per_hour": round(float(out["human"].to_numpy().sum()) / max(hours, 1e-9), 1)},
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--windows", nargs="+", required=True)
    ap.add_argument("--output", required=True)
    a = ap.parse_args()
    w = pd.concat([pd.read_parquet(f) for f in a.windows], ignore_index=True)
    w["y"] = (w["family"] != "benign").astype(int)
    ben = w["family"] == "benign"
    cut = w[ben].groupby("day")["t"].quantile(0.6)
    w["benign_test"] = ben & (w["t"] > w["day"].map(cut))
    w["benign_train"] = ben & ~w["benign_test"]
    fams = sorted(f for f in w["family"].unique() if f != "benign")
    hours = float((w.loc[w["benign_test"], "win"].nunique()) * pf.WIN / 3600)    # distinct test minutes, as hours of capture
    res = {"families": fams, "days": sorted(w["day"].unique().tolist()), "thresholds": {"HI": HI, "LO": LO, "STD_MAX": STD_MAX, "K": K},
           "benign_test_hours": round(hours, 2), "by_family": {}}
    for f in fams:
        tr = w[(w["benign_train"]) | ((w["y"] == 1) & (w["family"] != f))]
        te = w[(w["benign_test"]) | (w["family"] == f)]
        models, iso, cutoff = train(tr)
        out = decide(models, iso, cutoff, te)
        res["by_family"][f] = summarise(out, te["y"].to_numpy(), hours)
        s = res["by_family"][f]
        print(f"{f:18s} windows {s['attack_windows']:5d} | plain recall {s['plain']['recall']:.2f} fp {s['plain']['false_positives']:4d} | "
              f"abstain auto {s['abstain']['recall_auto']:.2f} unknown {s['abstain']['unknown_attack_share']:.2f} | escalate total {s['escalate']['recall_total']:.2f} "
              f"fp {s['escalate']['false_positives']} human/h {s['escalate']['human_windows_per_hour']}", flush=True)
    json.dump(res, open(a.output, "w"), indent=1)


if __name__ == "__main__":
    main()
