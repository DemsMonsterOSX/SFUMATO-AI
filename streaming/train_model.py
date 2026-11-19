"""Train the compact flow classifier used by the streaming scorer and report how good it really is.

  python streaming/train_model.py --sample <folder with the exported parquet files> --out streaming/model

Model: HistGradientBoostingClassifier (scikit-learn), binary attack vs benign, 26 numeric flow features.
Evaluation (printed and saved in metrics.json):
  * random 80/20 split on the stratified sample;
  * time hold-out: train on days before 2018-02-28, test on 2018-02-28 and later (attack families the model never saw).
The sample is NOT the natural traffic mix (about 120,000 benign flows against up to 20,000 per attack family), so precision and
recall describe this mix. The honest finding of the project holds: recall collapses on families absent from training.
"""
from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.metrics import average_precision_score, precision_recall_fscore_support, roc_auc_score
from sklearn.model_selection import train_test_split

META = {"Label", "ts", "day"}


def load(sample: Path) -> pd.DataFrame:
    frames = [pd.read_parquet(p) for p in sorted(sample.glob("*.parquet"))]
    df = pd.concat([f for f in frames if len(f)], ignore_index=True)
    df["is_attack"] = (df["Label"] != "Benign").astype(int)
    return df


def metrics(model, X, y) -> dict:
    p = model.predict_proba(X)[:, 1]
    pred = (p >= 0.5).astype(int)
    pr, rc, f1, _ = precision_recall_fscore_support(y, pred, average="binary", zero_division=0)
    tp = int(((pred == 1) & (y == 1)).sum())
    fp = int(((pred == 1) & (y == 0)).sum())
    fn = int(((pred == 0) & (y == 1)).sum())
    tn = int(((pred == 0) & (y == 0)).sum())
    out = {"rows": int(len(y)), "attack_share": round(float(y.mean()), 3), "precision": float(pr), "recall": float(rc), "f1": float(f1),
           "confusion": {"tp": tp, "fp": fp, "fn": fn, "tn": tn}}
    if len(set(y)) == 2:
        out["auc_roc"] = float(roc_auc_score(y, p))
        out["auc_pr"] = float(average_precision_score(y, p))
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--sample", required=True)
    ap.add_argument("--out", default="streaming/model")
    a = ap.parse_args()
    df = load(Path(a.sample))
    feats = [c for c in df.columns if c not in META and c != "is_attack"]
    X, y = df[feats].astype("float64"), df["is_attack"]
    print(f"{len(df)} flows, {len(feats)} features, attack share {y.mean():.3f}")
    mk = lambda: HistGradientBoostingClassifier(max_iter=200, learning_rate=0.1, max_depth=8, random_state=42)
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)

    # Scenario A, "known families": model trained on 80 % of the flows, replay of the 20 % that were held out.
    itr, ite = train_test_split(df.index, test_size=0.2, random_state=42, stratify=y)
    model_a = mk().fit(X.loc[itr], y.loc[itr])
    random_split = metrics(model_a, X.loc[ite], y.loc[ite])
    print("A known families (held-out flows):", {k: round(v, 4) if isinstance(v, float) else v for k, v in random_split.items() if k != "confusion"})
    joblib.dump({"model": model_a, "features": feats, "scenario": "known"}, out / "model_known.joblib", compress=3)
    df.loc[ite].to_parquet(out / "replay_known.parquet", index=False)

    # Scenario B, "unseen families": model trained on the days before 2018-02-28, replay of 2018-02-28 and later
    # (infiltration and botnet exist only there).
    day = pd.to_datetime(df["day"])
    early, late = day < pd.Timestamp("2018-02-28"), day >= pd.Timestamp("2018-02-28")
    model_b = mk().fit(X[early], y[early])
    time_hold = metrics(model_b, X[late], y[late])
    time_hold["cutoff_day"] = "2018-02-28"
    time_hold["test_families"] = sorted(df.loc[late & (y == 1), "Label"].unique().tolist())
    print("B unseen families (days >= 02-28):", {k: round(v, 4) if isinstance(v, float) else v for k, v in time_hold.items() if k not in ("confusion", "test_families")})
    joblib.dump({"model": model_b, "features": feats, "scenario": "unseen"}, out / "model_unseen.joblib", compress=3)
    df.loc[late].to_parquet(out / "replay_unseen.parquet", index=False)

    per_family = {}
    for fam, g in df.loc[ite][df.loc[ite, "is_attack"] == 1].groupby("Label"):
        per_family[fam] = {"held_out_flows": int(len(g)), "recall": float((model_a.predict_proba(g[feats].astype("float64"))[:, 1] >= 0.5).mean())}
    (out / "metrics.json").write_text(json.dumps({
        "trained_at": datetime.now(timezone.utc).isoformat(), "algorithm": "HistGradientBoostingClassifier", "features": feats,
        "sample_rows": int(len(df)), "known_families": random_split, "unseen_families": time_hold, "per_family_known": per_family,
        "scenarios": {"known": "model on 80 % of the flows, replay of the held-out 20 %",
                      "unseen": "model on days before 2018-02-28, replay of 2018-02-28 and later"},
        "caveat": "Sample mix is not natural traffic (attack share about 62 %); the model misses families absent from training (scenario unseen)."}, indent=1), encoding="utf-8")
    print("saved", out)


if __name__ == "__main__":
    main()
