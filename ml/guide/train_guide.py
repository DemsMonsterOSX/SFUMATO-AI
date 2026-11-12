#!/usr/bin/env python3
"""Train the GUIDE triage model (TruePositive / FalsePositive / BenignPositive) and publish it to a bucket.

Runs on a free Kaggle notebook (see sfumato_guide_kaggle.ipynb) or anywhere with the CSV files:

    python train_guide.py --csv GUIDE_Train.csv GUIDE_Test.csv --out guide_out \
        --publish-to gs://my-bucket/sfumato      # needs ARTIFACT_SIGNING_KEY + GCS credentials

Method
------
* Rows (evidence items) are aggregated per incident: categories, MITRE techniques, entity types, first timestamp.
  Only portable signals are used (see backend/app/ml/guide_features.py); anonymised IDs are ignored.
* Leakage control: an incident is one atomic example; whole *organisations* (15 %) are held out as the test set, so
  the reported metrics measure generalisation to organisations never seen in training — the real situation of a
  new SOC using Sfumato. Validation (for model selection) is a stratified split of the remaining incidents.
* Candidates: Logistic Regression (baseline), Random Forest, XGBoost; selection by validation macro-F1, the simpler
  model wins ties within 0.005. The report adds the binary view "threat (TP) vs non-threat (FP + BP)".
* An IsolationForest fitted on the training data lets the service abstain on out-of-distribution inputs.
* Dataset: Microsoft Security Incident Prediction (GUIDE), CDLA-Permissive-2.0, https://www.kaggle.com/datasets/Microsoft/microsoft-security-incident-prediction
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import confusion_matrix, f1_score, precision_recall_fscore_support, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.utils.class_weight import compute_sample_weight

HERE = Path(__file__).resolve().parent
for cand in (HERE, HERE.parent.parent / "backend" / "app" / "ml", HERE.parent.parent / "backend" / "app" / "storage"):
    if cand.exists() and str(cand) not in sys.path:
        sys.path.insert(0, str(cand))
import artifacts  # noqa: E402
import guide_features as gf  # noqa: E402

DATASET = {"name": "Microsoft Security Incident Prediction (GUIDE)", "license": "CDLA-Permissive-2.0",
           "url": "https://www.kaggle.com/datasets/Microsoft/microsoft-security-incident-prediction"}
COMPLEXITY = {"logistic_regression": 0, "random_forest": 1, "xgboost": 2}
USECOLS = {"IncidentId", "OrgId", "Timestamp", "Category", "MitreTechniques", "EntityType", "IncidentGrade"}
REQUIRED = {"IncidentId", "IncidentGrade"}


def aggregate(csv_paths: list[str], max_rows: int | None, log) -> tuple[pd.DataFrame, dict[str, pd.DataFrame]]:
    metas, pairs = [], {"cat": [], "tech": [], "ent": []}
    rows = 0
    for path in csv_paths:
        for chunk in pd.read_csv(path, usecols=lambda c: c in USECOLS, chunksize=1_000_000, dtype=str):
            missing = REQUIRED - set(chunk.columns)
            if missing:
                raise SystemExit(f"{path}: missing column(s) {sorted(missing)} — is this a GUIDE file?")
            if max_rows is not None and rows + len(chunk) > max_rows:
                chunk = chunk.iloc[: max_rows - rows]
            rows += len(chunk)
            if "OrgId" not in chunk:
                chunk["OrgId"] = "unknown"
            if "Timestamp" not in chunk:
                chunk["Timestamp"] = None
            metas.append(chunk.groupby("IncidentId").agg(org=("OrgId", "first"), grade=("IncidentGrade", "first"),
                                                         ts=("Timestamp", "min")))
            if "Category" in chunk:
                pairs["cat"].append(chunk[["IncidentId", "Category"]].dropna().drop_duplicates())
            if "MitreTechniques" in chunk:
                t = chunk[["IncidentId", "MitreTechniques"]].dropna().drop_duplicates()
                t["Tech"] = t["MitreTechniques"].map(gf.split_techniques)
                pairs["tech"].append(t[["IncidentId", "Tech"]].explode("Tech").dropna().drop_duplicates())
            if "EntityType" in chunk:
                pairs["ent"].append(chunk[["IncidentId", "EntityType"]].dropna().drop_duplicates())
            log(f"  {rows:,} rows read")
            if max_rows is not None and rows >= max_rows:
                break
    meta = pd.concat(metas).groupby(level=0).agg(org=("org", "first"), grade=("grade", "first"), ts=("ts", "min"))
    meta["label"] = meta["grade"].map(lambda g: gf.GRADE_MAP.get(gf.norm_key(g)) if isinstance(g, str) else None)
    meta = meta.dropna(subset=["label"])
    merged = {k: (pd.concat(v).drop_duplicates() if v else pd.DataFrame(columns=["IncidentId", "x"]))
              for k, v in pairs.items()}
    return meta, merged


def build_matrix(meta: pd.DataFrame, pairs: dict[str, pd.DataFrame], log):
    cat, tech, ent = pairs["cat"], pairs["tech"], pairs["ent"]
    in_meta = lambda df: df[df["IncidentId"].isin(meta.index)]  # noqa: E731
    cat, tech, ent = in_meta(cat), in_meta(tech), in_meta(ent)
    cat_col = cat.columns[1] if len(cat) else None
    vocab = gf.build_vocab(cat[cat_col].value_counts().to_dict() if cat_col else {},
                           tech["Tech"].value_counts().to_dict() if len(tech) else {},
                           ent[ent.columns[1]].value_counts().to_dict() if len(ent) else {})
    by = {k: (df.groupby("IncidentId")[df.columns[1]].agg(list) if len(df) else pd.Series(dtype=object))
          for k, df in (("cat", cat), ("tech", tech), ("ent", ent))}
    X = np.zeros((len(meta), len(gf.feature_names(vocab))), dtype=np.float32)
    empty: list = []
    for i, (iid, ts) in enumerate(zip(meta.index, meta["ts"])):
        X[i], _ = gf.featurize(vocab, by["cat"].get(iid, empty), by["tech"].get(iid, empty), by["ent"].get(iid, empty), ts)
        if i % 200_000 == 0 and i:
            log(f"  featurised {i:,}/{len(meta):,}")
    return X, vocab


def candidates(fast: bool, n_classes: int):
    from xgboost import XGBClassifier

    return {
        "logistic_regression": make_pipeline(StandardScaler(), LogisticRegression(max_iter=1000, C=1.0, class_weight="balanced")),
        "random_forest": RandomForestClassifier(n_estimators=60 if fast else 200, max_depth=16, min_samples_leaf=3,
                                                class_weight="balanced", n_jobs=-1, random_state=7,
                                                max_samples=0.6),
        "xgboost": XGBClassifier(n_estimators=80 if fast else 300, max_depth=7, learning_rate=0.1, subsample=0.8,
                                 colsample_bytree=0.8, objective="multi:softprob", num_class=n_classes,
                                 eval_metric="mlogloss", tree_method="hist", random_state=7, n_jobs=4),
    }


def metrics(model, X, y) -> dict:
    proba = model.predict_proba(X)
    pred = proba.argmax(axis=1)
    p, r, f, s = precision_recall_fscore_support(y, pred, labels=range(len(gf.LABELS)), zero_division=0)
    present = len(np.unique(y)) == len(gf.LABELS)
    threat = (y == 0)
    pred_threat = pred == 0
    tp = int((threat & pred_threat).sum())
    return {
        "macro_f1": round(float(f1_score(y, pred, average="macro")), 4),
        "accuracy": round(float((pred == y).mean()), 4),
        "roc_auc_ovr_macro": round(float(roc_auc_score(y, proba, multi_class="ovr", average="macro")), 4) if present else None,
        "per_class": {gf.LABELS[i]: {"precision": round(float(p[i]), 4), "recall": round(float(r[i]), 4),
                                     "f1": round(float(f[i]), 4), "support": int(s[i])} for i in range(len(gf.LABELS))},
        "confusion_matrix": {"labels": gf.LABELS, "matrix": confusion_matrix(y, pred, labels=range(len(gf.LABELS))).tolist()},
        "binary_threat_vs_non_threat": {
            "roc_auc": round(float(roc_auc_score(threat, proba[:, 0])), 4) if 0 < threat.sum() < len(y) else None,
            "threat_precision": round(tp / max(1, int(pred_threat.sum())), 4),
            "threat_recall": round(tp / max(1, int(threat.sum())), 4),
            "non_threat_precision": round(int((~threat & ~pred_threat).sum()) / max(1, int((~pred_threat).sum())), 4),
            "non_threat_recall": round(int((~threat & ~pred_threat).sum()) / max(1, int((~threat).sum())), 4)},
    }


def importance(name: str, model, names: list[str]) -> list[dict]:
    vals = np.abs(model[-1].coef_).mean(axis=0) if name == "logistic_regression" else model.feature_importances_
    vals = vals / (vals.sum() or 1)
    return [{"feature": names[i], "importance": round(float(vals[i]), 4)} for i in np.argsort(vals)[::-1][:40]]


def train(csv_paths: list[str], out_dir: str, max_rows: int | None = None, seed: int = 42, fast: bool = False,
          log=print) -> dict:
    t0 = time.time()
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    log(f"Aggregating {len(csv_paths)} file(s) per incident…")
    meta, pairs = aggregate(csv_paths, max_rows, log)
    if len(meta) < 200:
        raise SystemExit(f"Only {len(meta)} graded incidents found: need more data")
    X, vocab = build_matrix(meta, pairs, log)
    y = meta["label"].map({l: i for i, l in enumerate(gf.LABELS)}).to_numpy()
    names = gf.feature_names(vocab)

    rng = np.random.default_rng(seed)
    orgs = meta["org"].astype(str).unique()
    split_note = "organisation hold-out (15 % of organisations)"
    if len(orgs) >= 8:
        test_orgs = set(rng.choice(orgs, size=max(2, int(0.15 * len(orgs))), replace=False))
        is_test = meta["org"].astype(str).isin(test_orgs).to_numpy()
        tr_idx, te_idx = np.where(~is_test)[0], np.where(is_test)[0]
    else:  # too few organisations to hold any out
        tr_idx, te_idx = train_test_split(np.arange(len(y)), test_size=0.15, stratify=y, random_state=seed)
        split_note = "stratified incident split (fewer than 8 organisations in the data)"
    tr_idx, va_idx = train_test_split(tr_idx, test_size=0.15, stratify=y[tr_idx], random_state=seed)
    Xtr, ytr, Xva, yva, Xte, yte = X[tr_idx], y[tr_idx], X[va_idx], y[va_idx], X[te_idx], y[te_idx]
    log(f"train {len(ytr):,} / validation {len(yva):,} / test {len(yte):,} incidents ({split_note})")

    models = candidates(fast, len(gf.LABELS))
    evaluated = {}
    w = compute_sample_weight("balanced", ytr)
    for name, model in models.items():
        ts = time.time()
        if name == "xgboost":
            model.fit(Xtr, ytr, sample_weight=w)
        else:
            model.fit(Xtr, ytr)
        evaluated[name] = {"validation": metrics(model, Xva, yva), "fit_seconds": round(time.time() - ts, 1)}
        log(f"  {name}: validation macro-F1 {evaluated[name]['validation']['macro_f1']}")
    best = max(evaluated, key=lambda n: (evaluated[n]["validation"]["macro_f1"], -COMPLEXITY[n]))
    simpler = [n for n in evaluated if COMPLEXITY[n] < COMPLEXITY[best]
               and evaluated[best]["validation"]["macro_f1"] - evaluated[n]["validation"]["macro_f1"] <= 0.005]
    if simpler:
        best = min(simpler, key=lambda n: COMPLEXITY[n])
    model = models[best]
    test = metrics(model, Xte, yte)

    sub = Xtr[rng.choice(len(Xtr), size=min(len(Xtr), 200_000), replace=False)]
    iso = IsolationForest(n_estimators=100, random_state=seed, n_jobs=-1).fit(sub)
    ood_threshold = float(np.percentile(iso.score_samples(sub), 0.5))
    version = f"{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}-{best}"
    artifact = {"model": model, "model_name": best, "version": version, "vocab": vocab, "feature_names": names,
                "labels": gf.LABELS, "isolation_forest": iso, "ood_threshold": ood_threshold,
                "sklearn_version": sklearn.__version__, "trained_at": datetime.now(timezone.utc).isoformat(),
                "dataset": DATASET}
    joblib.dump(artifact, out / "guide_model.joblib", compress=3)
    report = {
        "model_name": best, "version": version, "trained_at": artifact["trained_at"], "dataset": DATASET,
        "data": {"rows_read_limit": max_rows, "incidents": int(len(y)), "organisations": int(len(orgs)),
                 "class_balance": {gf.LABELS[i]: int((y == i).sum()) for i in range(len(gf.LABELS))},
                 "split": {"method": split_note, "train": int(len(ytr)), "validation": int(len(yva)), "test": int(len(yte))},
                 "features": len(names), "vocabulary": {k: len(v) for k, v in vocab.items()}},
        "selection": {"criterion": "validation macro-F1, simpler model wins ties within 0.005", "candidates": evaluated},
        "test": test, "feature_importance": importance(best, model, names),
        "abstention": {"min_coverage": 0.34, "min_probability": 0.5, "ood_threshold": round(ood_threshold, 4),
                       "ood": "IsolationForest score below the 0.5th percentile of training scores"},
        "limitations": [
            "Only portable signals (category, ATT&CK techniques, entity types, hour) are used: anonymised GUIDE "
            "identifiers cannot be reproduced from a Sfumato alert, so this is a coarse, second-opinion model.",
            "GUIDE comes from Microsoft customers' detections (Defender / Sentinel); alerts from other sources can "
            "be out of distribution — the service abstains when its coverage or novelty checks fail.",
            "Labels are analyst decisions of those customers, not ground truth."],
        "training_seconds": round(time.time() - t0, 1), "sklearn_version": sklearn.__version__}
    (out / "metrics.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    log(f"Done in {report['training_seconds']} s — best: {best}, test macro-F1 {test['macro_f1']}, "
        f"threat-vs-rest ROC-AUC {test['binary_threat_vs_non_threat']['roc_auc']}")
    return report


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--csv", nargs="+", required=True, help="GUIDE_Train.csv [GUIDE_Test.csv]")
    ap.add_argument("--out", default="guide_out")
    ap.add_argument("--max-rows", type=int, default=None, help="limit rows read (quick runs)")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--fast", action="store_true", help="smaller models (smoke tests)")
    ap.add_argument("--publish-to", help="gs://bucket/prefix | hf://user/repo | folder (needs ARTIFACT_SIGNING_KEY)")
    args = ap.parse_args(argv)
    report = train(args.csv, args.out, args.max_rows, args.seed, args.fast)
    if args.publish_to:
        key = os.environ.get("ARTIFACT_SIGNING_KEY")
        if not key:
            raise SystemExit("Set ARTIFACT_SIGNING_KEY (same value in Sfumato's .env): remote models must be signed")
        store = artifacts.open_store(args.publish_to, os.environ.get("HF_TOKEN"))
        version = artifacts.publish(store, "guide_triage", args.out, signing_key=key,
                                    extra={"model": report["model_name"], "macro_f1": report["test"]["macro_f1"],
                                           "dataset": DATASET["name"]})
        print(f"Published guide_triage/{version} to {store.describe()}")
        print(f"In Sfumato's .env:  ML_ARTIFACT_URI={args.publish_to}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
