"""Train, evaluate and persist the triage model.

    python -m app.ml.train            (from backend/)

Candidates: Logistic Regression (baseline), Random Forest, XGBoost. Selection uses macro-F1 on the
validation split; a simpler model wins ties within 0.005. Final metrics are measured once on the
held-out test split. Leakage prevention: stratified 70/15/15 split, and any test/validation row whose
feature vector also appears in the training split is removed before evaluation.
"""
from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import sklearn
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import confusion_matrix, f1_score, precision_recall_fscore_support, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

from app.core.config import get_settings
from app.ml.features import FEATURES, LABELS
from app.ml.synthetic import DATASET_NAME, DATASET_VERSION, generate

MODEL_FILE = "triage_model.joblib"
METRICS_FILE = "metrics.json"
COMPLEXITY = {"logistic_regression": 0, "random_forest": 1, "xgboost": 2}


def _candidates(n_classes: int):
    from xgboost import XGBClassifier

    return {
        "logistic_regression": make_pipeline(StandardScaler(), LogisticRegression(max_iter=2000, C=1.0)),
        "random_forest": RandomForestClassifier(n_estimators=300, max_depth=14, min_samples_leaf=2,
                                                class_weight="balanced", n_jobs=-1, random_state=7),
        "xgboost": XGBClassifier(n_estimators=300, max_depth=5, learning_rate=0.08, subsample=0.9,
                                 colsample_bytree=0.9, objective="multi:softprob", num_class=n_classes,
                                 eval_metric="mlogloss", tree_method="hist", random_state=7, n_jobs=4),
    }


def _drop_overlap(X_train: np.ndarray, X: np.ndarray, y: np.ndarray) -> tuple[np.ndarray, np.ndarray, int]:
    seen = {row.tobytes() for row in np.round(X_train, 3)}
    mask = np.array([row.tobytes() not in seen for row in np.round(X, 3)])
    return X[mask], y[mask], int((~mask).sum())


def _metrics(model, X: np.ndarray, y: np.ndarray) -> dict:
    proba = model.predict_proba(X)
    pred = proba.argmax(axis=1)
    p, r, f, s = precision_recall_fscore_support(y, pred, labels=range(len(LABELS)), zero_division=0)
    return {
        "macro_f1": round(float(f1_score(y, pred, average="macro")), 4),
        "accuracy": round(float((pred == y).mean()), 4),
        "roc_auc_ovr_macro": round(float(roc_auc_score(y, proba, multi_class="ovr", average="macro")), 4),
        "per_class": {LABELS[i]: {"precision": round(float(p[i]), 4), "recall": round(float(r[i]), 4),
                                  "f1": round(float(f[i]), 4), "support": int(s[i])} for i in range(len(LABELS))},
        "confusion_matrix": {"labels": LABELS, "matrix": confusion_matrix(y, pred, labels=range(len(LABELS))).tolist()},
    }


def _importance(name: str, model) -> list[dict]:
    if name == "logistic_regression":
        coefs = np.abs(model[-1].coef_).mean(axis=0)
        vals = coefs / coefs.sum()
    else:
        vals = model.feature_importances_
        vals = vals / vals.sum()
    order = np.argsort(vals)[::-1]
    return [{"feature": FEATURES[i], "importance": round(float(vals[i]), 4)} for i in order]


def train(out_dir: str | None = None, eval_dir: str | None = None, n_samples: int = 12000, seed: int = 1337,
          save_dataset: bool = True) -> dict:
    settings = get_settings()
    out = Path(out_dir or settings.ml_model_dir)
    ev_dir = Path(eval_dir or settings.ml_eval_dir)
    out.mkdir(parents=True, exist_ok=True)
    ev_dir.mkdir(parents=True, exist_ok=True)
    t0 = time.time()

    df = generate(n_samples, seed)
    if save_dataset:
        ds_dir = Path(settings.repo_dir) / "ml" / "datasets"
        ds_dir.mkdir(parents=True, exist_ok=True)
        df.to_csv(ds_dir / "synthetic_soc_triage_v1.csv", index=False)
    X = df[FEATURES].to_numpy(dtype=float)
    y = df["label"].map({l: i for i, l in enumerate(LABELS)}).to_numpy()

    X_train, X_tmp, y_train, y_tmp = train_test_split(X, y, test_size=0.30, stratify=y, random_state=seed)
    X_val, X_test, y_val, y_test = train_test_split(X_tmp, y_tmp, test_size=0.50, stratify=y_tmp, random_state=seed)
    X_val, y_val, dropped_val = _drop_overlap(X_train, X_val, y_val)
    X_test, y_test, dropped_test = _drop_overlap(X_train, X_test, y_test)

    candidates = _candidates(len(LABELS))
    evaluated = {}
    for name, model in candidates.items():
        ts = time.time()
        model.fit(X_train, y_train)
        evaluated[name] = {"validation": _metrics(model, X_val, y_val), "fit_seconds": round(time.time() - ts, 2)}

    best = max(evaluated, key=lambda n: (evaluated[n]["validation"]["macro_f1"], -COMPLEXITY[n]))
    best_f1 = evaluated[best]["validation"]["macro_f1"]
    simpler = [n for n in evaluated if COMPLEXITY[n] < COMPLEXITY[best]
               and best_f1 - evaluated[n]["validation"]["macro_f1"] <= 0.005]
    if simpler:
        best = min(simpler, key=lambda n: COMPLEXITY[n])
    model = candidates[best]
    test_metrics = _metrics(model, X_test, y_test)

    iso = IsolationForest(n_estimators=200, contamination="auto", random_state=seed).fit(X_train)
    train_scores = iso.score_samples(X_train)
    ood_threshold = float(np.percentile(train_scores, 0.5))
    baseline = np.median(X_train, axis=0)

    version = f"{DATASET_VERSION}-{best}-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"
    artifact = {
        "model": model, "model_name": best, "version": version, "features": FEATURES, "labels": LABELS,
        "isolation_forest": iso, "ood_threshold": ood_threshold, "baseline": baseline.tolist(),
        "feature_min": X_train.min(axis=0).tolist(), "feature_max": X_train.max(axis=0).tolist(),
        "sklearn_version": sklearn.__version__, "trained_at": datetime.now(timezone.utc).isoformat(),
    }
    joblib.dump(artifact, out / MODEL_FILE)

    report = {
        "model_name": best, "version": version, "trained_at": artifact["trained_at"],
        "dataset": {"name": DATASET_NAME, "version": DATASET_VERSION, "synthetic": True, "rows": int(len(df)),
                    "seed": seed, "class_balance": df["label"].value_counts().to_dict(),
                    "archetypes": df["archetype"].value_counts().to_dict(),
                    "splits": {"train": int(len(y_train)), "validation": int(len(y_val)), "test": int(len(y_test))},
                    "overlap_rows_removed": {"validation": dropped_val, "test": dropped_test},
                    "label_noise_rate": 0.03, "feature_noise_rate": 0.02},
        "selection": {"criterion": "validation macro-F1, simpler model wins ties within 0.005",
                      "candidates": evaluated},
        "test": test_metrics,
        "feature_importance": _importance(best, model),
        "abstention": {"min_completeness": 0.4, "min_probability": 0.55,
                       "ood": "IsolationForest score below the 0.5th percentile of training scores",
                       "ood_threshold": round(ood_threshold, 4)},
        "limitations": [
            "Trained on synthetic, explicitly labelled demonstration data; metrics measure recovery of the "
            "generator's archetypes, not real-world SOC performance.",
            "Features overlap with the deterministic rules (behaviour, CTI, context), so the model is not an "
            "independent witness; the decision engine caps its influence.",
            "Retrain on your own labelled triage history (e.g. exported analyst verdicts) before operational use.",
        ],
        "training_seconds": round(time.time() - t0, 2),
        "sklearn_version": sklearn.__version__,
    }
    (ev_dir / METRICS_FILE).write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report


if __name__ == "__main__":
    r = train()
    print(json.dumps({"model": r["model_name"], "version": r["version"], "test_macro_f1": r["test"]["macro_f1"],
                      "candidates": {k: v["validation"]["macro_f1"] for k, v in r["selection"]["candidates"].items()}},
                     indent=2))
