"""Online inference with abstention and per-incident explanations."""
from __future__ import annotations

import json
import logging
import threading
import time
from pathlib import Path

import joblib
import numpy as np
import sklearn

from app.core.config import get_settings
from app.ml.features import FEATURES, vector
from app.ml.train import METRICS_FILE, MODEL_FILE, train

log = logging.getLogger("sfumato.ml")
MIN_COMPLETENESS = 0.4
MIN_PROBABILITY = 0.55


class ModelService:
    def __init__(self) -> None:
        self.artifact: dict | None = None
        self.metrics: dict | None = None
        self.error: str | None = None
        self.latencies: list[float] = []
        self._lock = threading.Lock()

    def load(self) -> None:
        settings = get_settings()
        path = Path(settings.ml_model_dir) / MODEL_FILE
        with self._lock:
            try:
                try:
                    art = joblib.load(path) if path.exists() else None
                except Exception as e:  # unreadable/incompatible pickle: retrain below
                    log.warning("Cannot load model artifact (%s): retraining", e)
                    art = None
                if art and art.get("sklearn_version") != sklearn.__version__:
                    log.warning("Model trained with scikit-learn %s, runtime is %s: retraining",
                                art.get("sklearn_version"), sklearn.__version__)
                    art = None
                if art and art.get("features") != FEATURES:
                    log.warning("Model feature set differs from the code: retraining")
                    art = None
                if art is None:
                    if not settings.ml_auto_train:
                        raise FileNotFoundError(f"No compatible model at {path} and ML_AUTO_TRAIN is disabled")
                    log.info("Training triage model (first start or incompatible artifact)…")
                    train()
                    art = joblib.load(path)
                self.artifact = art
                mpath = Path(settings.ml_eval_dir) / METRICS_FILE
                self.metrics = json.loads(mpath.read_text(encoding="utf-8")) if mpath.exists() else None
                self.error = None
                log.info("Loaded ML model %s (%s)", art["model_name"], art["version"])
            except Exception as e:  # keep the platform usable: ML then abstains
                log.exception("ML model unavailable")
                self.artifact = None
                self.error = f"{type(e).__name__}: {e}"

    @property
    def ready(self) -> bool:
        return self.artifact is not None

    def status(self) -> dict:
        if not self.ready:
            return {"ready": False, "error": self.error}
        a = self.artifact
        lat = self.latencies[-50:]
        return {"ready": True, "model_name": a["model_name"], "version": a["version"], "trained_at": a["trained_at"],
                "features": len(a["features"]), "labels": a["labels"],
                "avg_latency_ms": round(sum(lat) / len(lat), 2) if lat else None}

    def predict(self, features: dict[str, float], meta: dict) -> dict:
        if not self.ready:
            return {"status": "unavailable", "reason": self.error or "model not loaded", "label": None,
                    "probabilities": {}, "completeness": meta.get("completeness")}
        t0 = time.perf_counter()
        a = self.artifact
        x = np.array([vector(features)])
        proba = a["model"].predict_proba(x)[0]
        idx = int(proba.argmax())
        ood_score = float(a["isolation_forest"].score_samples(x)[0])
        out_of_range = []
        for i, v in enumerate(x[0]):
            lo, hi = a["feature_min"][i], a["feature_max"][i]
            tol = 0.05 * (hi - lo) + 1e-6  # tolerance: 1.0 vs a training max of 0.9999 is not "out of range"
            if v < lo - tol or v > hi + tol:
                out_of_range.append(FEATURES[i])
        reason = None
        if meta.get("completeness", 1) < MIN_COMPLETENESS:
            reason = "insufficient_features"
        elif ood_score < a["ood_threshold"] or out_of_range:
            reason = "out_of_distribution"
        elif proba[idx] < MIN_PROBABILITY:
            reason = "low_confidence"
        contributions = self._explain(x, idx, proba[idx])
        latency = (time.perf_counter() - t0) * 1000
        self.latencies.append(latency)
        self.latencies = self.latencies[-200:]
        return {
            "status": "abstained" if reason else "classified",
            "reason": reason,
            "label": None if reason else a["labels"][idx],
            "top_label": a["labels"][idx],
            "probabilities": {lab: round(float(p), 4) for lab, p in zip(a["labels"], proba)},
            "completeness": meta.get("completeness"),
            "evidence_sources": meta.get("sources"),
            "ood_score": round(ood_score, 4), "ood_threshold": round(a["ood_threshold"], 4),
            "out_of_range_features": out_of_range,
            "contributions": contributions,
            "model_name": a["model_name"], "model_version": a["version"],
            "latency_ms": round(latency, 2),
        }

    def _explain(self, x: np.ndarray, idx: int, p: float) -> list[dict]:
        """Occlusion: replace each non-baseline feature by the training median and measure the change."""
        a = self.artifact
        base = np.array(a["baseline"])
        rows, names = [], []
        for i, v in enumerate(x[0]):
            if abs(v - base[i]) > 1e-9:
                r = x[0].copy()
                r[i] = base[i]
                rows.append(r)
                names.append(i)
        if not rows:
            return []
        probs = a["model"].predict_proba(np.array(rows))[:, idx]
        contrib = [{"feature": FEATURES[i], "value": round(float(x[0][i]), 3),
                    "contribution": round(float(p - q), 4)} for i, q in zip(names, probs)]
        contrib.sort(key=lambda c: abs(c["contribution"]), reverse=True)
        return contrib[:10]


model_service = ModelService()
