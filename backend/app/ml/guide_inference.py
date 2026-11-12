"""Reference triage model trained on Microsoft GUIDE: loading (bucket or local folder), prediction, abstention.

The model is downloaded from the artifact store configured with ML_ARTIFACT_URI (gs://, hf://, folder). Remote
artifacts are only loaded if their HMAC signature and sha256 checksums verify (ARTIFACT_SIGNING_KEY), because a
model file is a pickle. Without any configured store, a model found in <ML_MODEL_DIR>/guide/ is used; with
neither, the service is simply "unavailable" and Sfumato works exactly as before.
"""
from __future__ import annotations

import json
import logging
import os
import threading
import time
from pathlib import Path

import joblib
import numpy as np
import sklearn

from app.core.config import get_settings
from app.ml import guide_features as gf
from app.ml.guide_adapter import incident_to_guide
from app.schemas.evidence import Evidence
from app.schemas.incident import IncidentIn
from app.services.credentials import get_credentials
from app.storage import artifacts

log = logging.getLogger("sfumato.guide")
MIN_COVERAGE = 0.34
MIN_PROBABILITY = 0.5
VOTE = {"true_positive": "TRUE_POSITIVE", "false_positive": "FALSE_POSITIVE", "benign_positive": "LEGITIMATE_ACTIVITY"}


class GuideModelService:
    def __init__(self) -> None:
        self.artifact: dict | None = None
        self.metrics: dict | None = None
        self.meta: dict = {}
        self.state = "not_loaded"
        self.error: str | None = None
        self.source: str | None = None
        self.loaded_at: float | None = None
        self.latencies: list[float] = []
        self._lock = threading.Lock()
        self._last_attempt = 0.0

    # ----------------------------------------------------------------------------------------- loading
    def _locate(self) -> tuple[Path | None, str | None, dict]:
        s = get_settings()
        if s.ml_artifact_uri:
            if s.google_application_credentials:
                os.environ.setdefault("GOOGLE_APPLICATION_CREDENTIALS", s.google_application_credentials)
            store = artifacts.open_store(s.ml_artifact_uri, get_credentials().get("hf_token"))
            remote = not isinstance(store, artifacts.LocalStore)
            got = artifacts.fetch_latest(store, s.ml_artifact_name, Path(s.ml_model_dir) / "downloads",
                                         signing_key=s.artifact_signing_key,
                                         require_signature=remote and s.ml_artifact_require_signature)
            if got:
                version, folder, meta = got
                return folder, f"{store.describe()}/{s.ml_artifact_name}@{version}", meta
            raise artifacts.ArtifactError(f"No '{s.ml_artifact_name}' published in {store.describe()}")
        local = Path(s.ml_model_dir) / "guide"
        if (local / "guide_model.joblib").exists():
            return local, f"local folder {local}", {}
        return None, None, {}

    def sync(self) -> dict:
        s = get_settings()
        with self._lock:
            self._last_attempt = time.time()
            try:
                self.state, self.error = "loading", None
                folder, source, meta = self._locate()
                if folder is None:
                    self.state = "not_configured"
                    return self.status()
                art = joblib.load(folder / "guide_model.joblib")
                if art.get("sklearn_version") != sklearn.__version__:
                    raise ValueError(f"model trained with scikit-learn {art.get('sklearn_version')}, "
                                     f"runtime is {sklearn.__version__}: retrain with the same version")
                mpath = folder / "metrics.json"
                self.metrics = json.loads(mpath.read_text(encoding="utf-8")) if mpath.exists() else None
                self.artifact, self.meta, self.source = art, meta, source
                self.loaded_at, self.state = time.time(), "ready"
                log.info("GUIDE reference model ready: %s (%s)", art["version"], source)
            except Exception as e:
                log.warning("GUIDE reference model unavailable: %s", e)
                self.state, self.error = "error", f"{type(e).__name__}: {e}"
                if s.ml_artifact_uri and self.artifact is None:
                    pass  # keep serving without it
        return self.status()

    def ensure_loaded(self) -> bool:
        if self.ready:
            return True
        if self.state == "loading" or time.time() - self._last_attempt < 60:
            return False
        return self.sync()["state"] == "ready"

    def start_background_sync(self) -> None:
        threading.Thread(target=self.sync, name="guide-sync", daemon=True).start()

    @property
    def ready(self) -> bool:
        return self.state == "ready" and self.artifact is not None

    # ------------------------------------------------------------------------------------- prediction
    def predict(self, incident: IncidentIn, evidence: list[Evidence]) -> dict:
        if not self.ready:
            return {"status": "unavailable", "reason": self.error or self.state}
        t0 = time.perf_counter()
        a = self.artifact
        sig = incident_to_guide(incident, evidence)
        x, cov = gf.featurize(a["vocab"], sig["categories"], sig["techniques"], sig["entities"], sig["timestamp"])
        proba = a["model"].predict_proba(x.reshape(1, -1))[0]
        idx = int(proba.argmax())
        ood_score = float(a["isolation_forest"].score_samples(x.reshape(1, -1))[0])
        reason = None
        discriminating = cov["matched"]["categories"] or cov["matched"]["techniques"]
        if cov["coverage"] < MIN_COVERAGE or not discriminating:
            # entity types alone (e.g. "a machine was involved") say nothing about whether the alert is real
            reason = "insufficient_coverage"
        elif ood_score < a["ood_threshold"]:
            reason = "out_of_distribution"
        elif proba[idx] < MIN_PROBABILITY:
            reason = "low_confidence"
        label = a["labels"][idx]
        p_threat = float(proba[a["labels"].index("true_positive")])
        latency = (time.perf_counter() - t0) * 1000
        self.latencies = (self.latencies + [latency])[-100:]
        return {
            "status": "abstained" if reason else "classified", "reason": reason,
            "label": None if reason else label, "top_label": label,
            "probabilities": {l: round(float(p), 4) for l, p in zip(a["labels"], proba)},
            "p_threat": round(p_threat, 4), "p_non_threat": round(1 - p_threat, 4),
            "is_false_positive_or_benign": None if reason else label != "true_positive",
            "coverage": cov, "ood_score": round(ood_score, 4), "ood_threshold": round(a["ood_threshold"], 4),
            "signals": {"categories": sig["categories"], "techniques": sig["techniques"], "entities": sig["entities"]},
            "model_name": a["model_name"], "model_version": a["version"], "dataset": a["dataset"]["name"],
            "latency_ms": round(latency, 2),
        }

    def status(self) -> dict:
        a = self.artifact or {}
        lat = self.latencies[-50:]
        return {"state": self.state, "error": self.error, "source": self.source,
                "uri": get_settings().ml_artifact_uri, "artifact_name": get_settings().ml_artifact_name,
                "signature_required": get_settings().ml_artifact_require_signature,
                "signing_key_configured": bool(get_settings().artifact_signing_key),
                "model_name": a.get("model_name"), "version": a.get("version"), "trained_at": a.get("trained_at"),
                "dataset": a.get("dataset"), "published": self.meta.get("created_at"),
                "avg_latency_ms": round(sum(lat) / len(lat), 2) if lat else None}


guide_service = GuideModelService()
