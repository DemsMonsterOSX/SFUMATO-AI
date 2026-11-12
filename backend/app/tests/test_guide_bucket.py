"""Bucket artifacts (integrity/signature), GUIDE training pipeline and the reference model in the investigation.

The CSV below is a TEST FIXTURE in the GUIDE column layout, generated here with planted correlations. It exists to
exercise the pipeline offline; it is not GUIDE data and says nothing about real performance."""
import importlib.util
import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from app.core.config import get_settings
from app.decision.engine import evaluate
from app.ml import guide_features as gf
from app.ml.guide_inference import guide_service
from app.storage import artifacts
from app.tests.conftest import HEADERS, REPO, load_scenario, run_pending_jobs

KEY = "unit-test-signing-key"


# ------------------------------------------------------------------------------------------ artifacts
def _folder(tmp_path, name="payload"):
    d = tmp_path / name
    d.mkdir()
    (d / "a.bin").write_bytes(b"model-bytes")
    (d / "metrics.json").write_text('{"ok": true}', encoding="utf-8")
    return d


def test_publish_fetch_roundtrip_and_tamper_detection(tmp_path):
    store = artifacts.LocalStore(tmp_path / "bucket")
    v1 = artifacts.publish(store, "guide_triage", _folder(tmp_path), signing_key=KEY)
    version, folder, meta = artifacts.fetch_latest(store, "guide_triage", tmp_path / "dl", signing_key=KEY)
    assert version == v1 and (folder / "a.bin").read_bytes() == b"model-bytes" and set(meta["files"]) == {"a.bin", "metrics.json"}
    assert artifacts.fetch_latest(store, "unknown", tmp_path / "dl", signing_key=KEY) is None

    # wrong key / missing key are refused for remote-style loading
    with pytest.raises(artifacts.ArtifactError, match="Invalid signature"):
        artifacts.fetch_latest(store, "guide_triage", tmp_path / "dl2", signing_key="other-key")
    with pytest.raises(artifacts.ArtifactError, match="ARTIFACT_SIGNING_KEY is required"):
        artifacts.fetch_latest(store, "guide_triage", tmp_path / "dl3", signing_key=None)

    # a modified file in the bucket is detected by its checksum
    (tmp_path / "bucket" / "guide_triage" / v1 / "a.bin").write_bytes(b"EVIL-PICKLE")
    with pytest.raises(artifacts.ArtifactError, match="Checksum mismatch"):
        artifacts.fetch_latest(store, "guide_triage", tmp_path / "dl4", signing_key=KEY)
    assert not (tmp_path / "dl4" / "guide_triage" / v1).exists()  # nothing half-installed

    # forged metadata (e.g. swapped file list) breaks the signature
    p = tmp_path / "bucket" / "guide_triage" / v1 / "ARTIFACT.json"
    doc = json.loads(p.read_text())
    doc["meta"]["files"]["a.bin"] = artifacts.sha256_file(tmp_path / "bucket" / "guide_triage" / v1 / "a.bin")
    p.write_text(json.dumps(doc))
    with pytest.raises(artifacts.ArtifactError, match="Invalid signature"):
        artifacts.fetch_latest(store, "guide_triage", tmp_path / "dl5", signing_key=KEY)


def test_path_traversal_and_new_versions(tmp_path):
    store = artifacts.LocalStore(tmp_path / "bucket")
    artifacts.publish(store, "m", _folder(tmp_path), signing_key=KEY, version="v1")
    (tmp_path / "bucket" / "m" / "LATEST.json").write_text('{"version": "../../etc"}')
    with pytest.raises(artifacts.ArtifactError, match="Invalid version"):
        artifacts.fetch_latest(store, "m", tmp_path / "dl", signing_key=KEY)
    with pytest.raises(artifacts.ArtifactError):
        artifacts.publish(store, "../evil", _folder(tmp_path, "p2"), signing_key=KEY)
    artifacts.publish(store, "m", _folder(tmp_path, "p3"), signing_key=KEY, version="v2")
    assert artifacts.fetch_latest(store, "m", tmp_path / "dl", signing_key=KEY)[0] == "v2"


class _Blob:
    def __init__(self, store, key):
        self.store, self.key = store, key

    def exists(self):
        return self.key in self.store

    def download_as_text(self):
        return self.store[self.key].decode()

    def upload_from_string(self, text, content_type=None):
        self.store[self.key] = text.encode()

    def download_to_filename(self, dest):
        Path(dest).write_bytes(self.store[self.key])

    def upload_from_filename(self, src):
        self.store[self.key] = Path(src).read_bytes()


class _Bucket:
    def __init__(self):
        self.objects = {}

    def blob(self, key):
        return _Blob(self.objects, key)


class _Client:
    def __init__(self):
        self.b = _Bucket()

    def bucket(self, name):
        assert name == "sfumato-ml"
        return self.b


def test_gcs_store_roundtrip_with_prefix(tmp_path):
    client = _Client()
    store = artifacts.GCSStore("sfumato-ml", "prod/models", client=client)
    v = artifacts.publish(store, "guide_triage", _folder(tmp_path), signing_key=KEY)
    assert f"prod/models/guide_triage/{v}/a.bin" in client.b.objects and "prod/models/guide_triage/LATEST.json" in client.b.objects
    got = artifacts.fetch_latest(store, "guide_triage", tmp_path / "dl", signing_key=KEY)
    assert got[0] == v and store.describe() == "gs://sfumato-ml/prod/models"
    assert isinstance(artifacts.open_store("/tmp/x"), artifacts.LocalStore)
    with pytest.raises(artifacts.ArtifactError):
        artifacts.open_store("hf://only-one-part")


# ------------------------------------------------------------------------------------ features / training
def test_features_match_guide_vocabulary_across_spellings():
    vocab = gf.build_vocab({"InitialAccess": 10, "Execution": 8}, {"T1059.001": 5, "T1059": 6, "T1566": 4},
                           {"Ip": 9, "Url": 4, "Process": 3})
    x, cov = gf.featurize(vocab, ["initial-access"], ["T1059.001", "T9999"], ["ip", "Process", "Registry"], "2026-10-22T03:00:00Z")
    names = gf.feature_names(vocab)
    on = {n for n, v in zip(names, x) if v and n.split(":")[0] in ("cat", "tech", "ent")}
    assert on == {"cat:initialaccess", "tech:T1059.001", "tech:T1059", "ent:ip", "ent:process"}
    assert cov["coverage"] == 1.0
    _, none = gf.featurize(vocab, ["unknown-category"], [], [], None)
    assert none["coverage"] == 0.0
    assert gf.split_techniques("T1059.001;T1566") == ["T1059.001", "T1059", "T1566"]


def write_fixture_csv(path: Path, n_incidents: int = 2400, seed: int = 3) -> None:
    rng = np.random.default_rng(seed)
    cats = {"TruePositive": (["InitialAccess", "Execution", "CommandAndControl", "CredentialAccess"], 0.12),
            "BenignPositive": (["Discovery", "Execution", "Persistence", "SuspiciousActivity"], 0.35),
            "FalsePositive": (["SuspiciousActivity", "Discovery", "Collection", "Execution"], 0.5)}
    techs = {"TruePositive": ["T1566.001", "T1059.001", "T1105", "T1027", "T1071.001", "T1110"],
             "BenignPositive": ["T1059.001", "T1053.005", "T1078", "T1021.002"],
             "FalsePositive": ["T1083", "T1082", "T1057", "T1059.003"]}
    ents = {"TruePositive": ["Ip", "Url", "File", "Process", "Machine", "User"],
            "BenignPositive": ["Machine", "User", "Process", "File"],
            "FalsePositive": ["Machine", "File", "User", "Ip"]}
    grades = rng.choice(list(cats), size=n_incidents, p=[0.2, 0.35, 0.45])
    rows = []
    for i, g in enumerate(grades):
        org = f"org-{i % 40}"
        c_pool, noise = cats[g]
        hour = int(rng.integers(0, 24)) if g != "TruePositive" else int(rng.choice([1, 2, 3, 22, 23, 12, 14]))
        for a in range(int(rng.integers(1, 4))):
            cat = rng.choice(c_pool) if rng.random() > noise else rng.choice(sum((v[0] for v in cats.values()), []))
            tl = [t for t in techs[g] if rng.random() < 0.5] or [techs[g][0]]
            for e in range(int(rng.integers(1, 4))):
                rows.append({"Id": len(rows), "OrgId": org, "IncidentId": i, "AlertId": i * 10 + a,
                             "Timestamp": f"2026-05-0{1 + i % 7}T{hour:02d}:{int(rng.integers(0, 60)):02d}:00.000Z",
                             "DetectorId": int(rng.integers(0, 500)), "AlertTitle": int(rng.integers(0, 9000)),
                             "Category": cat, "MitreTechniques": ";".join(tl) if rng.random() > 0.15 else None,
                             "IncidentGrade": g, "EntityType": rng.choice(ents[g]), "DeviceId": int(rng.integers(0, 1e6))})
    pd.DataFrame(rows).to_csv(path, index=False)


@pytest.fixture(scope="module")
def trained(tmp_path_factory) -> tuple[Path, dict]:
    spec = importlib.util.spec_from_file_location("train_guide", REPO / "ml" / "guide" / "train_guide.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["train_guide"] = mod
    spec.loader.exec_module(mod)
    work = tmp_path_factory.mktemp("guide")
    csv = work / "GUIDE_Train.csv"
    write_fixture_csv(csv)
    report = mod.train([str(csv)], str(work / "out"), fast=True, log=lambda *_: None)
    return work, report


def test_training_report_is_measured_and_leak_free(trained):
    work, r = trained
    assert (work / "out" / "guide_model.joblib").exists()
    assert r["data"]["split"]["method"].startswith("organisation hold-out")
    assert set(r["selection"]["candidates"]) == {"logistic_regression", "random_forest", "xgboost"}
    assert r["data"]["incidents"] == 2400 and sum(r["data"]["split"][k] for k in ("train", "validation", "test")) == 2400
    t = r["test"]
    assert 0.5 < t["macro_f1"] <= 1 and t["binary_threat_vs_non_threat"]["roc_auc"] > 0.8
    assert t["confusion_matrix"]["matrix"] and "AlertTitle" not in json.dumps(r["feature_importance"])  # IDs ignored
    assert any("portable signals" in s for s in r["limitations"])


# ---------------------------------------------------------------------- service + investigation (bucket)
@pytest.fixture
def published_model(trained, tmp_path, monkeypatch):
    work, _ = trained
    bucket = tmp_path / "bucket"
    artifacts.publish(artifacts.LocalStore(bucket), "guide_triage", work / "out", signing_key=KEY)
    monkeypatch.setenv("ML_ARTIFACT_URI", str(bucket))
    monkeypatch.setenv("ARTIFACT_SIGNING_KEY", KEY)
    monkeypatch.setenv("ML_MODEL_DIR", str(tmp_path / "models"))
    get_settings.cache_clear()
    yield bucket
    guide_service.artifact, guide_service.metrics, guide_service.state, guide_service.error = None, None, "not_loaded", None
    get_settings.cache_clear()


def test_service_downloads_model_from_bucket_and_abstains_on_unknown_input(published_model):
    assert guide_service.sync()["state"] == "ready"
    st = guide_service.status()
    assert st["model_name"] and st["source"].endswith(f"guide_triage@{st['source'].split('@')[-1]}") and st["signing_key_configured"]
    from app.schemas.incident import IncidentIn

    ok = guide_service.predict(IncidentIn.model_validate(load_scenario("suspicious_powershell")), [])
    assert ok["status"] in ("classified", "abstained") and set(ok["probabilities"]) == set(gf.LABELS)
    assert ok["signals"]["categories"] == ["execution"] and "Process" in ok["signals"]["entities"]
    odd = load_scenario("insufficient_evidence")
    odd["alert"]["category"] = "totally-unknown"
    odd["indicators"] = []
    res = guide_service.predict(IncidentIn.model_validate(odd), [])
    assert res["status"] == "abstained" and res["reason"] == "insufficient_coverage" and res["label"] is None


def test_unsigned_or_wrongly_signed_models_are_refused(published_model, monkeypatch):
    monkeypatch.setenv("ARTIFACT_SIGNING_KEY", "not-the-publisher-key")
    get_settings.cache_clear()
    st = guide_service.sync()
    assert st["state"] == "error" and "Invalid signature" in st["error"]
    assert not guide_service.ready


def test_investigation_uses_reference_model_as_bounded_second_opinion(client, published_model):
    assert guide_service.sync()["state"] == "ready"
    r = client.post("/api/v1/incidents?cti_mode=demo", json=load_scenario("suspicious_powershell", "GUIDE-E2E-1"), headers=HEADERS)
    assert r.status_code == 202
    run_pending_jobs()
    rep = client.get("/api/v1/incidents/GUIDE-E2E-1/report", headers=HEADERS).json()
    ref = rep["ml"]["reference"]
    assert ref["status"] in ("classified", "abstained") and ref["dataset"].startswith("Microsoft Security Incident")
    assert any(e["kind"] == "ml_reference" and e["weight"] == 0 for e in rep["evidence"])
    assert rep["decision"]["factors"]["reference"]["malicious"] + rep["decision"]["factors"]["reference"]["benign"] <= 10
    assert rep["decision"]["verdict"] == "TRUE_POSITIVE"  # evidence-based verdict is unchanged
    api = client.get("/api/v1/ml/guide", headers=HEADERS).json()
    assert api["status"]["state"] == "ready" and api["metrics"]["test"]["macro_f1"] > 0.5


def test_decision_caps_reference_vote_and_flags_disagreement():
    from app.services.evidence import EvidenceBook

    b = EvidenceBook()
    b.add("context", polarity="benign", kind="approved_software", title="t", description="d", weight=30, source="s",
          benign_class="misidentification")
    b.add("context", polarity="benign", kind="noisy_rule", title="t", description="d", weight=12, source="s",
          benign_class="misidentification")
    ref = {"status": "classified", "label": "true_positive",
           "probabilities": {"true_positive": 0.97, "false_positive": 0.02, "benign_positive": 0.01}}
    d = evaluate(b.all(), {"status": "abstained", "reason": "x", "reference": ref}, None, "low")
    assert d["verdict"] == "FALSE_POSITIVE" and d["factors"]["reference"]["malicious"] <= 10
    assert "Reference model (GUIDE) disagrees (TRUE_POSITIVE)" in d["review_reasons"] and d["ref_vote"] == "TRUE_POSITIVE"
    ab = evaluate(b.all(), {"status": "abstained", "reason": "x", "reference": {"status": "abstained", "reason": "ood"}}, None, "low")
    assert ab["factors"]["reference"] == {"malicious": 0.0, "benign": 0.0, "evidence_ids": []}


def test_notebooks_embed_current_sources():
    for nb_path, files in (("ml/guide/sfumato_guide_kaggle.ipynb",
                            {"artifacts.py": "backend/app/storage/artifacts.py",
                             "guide_features.py": "backend/app/ml/guide_features.py",
                             "train_guide.py": "ml/guide/train_guide.py"}),
                           ("ml/knowledge/sfumato_kb_kaggle.ipynb",
                            {"artifacts.py": "backend/app/storage/artifacts.py", "build_kb.py": "ml/knowledge/build_kb.py"})):
        cells = ["".join(c["source"]) for c in json.loads((REPO / nb_path).read_text(encoding="utf-8"))["cells"]]
        for name, src in files.items():
            body = (REPO / src).read_text(encoding="utf-8").strip("\n")
            assert f"%%writefile {name}\n{body}" in cells, f"{nb_path}: regenerate the notebook ({name} is stale)"


def test_quality_gate_refuses_a_model_that_does_not_beat_chance():
    from app.ml.guide_inference import GuideModelService

    def m(auc):
        return {"test": {"binary_threat_vs_non_threat": {"roc_auc": auc}}}

    gate = GuideModelService._quality_gate
    gate(m(0.82), 0.60)                       # good model passes
    gate(m(0.30), 0)                          # gate disabled
    for bad in (m(0.4563), m(0.599), None, {"test": {}}):
        with pytest.raises(ValueError, match="rejected"):
            gate(bad, 0.60)


def test_structure_experiment_is_marked_and_refused_by_the_service(trained, tmp_path, monkeypatch):
    work, _ = trained
    mod = sys.modules["train_guide"]
    out = tmp_path / "structure_out"
    r = mod.train([str(work / "GUIDE_Train.csv")], str(out), fast=True, log=lambda *_: None, structure=True)
    assert r["structure_features"] is True
    names = [f["feature"] for f in r["feature_importance"]]
    assert any(n in names for n in ("log_alerts", "log_evidence_rows", "log_detectors", "log_duration_hours"))

    from app.ml.guide_inference import GuideModelService

    monkeypatch.setenv("ML_ARTIFACT_URI", "")
    monkeypatch.setenv("ML_MODEL_DIR", str(tmp_path / "models"))
    get_settings.cache_clear()
    (tmp_path / "models" / "guide").mkdir(parents=True)
    for f in out.iterdir():
        (tmp_path / "models" / "guide" / f.name).write_bytes(f.read_bytes())
    svc = GuideModelService()
    status = svc.sync()
    assert status["state"] == "error" and "structure" in status["error"]
    get_settings.cache_clear()
