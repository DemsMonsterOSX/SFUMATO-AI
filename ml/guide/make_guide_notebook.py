#!/usr/bin/env python3
"""Regenerates sfumato_guide_kaggle.ipynb (embeds train_guide.py + the shared feature/storage modules)."""
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
FILES = {"artifacts.py": ROOT / "backend/app/storage/artifacts.py",
         "guide_features.py": ROOT / "backend/app/ml/guide_features.py",
         "train_guide.py": HERE / "train_guide.py"}


def md(t): return {"cell_type": "markdown", "metadata": {}, "source": t.strip("\n").splitlines(keepends=True)}
def code(t): return {"cell_type": "code", "execution_count": None, "metadata": {}, "outputs": [],
                     "source": t.strip("\n").splitlines(keepends=True)}


def notebook() -> dict:
    cells = [
        md("""
# Sfumato — GUIDE triage model (true positive / false positive / benign positive)

Trains the reference model on **Microsoft GUIDE** (real SOC incidents graded by analysts) and publishes it,
signed, to your **Google Cloud Storage bucket**. Sfumato downloads it and uses it as a second opinion.

**Before running**
1. *Add Input* → search **"Microsoft Security Incident Prediction"** (dataset by Microsoft) and add it.
2. *Add-ons → Secrets*:
   - `ARTIFACT_SIGNING_KEY`: a long random string, **the same value as in Sfumato's `.env`**;
   - `GCP_SA_JSON`: the JSON key of a service account that can *write* to the bucket (`roles/storage.objectAdmin` on the bucket only).
3. Accelerator: **None (CPU)**. The model is gradient-boosted trees, a GPU brings nothing.
4. Internet: **on** (needed to reach Google Cloud Storage).
"""),
        code("""
!pip install -q google-cloud-storage
import os, json
from kaggle_secrets import UserSecretsClient
sec = UserSecretsClient()
os.environ["ARTIFACT_SIGNING_KEY"] = sec.get_secret("ARTIFACT_SIGNING_KEY")
with open("/kaggle/working/sa.json", "w") as f:
    f.write(sec.get_secret("GCP_SA_JSON"))
os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = "/kaggle/working/sa.json"

BUCKET_URI = "gs://YOUR-BUCKET/sfumato"   # <- bucket (+ optional prefix) that receives the model
MAX_ROWS = None                           # e.g. 2_000_000 for a quick first run (full data: ~9.5M rows)
"""),
    ]
    for name, path in FILES.items():
        cells.append(md(f"`{name}` — generated from `{path.relative_to(ROOT).as_posix()}` in the Sfumato repository."))
        cells.append(code(f"%%writefile {name}\n" + path.read_text(encoding="utf-8")))
    cells += [
        code("""
import glob
# Train first, then Test; the dataset also ships GUIDE_Test_Queue_Rankings.csv, which has no triage labels
csvs = [p for n in ("GUIDE_Train.csv", "GUIDE_Test.csv") for p in sorted(glob.glob(f"/kaggle/input/**/{n}", recursive=True))]
print(csvs)
assert csvs, "GUIDE_Train.csv not found under /kaggle/input: Add Input > Datasets > 'Microsoft Security Incident Prediction' (the dataset, not a notebook of the same name)"
rows = "" if MAX_ROWS is None else f"--max-rows {MAX_ROWS}"
!python train_guide.py --csv {" ".join(csvs)} --out /kaggle/working/guide_out {rows} --publish-to {BUCKET_URI}
"""),
        code("""
import json
r = json.load(open("/kaggle/working/guide_out/metrics.json"))
print(r["model_name"], r["data"]["split"])
print("test macro-F1:", r["test"]["macro_f1"], "| threat vs non-threat:", r["test"]["binary_threat_vs_non_threat"])
print(r["test"]["confusion_matrix"])
"""),
        md("""
**Then, in Sfumato's `.env`:**
```
ML_ARTIFACT_URI=gs://YOUR-BUCKET/sfumato
ARTIFACT_SIGNING_KEY=<same value as the Kaggle secret>
GOOGLE_APPLICATION_CREDENTIALS=/run/secrets/gcs-reader.json   # service account with READ-ONLY access (roles/storage.objectViewer)
```
Restart Sfumato or call `POST /api/v1/ml/guide/sync`.
"""),
    ]
    return {"cells": cells, "metadata": {"kernelspec": {"display_name": "Python 3", "language": "python", "name": "python3"},
                                         "language_info": {"name": "python"}}, "nbformat": 4, "nbformat_minor": 5}


def experiment_notebook() -> dict:
    """Variant that trains with --structure (incident-structure features) and publishes NOTHING: no secrets needed."""
    nb = notebook()
    cells = nb["cells"]
    cells[0] = md("""
# Sfumato — GUIDE experiment: do incident-structure signals generalise across organisations?

Baseline (portable signals only, full data, organisation hold-out): test ROC-AUC threat-vs-non-threat **0.516**, macro-F1 **0.426**.
This run adds incident-structure features (number of alerts, evidence rows, detectors, duration, impacted share, entity counts).
Nothing is published: a Sfumato alert is a single alert, so these counts could not be reproduced when serving.

Before running: *Add Input* → dataset **Microsoft Security Incident Prediction**. Accelerator **None**. No secrets, no Internet needed.
""")
    cells[1] = code("""
MAX_ROWS = None   # full data (about 13.7M rows, roughly 11 minutes)
""")
    for c in cells:
        src = "".join(c["source"])
        if c["cell_type"] == "code" and "train_guide.py --csv" in src:
            src = src.replace("{rows} --publish-to {BUCKET_URI}", "{rows} --structure")
            c["source"] = src.splitlines(keepends=True)
    cells[-1] = md("""
**Reading the result:** compare `threat vs non-threat roc_auc` with the baseline 0.516. Above 0.60 on unseen organisations
means GUIDE carries transferable signal; below it, stop using GUIDE for the reference model.
""")
    return nb


if __name__ == "__main__":
    out = HERE / "sfumato_guide_kaggle.ipynb"
    out.write_text(json.dumps(notebook(), indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"wrote {out}")
    exp = HERE / "sfumato_guide_structure_experiment.ipynb"
    exp.write_text(json.dumps(experiment_notebook(), indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"wrote {exp}")
