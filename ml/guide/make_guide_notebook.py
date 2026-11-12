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
csvs = sorted(glob.glob("/kaggle/input/**/GUIDE_*.csv", recursive=True))
print(csvs)
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


if __name__ == "__main__":
    out = HERE / "sfumato_guide_kaggle.ipynb"
    out.write_text(json.dumps(notebook(), indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"wrote {out}")
