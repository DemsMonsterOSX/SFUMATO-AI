#!/usr/bin/env python3
"""Regenerates sfumato_kb_kaggle.ipynb from build_kb.py (run after editing the builder)."""
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent


def md(text: str) -> dict:
    return {"cell_type": "markdown", "metadata": {}, "source": text.strip("\n").splitlines(keepends=True)}


def code(text: str) -> dict:
    return {"cell_type": "code", "execution_count": None, "metadata": {}, "outputs": [],
            "source": text.strip("\n").splitlines(keepends=True)}


def notebook() -> dict:
    builder = (HERE / "build_kb.py").read_text(encoding="utf-8")
    artifacts_src = (HERE.parents[1] / "backend" / "app" / "storage" / "artifacts.py").read_text(encoding="utf-8")
    cells = [
        md("""
# Sfumato — knowledge base builder (RAG)

Builds the defensive knowledge base used by Sfumato's AI investigator from
[Vyber07/cyber-security](https://huggingface.co/datasets/Vyber07/cyber-security) and publishes it to a
**private** Hugging Face dataset repository.

**Before running**
1. On huggingface.co, open the dataset page and accept its access conditions (it is gated).
2. Create a Hugging Face access token with **write** permission (Settings → Access Tokens).
3. In this notebook: *Add-ons → Secrets* → add `HF_TOKEN` with that token.
4. *Settings → Internet* must be **on** (Kaggle requires a verified phone number for internet access).
5. Accelerator: **None (CPU) is enough**. A T4 only speeds up embedding (see the optional GPU cell).

Expected run time on CPU: roughly 10–40 minutes depending on the size limits below.
"""),
        code("""
!pip install -q "fastembed==0.9.1" "huggingface_hub==1.33.0"
# Optional, only with a GPU accelerator (replaces the CPU runtime):
# !pip uninstall -y -q fastembed onnxruntime && pip install -q "fastembed-gpu==0.9.1" "huggingface_hub==1.33.0"
"""),
        code("""
import os
from kaggle_secrets import UserSecretsClient
os.environ["HF_TOKEN"] = UserSecretsClient().get_secret("HF_TOKEN")

HF_REPO = "YOUR-HF-USERNAME/sfumato-kb"   # <- private dataset repo that will receive the knowledge base
USE_GPU = False                           # True only if you installed fastembed-gpu above
MAX_CHUNKS = 400_000                      # lower it for a faster first run (e.g. 50_000)
# Optional: also publish a signed copy to a bucket (gs://bucket/prefix). Needs the Kaggle secrets
# ARTIFACT_SIGNING_KEY and GCP_SA_JSON (service-account key with write access to the bucket).
BUCKET_URI = ""
"""),
        md("The builder below is generated from `ml/knowledge/build_kb.py` in the Sfumato repository."),
        code("%%writefile artifacts.py\n" + artifacts_src),
        code("%%writefile build_kb.py\n" + builder),
        code("""
gpu = "--gpu" if USE_GPU else ""
publish = ""
if BUCKET_URI:  # optional signed copy in a Google Cloud Storage bucket
    !pip install -q google-cloud-storage
    with open("/kaggle/working/sa.json", "w") as f:
        f.write(UserSecretsClient().get_secret("GCP_SA_JSON"))
    os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = "/kaggle/working/sa.json"
    os.environ["ARTIFACT_SIGNING_KEY"] = UserSecretsClient().get_secret("ARTIFACT_SIGNING_KEY")
    publish = f"--publish-to {BUCKET_URI}"
!python build_kb.py --out /kaggle/working/kb_out --max-chunks {MAX_CHUNKS} {gpu} --push-to {HF_REPO} {publish}
"""),
        code("""
# Sanity check: semantic search over the freshly built knowledge base
import gzip, json, numpy as np
from fastembed import TextEmbedding
emb = np.load("/kaggle/working/kb_out/embeddings.npy").astype(np.float32)
rows = [json.loads(l) for l in gzip.open("/kaggle/working/kb_out/chunks.jsonl.gz", "rt", encoding="utf-8")]
model = TextEmbedding("BAAI/bge-small-en-v1.5")
q = np.asarray(list(model.query_embed(["detect encoded PowerShell launched from a Word macro"])))[0]
for i in np.argsort(emb @ q)[::-1][:5]:
    print(round(float(emb[i] @ q), 3), rows[i]["domain"], "|", rows[i]["title"][:100])
print(json.load(open("/kaggle/working/kb_out/manifest.json"))["stats"])
"""),
        md("""
**Then, in Sfumato's `.env`:**
```
KB_HF_REPO=YOUR-HF-USERNAME/sfumato-kb
HF_TOKEN=hf_...   # read access is enough on the Sfumato side (or enter it on the Settings page)
```
Restart Sfumato (or click *Sync* on the ML & AI Observatory page): the knowledge base is downloaded once,
loaded into PostgreSQL/pgvector, and then works offline.
"""),
    ]
    return {"cells": cells, "metadata": {"kernelspec": {"display_name": "Python 3", "language": "python", "name": "python3"},
                                         "language_info": {"name": "python"}},
            "nbformat": 4, "nbformat_minor": 5}


if __name__ == "__main__":
    out = HERE / "sfumato_kb_kaggle.ipynb"
    out.write_text(json.dumps(notebook(), indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"wrote {out}")
