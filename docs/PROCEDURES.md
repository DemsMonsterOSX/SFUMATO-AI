# Response procedure library

102 draft runbooks (`ml/procedures/`), searchable in the web app (**Procedures** page) and by the Da Vinci AI pop-up.

> **Status: draft.** The content was written by an AI assistant for a course project. It has **not** been validated by a security
> professional. Review before any operational use. Every file carries `status: draft-generated-not-validated`.

## Content

* Structure of each procedure (NIST SP 800-61 lifecycle): detection signals, triage, containment, eradication, recovery,
  evidence to keep, possible false positives. Tagged with MITRE ATT&CK technique ids, tactic, severity and tags.
* Coverage: initial access, execution, persistence, privilege escalation, defense evasion, credential access, discovery, lateral
  movement, command and control, exfiltration, impact, cloud (GCP-oriented), general SOC process (triage, evidence, escalation,
  breach notification, post-incident review) and Sfumato's own scenarios (prompt injection in an alert, KEV triage, PHP-CGI
  CVE-2024-4577, benign software, legitimate admin activity).
* **14 procedures map one-to-one to the attack families of CSE-CIC-IDS2018** (`dataset_families`). Their triage section quotes the
  recall measured in this project's experiments (`ml/bigdata/advanced.json`), e.g. a model that never saw botnet traffic detects
  0 % of it. These lines are facts about our experiments, not general claims.

## Files

| Path | Role |
|---|---|
| `ml/procedures/src/part*.py` | Source of truth (compact Python declarations) |
| `scripts/build_procedures.py` | Validates (unique ids, required fields, ATT&CK id format) and generates the files below |
| `ml/procedures/md/PROC-*.md` | One Markdown file per procedure (human reading, bucket) |
| `ml/procedures/index.json`, `manifest.json` | Full text for search, with count, date and sha256 |

```powershell
python scripts/build_procedures.py --check   # validate
python scripts/build_procedures.py           # regenerate md, index.json and manifest.json
```

## Search

`backend/app/services/procedures.py`: lexical **BM25**, pure Python, no model to download, offline, light enough for the 1 GB VM.
Direct boosts for a procedure id, an ATT&CK id or a dataset family name; small French-to-English hints so French questions
reach the English library. API: `GET /api/v1/procedures?q=&tactic=&severity=` and `GET /api/v1/procedures/{id}`.

BM25 was chosen over embeddings because the library is small and highly keyworded (technique ids, tool names), and it needs no
GPU, no download and no extra memory. Semantic search through the existing knowledge-base embeddings is a possible later step.

## Da Vinci AI

A question that asks what to do ("procedure", "runbook", "que faire", "comment réagir", a technique id…) or that no Big Data rule
matches retrieves the three closest procedures. Without an LLM the answer is a deterministic summary of the best match. With
Gemini configured, the retrieved procedures are given to the model, which is told they are unvalidated drafts.

## Bucket

Copy for sharing and backup: `gs://<bucket>/procedures/` (`index.json`, `manifest.json`, `md/`). The web app reads the copy shipped
in the deployment package, not the bucket.

## Limits

* Unvalidated generated content (see above); no review by a SOC analyst yet.
* English only; the agent translates when an LLM is available.
* Lexical search misses synonyms that are not in the library or the small French hint table.
* Procedures are generic: they do not know your tooling, asset inventory or legal context.
