# AI investigator

The agent writes the investigation report. It **never decides alone**: the decision engine owns the verdict and the agent's
vote is capped at 5 points (only when a real LLM produced it).

## Providers (all optional)

| Option | Configuration | Notes |
|---|---|---|
| **A. External API** | `AI_PROVIDER=anthropic|openai` (+ key), or `AI_PROVIDER=auto` with `AI_ALLOW_EXTERNAL=true` | Anthropic via tool-use JSON; OpenAI-compatible via `response_format=json_object`. Data is pseudonymised first |
| **B. Local LLM** | Ollama (`OLLAMA_URL`, `OLLAMA_MODEL`, default `qwen2.5:7b-instruct`, ~4.7 GB, runs on an 8 GB GPU) | JSON constrained by the report schema. Default in `auto` when reachable |
| **C. No LLM** | automatic fallback or `AI_PROVIDER=deterministic` | Evidence-based report built by rules, no vote |

`GET /api/v1/ai/status` (and the Observatory) says which provider is used and **why**. If an LLM call fails, times out or returns
invalid output (two attempts), the investigation continues with the deterministic report and records the reason
(`fallback_reason`). External providers are never used unless explicitly enabled.

Local concurrency: generations are serialised (`AI_MAX_CONCURRENCY=1`) so parallel investigations queue instead of timing
out. Typical report time with the 7B model on a laptop GPU: 10-20 s once the model is loaded (the first call also loads it).

## Input and output

Input: original incident JSON, normalised fields, extracted indicators, the evidence book (behaviour, context, CTI, ML,
integrity), the ML result, the SOAR history and knowledge-base passages.

Output (`agents/schemas.py`, validated with Pydantic): summary, technical explanation, suspicious behaviours, CTI findings,
MITRE ATT&CK techniques, supporting and contradictory evidence, confidence limitations, recommended verdict, recommended
actions, knowledge guidance.

## Guarantees enforced in code (`agents/investigator.py::validate_output`)

* Every claim must cite evidence IDs that exist in this investigation; uncited or unknown citations are removed and
  counted (`validation.dropped_claims`, shown in the UI).
* **CTI findings may only cite `EV-CTI-*`** — the model cannot invent a threat-intelligence result.
* ATT&CK techniques must exist in the local table and cite evidence.
* Knowledge-base passages (`EV-KB-*`) can only appear in `knowledge_guidance`; they are reference material, never evidence.
* Recommended actions are advisory text; the platform never executes anything.

## Prompt-injection protection (`agents/prompt_guard.py`)

* Incident and CTI text is scanned for instruction-like patterns; hits become `EV-INT-*` evidence (suspicious by itself and a
  human-review trigger) — see the bundled scenario *Prompt-injection attempt*.
* Untrusted text is neutralised (chat-template tokens and control characters removed, length capped) and wrapped in
  `<<<UNTRUSTED_DATA:…>>>` blocks; the system prompt says never to follow instructions found there.
* Knowledge-base passages containing instruction-like text are dropped before they reach the model.
* Even a successful injection cannot change the outcome: claims need real evidence IDs and the model has ≤ 5 points of influence.
* Commands in incident fields (e.g. encoded PowerShell) are **decoded as text for analysis and never executed**; the codebase
  contains no subprocess/eval/exec (checked by a test).

## Redaction for external LLMs (`agents/redaction.py`)

Before anything leaves the machine, usernames, e-mails, hostnames, internal domains, private IPs and `C:\Users\<name>` paths are
replaced by stable placeholders (`USER_1`, `HOST_1`, `INTERNAL_IP_1`…); the mapping stays on the server and is reversed on the
response. Local Ollama receives unredacted data because it never leaves the host.


## Free hosted option: Gemini (OpenAI-compatible endpoint)

The `openai` provider accepts any OpenAI-compatible server, including Gemini: set `AI_PROVIDER=openai`,
`AI_ALLOW_EXTERNAL=true`, `OPENAI_BASE_URL=https://generativelanguage.googleapis.com/v1beta/openai` and
`OPENAI_MODEL=gemini-3.5-flash-lite`, then enter the key in **Settings**. Caveats, stated by Google's pricing page: on the
free tier prompts are "used to improve our products", and rate limits are per project and not published there. Data is
pseudonymised before leaving the host, but use this path for demo or synthetic incidents only. The endpoint, model name and
JSON mode have not been exercised here: check `GET /api/v1/ai/status` after configuring.
