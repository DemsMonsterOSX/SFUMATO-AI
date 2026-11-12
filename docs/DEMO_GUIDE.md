# Demo guide (5-10 minutes)

## Before the jury (10 minutes earlier)

```bash
./start.sh            # or .\start.ps1  — prints the API key
```
Open http://localhost:3000. Check the sidebar: **API online**, and on the Command Center that the three seeded incidents are done.
Warm the LLM once (the first generation loads the model): submit any scenario from the simulator and wait for it.
If the machine is slow or has no GPU, set `AI_PROVIDER=deterministic` in `.env` and restart: instant, reproducible reports.

Keep a terminal ready with `export KEY=<your API key>`.

## Script

**0:00 — Command Center (1 min).** "Every number comes from the backend." Show total, verdict distribution, CTI provider health,
SOAR/ML/AI status. Point at the banner *CTI default: REPRODUCIBLE DEMO* — the fixtures are labelled, never passed off as live.

**1:00 — Submit by API, not by UI (1 min).**
```bash
curl -X POST "http://localhost:8000/api/v1/incidents?resubmit=true" -H "X-API-Key: $KEY" \
  -H "Content-Type: application/json" --data @examples/incidents/02_suspicious_powershell.json
```
Open the new incident. "The simulator calls the same endpoint."

**2:00 — Live investigation (2 min).** Watch the ten milestones light up. Explain: SSE stream of *persisted* events; each stage has a real duration.
Open **SOAR workflow**: parallel branches (CTI ‖ behaviour), conditional nodes, per-task logs.

**4:00 — CTI enrichment (1 min).** Tab *Indicators & CTI*: indicators classified by scope (private/documentation/public), the privacy
filter ("never sent" list), per-provider answers with the **DEMO FIXTURE** badge, expandable raw responses. Say: "unknown is never benign".

**5:00 — ML (1 min).** Tab *ML*: probabilities, occlusion explanation, abstention reasons. Say: capped at 15 points; trained on synthetic
data — see the Observatory for the dataset card and honest limits. If a GUIDE model is loaded, show the reference card.

**6:00 — AI agent (1 min).** Tab *AI report*: structured output, every claim chips to an evidence ID; provenance (provider, latency,
dropped claims). Say: "the LLM cannot invent a CTI finding, and it only has 5 points of influence."

**7:00 — Verdicts (2 min).** Show the three principal incidents side by side:

| Incident | Expected verdict | Why |
|---|---|---|
| `SFUMATO-2026-0102` PowerShell from Word | TRUE_POSITIVE | Office→PowerShell, encoded download cradle, indicators flagged by 3 fixture providers |
| `SFUMATO-2026-0101` encoded PowerShell on a server | LEGITIMATE_ACTIVITY | Same technique, but verified change CHG-2026-1042 + admin on a management host |
| `SFUMATO-2026-0106` rare domain, no telemetry | INCONCLUSIVE | Almost no evidence; ML abstains; routed to human review |

Optionally: scenario *Known benign software* → FALSE_POSITIVE (the detection misidentified approved, signed 7-Zip);
*Prompt-injection attempt* → injection flagged, verdict unchanged.

**9:00 — Recommendations (30 s).** "Display only — nothing is ever executed." Open the incident's recommended actions.

**9:30 — Reopen.** Go to *Investigations*, reopen an old incident: the full execution history replays.

## Expected results note

Verdicts above are from the bundled scenarios in demo mode with the shipped decision thresholds. Exact scores and AI wording vary with
the model; if a verdict differs, open the incident and use *Why this verdict* — that explanation is the point of the demo.

## Edit the JSON live

*Incident Simulator*: select a scenario, change e.g. `process.parent` to `explorer.exe` or the `change_ticket`, click **Analyze Incident**.
Re-submitted IDs get an `-R2` suffix.

## Internet outage / recovery

* Demo mode needs **no internet**: CTI from fixtures, the ML model and the embedding model are local, Ollama is local.
  To be safe, pre-pull the Ollama model and open the app once while online.
* If live mode was selected and providers fail, the incident still completes with `unknown` results and explicit errors
  (`timeout`, `rate_limited`, …); switch to demo mode in the simulator and resubmit.
* If the LLM is down, the report falls back to the deterministic investigator and says so.
* If Docker misbehaves: `docker compose restart api worker`, or run the local development setup (INSTALLATION.md, option B).
* Last resort: show a previously completed incident (history is persisted) and the OpenAPI page.
