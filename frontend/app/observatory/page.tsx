"use client";

import { Bot, Brain, Database, Gauge, ListOrdered } from "lucide-react";
import Link from "next/link";
import { Fragment } from "react";
import { Bar, BarChart, CartesianGrid, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { Badge, Card, CardHeader, Dot, Empty, KV, PageHeader, Skeleton, Stat, VerdictBadge } from "@/components/ui";
import { useApi } from "@/hooks/useApi";
import { fmtMs } from "@/lib/api";

const tooltipStyle = { background: "#08102a", border: "1px solid rgba(148,178,255,0.15)", borderRadius: 12, fontSize: 12 };
const LABEL_NAMES: Record<string, string> = { true_positive: "True positive", false_positive: "False positive", benign_positive: "Benign positive (legitimate)" };

export default function ObservatoryPage() {
  const { data: ml } = useApi<any>("ml/model");
  const { data: ai } = useApi<any>("ai/status", 10000);
  const { data: recent } = useApi<any[]>("observatory/recent", 6000);
  const { data: guide } = useApi<any>("ml/guide", 10000);
  const { data: kb } = useApi<any>("knowledge/status", 10000);
  const m = ml?.metrics;
  const st = ml?.status;
  const candidates = m ? Object.entries(m.selection.candidates).map(([k, v]: any) => ({ name: k.replace("_", " "), key: k, f1: v.validation.macro_f1, auc: v.validation.roc_auc_ovr_macro })) : [];
  const importance = (m?.feature_importance ?? []).slice(0, 14);
  const cm = m?.test.confusion_matrix;
  const cmMax = cm ? Math.max(...cm.matrix.flat()) : 1;
  const aiLat = (recent ?? []).filter((r) => r.ai_latency_ms != null).map((r) => r.ai_latency_ms);

  return (
    <div>
      <PageHeader kicker="ML & AI Observatory" title="Models you can audit" description="Measured metrics, the dataset they come from, and the live state of the AI investigator. Nothing on this page is hard-coded: it is read from the training report and the running services." />
      <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
        <Stat label="Active model" value={<span className="text-2xl">{st?.model_name?.replace("_", " ") ?? "—"}</span>} sub={<span className="font-mono text-[10px]">{st?.version}</span>} icon={<Brain className="h-4 w-4" />} />
        <Stat label="Test macro-F1" value={m ? m.test.macro_f1.toFixed(3) : "—"} sub={m ? `ROC-AUC ${m.test.roc_auc_ovr_macro.toFixed(3)} · acc ${m.test.accuracy.toFixed(3)}` : ""} accent="#34d399" icon={<Gauge className="h-4 w-4" />} />
        <Stat label="AI investigator" value={<span className="text-2xl">{ai?.selected ?? "—"}</span>} sub={ai?.model} accent="#a78bfa" icon={<Bot className="h-4 w-4" />} />
        <Stat label="AI latency (recent)" value={aiLat.length ? fmtMs(aiLat.reduce((a, b) => a + b, 0) / aiLat.length) : "—"} sub={st?.avg_latency_ms != null ? `ML inference ${st.avg_latency_ms} ms` : ""} accent="#fbbf24" icon={<Gauge className="h-4 w-4" />} />
      </div>


      <div className="mt-5 grid gap-5 xl:grid-cols-3">
        <Card>
          <CardHeader title="Training dataset" icon={<Database className="h-4 w-4" />} />
          {m ? (
            <div>
              <KV k="Name" v={m.dataset.name} mono />
              <KV k="Version / seed" v={`${m.dataset.version} / ${m.dataset.seed}`} />
              <KV k="Rows" v={m.dataset.rows.toLocaleString()} />
              <KV k="Synthetic" v={<Badge color="#fbbf24">yes — labelled</Badge>} />
              <KV k="Split train / val / test" v={`${m.dataset.splits.train} / ${m.dataset.splits.validation} / ${m.dataset.splits.test}`} />
              <KV k="Leakage: duplicate rows removed" v={`val ${m.dataset.overlap_rows_removed.validation} · test ${m.dataset.overlap_rows_removed.test}`} />
              <KV k="Label / feature noise" v={`${m.dataset.label_noise_rate * 100}% / ${m.dataset.feature_noise_rate * 100}%`} />
              <KV k="Class balance" v={Object.entries(m.dataset.class_balance).map(([k, v]) => `${k}: ${v}`).join(" · ")} />
              <KV k="Trained" v={new Date(m.trained_at).toLocaleString()} />
            </div>
          ) : <Skeleton className="h-64" />}
        </Card>
        <Card>
          <CardHeader title="Model selection" subtitle={m?.selection.criterion} icon={<ListOrdered className="h-4 w-4" />} />
          <div className="h-[230px]">
            <ResponsiveContainer>
              <BarChart data={candidates} margin={{ left: -20 }}>
                <CartesianGrid stroke="rgba(148,178,255,0.06)" vertical={false} />
                <XAxis dataKey="name" tick={{ fill: "#94a3b8", fontSize: 11 }} axisLine={false} tickLine={false} />
                <YAxis domain={[0.5, 1]} tick={{ fill: "#64748b", fontSize: 11 }} axisLine={false} tickLine={false} />
                <Tooltip contentStyle={tooltipStyle} cursor={{ fill: "rgba(148,178,255,0.05)" }} />
                <Bar dataKey="f1" name="validation macro-F1" radius={[6, 6, 0, 0]}>
                  {candidates.map((c) => <Cell key={c.key} fill={c.key === m.model_name ? "#22d3ee" : "#334155"} />)}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
          <div className="mt-2 space-y-1 text-xs">
            {candidates.map((c) => (
              <div key={c.key} className="flex justify-between text-slate-400"><span>{c.name}{c.key === m.model_name && <Badge color="#22d3ee" className="ml-2">selected</Badge>}</span><span className="font-mono text-slate-200">F1 {c.f1.toFixed(4)} · AUC {c.auc.toFixed(4)}</span></div>
            ))}
          </div>
        </Card>
        <Card>
          <CardHeader title="Confusion matrix (test)" subtitle="rows = true label, columns = predicted" />
          {cm ? (
            <div>
              <div className="grid grid-cols-[110px_repeat(3,1fr)] gap-1 text-[11px]">
                <div />
                {cm.labels.map((l: string) => <div key={l} className="text-center text-slate-500">{l.split("_")[0]}</div>)}
                {cm.matrix.map((row: number[], i: number) => (
                  <Fragment key={i}>
                    <div className="flex items-center text-slate-400">{cm.labels[i]}</div>
                    {row.map((v: number, j: number) => (
                      <div key={`${i}-${j}`} className="grid h-14 place-items-center rounded-lg font-mono text-sm text-white" style={{ background: i === j ? `rgba(34,211,238,${0.15 + 0.65 * (v / cmMax)})` : `rgba(251,113,133,${0.05 + 0.6 * (v / cmMax)})` }}>{v}</div>
                    ))}
                  </Fragment>
                ))}
              </div>
              <div className="mt-4 space-y-1.5">
                {Object.entries(m.test.per_class).map(([k, v]: any) => (
                  <div key={k} className="grid grid-cols-[1fr_auto] text-xs"><span className="text-slate-400">{LABEL_NAMES[k]}</span><span className="font-mono text-slate-200">P {v.precision.toFixed(3)} · R {v.recall.toFixed(3)} · F1 {v.f1.toFixed(3)}</span></div>
                ))}
              </div>
            </div>
          ) : <Skeleton className="h-64" />}
        </Card>
      </div>

      <div className="mt-5 grid gap-5 xl:grid-cols-[1.2fr_1fr]">
        <Card>
          <CardHeader title="Global feature importance" subtitle={`${m?.model_name ?? ""} — normalised`} />
          <div className="h-[380px]">
            <ResponsiveContainer>
              <BarChart data={importance} layout="vertical" margin={{ left: 40 }}>
                <CartesianGrid stroke="rgba(148,178,255,0.06)" horizontal={false} />
                <XAxis type="number" tick={{ fill: "#64748b", fontSize: 11 }} axisLine={false} tickLine={false} />
                <YAxis type="category" dataKey="feature" tick={{ fill: "#94a3b8", fontSize: 10.5 }} width={150} axisLine={false} tickLine={false} />
                <Tooltip contentStyle={tooltipStyle} cursor={{ fill: "rgba(148,178,255,0.05)" }} />
                <Bar dataKey="importance" fill="#8b5cf6" radius={[0, 6, 6, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
          {m && <div className="mt-3 text-[11px] text-slate-500">Abstention: completeness &lt; {m.abstention.min_completeness}, top probability &lt; {m.abstention.min_probability}, or {m.abstention.ood}.</div>}
        </Card>
        <Card>
          <CardHeader title="AI investigator" subtitle={ai?.reason} icon={<Bot className="h-4 w-4" />} />
          {ai ? (
            <div>
              <KV k="Configured provider" v={ai.configured_provider} />
              <KV k="Selected now" v={<span className="flex items-center gap-1.5"><Dot ok={ai.selected !== "deterministic"} warn={ai.selected === "deterministic"} />{ai.selected}</span>} />
              <KV k="Model" v={ai.model} />
              <KV k="Ollama" v={ai.ollama.url ? `${ai.ollama.reachable ? "reachable" : "unreachable"} · ${ai.ollama.url}` : "not configured"} />
              <KV k="Local models" v={ai.ollama.models.join(", ") || "—"} />
              <KV k="Anthropic / OpenAI keys" v={`${ai.anthropic.configured ? "yes" : "no"} / ${ai.openai.configured ? "yes" : "no"}`} />
              <KV k="External LLM allowed" v={ai.allow_external ? "yes (redacted)" : "no"} />
              <p className="mt-3 text-[11px] leading-relaxed text-slate-500">The LLM receives incident data inside delimited untrusted-data blocks, must cite evidence IDs, and its vote is capped at 5 points. Without an LLM, a deterministic evidence-based investigator writes the report.</p>
            </div>
          ) : <Skeleton className="h-60" />}
        </Card>
      </div>

      <div className="mt-5 grid gap-5 xl:grid-cols-2">
        <Card>
          <CardHeader title="Reference model (Microsoft GUIDE) — cloud bucket" subtitle="Real SOC labels · downloaded from the bucket, signature verified" icon={<Database className="h-4 w-4" />}
            right={<Badge color={guide?.status.state === "ready" ? "#34d399" : guide?.status.state === "error" ? "#fb7185" : "#64748b"}>{guide?.status.state ?? "…"}</Badge>} />
          {guide ? (
            <div>
              <KV k="Bucket" v={guide.status.uri ?? "not configured (ML_ARTIFACT_URI)"} mono />
              <KV k="Source" v={guide.status.source ?? "—"} mono />
              <KV k="Signature" v={guide.status.signature_required ? (guide.status.signing_key_configured ? "enforced for gs:// and hf:// · key configured" : "enforced for gs:// and hf:// · KEY MISSING") : "not enforced"} />
              <KV k="Model / version" v={guide.status.model_name ? `${guide.status.model_name} · ${guide.status.version}` : "—"} mono />
              {guide.metrics && <>
                <KV k="Split" v={`${guide.metrics.data.split.method} — ${guide.metrics.data.incidents.toLocaleString()} incidents`} />
                <KV k="Test macro-F1" v={guide.metrics.test.macro_f1} />
                <KV k="Threat vs non-threat (ROC-AUC)" v={guide.metrics.test.binary_threat_vs_non_threat.roc_auc} />
              </>}
              {guide.status.error && <div className="mt-2 text-xs text-rose-300">{guide.status.error}</div>}
              {!guide.status.model_name && !guide.status.error && <p className="mt-2 text-xs text-slate-500">No model yet: run ml/guide/sfumato_guide_kaggle.ipynb, then set ML_ARTIFACT_URI.</p>}
            </div>
          ) : <Skeleton className="h-40" />}
        </Card>
        <Card>
          <CardHeader title="Knowledge base (RAG)" subtitle="Defensive guidance retrieved for the AI investigator" icon={<Database className="h-4 w-4" />}
            right={<Badge color={kb?.state === "ready" ? "#34d399" : kb?.state === "error" ? "#fb7185" : "#64748b"}>{kb?.state ?? "…"}</Badge>} />
          {kb ? (
            <div>
              <KV k="Source" v={kb.source ?? kb.configured_repo ?? "not configured (KB_ARTIFACT_URI / KB_HF_REPO)"} mono />
              <KV k="Store" v={kb.store ?? "—"} />
              <KV k="Passages / records" v={kb.chunks != null ? `${kb.chunks.toLocaleString()} / ${(kb.records ?? 0).toLocaleString()}` : "—"} />
              <KV k="Embedding model" v={kb.embedding_model} mono />
              <KV k="Dataset" v={kb.dataset ?? "—"} />
              <KV k="License" v={kb.license ?? "—"} />
              <KV k="Avg search" v={kb.avg_search_ms != null ? `${kb.avg_search_ms} ms` : "—"} />
              {kb.error && <div className="mt-2 text-xs text-rose-300">{kb.error}</div>}
            </div>
          ) : <Skeleton className="h-40" />}
        </Card>
      </div>

      <Card className="mt-5">
        <CardHeader title="Recent investigations" subtitle="ML output, AI provider, latency and votes per incident" />
        {!recent ? <Skeleton className="h-40" /> : recent.length === 0 ? <Empty title="No investigations yet" /> : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead><tr className="label text-left"><th className="pb-2">Incident</th><th className="pb-2">ML</th><th className="pb-2 text-right">ML latency</th><th className="pb-2">AI provider</th><th className="pb-2 text-right">AI latency</th><th className="pb-2">AI suggestion</th><th className="pb-2">Final verdict</th></tr></thead>
              <tbody>
                {recent.map((r) => (
                  <tr key={r.incident_id} className="border-t border-line/60">
                    <td className="py-2 pr-3"><Link href={`/incidents/${r.incident_id}`} className="font-mono text-xs text-cyan-300 hover:underline">{r.incident_id}</Link><div className="max-w-[240px] truncate text-[11px] text-slate-500">{r.alert_name}</div></td>
                    <td className="pr-3 text-xs">{r.ml_status === "classified" ? <Badge color="#34d399">{r.ml_label}</Badge> : <Badge color="#fbbf24" title={r.ml_reason}>abstained · {r.ml_reason}</Badge>}</td>
                    <td className="pr-3 text-right font-mono text-xs text-slate-400">{r.ml_latency_ms ?? "—"} ms</td>
                    <td className="pr-3 text-xs text-slate-300">{r.ai_provider}<div className="text-[10.5px] text-slate-500">{r.ai_model}</div></td>
                    <td className="pr-3 text-right font-mono text-xs text-slate-400">{fmtMs(r.ai_latency_ms)}</td>
                    <td className="pr-3"><VerdictBadge verdict={r.ai_verdict} /></td>
                    <td><VerdictBadge verdict={r.verdict} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  );
}
