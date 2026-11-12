"use client";

import { AlertOctagon, Bot, Brain, ChevronDown, ChevronRight, Clock, ExternalLink, FileJson, Fingerprint, Gavel, GitBranch, Lock, Radar, ShieldAlert, Sparkles, UserCheck } from "lucide-react";
import Link from "next/link";
import { useParams } from "next/navigation";
import { Fragment, useEffect, useMemo, useState } from "react";
import { Bar as RBar, BarChart, CartesianGrid, Legend, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { JsonEditor } from "@/components/json-editor";
import { Pipeline } from "@/components/pipeline";
import { PlaybookGraph } from "@/components/playbook-graph";
import { Badge, Bar, Card, CardHeader, CtiVerdictBadge, Empty, ErrorNote, EvidenceChip, JsonBlock, KV, OriginBadge, PolarityBadge, SeverityBadge, Skeleton, StatusBadge, Tabs, VerdictBadge } from "@/components/ui";
import { Gauge, VerdictTitle, scoreColor } from "@/components/verdict";
import { useApi } from "@/hooks/useApi";
import { useInvestigationStream } from "@/hooks/useInvestigationStream";
import { api, fmtMs, fmtTime } from "@/lib/api";
import { POLARITY_COLORS, cn } from "@/lib/utils";

const TERMINAL = ["completed", "needs_review", "failed"];
const tooltipStyle = { background: "#08102a", border: "1px solid rgba(148,178,255,0.15)", borderRadius: 12, fontSize: 12 };

export default function InvestigationPage() {
  const { id } = useParams<{ id: string }>();
  const incidentId = decodeURIComponent(id);
  const { data: inc, error, reload } = useApi<any>(`incidents/${encodeURIComponent(incidentId)}`);
  const [pace, setPace] = useState<boolean | null>(null);
  useEffect(() => {
    if (inc && pace === null) setPace(!TERMINAL.includes(inc.status));
  }, [inc, pace]);
  const { events, ended } = useInvestigationStream(pace === null ? null : incidentId, !!pace);
  const [cti, setCti] = useState<any[] | null>(null);

  const milestones = events.filter((e) => e.type === "milestone").length;
  useEffect(() => {
    if (milestones > 0 || ended) reload();
  }, [milestones, ended, reload]);
  useEffect(() => {
    if (!inc) return;
    api<any[]>(`incidents/${encodeURIComponent(incidentId)}/cti`).then(setCti).catch(() => setCti([]));
  }, [inc?.status, milestones, incidentId]); // eslint-disable-line react-hooks/exhaustive-deps

  const report = inc?.report;
  const liveIndicators = useMemo(() => {
    const ev = events.find((e) => e.type === "task" && e.stage === "extract_indicators" && e.status === "completed");
    return ev?.data?.output?.indicators ?? null;
  }, [events]);
  const indicators = report?.indicators ?? liveIndicators ?? [];
  const status = TERMINAL.includes(inc?.status) && ended ? inc.status : events.length ? deriveStatus(events, inc?.status) : inc?.status;
  const decision = report?.decision;
  const running = !TERMINAL.includes(status ?? "");

  if (error && !inc) return <ErrorNote error={error} />;
  if (!inc) return <Skeleton className="h-[600px]" />;

  return (
    <div>
      <div className="mb-6 flex flex-wrap items-start justify-between gap-4">
        <div>
          <Link href="/incidents" className="text-xs text-slate-400 hover:text-cyan-300">← Investigations</Link>
          <div className="mt-2 flex flex-wrap items-center gap-2">
            <h1 className="font-mono text-2xl font-semibold tracking-tight text-white md:text-3xl">{inc.incident_id}</h1>
            <StatusBadge status={status} />
            <SeverityBadge severity={inc.severity} />
            {inc.cti_mode === "demo" ? (
              <Badge color="#a78bfa" title="CTI answers come from labelled local fixtures">REPRODUCIBLE DEMO MODE</Badge>
            ) : (
              <Badge color="#22d3ee">LIVE INTELLIGENCE MODE</Badge>
            )}
          </div>
          <div className="mt-1.5 text-lg text-slate-200">{inc.alert_name}</div>
          <div className="mt-1 flex flex-wrap gap-x-4 gap-y-1 text-xs text-slate-400">
            <span>Source: <b className="text-slate-200">{inc.source}</b></span>
            <span>Alert time: <b className="text-slate-200">{fmtTime(inc.timestamp, true)}</b></span>
            <span>Host: <b className="text-slate-200">{inc.hostname ?? "—"}</b></span>
            <span>Submitted via: <b className="text-slate-200">{inc.submitted_via}</b></span>
            <span>Investigation time: <b className="text-slate-200">{fmtMs(inc.duration_ms)}</b></span>
          </div>
          {inc.raw?.alert?.description && <p className="mt-2 max-w-3xl text-sm text-slate-400">{inc.raw.alert.description}</p>}
        </div>
      </div>

      <div className="grid gap-5 xl:grid-cols-[1.2fr_1fr]">
        <Card className="relative overflow-hidden">
          <div className="pointer-events-none absolute -right-20 -top-20 h-64 w-64 rounded-full opacity-25 blur-3xl" style={{ background: decision ? scoreColor(decision.threat_score) : "#22d3ee" }} />
          <div className="flex flex-wrap items-center gap-6">
            <div className="min-w-[220px] flex-1">
              <VerdictTitle verdict={running ? null : decision?.verdict} />
              {inc.status === "failed" && <div className="mt-2 text-sm text-rose-300">Investigation error: {inc.error}</div>}
              {decision?.human_review_required && !running && (
                <div className="mt-3 flex items-start gap-2 rounded-xl border border-amber-400/30 bg-amber-500/10 px-3 py-2 text-xs text-amber-200">
                  <UserCheck className="mt-0.5 h-4 w-4 shrink-0" />
                  <div><b>Human review required</b> — {decision.review_reasons.join("; ")}</div>
                </div>
              )}
              {running && <p className="mt-2 text-sm text-slate-400">The playbook is executing. Stages below update from real backend events.</p>}
            </div>
            <Gauge value={running ? null : decision?.threat_score} label="Threat score" color={scoreColor(decision?.threat_score)} />
            <Gauge value={running ? null : decision?.confidence} label="Confidence" color="#60a5fa" />
          </div>
          {decision && !running && (
            <div className="mt-5 space-y-1.5 border-t border-line pt-4">
              <div className="label mb-2">Why this verdict</div>
              {decision.rationale.map((r: string, i: number) => (
                <div key={i} className="flex gap-2 text-sm text-slate-300"><span className="text-cyan-400">›</span>{r}</div>
              ))}
            </div>
          )}
        </Card>
        <Card>
          <CardHeader title="Evidence balance" subtitle="Points contributed by each source (threat score and ML probability are kept separate)" icon={<Gavel className="h-4 w-4" />} />
          {decision ? <FactorChart decision={decision} /> : <Skeleton className="h-[230px]" />}
        </Card>
      </div>

      <Card className="mt-5">
        <CardHeader title="Investigation pipeline" subtitle={running ? "Live — Server-Sent Events from the SOAR engine" : "Replay of the stored execution events"} icon={<Sparkles className="h-4 w-4" />} right={running ? <Badge color="#22d3ee">● LIVE</Badge> : <Badge className="border-line text-slate-400">{events.length} events</Badge>} />
        <Pipeline events={events} incidentStatus={status} />
      </Card>

      <div className="mt-6">
        <Tabs
          tabs={[
            { value: "overview", label: "Overview", content: <Overview report={report} running={running} /> },
            { value: "evidence", label: `Evidence${report ? ` (${report.evidence.length})` : ""}`, content: <EvidenceTab report={report} /> },
            { value: "cti", label: "Indicators & CTI", content: <CtiTab indicators={indicators} cti={cti} report={report} /> },
            { value: "soar", label: "SOAR workflow", content: <SoarTab soar={inc.soar} /> },
            { value: "ml", label: "ML", content: <MlTab report={report} /> },
            { value: "ai", label: "AI report", content: <AiTab report={report} /> },
            { value: "timeline", label: "Timeline", content: <TimelineTab events={events} /> },
            { value: "json", label: "Original JSON", content: <JsonTab inc={inc} /> },
          ]}
        />
      </div>
    </div>
  );
}

function deriveStatus(events: any[], fallback: string) {
  for (let i = events.length - 1; i >= 0; i--) {
    if (events[i].type === "incident" && events[i].status) return events[i].status;
  }
  const done = events.find((e) => e.type === "task" && e.stage === "publish_results" && e.status === "completed");
  return done?.data?.output?.status ?? fallback;
}

function FactorChart({ decision }: { decision: any }) {
  const labels: Record<string, string> = { cti: "CTI", behavior: "Behaviour", context: "Context", integrity: "Integrity", ml: "ML (≤15)", reference: "GUIDE ref (≤10)", ai: "AI vote (≤5)" };
  const data = Object.entries(decision.factors).map(([k, v]: any) => ({ name: labels[k] ?? k, malicious: v.malicious, benign: v.benign }));
  return (
    <div>
      <div className="h-[220px]">
        <ResponsiveContainer>
          <BarChart data={data} layout="vertical" margin={{ left: 10, right: 10 }}>
            <CartesianGrid stroke="rgba(148,178,255,0.06)" horizontal={false} />
            <XAxis type="number" tick={{ fill: "#64748b", fontSize: 11 }} axisLine={false} tickLine={false} />
            <YAxis type="category" dataKey="name" tick={{ fill: "#94a3b8", fontSize: 11 }} axisLine={false} tickLine={false} width={86} />
            <Tooltip contentStyle={tooltipStyle} cursor={{ fill: "rgba(148,178,255,0.05)" }} />
            <Legend wrapperStyle={{ fontSize: 11 }} />
            <RBar dataKey="malicious" name="malicious / suspicious" fill="#fb7185" radius={[0, 5, 5, 0]} />
            <RBar dataKey="benign" name="benign" fill="#34d399" radius={[0, 5, 5, 0]} />
          </BarChart>
        </ResponsiveContainer>
      </div>
      <div className="mt-2 grid grid-cols-3 gap-2 text-center text-xs">
        <div className="rounded-lg bg-ink-900/70 p-2"><div className="text-slate-400">Malicious pts</div><div className="text-lg font-semibold text-rose-300">{decision.points.malicious}</div></div>
        <div className="rounded-lg bg-ink-900/70 p-2"><div className="text-slate-400">Authorisation</div><div className="text-lg font-semibold text-emerald-300">{decision.points.benign_authorization}</div></div>
        <div className="rounded-lg bg-ink-900/70 p-2"><div className="text-slate-400">Misidentification</div><div className="text-lg font-semibold text-sky-300">{decision.points.benign_misidentification}</div></div>
      </div>
    </div>
  );
}

function Overview({ report, running }: { report: any; running: boolean }) {
  if (!report) return running ? <Skeleton className="h-64" /> : <Empty title="No report available" />;
  const ai = report.ai;
  return (
    <div className="grid gap-5 xl:grid-cols-[1.3fr_1fr]">
      <Card>
        <CardHeader title="AI investigation summary" subtitle={`${ai.provider} · ${ai.model} · ${fmtMs(ai.latency_ms)}`} icon={<Bot className="h-4 w-4" />} right={<VerdictBadge verdict={ai.recommended_verdict} />} />
        <p className="text-[15px] leading-relaxed text-slate-200">{ai.summary}</p>
        <p className="mt-3 text-sm leading-relaxed text-slate-400">{ai.technical_explanation}</p>
        {ai.fallback_reason && <div className="mt-3 rounded-lg border border-amber-400/20 bg-amber-500/5 px-3 py-2 text-xs text-amber-200">{ai.fallback_reason}</div>}
        {report.mitre.length > 0 && (
          <div className="mt-4">
            <div className="label mb-2">MITRE ATT&CK techniques</div>
            <div className="flex flex-wrap gap-2">
              {report.mitre.map((t: any) => (
                <a key={t.id} href={t.url} target="_blank" rel="noreferrer" className="group">
                  <Badge color="#a78bfa" title={`${t.tactic} — evidence ${t.evidence_ids.join(", ")}`}>
                    <span className="font-mono">{t.id}</span> {t.name} <ExternalLink className="h-3 w-3 opacity-60" />
                  </Badge>
                </a>
              ))}
            </div>
          </div>
        )}
      </Card>
      <Card>
        <CardHeader title="Recommended response actions" subtitle="Display only — nothing is executed automatically" icon={<Lock className="h-4 w-4" />} />
        <Recommendations recs={report.recommendations} />
      </Card>
    </div>
  );
}

const PRIORITY_COLORS: Record<string, string> = { P1: "#fb7185", P2: "#fb923c", P3: "#fbbf24", P4: "#94a3b8" };

function Recommendations({ recs }: { recs: any[] }) {
  const [open, setOpen] = useState<string | null>(recs[0]?.id ?? null);
  return (
    <div className="space-y-2">
      {recs.map((r) => (
        <div key={r.id} className="rounded-xl border border-line bg-ink-900/60">
          <button className="flex w-full items-center gap-3 px-3 py-2.5 text-left" onClick={() => setOpen(open === r.id ? null : r.id)}>
            <Badge color={PRIORITY_COLORS[r.priority]}>{r.priority}</Badge>
            <span className="flex-1 text-sm text-slate-100">{r.action}</span>
            {open === r.id ? <ChevronDown className="h-4 w-4 text-slate-500" /> : <ChevronRight className="h-4 w-4 text-slate-500" />}
          </button>
          {open === r.id && (
            <div className="space-y-2 border-t border-line px-3 py-3 text-xs">
              <p className="text-slate-300">{r.explanation}</p>
              <div className="grid gap-2 sm:grid-cols-2">
                <div><span className="text-slate-500">Operational impact: </span><span className="text-slate-300">{r.operational_impact}</span></div>
                <div><span className="text-slate-500">Risk: </span><span className="text-slate-300">{r.risk}</span></div>
              </div>
              <div className="flex flex-wrap items-center gap-1.5"><span className="text-slate-500">Evidence:</span>{r.evidence_ids.length ? r.evidence_ids.map((e: string) => <EvidenceChip key={e} id={e} />) : <span className="text-slate-500">—</span>}</div>
              <div className="flex items-center gap-1.5 text-[10.5px] text-slate-500"><Lock className="h-3 w-3" /> display_only · automated = false</div>
            </div>
          )}
        </div>
      ))}
    </div>
  );
}

function EvidenceTab({ report }: { report: any }) {
  if (!report) return <Skeleton className="h-64" />;
  return (
    <div className="grid gap-3 md:grid-cols-2">
      {report.evidence.map((e: any) => (
        <div id={e.id} key={e.id} className="glass scroll-mt-24 p-4" style={{ borderLeft: `3px solid ${POLARITY_COLORS[e.polarity]}` }}>
          <div className="flex flex-wrap items-center gap-2">
            <span className="font-mono text-xs text-cyan-300">{e.id}</span>
            <PolarityBadge polarity={e.polarity} />
            {e.benign_class && <Badge color="#34d399">{e.benign_class}</Badge>}
            <span className="ml-auto text-xs text-slate-400">weight <b className="text-slate-100">{e.weight}</b></span>
          </div>
          <div className="mt-2 text-sm font-medium text-slate-100">{e.title}</div>
          <p className="mt-1 text-xs leading-relaxed text-slate-400">{e.description}</p>
          <div className="mt-2 flex flex-wrap items-center gap-1.5 text-[11px] text-slate-500">
            <span>{e.source}</span>
            {e.mitre.map((t: string) => <Badge key={t} color="#a78bfa">{t}</Badge>)}
            {e.data?.data_origin?.map((o: string) => <OriginBadge key={o} origin={o} />)}
          </div>
          {e.data?.decoded_preview && <pre className="mt-2 overflow-x-auto rounded-lg bg-ink-950 p-2 font-mono text-[11px] text-amber-200">{e.data.decoded_preview}</pre>}
        </div>
      ))}
    </div>
  );
}

function CtiTab({ indicators, cti, report }: { indicators: any[]; cti: any[] | null; report: any }) {
  const [open, setOpen] = useState<number | null>(null);
  return (
    <div className="space-y-5">
      <Card>
        <CardHeader title="Extracted indicators" subtitle="Normalised, de-duplicated and classified. Only 'shareable' indicators may reach public providers." icon={<Fingerprint className="h-4 w-4" />} />
        {indicators.length === 0 ? <Empty title="No indicators extracted" /> : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead><tr className="label text-left"><th className="pb-2">Type</th><th className="pb-2">Value</th><th className="pb-2">Scope</th><th className="pb-2">Public CTI</th><th className="pb-2">Found in</th></tr></thead>
              <tbody>
                {indicators.map((i: any) => (
                  <tr key={i.type + i.value} className="border-t border-line/70">
                    <td className="py-2 pr-3"><Badge className="border-line text-slate-300">{i.type}</Badge></td>
                    <td className="max-w-[420px] break-all py-2 pr-3 font-mono text-xs text-slate-100">{i.value}</td>
                    <td className="pr-3"><Badge color={i.scope === "public" ? "#22d3ee" : i.scope === "documentation" ? "#a78bfa" : "#94a3b8"} title={i.note ?? undefined}>{i.scope}</Badge></td>
                    <td className="pr-3 text-xs">{i.shareable ? <span className="text-cyan-300">eligible</span> : <span className="text-slate-500">never sent</span>}</td>
                    <td className="text-[11px] text-slate-500">{i.origins.join(", ")}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        {report?.decoded_command && (
          <div className="mt-4">
            <div className="label mb-1.5">Decoded PowerShell payload (static decoding — never executed)</div>
            <pre className="overflow-x-auto rounded-xl border border-amber-400/20 bg-ink-950 p-3 font-mono text-xs text-amber-200">{report.decoded_command}</pre>
          </div>
        )}
      </Card>
      <Card>
        <CardHeader title="Threat intelligence queries" subtitle={report ? `${report.cti.planned_queries} planned · coverage ${(report.cti.coverage * 100).toFixed(0)}% · mode ${report.cti.mode}` : "Provider responses as they arrive"} icon={<Radar className="h-4 w-4" />} />
        {!cti ? <Skeleton className="h-40" /> : cti.length === 0 ? (
          <Empty title="No CTI query executed">The playbook skipped CTI when no indicator was eligible, or providers are not configured in live mode.</Empty>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead><tr className="label text-left"><th className="pb-2" /><th className="pb-2">Provider</th><th className="pb-2">Indicator</th><th className="pb-2">Status</th><th className="pb-2">Result</th><th className="pb-2">Classification / malware</th><th className="pb-2">Origin</th><th className="pb-2 text-right">Duration</th><th className="pb-2 text-right">Queried</th></tr></thead>
              <tbody>
                {cti.map((q: any) => (
                  <Fragment key={q.id}>
                    <tr className="cursor-pointer border-t border-line/70 hover:bg-ink-800/40" onClick={() => setOpen(open === q.id ? null : q.id)}>
                      <td className="py-2 pr-2 text-slate-500">{open === q.id ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}</td>
                      <td className="pr-3 text-slate-200">{q.provider}</td>
                      <td className="max-w-[260px] truncate pr-3 font-mono text-xs text-slate-300" title={q.indicator}>{q.indicator}</td>
                      <td className="pr-3"><Badge color={q.status === "ok" || q.status === "no_results" ? "#34d399" : "#fb7185"}>{q.status}</Badge></td>
                      <td className="pr-3"><CtiVerdictBadge verdict={q.verdict} /></td>
                      <td className="max-w-[220px] truncate pr-3 text-xs text-slate-400">{[q.threat_type, ...(q.malware ?? [])].filter(Boolean).join(" · ") || "—"}</td>
                      <td className="pr-3"><OriginBadge origin={q.data_origin} /></td>
                      <td className="pr-3 text-right font-mono text-xs text-slate-400">{fmtMs(q.duration_ms)}</td>
                      <td className="text-right text-xs text-slate-500">{fmtTime(q.queried_at)}</td>
                    </tr>
                    {open === q.id && (
                      <tr>
                        <td colSpan={9} className="pb-4">
                          <div className="grid gap-3 lg:grid-cols-[1fr_1.4fr]">
                            <div className="rounded-xl border border-line bg-ink-900/60 p-3">
                              <KV k="Evidence" v={q.evidence_id ? <EvidenceChip id={q.evidence_id} /> : "—"} />
                              <KV k="Confidence" v={q.confidence ?? "—"} />
                              <KV k="First / last seen" v={`${q.first_seen ?? "—"} / ${q.last_seen ?? "—"}`} mono />
                              <KV k="Freshness" v={q.freshness_days != null ? `${q.freshness_days} days` : "—"} />
                              <KV k="Threat actors" v={(q.threat_actors ?? []).join(", ") || "—"} />
                              <KV k="ATT&CK" v={(q.mitre ?? []).join(", ") || "—"} />
                              <KV k="Tags" v={(q.tags ?? []).slice(0, 8).join(", ") || "—"} />
                              <KV k="HTTP status" v={q.http_status ?? "—"} />
                              {q.error && <KV k="Error" v={<span className="text-rose-300">{q.error}</span>} />}
                              <div className="mt-2 space-y-1">{(q.references ?? []).slice(0, 5).map((r: string) => <a key={r} href={r} target="_blank" rel="noreferrer" className="block truncate text-xs text-cyan-300 hover:underline">{r}</a>)}</div>
                            </div>
                            <div>
                              <div className="label mb-1.5">Raw provider response {q.data_origin === "demo_fixture" && "(demonstration fixture)"}</div>
                              <JsonBlock value={q.raw_response} max="max-h-[340px]" />
                            </div>
                          </div>
                        </td>
                      </tr>
                    )}
                  </Fragment>
                ))}
              </tbody>
            </table>
          </div>
        )}
        {report?.cti.skipped?.length > 0 && (
          <div className="mt-4 rounded-xl border border-line bg-ink-900/60 p-3">
            <div className="label mb-2 flex items-center gap-1.5"><Lock className="h-3 w-3" /> Privacy filter — not sent</div>
            {report.cti.skipped.map((s: any, i: number) => (
              <div key={i} className="text-xs text-slate-400"><span className="font-mono text-slate-300">{s.indicator}</span> → {s.provider}: {s.reason}</div>
            ))}
          </div>
        )}
      </Card>
    </div>
  );
}

function SoarTab({ soar }: { soar: any[] }) {
  const { data: pbs } = useApi<any[]>("soar/playbooks");
  const run = soar?.[soar.length - 1];
  const [sel, setSel] = useState<string | null>(null);
  if (!run || !pbs) return <Skeleton className="h-96" />;
  const states = Object.fromEntries(run.tasks.map((t: any) => [t.node_id, t]));
  const task = run.tasks.find((t: any) => t.node_id === (sel ?? run.tasks.find((x: any) => x.status === "running")?.node_id ?? run.tasks[0].node_id));
  return (
    <div className="grid gap-5 xl:grid-cols-[1.6fr_1fr]">
      <Card>
        <CardHeader title={`${run.playbook} v${run.version}`} subtitle={`Run #${run.run_id} · attempt ${run.attempt} · ${run.status} · ${fmtMs(run.duration_ms)}`} icon={<GitBranch className="h-4 w-4" />} right={<StatusBadge status={run.status} />} />
        <PlaybookGraph nodes={pbs[0].nodes} states={states} selected={task?.node_id} onSelect={setSel} />
      </Card>
      <Card>
        <CardHeader title={task?.name ?? "Task"} subtitle={task ? `${task.status} · ${task.attempts} attempt(s) · ${fmtMs(task.duration_ms)}` : ""} icon={<Clock className="h-4 w-4" />} />
        {task && (
          <div className="space-y-3">
            <div className="max-h-[260px] space-y-1 overflow-auto rounded-xl border border-line bg-ink-950/80 p-3 font-mono text-[11px]">
              {(task.logs ?? []).length === 0 && <div className="text-slate-500">No log lines.</div>}
              {(task.logs ?? []).map((l: any, i: number) => (
                <div key={i} className={cn(l.level === "error" ? "text-rose-300" : l.level === "warning" ? "text-amber-200" : "text-slate-300")}>
                  <span className="text-slate-600">{fmtTime(l.ts)} </span>{l.message}
                </div>
              ))}
            </div>
            {task.error && <div className="text-xs text-rose-300">{task.error}</div>}
            <div className="label">Task output</div>
            <JsonBlock value={task.output} max="max-h-[260px]" />
          </div>
        )}
      </Card>
    </div>
  );
}

function MlTab({ report }: { report: any }) {
  if (!report) return <Skeleton className="h-64" />;
  const ml = report.ml;
  return (
    <div className="grid gap-5 xl:grid-cols-2">
      <Card>
        <CardHeader title="ML classification" subtitle={`${ml.model_name ?? "—"} · ${ml.model_version ?? ""}`} icon={<Brain className="h-4 w-4" />} right={<Badge color={ml.status === "classified" ? "#34d399" : "#fbbf24"}>{ml.status}{ml.reason ? `: ${ml.reason}` : ""}</Badge>} />
        <div className="space-y-3">
          {Object.entries(ml.probabilities ?? {}).map(([k, v]: any) => (
            <div key={k}>
              <div className="mb-1 flex justify-between text-xs"><span className="text-slate-300">{k}</span><span className="font-mono text-slate-200">{(v * 100).toFixed(1)}%</span></div>
              <Bar value={v * 100} color={k === "true_positive" ? "#fb7185" : k === "false_positive" ? "#38bdf8" : "#34d399"} />
            </div>
          ))}
        </div>
        <div className="mt-4 grid grid-cols-2 gap-x-6">
          <KV k="Feature completeness" v={`${Math.round((ml.completeness ?? 0) * 100)}%`} />
          <KV k="Latency" v={`${ml.latency_ms ?? "—"} ms`} />
          <KV k="OOD score / threshold" v={`${ml.ood_score ?? "—"} / ${ml.ood_threshold ?? "—"}`} mono />
          <KV k="Decision weight" v="max 15 pts" />
        </div>
        <p className="mt-3 text-[11px] text-slate-500">The model abstains when evidence completeness is below 40%, when the input is out of the training distribution, or when its top probability is below 0.55. Trained on explicitly labelled synthetic data — see the ML Observatory.</p>
      </Card>
      <Card>
        <CardHeader title="Why the model thinks so" subtitle="Occlusion contributions to the top class (feature → training median)" />
        {(ml.contributions ?? []).length === 0 ? <Empty title="No contributions" /> : (
          <div className="space-y-2">
            {ml.contributions.map((c: any) => (
              <div key={c.feature} className="flex items-center gap-3 text-xs">
                <span className="w-44 truncate font-mono text-slate-300">{c.feature} = {c.value}</span>
                <div className="relative h-2 flex-1 rounded-full bg-ink-700">
                  <div className="absolute top-0 h-2 rounded-full" style={{ left: c.contribution >= 0 ? "50%" : `${50 - Math.min(50, Math.abs(c.contribution) * 50)}%`, width: `${Math.min(50, Math.abs(c.contribution) * 50)}%`, background: c.contribution >= 0 ? "#22d3ee" : "#fb7185" }} />
                  <div className="absolute left-1/2 top-[-2px] h-3 w-px bg-slate-500" />
                </div>
                <span className="w-14 text-right font-mono text-slate-400">{c.contribution > 0 ? "+" : ""}{c.contribution.toFixed(3)}</span>
              </div>
            ))}
          </div>
        )}
        <div className="label mb-2 mt-5">Non-zero features</div>
        <div className="flex flex-wrap gap-1.5">
          {Object.entries(report.features ?? {}).filter(([, v]: any) => v).map(([k, v]: any) => <Badge key={k} className="border-line font-mono text-slate-300">{k}={v}</Badge>)}
        </div>
      </Card>
      <ReferenceCard ref_={ml.reference} />
    </div>
  );
}

function ReferenceCard({ ref_ }: { ref_?: any }) {
  return (
    <Card className="xl:col-span-2">
      <CardHeader title="Reference model — trained on Microsoft GUIDE" subtitle="Real SOC labels (true / false / benign positive). Second opinion capped at 10 points; it cannot decide alone." icon={<Brain className="h-4 w-4" />}
        right={ref_ ? <Badge color={ref_.status === "classified" ? "#34d399" : ref_.status === "abstained" ? "#fbbf24" : "#64748b"}>{ref_.status}{ref_.reason ? `: ${ref_.reason}` : ""}</Badge> : undefined} />
      {!ref_ || ref_.status === "unavailable" ? (
        <Empty title="Reference model not loaded">Publish one with ml/guide/train_guide.py and set ML_ARTIFACT_URI (bucket). Investigations work without it.</Empty>
      ) : (
        <div className="grid gap-6 lg:grid-cols-2">
          <div className="space-y-3">
            {Object.entries(ref_.probabilities ?? {}).map(([k, v]: any) => (
              <div key={k}>
                <div className="mb-1 flex justify-between text-xs"><span className="text-slate-300">{k}</span><span className="font-mono text-slate-200">{(v * 100).toFixed(1)}%</span></div>
                <Bar value={v * 100} color={k === "true_positive" ? "#fb7185" : k === "false_positive" ? "#38bdf8" : "#34d399"} />
              </div>
            ))}
            {ref_.status === "classified" && (
              <div className="rounded-xl border border-line bg-ink-900/60 p-3 text-sm text-slate-200">
                {ref_.is_false_positive_or_benign ? "Looks like a false positive or benign activity" : "Looks like a genuine threat"} — P(threat) = {(ref_.p_threat * 100).toFixed(1)} %
              </div>
            )}
          </div>
          <div>
            <KV k="Model" v={`${ref_.model_name ?? "—"} · ${ref_.model_version ?? ""}`} mono />
            <KV k="Signals mapped to GUIDE" v={`${ref_.coverage?.matched?.categories?.length ?? 0} category · ${ref_.coverage?.matched?.techniques?.length ?? 0} technique · ${ref_.coverage?.matched?.entities?.length ?? 0} entity`} />
            <KV k="Coverage" v={`${Math.round((ref_.coverage?.coverage ?? 0) * 100)}%`} />
            <KV k="OOD score / threshold" v={`${ref_.ood_score ?? "—"} / ${ref_.ood_threshold ?? "—"}`} mono />
            <KV k="Latency" v={`${ref_.latency_ms ?? "—"} ms`} />
            <KV k="Dataset" v={ref_.dataset} />
          </div>
        </div>
      )}
    </Card>
  );
}

function ClaimList({ title, claims, color }: { title: string; claims: any[]; color: string }) {
  if (!claims?.length) return null;
  return (
    <div>
      <div className="label mb-2" style={{ color }}>{title}</div>
      <div className="space-y-2">
        {claims.map((c: any, i: number) => (
          <div key={i} className="rounded-xl border border-line bg-ink-900/60 p-3 text-sm text-slate-200">
            {c.statement}
            <div className="mt-1.5 flex flex-wrap gap-1">{c.evidence_ids.map((e: string) => <EvidenceChip key={e} id={e} />)}</div>
          </div>
        ))}
      </div>
    </div>
  );
}

function AiTab({ report }: { report: any }) {
  if (!report) return <Skeleton className="h-64" />;
  const ai = report.ai;
  return (
    <div className="grid gap-5 xl:grid-cols-[1.5fr_1fr]">
      <Card className="space-y-5">
        <CardHeader title="Structured AI investigation" subtitle="Every claim cites evidence IDs validated server-side" icon={<Bot className="h-4 w-4" />} right={<VerdictBadge verdict={ai.recommended_verdict} />} />
        <ClaimList title="Suspicious behaviour" claims={ai.suspicious_behaviors} color="#fb7185" />
        <ClaimList title="CTI findings" claims={ai.cti_findings} color="#22d3ee" />
        <ClaimList title="Supporting evidence" claims={ai.supporting_evidence} color="#34d399" />
        <ClaimList title="Contradictory evidence" claims={ai.contradictory_evidence} color="#fbbf24" />
        <ClaimList title="Knowledge base guidance (reference material, not evidence)" claims={ai.knowledge_guidance} color="#a78bfa" />
        {report.knowledge?.passages?.length > 0 && (
          <div>
            <div className="label mb-2">Retrieved from the knowledge base ({report.knowledge.dataset ?? "bucket"}, {report.knowledge.store})</div>
            <div className="space-y-2">
              {report.knowledge.passages.map((p: any) => (
                <div key={p.evidence_id} className="rounded-xl border border-line bg-ink-900/60 p-3 text-xs">
                  <div className="flex flex-wrap items-center gap-2"><EvidenceChip id={p.evidence_id} /><Badge className="border-line text-slate-300">{p.domain ?? "general"}</Badge><span className="text-slate-500">relevance {p.score}</span></div>
                  <div className="mt-1 text-sm font-medium text-slate-100">{p.title}</div>
                  <p className="mt-1 line-clamp-4 text-slate-400">{p.excerpt}</p>
                </div>
              ))}
            </div>
            <p className="mt-1 text-[11px] text-slate-500">License: {report.knowledge.license}. Passages never influence the verdict.</p>
          </div>
        )}
        {ai.mitre_techniques?.length > 0 && (
          <div>
            <div className="label mb-2 text-violet-300">Potential ATT&CK techniques</div>
            <div className="space-y-2">
              {ai.mitre_techniques.map((t: any) => (
                <div key={t.technique_id} className="rounded-xl border border-line bg-ink-900/60 p-3 text-sm">
                  <span className="font-mono text-violet-300">{t.technique_id}</span> <span className="text-slate-200">{t.name}</span>
                  <div className="mt-1 text-xs text-slate-400">{t.rationale}</div>
                  <div className="mt-1.5 flex flex-wrap gap-1">{t.evidence_ids.map((e: string) => <EvidenceChip key={e} id={e} />)}</div>
                </div>
              ))}
            </div>
          </div>
        )}
        {ai.recommended_actions?.length > 0 && (
          <div>
            <div className="label mb-2">Agent suggested actions (advisory)</div>
            {ai.recommended_actions.map((a: any, i: number) => (
              <div key={i} className="mb-2 rounded-xl border border-line bg-ink-900/60 p-3 text-sm text-slate-200">{a.action}<div className="text-xs text-slate-400">{a.rationale}</div></div>
            ))}
          </div>
        )}
      </Card>
      <div className="space-y-5">
        <Card>
          <CardHeader title="Provenance" icon={<ShieldAlert className="h-4 w-4" />} />
          <KV k="Mode" v={ai.mode === "llm" ? "Language model" : "Deterministic (no LLM)"} />
          <KV k="Provider" v={ai.provider} />
          <KV k="Model" v={ai.model} />
          <KV k="Latency" v={fmtMs(ai.latency_ms)} />
          <KV k="Redaction" v={ai.redaction_applied ? "applied (external provider)" : "not needed (local)"} />
          <KV k="Dropped claims" v={(ai.validation?.dropped_claims ?? 0) + (ai.validation?.second_pass?.dropped_claims ?? 0)} />
          <KV k="Dropped citations" v={ai.validation?.dropped_citations ?? 0} />
          <KV k="Final decision weight" v={ai.mode === "llm" ? "max 5 pts" : "none"} />
        </Card>
        <Card>
          <CardHeader title="Confidence limitations" icon={<AlertOctagon className="h-4 w-4" />} />
          <ul className="space-y-1.5 text-sm text-slate-300">{ai.confidence_limitations.map((l: string, i: number) => <li key={i} className="flex gap-2"><span className="text-amber-300">!</span>{l}</li>)}</ul>
        </Card>
      </div>
    </div>
  );
}

function TimelineTab({ events }: { events: any[] }) {
  const [filter, setFilter] = useState("all");
  const shown = events.filter((e) => filter === "all" || e.type === filter);
  return (
    <Card>
      <CardHeader title="Execution journal" subtitle="Every event persisted by the backend, in order" icon={<Clock className="h-4 w-4" />} right={
        <div className="flex gap-1">{["all", "milestone", "task", "cti_result", "log"].map((f) => <button key={f} onClick={() => setFilter(f)} className={cn("rounded-lg px-2 py-1 text-[11px]", filter === f ? "bg-ink-700 text-white" : "text-slate-400")}>{f}</button>)}</div>
      } />
      <div className="max-h-[600px] space-y-0.5 overflow-auto font-mono text-[11.5px]">
        {shown.map((e) => (
          <div key={e.seq} className="flex gap-3 rounded px-2 py-1 hover:bg-ink-800/50">
            <span className="w-8 text-right text-slate-600">{e.seq}</span>
            <span className="w-[72px] shrink-0 text-slate-500">{fmtTime(e.ts)}</span>
            <span className={cn("w-[84px] shrink-0", e.type === "milestone" ? "text-emerald-300" : e.type === "cti_result" ? "text-cyan-300" : e.type === "task" ? "text-violet-300" : "text-slate-500")}>{e.type}</span>
            <span className="w-[150px] shrink-0 truncate text-slate-500">{e.stage ?? ""}</span>
            <span className={cn("flex-1", e.status === "error" || e.status === "failed" ? "text-rose-300" : e.status === "warning" ? "text-amber-200" : "text-slate-200")}>{e.message}</span>
          </div>
        ))}
      </div>
    </Card>
  );
}

function JsonTab({ inc }: { inc: any }) {
  return (
    <div className="grid gap-5 xl:grid-cols-2">
      <Card>
        <CardHeader title="Original incident JSON" subtitle="As accepted by POST /api/v1/incidents" icon={<FileJson className="h-4 w-4" />} />
        <JsonEditor value={JSON.stringify(inc.raw, null, 2)} readOnly height={560} />
      </Card>
      <Card>
        <CardHeader title="Normalised incident" subtitle="Produced by the 'Normalize incident' task" />
        <JsonBlock value={inc.normalized ?? {}} max="max-h-[560px]" />
      </Card>
    </div>
  );
}
