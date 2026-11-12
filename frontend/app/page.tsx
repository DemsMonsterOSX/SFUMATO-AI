"use client";

import { AlertTriangle, Bot, BrainCircuit, CheckCircle2, CircleHelp, Clock, Cpu, GitBranch, Radar, ShieldAlert, ShieldCheck, Sparkles, Workflow } from "lucide-react";
import Link from "next/link";
import { Bar, BarChart, CartesianGrid, Cell, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { Badge, Card, CardHeader, Dot, Empty, ErrorNote, PageHeader, SeverityBadge, Skeleton, Stat, StatusBadge, VerdictBadge } from "@/components/ui";
import { useApi } from "@/hooks/useApi";
import { fmtMs, timeAgo } from "@/lib/api";
import { SEVERITY_COLORS, VERDICTS } from "@/lib/utils";

type Stats = {
  total: number; active: number; needs_review: number; failed: number; avg_investigation_ms: number | null;
  verdicts: Record<string, number>; severity: Record<string, number>;
  timeline: Record<string, any>[]; recent: any[]; cti_health_24h: Record<string, { ok: number; errors: number }>;
};

const tooltipStyle = { background: "#08102a", border: "1px solid rgba(148,178,255,0.15)", borderRadius: 12, fontSize: 12 };

export default function CommandCenter() {
  const { data: s, error } = useApi<Stats>("stats", 4000);
  const { data: status } = useApi<any>("status", 8000);
  const { data: cti } = useApi<any>("cti/status", 10000);

  const verdictData = s ? Object.entries(s.verdicts).map(([k, v]) => ({ name: VERDICTS[k as keyof typeof VERDICTS].label, key: k, value: v })) : [];
  const sevData = s ? Object.entries(s.severity).map(([k, v]) => ({ name: k, value: v })) : [];
  const timeline = (s?.timeline ?? []).map((t) => ({ ...t, label: new Date(`${t.hour}:00Z`).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }) }));

  return (
    <div>
      <PageHeader
        kicker="SOC Command Center"
        title="Autonomous investigations, at a glance"
        description="Every number on this page is computed by the backend from persisted investigations. Verdicts are produced by the evidence-based decision engine, never by the LLM alone."
        right={<Link href="/simulator" className="rounded-xl bg-gradient-to-r from-cyan-500 via-electric-500 to-violet-500 px-4 py-2 text-sm font-medium text-white shadow-glow hover:brightness-110">Launch an investigation</Link>}
      />
      <ErrorNote error={error && !s ? `Backend unavailable: ${error}` : null} />

      <div className="grid grid-cols-2 gap-4 md:grid-cols-4 xl:grid-cols-7">
        <Stat label="Total incidents" value={s?.total ?? "—"} icon={<ShieldAlert className="h-4 w-4" />} href="/incidents" delay={0} />
        <Stat label="Active" value={s?.active ?? "—"} sub="queued + running" accent="#22d3ee" icon={<Workflow className="h-4 w-4" />} delay={0.03} />
        <Stat label="True positives" value={s?.verdicts.TRUE_POSITIVE ?? "—"} accent={VERDICTS.TRUE_POSITIVE.color} icon={<AlertTriangle className="h-4 w-4" />} delay={0.06} />
        <Stat label="False positives" value={s?.verdicts.FALSE_POSITIVE ?? "—"} accent={VERDICTS.FALSE_POSITIVE.color} icon={<ShieldCheck className="h-4 w-4" />} delay={0.09} />
        <Stat label="Legitimate" value={s?.verdicts.LEGITIMATE_ACTIVITY ?? "—"} accent={VERDICTS.LEGITIMATE_ACTIVITY.color} icon={<CheckCircle2 className="h-4 w-4" />} delay={0.12} />
        <Stat label="Inconclusive" value={s?.verdicts.INCONCLUSIVE ?? "—"} sub={s ? `${s.needs_review} need review` : undefined} accent={VERDICTS.INCONCLUSIVE.color} icon={<CircleHelp className="h-4 w-4" />} delay={0.15} />
        <Stat label="Avg. investigation" value={fmtMs(s?.avg_investigation_ms)} accent="#a78bfa" icon={<Clock className="h-4 w-4" />} delay={0.18} />
      </div>

      <div className="mt-5 grid gap-5 xl:grid-cols-3">
        <Card className="xl:col-span-2" delay={0.1}>
          <CardHeader title="Incident activity" subtitle="Alerts of the last 24 hours (alert time), by verdict" icon={<Sparkles className="h-4 w-4" />} />
          <div className="h-[260px]">
            {s ? (
              <ResponsiveContainer>
                <BarChart data={timeline} margin={{ left: -20, right: 8, top: 8 }}>
                  <CartesianGrid stroke="rgba(148,178,255,0.06)" vertical={false} />
                  <XAxis dataKey="label" tick={{ fill: "#64748b", fontSize: 11 }} axisLine={false} tickLine={false} interval={2} />
                  <YAxis allowDecimals={false} tick={{ fill: "#64748b", fontSize: 11 }} axisLine={false} tickLine={false} />
                  <Tooltip contentStyle={tooltipStyle} cursor={{ fill: "rgba(148,178,255,0.05)" }} />
                  {Object.entries(VERDICTS).map(([k, v], i, arr) => (
                    <Bar key={k} dataKey={k} name={v.label} stackId="v" fill={v.color} radius={i === arr.length - 1 ? [4, 4, 0, 0] : 0} maxBarSize={22} />
                  ))}
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <Skeleton className="h-full" />
            )}
          </div>
        </Card>
        <Card delay={0.15}>
          <CardHeader title="Verdict distribution" subtitle="Final decisions of the verdict engine" icon={<BrainCircuit className="h-4 w-4" />} />
          <div className="flex items-center gap-4">
            <div className="h-[200px] w-[200px] shrink-0">
              <ResponsiveContainer>
                <PieChart>
                  <Pie data={verdictData} dataKey="value" innerRadius={62} outerRadius={88} paddingAngle={3} stroke="none">
                    {verdictData.map((d) => (
                      <Cell key={d.key} fill={VERDICTS[d.key as keyof typeof VERDICTS].color} />
                    ))}
                  </Pie>
                  <Tooltip contentStyle={tooltipStyle} />
                </PieChart>
              </ResponsiveContainer>
            </div>
            <div className="flex-1 space-y-2.5">
              {verdictData.map((d) => (
                <div key={d.key} className="flex items-center justify-between text-sm">
                  <span className="flex items-center gap-2 text-slate-300">
                    <span className="h-2 w-2 rounded-full" style={{ background: VERDICTS[d.key as keyof typeof VERDICTS].color }} />
                    {d.name}
                  </span>
                  <span className="tabular-nums text-white">{d.value}</span>
                </div>
              ))}
            </div>
          </div>
        </Card>
      </div>

      <div className="mt-5 grid gap-5 xl:grid-cols-3">
        <Card className="xl:col-span-2" delay={0.2}>
          <CardHeader title="Recent alerts" subtitle="Click to open the investigation" icon={<ShieldAlert className="h-4 w-4" />} right={<Link href="/incidents" className="text-xs text-cyan-300 hover:underline">View all</Link>} />
          {!s ? (
            <Skeleton className="h-48" />
          ) : s.recent.length === 0 ? (
            <Empty title="No incidents yet">Submit one from the simulator or the REST API.</Empty>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="label text-left">
                    <th className="pb-2 font-medium">Incident</th>
                    <th className="pb-2 font-medium">Alert</th>
                    <th className="pb-2 font-medium">Severity</th>
                    <th className="pb-2 font-medium">Status</th>
                    <th className="pb-2 font-medium">Verdict</th>
                    <th className="pb-2 text-right font-medium">Score</th>
                  </tr>
                </thead>
                <tbody>
                  {s.recent.map((r) => (
                    <tr key={r.incident_id} className="border-t border-line/70 transition-colors hover:bg-ink-800/50">
                      <td className="py-2.5 pr-3">
                        <Link href={`/incidents/${r.incident_id}`} className="font-mono text-xs text-cyan-300 hover:underline">{r.incident_id}</Link>
                        <div className="text-[11px] text-slate-500">{timeAgo(r.created_at)}</div>
                      </td>
                      <td className="max-w-[280px] truncate pr-3 text-slate-200">{r.alert_name}<div className="text-[11px] text-slate-500">{r.source} · {r.hostname ?? "—"}</div></td>
                      <td className="pr-3"><SeverityBadge severity={r.severity} /></td>
                      <td className="pr-3"><StatusBadge status={r.status} /></td>
                      <td className="pr-3"><VerdictBadge verdict={r.verdict} /></td>
                      <td className="text-right font-mono tabular-nums text-slate-200">{r.threat_score ?? "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>
        <Card delay={0.25}>
          <CardHeader title="Severity distribution" subtitle="All ingested incidents" />
          <div className="h-[220px]">
            <ResponsiveContainer>
              <BarChart data={sevData} margin={{ left: -24, right: 4 }}>
                <CartesianGrid stroke="rgba(148,178,255,0.06)" vertical={false} />
                <XAxis dataKey="name" tick={{ fill: "#64748b", fontSize: 11 }} axisLine={false} tickLine={false} />
                <YAxis allowDecimals={false} tick={{ fill: "#64748b", fontSize: 11 }} axisLine={false} tickLine={false} />
                <Tooltip contentStyle={tooltipStyle} cursor={{ fill: "rgba(148,178,255,0.05)" }} />
                <Bar dataKey="value" radius={[6, 6, 0, 0]}>
                  {sevData.map((d) => (
                    <Cell key={d.name} fill={SEVERITY_COLORS[d.name]} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </Card>
      </div>

      <div className="mt-5 grid gap-5 md:grid-cols-2 xl:grid-cols-4">
        <Card delay={0.3}>
          <CardHeader title="CTI providers" subtitle={cti ? `Default mode: ${cti.default_mode}` : ""} icon={<Radar className="h-4 w-4" />} />
          <div className="space-y-2.5">
            {(cti?.providers ?? []).map((p: any) => (
              <div key={p.key} className="flex items-center justify-between gap-2 text-sm">
                <span className="flex items-center gap-2 text-slate-200">
                  <Dot ok={p.configured && p.health.errors === 0} warn={!p.configured || p.health.errors > 0} />
                  {p.name}
                </span>
                <span className="text-[11px] text-slate-400">
                  {p.configured ? `${p.health.queries} q · ${p.health.errors} err` : "not configured"}
                </span>
              </div>
            ))}
            {!cti && <Skeleton className="h-28" />}
          </div>
          <p className="mt-3 text-[11px] text-slate-500">Unconfigured providers still answer in demo mode from labelled fixtures.</p>
        </Card>
        <Card delay={0.33}>
          <CardHeader title="SOAR orchestrator" subtitle="Lightweight Python engine" icon={<GitBranch className="h-4 w-4" />} />
          {status ? (
            <div className="space-y-2 text-sm">
              <Row k="Playbook" v={<span className="font-mono text-xs">{status.soar.playbook}</span>} />
              <Row k="Nodes" v={status.soar.nodes} />
              <Row k="Worker" v={<span className="flex items-center gap-1.5"><Dot ok pulse />{status.soar.worker.mode}</span>} />
              <Row k="Queue / running" v={`${status.soar.queued} / ${status.soar.running}`} />
              <Row k="Last run" v={status.soar.last_run ? `${status.soar.last_run.status} · ${fmtMs(status.soar.last_run.duration_ms)}` : "—"} />
            </div>
          ) : <Skeleton className="h-28" />}
        </Card>
        <Card delay={0.36}>
          <CardHeader title="Machine learning" subtitle="Triage classifier" icon={<Cpu className="h-4 w-4" />} />
          {status ? (
            <div className="space-y-2 text-sm">
              <Row k="Status" v={<span className="flex items-center gap-1.5"><Dot ok={status.ml.ready} />{status.ml.ready ? "loaded" : "unavailable"}</span>} />
              <Row k="Model" v={status.ml.model_name ?? "—"} />
              <Row k="Version" v={<span className="font-mono text-[10px]">{status.ml.version ?? "—"}</span>} />
              <Row k="Avg latency" v={status.ml.avg_latency_ms ? `${status.ml.avg_latency_ms} ms` : "—"} />
            </div>
          ) : <Skeleton className="h-28" />}
        </Card>
        <Card delay={0.39}>
          <CardHeader title="AI investigator" subtitle="LLM with deterministic fallback" icon={<Bot className="h-4 w-4" />} />
          {status ? (
            <div className="space-y-2 text-sm">
              <Row k="Provider" v={<span className="flex items-center gap-1.5"><Dot ok={status.ai.selected !== "deterministic"} warn={status.ai.selected === "deterministic"} />{status.ai.selected}</span>} />
              <Row k="Model" v={<span className="text-xs">{status.ai.model}</span>} />
              <Row k="Ollama" v={status.ai.ollama.reachable ? "reachable" : "not reachable"} />
              <Row k="Why" v={<span className="text-xs text-slate-400">{status.ai.reason}</span>} />
            </div>
          ) : <Skeleton className="h-28" />}
        </Card>
      </div>
      <div className="mt-6 flex justify-center">
        <Badge className="border-line text-slate-500">All response actions are display-only — Sfumato never blocks, isolates or disables anything.</Badge>
      </div>
    </div>
  );
}

function Row({ k, v }: { k: string; v: React.ReactNode }) {
  return (
    <div className="flex items-center justify-between gap-3">
      <span className="text-slate-400">{k}</span>
      <span className="text-right text-slate-200">{v}</span>
    </div>
  );
}
