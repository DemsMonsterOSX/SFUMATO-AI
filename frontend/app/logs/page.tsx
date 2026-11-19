"use client";

import { FileSearch, ScrollText } from "lucide-react";
import { useEffect, useState } from "react";
import { Bar, BarChart, CartesianGrid, Legend, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { Badge, Card, CardHeader, Empty, ErrorNote, PageHeader, Skeleton, Stat } from "@/components/ui";
import { useApi } from "@/hooks/useApi";

const tooltipStyle = { background: "#08102a", border: "1px solid rgba(148,178,255,0.15)", borderRadius: 12, fontSize: 12 };
const LEVEL_COLORS: Record<string, string> = { INFO: "#3b82f6", WARNING: "#fbbf24", ERROR: "#f43f5e", CRITICAL: "#a855f7", DEBUG: "#64748b" };
const n = (v: number) => v.toLocaleString("en-US");

type Status = { configured: boolean; reachable: boolean; reason: string | null; cluster?: { status: string; number_of_nodes: number } | null };
type Overview = {
  minutes: number; total: number; levels: Record<string, number>; services: Record<string, number>; status_classes: Record<string, number>;
  timeline: ({ t: string; total: number } & Record<string, number | string>)[];
  routes: { route: string; requests: number; avg_ms: number; p95_ms: number; errors: number }[];
  slowest: { route: string; ms: number; status: number; "@timestamp": string }[];
};
type Hit = { "@timestamp": string; service: string; level: string; message: string; route?: string; method?: string; status?: number; ms?: number; host?: string };

export default function LogsPage() {
  const [minutes, setMinutes] = useState(60);
  const [service, setService] = useState("");
  const [level, setLevel] = useState("");
  const [q, setQ] = useState("");
  const [dq, setDq] = useState("");
  useEffect(() => { const t = setTimeout(() => setDq(q.trim()), 300); return () => clearTimeout(t); }, [q]);

  const { data: st } = useApi<Status>("logs/status", 15000);
  const live = !!st?.reachable;
  const { data: ov, error: ovErr } = useApi<Overview>(live ? `logs/overview?minutes=${minutes}${service ? `&service=${service}` : ""}` : null, 10000);
  const qs = new URLSearchParams({ minutes: String(minutes), size: "60" });
  if (service) qs.set("service", service);
  if (level) qs.set("level", level);
  if (dq) qs.set("q", dq);
  const { data: res } = useApi<{ total: number; items: Hit[] }>(live ? `logs/search?${qs}` : null, 10000);
  const levels = ["INFO", "WARNING", "ERROR"];

  return (
    <div>
      <PageHeader kicker="Observability" title="Logs" description="Application logs (the API, the streaming applications) are pushed to Logstash, indexed in Elasticsearch and analysed here: volume by level, slowest routes, errors and a full-text search. Kibana is not deployed: this tab replaces it." />
      {!st && <Skeleton className="h-24" />}
      {st && !live && (
        <Empty title="The log platform is not reachable" icon={<ScrollText className="h-5 w-5" />}>
          {st.reason ?? "Elasticsearch did not answer."} Start it with <span className="font-mono">scripts\gcp_elk.ps1 start</span>; events sent while it is off are dropped, not queued.
        </Empty>
      )}
      <ErrorNote error={ovErr} />
      {live && (
        <>
          <div className="mb-4 flex flex-wrap items-center gap-2 text-xs">
            {[15, 60, 360, 1440].map((m) => <button key={m} onClick={() => setMinutes(m)} className={`rounded-lg border px-2.5 py-1 ${minutes === m ? "border-cyan-400/50 bg-cyan-400/10 text-white" : "border-line text-slate-400"}`}>{m < 60 ? `${m} min` : `${m / 60} h`}</button>)}
            <select value={service} onChange={(e) => setService(e.target.value)} aria-label="Service" className="rounded-lg border border-line bg-ink-900/70 px-2 py-1 text-slate-200">
              <option value="">All services</option>{Object.keys(ov?.services ?? {}).map((s) => <option key={s}>{s}</option>)}
            </select>
            <select value={level} onChange={(e) => setLevel(e.target.value)} aria-label="Level" className="rounded-lg border border-line bg-ink-900/70 px-2 py-1 text-slate-200">
              <option value="">All levels</option>{["INFO", "WARNING", "ERROR", "CRITICAL"].map((s) => <option key={s}>{s}</option>)}
            </select>
            <Badge color="#34d399">Elasticsearch {st?.cluster?.status ?? "up"}</Badge>
          </div>
          <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
            <Stat label="Events" value={ov ? n(ov.total) : "—"} sub={`last ${minutes < 60 ? `${minutes} min` : `${minutes / 60} h`}`} icon={<FileSearch className="h-4 w-4" />} />
            <Stat label="Errors (5xx / ERROR)" value={ov ? n(ov.levels.ERROR ?? 0) : "—"} sub={ov ? `${n(ov.levels.WARNING ?? 0)} warnings` : ""} accent="#f43f5e" />
            <Stat label="Client errors (4xx)" value={ov ? n(ov.status_classes["4xx"] ?? 0) : "—"} sub="HTTP responses 400-499" accent="#fbbf24" />
            <Stat label="Services" value={ov ? Object.keys(ov.services).length : "—"} sub={ov ? Object.entries(ov.services).map(([k, v]) => `${k} ${n(v)}`).join(" · ") : ""} accent="#a78bfa" />
          </div>
          <Card className="mt-5">
            <CardHeader title="Events over time, by level" />
            {!ov ? <Skeleton className="h-48" /> : (
              <div className="h-[230px]">
                <ResponsiveContainer>
                  <BarChart data={ov.timeline.map((x) => ({ ...x, t: x.t.slice(11, 16) }))} margin={{ left: -10 }}>
                    <CartesianGrid stroke="rgba(148,178,255,0.06)" vertical={false} />
                    <XAxis dataKey="t" interval="preserveStartEnd" tick={{ fill: "#94a3b8", fontSize: 10 }} axisLine={false} tickLine={false} />
                    <YAxis tick={{ fill: "#64748b", fontSize: 11 }} axisLine={false} tickLine={false} />
                    <Tooltip contentStyle={tooltipStyle} />
                    <Legend wrapperStyle={{ fontSize: 10 }} />
                    {levels.map((l) => <Bar key={l} dataKey={l} stackId="a" fill={LEVEL_COLORS[l]} />)}
                  </BarChart>
                </ResponsiveContainer>
              </div>
            )}
          </Card>
          <div className="mt-5 grid gap-5 xl:grid-cols-2">
            <Card>
              <CardHeader title="Busiest API routes" subtitle="Latency measured by the API itself" />
              {!ov ? <Skeleton className="h-32" /> : ov.routes.length === 0 ? <Empty title="No request logged" /> : (
                <table className="w-full text-left text-xs"><thead className="text-slate-500"><tr><th className="py-1">Route</th><th>Req</th><th>avg ms</th><th>p95 ms</th><th>5xx</th></tr></thead>
                  <tbody>{ov.routes.map((r) => <tr key={r.route} className="border-t border-line text-slate-200"><td className="py-1 font-mono">{r.route}</td><td>{n(r.requests)}</td><td>{r.avg_ms}</td><td>{r.p95_ms}</td><td>{r.errors}</td></tr>)}</tbody></table>
              )}
              {ov?.slowest?.[0] && <p className="mt-2 text-[11px] text-slate-500">Slowest request: {ov.slowest[0].route} took {Math.round(ov.slowest[0].ms)} ms (HTTP {ov.slowest[0].status}).</p>}
            </Card>
            <Card>
              <CardHeader title="Search" subtitle="Full text on message, route and service" />
              <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="ERROR, /api/v1/incidents, kafka…" aria-label="Search logs"
                className="w-full rounded-xl border border-line bg-ink-900/70 px-3 py-2 text-sm text-slate-100 outline-none placeholder:text-slate-500 focus:border-cyan-400/50" />
              <p className="mt-2 text-[11px] text-slate-500">{res ? `${n(res.total)} matching events, the latest ${res.items.length} shown` : "…"}</p>
            </Card>
          </div>
          <Card className="mt-5">
            <CardHeader title="Latest events" />
            {!res ? <Skeleton className="h-40" /> : res.items.length === 0 ? <Empty title="No event matches" /> : (
              <div className="max-h-[480px] overflow-auto">
                <table className="w-full text-left text-xs"><thead className="sticky top-0 bg-ink-900 text-slate-500"><tr><th className="py-1">Time</th><th>Level</th><th>Service</th><th>Message</th><th>ms</th></tr></thead>
                  <tbody>{res.items.map((h, i) => (
                    <tr key={i} className="border-t border-line text-slate-200">
                      <td className="whitespace-nowrap py-1 font-mono text-slate-400">{h["@timestamp"].slice(11, 19)}</td>
                      <td><Badge color={LEVEL_COLORS[h.level] ?? "#64748b"}>{h.level}</Badge></td><td>{h.service}</td>
                      <td className="max-w-[520px] truncate font-mono" title={h.message}>{h.message}</td><td className="font-mono">{h.ms ?? ""}</td>
                    </tr>))}</tbody></table>
              </div>
            )}
          </Card>
        </>
      )}
    </div>
  );
}
