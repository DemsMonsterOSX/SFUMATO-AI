"use client";

import { Activity, Radio, Server, ShieldCheck, Zap } from "lucide-react";
import { Bar, BarChart, CartesianGrid, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { Badge, Card, CardHeader, Empty, ErrorNote, PageHeader, Skeleton, Stat } from "@/components/ui";
import { useApi } from "@/hooks/useApi";

const tooltipStyle = { background: "#08102a", border: "1px solid rgba(148,178,255,0.15)", borderRadius: 12, fontSize: 12 };
const n = (v: number) => v.toLocaleString("en-US");

type Cm = { tp: number; fp: number; fn: number; tn: number };
type Scorer = { host: string; scenario: string; consumed: number; alerts: number; throughput_per_s: number; partitions: number[]; lag_by_partition: Record<string, number>;
  latency_ms: { p50: number | null; p95: number | null }; age_s: number; active: boolean; uptime_s: number };
type Producer = { host: string; scenario: string; target_rate: number; sent: number; errors: number; avg_rate: number; age_s: number; active: boolean };
type Scenario = { description: string; flows_scored: number; confusion: Cm; precision: number; recall: number; rate_flows_per_s: number; per_label?: Record<string, { flows: number; flagged: number }>; offline_reference: { precision: number; recall: number } };
type Overview = {
  active: boolean; live_available: boolean; scorers: Scorer[]; producers: Producer[];
  cve_consumer: { events_consumed: number; counts: Record<string, number>; recent: { type: string; id: string; severity: string | null; kev: boolean }[] } | null;
  cve_bridge: { published: number; last_generated_at: string } | null;
  totals: { confusion: Cm; precision: number | null; recall: number | null; consumed: number; throughput_per_s: number; per_label: Record<string, { flows: number; flagged: number }> };
  results: null | {
    measured_on: string;
    cluster: { kafka_version: string; mode: string; brokers: number; machine: string; min_insync_replicas: number; producer: string; consumers: string; topics: Record<string, { partitions: number; replication: number }> };
    scenarios: { known: Scenario; unseen: Scenario };
    fault_tolerance_test: { action: string; producer_errors: number; during_failure: string; after_restart: string; limits: string[] };
    throughput: { producer_flows_per_s: number; note: string };
  };
};

export default function StreamPage() {
  const { data, error } = useApi<Overview>("stream/overview", 5000);
  const r = data?.results;
  const compare = r ? [
    { name: "Known families", recall: r.scenarios.known.recall, precision: r.scenarios.known.precision },
    { name: "Unseen families", recall: r.scenarios.unseen.recall, precision: r.scenarios.unseen.precision },
  ] : [];
  const live = data?.totals;
  const labels = live ? Object.entries(live.per_label).sort((a, b) => b[1].flows - a[1].flows) : [];

  return (
    <div>
      <PageHeader kicker="Streaming" title="Distributed data streaming" description="A Kafka cluster of three brokers receives network flows continuously; a group of three scorers shares the partitions and raises alerts; hourly CVE changes flow through the same cluster. If one VM fails, the others take over. The cluster runs on demand to keep the cloud bill low." />
      <ErrorNote error={error} />
      {!data && !error && <Skeleton className="h-48" />}
      {data && (
        <>
          <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
            <Stat label="Pipeline" value={<span className="text-2xl">{data.active ? "RUNNING" : "IDLE"}</span>} sub={data.active ? "live data below" : "start it with scripts\\gcp_stream.ps1 run"} accent={data.active ? "#34d399" : "#94a3b8"} icon={<Radio className="h-4 w-4" />} />
            <Stat label="Brokers" value={r ? r.cluster.brokers : "—"} sub={r ? `Kafka ${r.cluster.kafka_version}, KRaft, ${r.cluster.machine}` : ""} icon={<Server className="h-4 w-4" />} />
            <Stat label="Throughput" value={data.active ? `${live?.throughput_per_s ?? 0}/s` : r ? `${r.throughput.producer_flows_per_s}/s` : "—"} sub={data.active ? "flows scored now" : "rate tested (not a maximum)"} accent="#a78bfa" icon={<Zap className="h-4 w-4" />} />
            <Stat label="Replication" value={r ? `${Object.values(r.cluster.topics)[0].replication}x` : "—"} sub={r ? `min in-sync replicas ${r.cluster.min_insync_replicas}` : ""} accent="#fbbf24" icon={<ShieldCheck className="h-4 w-4" />} />
          </div>

          {data.live_available && data.scorers.length > 0 && (
            <Card className="mt-5">
              <CardHeader title="Live: consumer group" subtitle={data.active ? "Refreshed every 5 seconds from the streaming applications" : "Last published state (the applications are stopped)"} icon={<Activity className="h-4 w-4" />} />
              <div className="grid gap-3 md:grid-cols-3">
                {data.scorers.map((s) => (
                  <div key={s.host} className="rounded-xl border border-line bg-ink-900/50 p-3 text-xs">
                    <div className="flex items-center justify-between"><span className="font-mono text-slate-200">{s.host}</span><Badge color={s.active ? "#34d399" : "#64748b"}>{s.active ? "active" : `${s.age_s}s ago`}</Badge></div>
                    <div className="mt-2 text-slate-400">Partitions <span className="font-mono text-cyan-300">{s.partitions.join(", ") || "none"}</span></div>
                    <div className="text-slate-400">Consumed <span className="font-mono text-slate-100">{n(s.consumed)}</span> · alerts <span className="font-mono text-slate-100">{n(s.alerts)}</span></div>
                    <div className="text-slate-400">Rate <span className="font-mono text-slate-100">{s.throughput_per_s}/s</span> · p50 latency <span className="font-mono text-slate-100">{s.latency_ms.p50 ?? "—"} ms</span></div>
                    <div className="text-slate-400">Lag <span className="font-mono text-slate-100">{n(Object.values(s.lag_by_partition).reduce((a, b) => a + b, 0))}</span> messages</div>
                  </div>
                ))}
              </div>
              {live && live.recall !== null && (
                <div className="mt-4 text-xs text-slate-300">
                  Against the replay labels: precision <b className="text-white">{live.precision?.toFixed(4)}</b> · recall <b className="text-white">{live.recall.toFixed(4)}</b> over {n(live.consumed)} flows
                  (TP {n(live.confusion.tp)} · FP {n(live.confusion.fp)} · FN {n(live.confusion.fn)} · TN {n(live.confusion.tn)}). {data.producers[0] && <>Producer: {n(data.producers[0].sent)} sent, {data.producers[0].errors} errors, scenario <b>{data.producers[0].scenario}</b>.</>}
                </div>
              )}
              {labels.length > 0 && (
                <div className="mt-4 h-[200px]">
                  <ResponsiveContainer>
                    <BarChart data={labels.map(([name, v]) => ({ name, rate: v.flagged / Math.max(1, v.flows) }))} margin={{ left: -10 }}>
                      <CartesianGrid stroke="rgba(148,178,255,0.06)" vertical={false} />
                      <XAxis dataKey="name" interval={0} tick={{ fill: "#94a3b8", fontSize: 10 }} axisLine={false} tickLine={false} />
                      <YAxis domain={[0, 1]} tick={{ fill: "#64748b", fontSize: 11 }} axisLine={false} tickLine={false} />
                      <Tooltip contentStyle={tooltipStyle} formatter={(v: number) => `${(v * 100).toFixed(1)} % flagged`} />
                      <Bar dataKey="rate" radius={[4, 4, 0, 0]}>{labels.map(([name]) => <Cell key={name} fill={name === "Benign" ? "#3b82f6" : "#f43f5e"} />)}</Bar>
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              )}
            </Card>
          )}
          {!data.live_available && <div className="mt-5"><Empty title="No live data" icon={<Radio className="h-5 w-5" />}>The streaming applications publish their state to the bucket while they run: start them with <span className="font-mono">scripts\gcp_stream.ps1 run -Scenario known</span>. The measured results below stay available.</Empty></div>}

          {r && (
            <>
              <Card className="mt-5">
                <CardHeader title="Measured results" subtitle={`Measured on ${r.measured_on} on the real cluster, 300 flows per second`} />
                <div className="h-[220px]">
                  <ResponsiveContainer>
                    <BarChart data={compare} margin={{ left: -10 }}>
                      <CartesianGrid stroke="rgba(148,178,255,0.06)" vertical={false} />
                      <XAxis dataKey="name" tick={{ fill: "#94a3b8", fontSize: 11 }} axisLine={false} tickLine={false} />
                      <YAxis domain={[0, 1]} tick={{ fill: "#64748b", fontSize: 11 }} axisLine={false} tickLine={false} />
                      <Tooltip contentStyle={tooltipStyle} formatter={(v: number) => v.toFixed(4)} />
                      <Bar dataKey="precision" fill="#3b82f6" radius={[4, 4, 0, 0]} />
                      <Bar dataKey="recall" fill="#f43f5e" radius={[4, 4, 0, 0]} />
                    </BarChart>
                  </ResponsiveContainer>
                </div>
                <div className="mt-3 grid gap-3 md:grid-cols-2">
                  {(["known", "unseen"] as const).map((k) => {
                    const s = r.scenarios[k];
                    return (
                      <div key={k} className="rounded-xl border border-line bg-ink-900/50 p-3 text-xs text-slate-300">
                        <div className="mb-1 font-semibold text-white">{k === "known" ? "Known families" : "Unseen families"}</div>
                        <p className="text-slate-400">{s.description}</p>
                        <p className="mt-2">{n(s.flows_scored)} flows · precision <b className="text-white">{s.precision}</b> · recall <b className="text-white">{s.recall}</b> <span className="text-slate-500">(offline: {s.offline_reference.precision} / {s.offline_reference.recall})</span></p>
                        {s.per_label && <p className="mt-1 text-slate-400">{Object.entries(s.per_label).map(([l, v]) => `${l}: ${v.flagged}/${n(v.flows)} flagged`).join(" · ")}</p>}
                      </div>
                    );
                  })}
                </div>
                <p className="mt-3 text-xs text-amber-200">The model detects 93 % of the attacks it has learned about and almost none of the families it has never seen. Streaming makes detection continuous and resilient; it does not make the model generalise.</p>
              </Card>

              <Card className="mt-5">
                <CardHeader title="Failure test" subtitle="One VM stopped while the flow was running" icon={<ShieldCheck className="h-4 w-4" />} />
                <ul className="list-disc space-y-1 pl-5 text-xs text-slate-200">
                  <li>{r.fault_tolerance_test.action}</li>
                  <li>Producer errors: <b>{r.fault_tolerance_test.producer_errors}</b></li>
                  <li>During the failure: {r.fault_tolerance_test.during_failure}</li>
                  <li>After the restart: {r.fault_tolerance_test.after_restart}</li>
                </ul>
                <h4 className="mt-3 text-[11px] font-semibold uppercase tracking-wide text-slate-400">Limits</h4>
                <ul className="mt-1 list-disc space-y-1 pl-5 text-xs text-slate-400">{r.fault_tolerance_test.limits.map((l) => <li key={l}>{l}</li>)}</ul>
              </Card>

              <Card className="mt-5">
                <CardHeader title="Cluster design" />
                <ul className="list-disc space-y-1 pl-5 text-xs text-slate-300">
                  <li>{r.cluster.mode}; {r.cluster.brokers} brokers on {r.cluster.machine}.</li>
                  <li>Topics: {Object.entries(r.cluster.topics).map(([t, v]) => `${t} (${v.partitions} partitions, replication ${v.replication})`).join(" · ")}.</li>
                  <li>Producer: {r.cluster.producer}. Consumers: {r.cluster.consumers}.</li>
                </ul>
              </Card>
            </>
          )}

          {data.cve_consumer && (
            <Card className="mt-5">
              <CardHeader title="CVE events through Kafka" subtitle={`${n(data.cve_consumer.events_consumed)} events consumed`} />
              <div className="flex flex-wrap gap-2 text-[11px]">{Object.entries(data.cve_consumer.counts).map(([k, v]) => <Badge key={k} color="#22d3ee">{k}: {n(v)}</Badge>)}</div>
              <ul className="mt-3 max-h-48 space-y-1 overflow-y-auto text-xs text-slate-300">
                {data.cve_consumer.recent.slice(0, 12).map((e, i) => <li key={`${e.id}-${i}`}><span className="font-mono text-cyan-300">{e.id}</span> · {e.type}{e.severity ? ` · ${e.severity}` : ""}{e.kev ? " · KEV" : ""}</li>)}
              </ul>
            </Card>
          )}
        </>
      )}
    </div>
  );
}
