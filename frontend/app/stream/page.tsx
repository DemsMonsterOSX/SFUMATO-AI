"use client";

import { Activity, Gauge, Radio, Server, ShieldCheck, Zap } from "lucide-react";
import { useState } from "react";
import { Bar, BarChart, CartesianGrid, Cell, Line, LineChart, Legend, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { Badge, Button, Card, CardHeader, Empty, ErrorNote, PageHeader, Skeleton, Stat } from "@/components/ui";
import { useApi } from "@/hooks/useApi";
import { api } from "@/lib/api";

const tooltipStyle = { background: "#08102a", border: "1px solid rgba(148,178,255,0.15)", borderRadius: 12, fontSize: 12 };
const n = (v: number) => v.toLocaleString("en-US");

type Cm = { tp: number; fp: number; fn: number; tn: number };
type Scorer = { host: string; scenario: string; consumed: number; alerts: number; throughput_per_s: number; partitions: number[]; lag_by_partition: Record<string, number>;
  latency_ms: { p50: number | null; p95: number | null }; age_s: number; active: boolean; uptime_s: number };
type Producer = { host: string; scenario: string; target_rate: number; sent: number; errors: number; avg_rate: number; age_s: number; active: boolean };
type Scenario = { description: string; flows_scored: number; confusion: Cm; precision: number; recall: number; rate_flows_per_s: number; per_label?: Record<string, { flows: number; flagged: number }>; offline_reference: { precision: number; recall: number } };
type FlinkWin = { window_start: string; window_end: string; flows: number; attack_flows: number; distinct_dst_ports: number; avg_duration_us: number | null; syn_flows: number };
type FlinkAlert = { window_start: string; dst_port: number; flows: number; attack_flows: number; avg_duration_us: number | null; rule: string };
type Flink = { windows: FlinkWin[]; alerts: FlinkAlert[]; windows_seen: number; alerts_by_rule: Record<string, number>; alert_flows: number; alert_attack_share: number | null; age_s: number; active: boolean };
type Overview = {
  flink?: Flink | null;
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


type StressStep = { target: number; stress_producers: number; producer_limited?: boolean; background_rate?: number; produced_per_s: number; consumed_per_s: number; lag_end: number; p95_latency_ms: number | null; errors: number; passed: boolean; reason: string | null };
type Stress = {
  reachable: boolean; reason?: string; status?: string; steps?: StressStep[]; max_sustainable?: number | null; current_target?: number | null; error?: string;
  ceiling?: string; background_rate?: number; max_target_passed?: number | null; drain_seconds?: number; lag_after_drain?: number; duration_s?: number; verdict?: string; active_scorers?: number; scenario?: string; finished_at?: number;
  last?: Omit<Stress, "reachable" | "last"> | null;
};

/** Stress test: ramps the flow rate step by step and reports the highest rate the scorers keep up with. */
function StressCard() {
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const { data, reload } = useApi<Stress>("stream/stress", 3000);
  const running = data?.status === "running";
  const view = data?.reachable ? data : data?.last ? { ...data.last, reachable: false, reason: data.reason } : data;
  const steps = view?.steps ?? [];

  async function start() {
    if (!window.confirm("Run the stress test?\n\nIt raises the flow rate step by step (300 up to 7,200 flows per second, 30 seconds per step, about 3 to 5 minutes in total) on the Kafka cluster and stops at the first rate the scorers cannot keep up with. It adds a little cloud cost and its flows appear in the live counters.")) return;
    setBusy(true);
    setErr(null);
    try {
      await api("stream/stress", { method: "POST", body: JSON.stringify({ max_rate: 7200, step_seconds: 30 }) });
      reload();
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Card className="mt-5">
      <CardHeader title="Stress test" subtitle="Finds the highest flow rate the pipeline sustains: the producers ramp up, the scorers must keep the backlog under three seconds of traffic" icon={<Gauge className="h-4 w-4" />}
        right={<Button onClick={start} disabled={busy || running || !data?.reachable}>{running ? `Running… ${view?.current_target ?? ""} flows/s` : "Run stress test"}</Button>} />
      {!data?.reachable && <p className="text-xs text-amber-200">The streaming cluster is not reachable: {data?.reason ?? "checking…"} Start it with <span className="font-mono">scripts\gcp_stream.ps1 start</span> then <span className="font-mono">run</span>. {data?.last ? "The last recorded result is shown below." : ""}</p>}
      {err && <p className="mt-2 text-xs text-red-300">{err}</p>}
      {view?.status === "error" && <p className="mt-2 text-xs text-red-300">The test could not run: {view.error}</p>}
      {steps.length > 0 && (
        <>
          <div className="mt-3 flex flex-wrap items-center gap-3 text-xs text-slate-200">
            <Badge color={view?.max_sustainable ? "#34d399" : "#f43f5e"}>highest rate scored without backlog: {view?.max_sustainable ? `${n(view.max_sustainable)} flows/s` : "below the first step"}</Badge>
            {view?.ceiling && <Badge color="#fbbf24">limit seen: {view.ceiling}</Badge>}
            {view?.verdict && <span className="text-slate-400">{view.verdict}</span>}
            {view?.drain_seconds !== undefined && <span className="text-slate-400">backlog drained in {view.drain_seconds}s</span>}
            {view?.active_scorers !== undefined && <span className="text-slate-400">{view.active_scorers} scorers active</span>}
          </div>
          <div className="mt-3 h-[220px]">
            <ResponsiveContainer>
              <LineChart data={steps} margin={{ left: -5 }}>
                <CartesianGrid stroke="rgba(148,178,255,0.06)" vertical={false} />
                <XAxis dataKey="target" tick={{ fill: "#94a3b8", fontSize: 11 }} axisLine={false} tickLine={false} />
                <YAxis tick={{ fill: "#64748b", fontSize: 11 }} axisLine={false} tickLine={false} />
                <Tooltip contentStyle={tooltipStyle} />
                <Legend wrapperStyle={{ fontSize: 10 }} />
                <Line type="monotone" dataKey="target" name="target (flows/s)" stroke="#64748b" strokeDasharray="4 4" dot={false} />
                <Line type="monotone" dataKey="produced_per_s" name="produced" stroke="#3b82f6" />
                <Line type="monotone" dataKey="consumed_per_s" name="consumed (scored)" stroke="#34d399" />
              </LineChart>
            </ResponsiveContainer>
          </div>
          <div className="mt-3 overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="text-slate-400"><tr>{["Target /s", "Stress producers", "Total produced /s", "Consumed /s", "Backlog at end", "p95 latency", "Errors", "Result"].map((h) => <th key={h} className="px-2 py-2 font-medium">{h}</th>)}</tr></thead>
              <tbody>
                {steps.map((r) => (
                  <tr key={r.target} className="border-t border-line text-slate-200">
                    <td className="px-2 py-2 font-mono">{n(r.target)}</td><td className="px-2 py-2 font-mono">{r.stress_producers}</td>
                    <td className="px-2 py-2 font-mono">{n(r.produced_per_s)}</td><td className="px-2 py-2 font-mono">{n(r.consumed_per_s)}</td>
                    <td className="px-2 py-2 font-mono">{n(r.lag_end)}</td><td className="px-2 py-2 font-mono">{r.p95_latency_ms ?? "—"} ms</td><td className="px-2 py-2 font-mono">{r.errors}</td>
                    <td className="px-2 py-2">{r.passed && !r.producer_limited ? <Badge color="#34d399">sustained</Badge> : r.passed ? <Badge color="#fbbf24" title={r.reason ?? ""}>producer-limited</Badge> : <Badge color="#f43f5e" title={r.reason ?? ""}>{r.reason ?? "failed"}</Badge>}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <p className="mt-2 text-[11px] text-slate-500">A step is sustained when the scorers consume at least 95 % of what is produced and the backlog stays under three seconds of traffic. When the producer is the limit, the figure is a lower bound for the scorers. The regular replay producer's own rate is subtracted from the stress producers. It measures this setup (three e2-small VMs, Python scorers), not Kafka itself.</p>
        </>
      )}
    </Card>
  );
}

/** Flink: stateful 10-second windows and rate rules computed on the Kafka flow, next to the model-based scorers. */
function FlinkCard({ f }: { f: Flink }) {
  const wins = f.windows.map((w) => ({ t: w.window_end.slice(11, 19), flows: w.flows, attacks: w.attack_flows }));
  return (
    <Card className="mt-5">
      <CardHeader title="Apache Flink: windows and rate rules" subtitle="Tumbling 10-second event-time windows over the same Kafka topic; the rules need no model, so they also see families the model never learned" icon={<Activity className="h-4 w-4" />}
        right={<Badge color={f.active ? "#34d399" : "#64748b"}>{f.active ? "job producing" : `last result ${f.age_s}s ago`}</Badge>} />
      <div className="h-[210px]">
        <ResponsiveContainer>
          <LineChart data={wins} margin={{ left: -5 }}>
            <CartesianGrid stroke="rgba(148,178,255,0.06)" vertical={false} />
            <XAxis dataKey="t" tick={{ fill: "#94a3b8", fontSize: 10 }} axisLine={false} tickLine={false} interval="preserveStartEnd" />
            <YAxis tick={{ fill: "#64748b", fontSize: 11 }} axisLine={false} tickLine={false} />
            <Tooltip contentStyle={tooltipStyle} />
            <Legend wrapperStyle={{ fontSize: 10 }} />
            <Line type="monotone" dataKey="flows" name="flows per window" stroke="#3b82f6" dot={false} />
            <Line type="monotone" dataKey="attacks" name="attack flows (replay labels)" stroke="#f43f5e" dot={false} />
          </LineChart>
        </ResponsiveContainer>
      </div>
      <p className="mt-2 text-xs text-slate-300">{n(f.windows_seen)} windows computed. Rule alerts by rule: {Object.entries(f.alerts_by_rule).map(([k, v]) => `${k} ${n(v)}`).join(" · ") || "none yet"}.
        {f.alert_attack_share !== null && <> Among the flows inside alerted windows, <b className="text-white">{(f.alert_attack_share * 100).toFixed(1)} %</b> are attacks according to the replay labels (the rules never read the labels).</>}</p>
      {f.alerts.length > 0 && (
        <div className="mt-2 max-h-48 overflow-auto">
          <table className="w-full text-left text-xs"><thead className="text-slate-500"><tr><th className="py-1">Window end</th><th>Rule</th><th>Port</th><th>Flows</th><th>Attack flows</th><th>Mean duration (ms)</th></tr></thead>
            <tbody>{f.alerts.slice(0, 12).map((a, i) => <tr key={i} className="border-t border-line text-slate-200"><td className="py-1 font-mono">{a.window_start.slice(11, 19)}</td><td>{a.rule}</td><td className="font-mono">{a.dst_port}</td><td className="font-mono">{n(a.flows)}</td><td className="font-mono">{n(a.attack_flows)}</td><td className="font-mono">{a.avg_duration_us !== null ? (a.avg_duration_us / 1000).toFixed(1) : "—"}</td></tr>)}</tbody></table>
        </div>
      )}
    </Card>
  );
}

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

          <StressCard />

          {data.flink && <FlinkCard f={data.flink} />}

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
