"use client";

import { Gauge } from "lucide-react";
import { Bar, BarChart, CartesianGrid, Legend, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { Badge, Card, CardHeader, Empty, ErrorNote, PageHeader, Skeleton, Stat } from "@/components/ui";
import { useApi } from "@/hooks/useApi";

const tooltipStyle = { background: "#08102a", border: "1px solid rgba(148,178,255,0.15)", borderRadius: 12, fontSize: 12 };
const COLORS = ["#22d3ee", "#a78bfa", "#34d399", "#fbbf24"];
const n = (v: number) => v.toLocaleString("en-US");

type SparkRun = { executors: number; vcpu: number; state: string; prep_seconds: number | null; batch_wall_seconds: number };
type KafkaStep = { target: number; produced_per_s: number; consumed_per_s: number; lag_end: number; kept_up: boolean; producer_limited: boolean };
type Kafka = { label: string; steps: KafkaStep[]; max_kept_up_per_s: number; ceiling: string; step_seconds: number };
type Level = { connections: number; rps: number; p50_ms: number | null; p95_ms: number | null; p99_ms?: number | null; errors: number; rate_limited: number };
type ApiRun = { endpoint: string; levels: Level[]; best_clean_rps: number; measured_at: string };
type Data = { spark: { runs: SparkRun[]; input_gb: number } | null; kafka: Kafka[]; api: Record<string, { before?: ApiRun; after?: ApiRun; medium?: ApiRun }>; published: boolean };

export default function ScalabilityPage() {
  const { data, error } = useApi<Data>("bigdata/scalability");
  const spark = data?.spark?.runs?.filter((r) => r.prep_seconds != null) ?? [];
  const base = spark[0];
  const sparkRows = spark.map((r) => ({ name: `${r.executors} exec. (${r.vcpu} vCPU)`, prep: r.prep_seconds, speedup: base ? +((base.prep_seconds ?? 0) / (r.prep_seconds ?? 1)).toFixed(2) : 1, ideal: base ? +(r.executors / base.executors).toFixed(2) : 1 }));
  const kafka = data?.kafka ?? [];
  const targets = Array.from(new Set(kafka.flatMap((k) => k.steps.map((s) => s.target)))).sort((a, b) => a - b);
  const kafkaRows = targets.map((t) => {
    const row: Record<string, number | null> = { target: t };
    kafka.forEach((k) => { row[k.label] = k.steps.find((s) => s.target === t)?.consumed_per_s ?? null; });
    return row;
  });
  const apiEntries = Object.entries(data?.api ?? {});

  return (
    <div>
      <PageHeader kicker="Scalability" title="Scalability and stress tests" description="Measured, not assumed: how the batch job, the streaming scorers and the exposed API behave when resources or load change. Every figure comes from a test script in the repository (ml/scale). Limits are shown as found." />
      {!data && !error && <Skeleton className="h-40" />}
      <ErrorNote error={error} />
      {data && !data.published && <Empty title="No scalability results published yet" icon={<Gauge className="h-5 w-5" />}>Run the tests (scripts/gcp_spark_scale.ps1, gcp_scale.ps1, api_loadtest.py) and publish ml/scale/*.json.</Empty>}

      {spark.length > 0 && (
        <Card className="mb-5">
          <CardHeader title="Batch: Spark executors" subtitle={`Same preparation job on ${data?.spark?.input_gb} GB, fixed number of 4-vCPU executors (ML skipped)`} right={<Badge color="#22d3ee">Dataproc Serverless</Badge>} />
          <div className="grid gap-4 p-4 md:grid-cols-2">
            <div className="h-64"><ResponsiveContainer><BarChart data={sparkRows}><CartesianGrid strokeDasharray="3 3" stroke="rgba(148,178,255,0.1)" /><XAxis dataKey="name" tick={{ fill: "#94a3b8", fontSize: 11 }} /><YAxis tick={{ fill: "#94a3b8", fontSize: 11 }} unit=" s" /><Tooltip contentStyle={tooltipStyle} /><Bar dataKey="prep" name="Preparation time" fill="#22d3ee" radius={[6, 6, 0, 0]} /></BarChart></ResponsiveContainer></div>
            <div className="h-64"><ResponsiveContainer><LineChart data={sparkRows}><CartesianGrid strokeDasharray="3 3" stroke="rgba(148,178,255,0.1)" /><XAxis dataKey="name" tick={{ fill: "#94a3b8", fontSize: 11 }} /><YAxis tick={{ fill: "#94a3b8", fontSize: 11 }} unit="×" /><Tooltip contentStyle={tooltipStyle} /><Legend /><Line dataKey="speedup" name="Measured speed-up" stroke="#22d3ee" strokeWidth={2} /><Line dataKey="ideal" name="Ideal (linear)" stroke="#64748b" strokeDasharray="5 4" /></LineChart></ResponsiveContainer></div>
          </div>
        </Card>
      )}

      {kafka.length > 0 && (
        <Card className="mb-5">
          <CardHeader title="Streaming: scorers in the Kafka group" subtitle="Flows consumed per second as the target rate rises; producers run on a separate VM" right={<Badge color="#a78bfa">Kafka + scorers</Badge>} />
          <div className="grid gap-3 p-4 md:grid-cols-3">
            {kafka.map((k) => <Stat key={k.label} label={k.label} value={`${n(k.max_kept_up_per_s)}/s`} sub={`limit seen: ${k.ceiling}`} />)}
          </div>
          <div className="h-72 p-4"><ResponsiveContainer><LineChart data={kafkaRows}><CartesianGrid strokeDasharray="3 3" stroke="rgba(148,178,255,0.1)" /><XAxis dataKey="target" tick={{ fill: "#94a3b8", fontSize: 11 }} unit="/s" /><YAxis tick={{ fill: "#94a3b8", fontSize: 11 }} /><Tooltip contentStyle={tooltipStyle} /><Legend />{kafka.map((k, i) => <Line key={k.label} dataKey={k.label} stroke={COLORS[i % COLORS.length]} strokeWidth={2} connectNulls />)}</LineChart></ResponsiveContainer></div>
        </Card>
      )}

      {apiEntries.length > 0 && (
        <Card className="mb-5">
          <CardHeader title="Exposed API: concurrency steps" subtitle="From the Internet through HTTPS, the Next.js proxy and FastAPI on a 0.25-vCPU VM; e2-micro before and after a response cache, then e2-medium" right={<Badge color="#34d399">HTTP load test</Badge>} />
          <div className="overflow-x-auto p-4">
            <table className="w-full text-left text-xs text-slate-300">
              <thead className="text-slate-500"><tr><th className="py-1 pr-3">Endpoint</th><th className="pr-3">Connections</th><th className="pr-3">req/s before</th><th className="pr-3">p95 before</th><th className="pr-3">req/s + cache</th><th className="pr-3">p95 + cache</th><th className="pr-3">req/s e2-medium</th><th className="pr-3">p95 e2-medium</th></tr></thead>
              <tbody>
                {apiEntries.flatMap(([ep, v]) => {
                  const conns = Array.from(new Set([...(v.before?.levels ?? []), ...(v.after?.levels ?? []), ...(v.medium?.levels ?? [])].map((l) => l.connections))).sort((a, b) => a - b);
                  return conns.map((c, i) => {
                    const b = v.before?.levels.find((l) => l.connections === c), a = v.after?.levels.find((l) => l.connections === c), m = v.medium?.levels.find((l) => l.connections === c);
                    return (<tr key={ep + c} className="border-t border-line"><td className="py-1 pr-3 font-mono">{i === 0 ? ep : ""}</td><td className="pr-3">{c}</td><td className="pr-3">{b?.rps ?? "–"}</td><td className="pr-3">{b?.p95_ms != null ? `${b.p95_ms} ms` : "–"}</td><td className="pr-3">{a?.rps ?? "–"}</td><td className="pr-3">{a?.p95_ms != null ? `${a.p95_ms} ms` : "–"}</td><td className="pr-3">{m?.rps ?? "–"}</td><td className="pr-3">{m?.p95_ms != null ? `${m.p95_ms} ms` : "–"}</td></tr>);
                  });
                })}
              </tbody>
            </table>
          </div>
        </Card>
      )}
    </div>
  );
}
