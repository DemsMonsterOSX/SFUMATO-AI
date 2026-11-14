"use client";

import { Cloud, Database, Gauge, HardDrive, Layers } from "lucide-react";
import { Bar, BarChart, CartesianGrid, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { Badge, Card, CardHeader, Empty, ErrorNote, KV, PageHeader, Skeleton, Stat } from "@/components/ui";
import { useApi } from "@/hooks/useApi";

const tooltipStyle = { background: "#08102a", border: "1px solid rgba(148,178,255,0.15)", borderRadius: 12, fontSize: 12 };

type Stage = { id: string; phase: string; title: string; tech: string; what: string };
type Metrics = { auc_roc: number; auc_pr: number; precision: number; recall: number; f1: number; test_rows: number; confusion: { tp: number; fp: number; fn: number; tn: number } };
type Overview = {
  dataset: { name: string; size_gb: number; files: number; source: string; domain: string };
  stages: Stage[];
  results_published: boolean;
  results: null | {
    raw_rows: number; clean_rows: number; dropped_rows: number; total_seconds: number; prep_seconds: number;
    eda: { label_counts: Record<string, number>; per_day: { day: string; flows: number; attacks: number }[]; attacks_by_hour: Record<string, number> };
    ml?: { features: number; random_split?: Metrics; time_holdout?: Metrics & { cutoff_day: string }; feature_importances: { feature: string; importance: number }[] };
  };
};

const n = (v: number) => v.toLocaleString("en-US");

function MetricsTable({ rows }: { rows: { name: string; m: Metrics }[] }) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-left text-xs">
        <thead className="text-slate-400">
          <tr>{["Evaluation", "AUC-ROC", "AUC-PR", "Precision", "Recall", "F1", "Test rows", "TP / FP / FN / TN"].map((h) => <th key={h} className="px-2 py-2 font-medium">{h}</th>)}</tr>
        </thead>
        <tbody>
          {rows.map(({ name, m }) => (
            <tr key={name} className="border-t border-line text-slate-200">
              <td className="px-2 py-2">{name}</td>
              {[m.auc_roc, m.auc_pr, m.precision, m.recall, m.f1].map((v, i) => <td key={i} className="px-2 py-2 font-mono">{v.toFixed(4)}</td>)}
              <td className="px-2 py-2 font-mono">{n(m.test_rows)}</td>
              <td className="px-2 py-2 font-mono">{n(m.confusion.tp)} / {n(m.confusion.fp)} / {n(m.confusion.fn)} / {n(m.confusion.tn)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export default function BigDataPage() {
  const { data, error } = useApi<Overview>("bigdata/overview");
  const r = data?.results;
  const labels = r ? Object.entries(r.eda.label_counts).map(([name, count]) => ({ name, count })).sort((a, b) => b.count - a.count) : [];
  const hours = r ? Array.from({ length: 24 }, (_, h) => ({ hour: h, attacks: r.eda.attacks_by_hour[String(h)] ?? 0 })) : [];
  const metricRows = r?.ml ? [
    ...(r.ml.random_split ? [{ name: "Random 80/20 split", m: r.ml.random_split }] : []),
    ...(r.ml.time_holdout ? [{ name: `Time hold-out (from ${r.ml.time_holdout.cutoff_day})`, m: r.ml.time_holdout }] : []),
  ] : [];

  return (
    <div>
      <PageHeader kicker="Big Data Lab" title="Intrusion detection at 6.9 GB" description="The batch pipeline behind the course project: acquisition, Spark cleaning, SQL analytics and machine learning on real labelled network flows. Figures come from the Spark job's output; until it has been published, this page shows the pipeline only." />
      <ErrorNote error={error} />
      <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
        <Stat label="Dataset" value={<span className="text-2xl">{data ? `${data.dataset.size_gb} GB` : "—"}</span>} sub={data ? `${data.dataset.files} CSV files` : ""} icon={<HardDrive className="h-4 w-4" />} />
        <Stat label="Raw flows" value={r ? n(r.raw_rows) : "—"} sub={r ? `${n(r.clean_rows)} after cleaning` : "not published yet"} accent="#34d399" icon={<Database className="h-4 w-4" />} />
        <Stat label="Dropped (quality)" value={r ? n(r.dropped_rows) : "—"} sub="headers, NaN, Infinity, negative durations" accent="#fbbf24" icon={<Layers className="h-4 w-4" />} />
        <Stat label="Spark run" value={r ? `${Math.round(r.total_seconds / 60)} min` : "—"} sub="Dataproc Serverless" accent="#a78bfa" icon={<Cloud className="h-4 w-4" />} />
      </div>

      <Card className="mt-5">
        <CardHeader title="Pipeline" subtitle={data ? `${data.dataset.name} · ${data.dataset.source}` : ""} icon={<Layers className="h-4 w-4" />} />
        {data ? (
          <ol className="grid gap-3 md:grid-cols-5">
            {data.stages.map((s) => (
              <li key={s.id} className="rounded-xl border border-line bg-ink-900/50 p-3 text-xs">
                <Badge color="#22d3ee">{s.phase}</Badge>
                <div className="mt-2 text-sm font-semibold text-white">{s.title}</div>
                <div className="mt-0.5 text-cyan-300">{s.tech}</div>
                <p className="mt-2 leading-relaxed text-slate-400">{s.what}</p>
              </li>
            ))}
          </ol>
        ) : <Skeleton className="h-32" />}
      </Card>

      {data && !data.results_published && (
        <div className="mt-5">
          <Empty title="Spark results not published yet" icon={<Gauge className="h-5 w-5" />}>
            Run <span className="font-mono">scripts\gcp_bigdata.ps1 run</span> then <span className="font-mono">report</span>, and copy the results to <span className="font-mono">ml/bigdata/results.json</span>. No number is shown before that.
          </Empty>
        </div>
      )}

      {r && (
        <>
          <div className="mt-5 grid gap-5 xl:grid-cols-2">
            <Card>
              <CardHeader title="Traffic classes (log scale)" />
              <div className="h-[280px]">
                <ResponsiveContainer>
                  <BarChart data={labels} layout="vertical" margin={{ left: 40 }}>
                    <CartesianGrid stroke="rgba(148,178,255,0.06)" horizontal={false} />
                    <XAxis type="number" scale="log" domain={[1, "auto"]} tick={{ fill: "#64748b", fontSize: 11 }} axisLine={false} tickLine={false} />
                    <YAxis type="category" dataKey="name" width={150} tick={{ fill: "#94a3b8", fontSize: 11 }} axisLine={false} tickLine={false} />
                    <Tooltip contentStyle={tooltipStyle} />
                    <Bar dataKey="count" radius={[0, 6, 6, 0]}>{labels.map((l) => <Cell key={l.name} fill={l.name === "Benign" ? "#3b82f6" : "#f43f5e"} />)}</Bar>
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </Card>
            <Card>
              <CardHeader title="Flows and attacks per day" />
              <div className="h-[280px]">
                <ResponsiveContainer>
                  <BarChart data={r.eda.per_day} margin={{ left: -10 }}>
                    <CartesianGrid stroke="rgba(148,178,255,0.06)" vertical={false} />
                    <XAxis dataKey="day" tick={{ fill: "#94a3b8", fontSize: 10 }} axisLine={false} tickLine={false} />
                    <YAxis tick={{ fill: "#64748b", fontSize: 11 }} axisLine={false} tickLine={false} />
                    <Tooltip contentStyle={tooltipStyle} />
                    <Bar dataKey="flows" fill="#3b82f6" radius={[4, 4, 0, 0]} />
                    <Bar dataKey="attacks" fill="#f43f5e" radius={[4, 4, 0, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </Card>
          </div>
          <div className="mt-5 grid gap-5 xl:grid-cols-2">
            <Card>
              <CardHeader title="Malicious flows by hour" />
              <div className="h-[240px]">
                <ResponsiveContainer>
                  <BarChart data={hours} margin={{ left: -10 }}>
                    <CartesianGrid stroke="rgba(148,178,255,0.06)" vertical={false} />
                    <XAxis dataKey="hour" tick={{ fill: "#94a3b8", fontSize: 10 }} axisLine={false} tickLine={false} />
                    <YAxis tick={{ fill: "#64748b", fontSize: 11 }} axisLine={false} tickLine={false} />
                    <Tooltip contentStyle={tooltipStyle} />
                    <Bar dataKey="attacks" fill="#f43f5e" radius={[4, 4, 0, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </Card>
            <Card>
              <CardHeader title="Top feature importances" subtitle={r.ml ? `${r.ml.features} features` : undefined} />
              {r.ml ? (
                <div className="h-[240px]">
                  <ResponsiveContainer>
                    <BarChart data={r.ml.feature_importances.slice(0, 10)} layout="vertical" margin={{ left: 60 }}>
                      <XAxis type="number" tick={{ fill: "#64748b", fontSize: 11 }} axisLine={false} tickLine={false} />
                      <YAxis type="category" dataKey="feature" width={150} tick={{ fill: "#94a3b8", fontSize: 10 }} axisLine={false} tickLine={false} />
                      <Tooltip contentStyle={tooltipStyle} />
                      <Bar dataKey="importance" fill="#34d399" radius={[0, 6, 6, 0]} />
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              ) : <Empty title="ML step not run" />}
            </Card>
          </div>
          {metricRows.length > 0 && (
            <Card className="mt-5">
              <CardHeader title="Random Forest: attack vs benign" subtitle="Imbalanced classes: read AUC-PR, precision and recall, not accuracy" />
              <MetricsTable rows={metricRows} />
            </Card>
          )}
        </>
      )}

      {data && (
        <Card className="mt-5">
          <CardHeader title="Dataset" />
          <KV k="Name" v={data.dataset.name} />
          <KV k="Domain" v={data.dataset.domain} />
          <KV k="Source" v={data.dataset.source} />
        </Card>
      )}
    </div>
  );
}
