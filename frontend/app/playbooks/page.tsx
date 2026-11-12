"use client";

import { GitBranch, History, Info } from "lucide-react";
import Link from "next/link";
import { useEffect, useState } from "react";
import { PlaybookGraph } from "@/components/playbook-graph";
import { Badge, Card, CardHeader, Empty, JsonBlock, KV, PageHeader, Skeleton, StatusBadge } from "@/components/ui";
import { useApi } from "@/hooks/useApi";
import { api, fmtMs, fmtTime } from "@/lib/api";
import { cn } from "@/lib/utils";

export default function PlaybooksPage() {
  const { data: pbs } = useApi<any[]>("soar/playbooks", 6000);
  const { data: runs } = useApi<any[]>("soar/runs?limit=40", 3000);
  const [runId, setRunId] = useState<number | null>(null);
  const [node, setNode] = useState<string | null>(null);
  const [detail, setDetail] = useState<any | null>(null);
  const run = runs?.find((r) => r.run_id === runId) ?? runs?.[0];

  useEffect(() => {
    if (!run) return;
    api<any[]>(`incidents/${encodeURIComponent(run.incident_id)}/soar`).then((rs) => setDetail(rs.find((r) => r.run_id === run.run_id) ?? null)).catch(() => setDetail(null));
  }, [run?.run_id, run?.status, runs]); // eslint-disable-line react-hooks/exhaustive-deps

  const pb = pbs?.[0];
  const states = Object.fromEntries((detail?.tasks ?? run?.tasks ?? []).map((t: any) => [t.node_id, t]));
  const nodeSpec = pb?.nodes.find((n: any) => n.id === node);
  const task = detail?.tasks.find((t: any) => t.node_id === node);

  return (
    <div>
      <PageHeader kicker="SOAR Playbook Visualizer" title={pb?.name ?? "Playbooks"} description={pb?.description} right={pb && <Badge color="#22d3ee">{pb.engine} · {pb.id} v{pb.version}</Badge>} />
      <div className="grid gap-5 xl:grid-cols-[1fr_380px]">
        <Card>
          <CardHeader title="Execution graph" subtitle={run ? `Overlay: run #${run.run_id} for ${run.incident_id} (${run.status})` : "Static definition"} icon={<GitBranch className="h-4 w-4" />} right={
            <div className="flex gap-3 text-[10.5px] text-slate-400">
              <span>— dependency</span><span>- - conditional</span>
            </div>
          } />
          {pb ? <PlaybookGraph nodes={pb.nodes} states={states} selected={node} onSelect={setNode} height={700} /> : <Skeleton className="h-[620px]" />}
        </Card>
        <div className="space-y-5">
          <Card>
            <CardHeader title={nodeSpec ? nodeSpec.name : "Node details"} subtitle={nodeSpec ? `handler: ${nodeSpec.handler}` : "Click a node in the graph"} icon={<Info className="h-4 w-4" />} />
            {nodeSpec ? (
              <div>
                <KV k="Stage" v={nodeSpec.stage} />
                <KV k="Depends on" v={nodeSpec.depends_on.join(", ") || "—"} mono />
                <KV k="Condition" v={nodeSpec.when ?? "always"} mono />
                <KV k="Retry" v={`${nodeSpec.retry.max_attempts} attempt(s), backoff ${nodeSpec.retry.backoff_seconds}s`} />
                <KV k="Timeout" v={`${nodeSpec.timeout}s`} />
                <KV k="On failure" v={nodeSpec.on_failure} />
                <KV k="Milestone" v={nodeSpec.milestone ?? "—"} mono />
                <KV k="Avg duration" v={fmtMs(pb.node_stats[nodeSpec.id]?.avg_ms)} />
                <KV k="Executions" v={Object.entries(pb.node_stats[nodeSpec.id]?.by_status ?? {}).map(([s, n]) => `${s}: ${n}`).join(" · ") || "—"} />
                {task && (
                  <div className="mt-3">
                    <div className="label mb-1.5">Logs (run #{run?.run_id})</div>
                    <div className="max-h-48 space-y-0.5 overflow-auto rounded-lg border border-line bg-ink-950 p-2 font-mono text-[10.5px]">
                      {(task.logs ?? []).map((l: any, i: number) => <div key={i} className={l.level === "error" ? "text-rose-300" : l.level === "warning" ? "text-amber-200" : "text-slate-300"}>{l.message}</div>)}
                      {!task.logs?.length && <div className="text-slate-500">no logs</div>}
                    </div>
                    <div className="label mb-1.5 mt-3">Output</div>
                    <JsonBlock value={task.output} max="max-h-52" />
                  </div>
                )}
              </div>
            ) : <Empty title="No node selected" />}
          </Card>
          <Card>
            <CardHeader title="Recent executions" subtitle={pb ? Object.entries(pb.executions).map(([s, n]) => `${s}: ${n}`).join(" · ") : ""} icon={<History className="h-4 w-4" />} />
            {!runs ? <Skeleton className="h-40" /> : runs.length === 0 ? <Empty title="No executions yet" /> : (
              <div className="max-h-[360px] space-y-1.5 overflow-auto">
                {runs.map((r) => (
                  <button key={r.run_id} onClick={() => setRunId(r.run_id)} className={cn("flex w-full items-center justify-between gap-2 rounded-lg border px-3 py-2 text-left text-xs", run?.run_id === r.run_id ? "border-cyan-400/40 bg-ink-700/60" : "border-line bg-ink-900/50 hover:border-cyan-400/20")}>
                    <div>
                      <div className="font-mono text-slate-200">#{r.run_id} · {r.incident_id}</div>
                      <div className="text-[10.5px] text-slate-500">{fmtTime(r.started_at, true)} · {fmtMs(r.duration_ms)}</div>
                    </div>
                    <StatusBadge status={r.status} />
                  </button>
                ))}
              </div>
            )}
            {run && <Link href={`/incidents/${run.incident_id}`} className="mt-3 block text-xs text-cyan-300 hover:underline">Open investigation →</Link>}
          </Card>
        </div>
      </div>
    </div>
  );
}
