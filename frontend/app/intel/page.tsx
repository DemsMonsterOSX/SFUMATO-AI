"use client";

import { Background, Controls, Edge, Handle, MarkerType, Node, NodeProps, Position, ReactFlow } from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { Bug, Crosshair, Fingerprint, Radar, Search, ShieldAlert, Users } from "lucide-react";
import Link from "next/link";
import { useMemo, useState } from "react";
import { useStableFlowNodes } from "@/hooks/useStableFlowNodes";
import { Badge, Card, CardHeader, CtiVerdictBadge, Dot, Empty, KV, OriginBadge, PageHeader, Skeleton } from "@/components/ui";
import { useApi } from "@/hooks/useApi";
import { fmtMs, fmtTime } from "@/lib/api";
import { CTI_VERDICT_COLORS, cn } from "@/lib/utils";

const KIND: Record<string, { color: string; icon: any }> = {
  incident: { color: "#60a5fa", icon: ShieldAlert },
  indicator: { color: "#22d3ee", icon: Fingerprint },
  malware: { color: "#fb7185", icon: Bug },
  threat_actor: { color: "#f472b6", icon: Users },
  "intrusion-set": { color: "#f472b6", icon: Users },
  attack_pattern: { color: "#a78bfa", icon: Crosshair },
  "attack-pattern": { color: "#a78bfa", icon: Crosshair },
};

function GNode({ data }: NodeProps<Node<{ label: string; kind: string }>>) {
  const k = KIND[data.kind] ?? { color: "#94a3b8", icon: Radar };
  const Icon = k.icon;
  return (
    <div className="flex max-w-[210px] items-center gap-2 rounded-xl border bg-ink-850/95 px-2.5 py-1.5 text-[11px] text-slate-100 shadow-card" style={{ borderColor: `${k.color}66` }}>
      <Handle type="target" position={Position.Left} className="!h-1.5 !w-1.5 !border-0 !bg-slate-600" />
      <Icon className="h-3.5 w-3.5 shrink-0" style={{ color: k.color }} />
      <span className="truncate">{data.label}</span>
      <Handle type="source" position={Position.Right} className="!h-1.5 !w-1.5 !border-0 !bg-slate-600" />
    </div>
  );
}

const NODE_TYPES = { g: GNode };

function Graph({ graph }: { graph: { nodes: any[]; edges: any[] } }) {
  const { nodes, edges } = useMemo(() => {
    const cols: Record<string, number> = { incident: 0, indicator: 1 };
    const groups: Record<number, any[]> = {};
    graph.nodes.forEach((n) => (groups[cols[n.kind] ?? 2] ||= []).push(n));
    const nodes: Node<{ label: string; kind: string }>[] = [];
    Object.entries(groups).forEach(([c, list]) =>
      list.forEach((n, i) => nodes.push({ id: n.id, type: "g", position: { x: Number(c) * 300, y: (i - (list.length - 1) / 2) * 56 }, data: { label: n.label, kind: n.kind } })),
    );
    const edges: Edge[] = graph.edges.map((e, i) => ({
      id: `e${i}`, source: e.source, target: e.target, label: e.label,
      labelStyle: { fill: "#64748b", fontSize: 9 }, labelBgStyle: { fill: "#060b1a" },
      style: { stroke: "rgba(148,178,255,0.35)" }, markerEnd: { type: MarkerType.ArrowClosed, color: "rgba(148,178,255,0.5)" },
    }));
    return { nodes, edges };
  }, [graph]);
  const { nodes: flowNodes, onNodesChange } = useStableFlowNodes(nodes);
  if (!graph.nodes.length) return <Empty title="No relationships yet">The graph only shows relationships actually returned by providers (malware, actors, ATT&CK, OpenCTI relations).</Empty>;
  return (
    <div className="grid-bg h-[520px] overflow-hidden rounded-xl border border-line bg-ink-950/60">
      <ReactFlow nodes={flowNodes} edges={edges} onNodesChange={onNodesChange} nodeTypes={NODE_TYPES} fitView nodesConnectable={false} proOptions={{ hideAttribution: true }} minZoom={0.2}>
        <Background color="rgba(148,178,255,0.08)" gap={24} />
        <Controls showInteractive={false} />
      </ReactFlow>
    </div>
  );
}

export default function IntelPage() {
  const { data: status } = useApi<any>("cti/status", 10000);
  const { data: inds } = useApi<any[]>("cti/indicators", 8000);
  const [incident, setIncident] = useState("");
  const { data: graph } = useApi<any>(`cti/graph${incident ? `?incident_id=${encodeURIComponent(incident)}` : ""}`, 15000);
  const [q, setQ] = useState("");
  const [sel, setSel] = useState<string | null>(null);
  const filtered = (inds ?? []).filter((i) => !q || i.indicator.includes(q.toLowerCase()) || i.malware.join(" ").toLowerCase().includes(q.toLowerCase()));
  const current = filtered.find((i) => i.indicator === sel) ?? filtered[0];
  const incidents = Array.from(new Set((inds ?? []).flatMap((i) => i.incidents))).sort();

  return (
    <div>
      <PageHeader kicker="Threat Intelligence Explorer" title="What the intelligence actually says" description={status?.privacy} />
      <div className="grid gap-4 md:grid-cols-3 xl:grid-cols-5">
        {(status?.providers ?? []).map((p: any, i: number) => (
          <Card key={p.key} delay={i * 0.04} className="p-4">
            <div className="flex items-center justify-between">
              <span className="text-sm font-medium text-slate-100">{p.name}</span>
              <Dot ok={p.configured} warn={!p.configured} />
            </div>
            <div className="mt-1 text-[11px] text-slate-500">{p.self_hosted ? "self-hosted" : "public"} · {p.supports.join(", ")}</div>
            <div className="mt-3 grid grid-cols-3 gap-1 text-center text-[11px]">
              <div><div className="text-base font-semibold text-white">{p.health.queries}</div><div className="text-slate-500">queries</div></div>
              <div><div className="text-base font-semibold text-emerald-300">{p.health.ok}</div><div className="text-slate-500">ok</div></div>
              <div><div className="text-base font-semibold text-rose-300">{p.health.errors}</div><div className="text-slate-500">errors</div></div>
            </div>
            <div className="mt-2 flex flex-wrap gap-1">{Object.entries(p.health.by_origin).map(([o, n]: any) => <OriginBadge key={o} origin={o} />)}</div>
            <div className="mt-2 text-[10.5px] text-slate-500">{p.configured ? `avg ${fmtMs(p.health.avg_latency_ms)} · last ${fmtTime(p.health.last_query)}` : p.hint}</div>
          </Card>
        ))}
        {!status && <Skeleton className="col-span-5 h-36" />}
      </div>

      <div className="mt-5 grid gap-5 xl:grid-cols-[1.4fr_1fr]">
        <Card>
          <CardHeader title="Queried indicators" subtitle={`${inds?.length ?? 0} unique indicators across all investigations`} icon={<Fingerprint className="h-4 w-4" />} right={
            <div className="flex items-center gap-2 rounded-xl border border-line bg-ink-950/60 px-2.5 py-1.5"><Search className="h-3.5 w-3.5 text-slate-500" /><input value={q} onChange={(e) => setQ(e.target.value)} placeholder="filter" className="w-28 bg-transparent text-xs outline-none" /></div>
          } />
          {!inds ? <Skeleton className="h-72" /> : filtered.length === 0 ? <Empty title="No CTI queries yet" /> : (
            <div className="max-h-[560px] overflow-auto">
              <table className="w-full text-sm">
                <thead className="sticky top-0 bg-ink-850"><tr className="label text-left"><th className="pb-2">Indicator</th><th className="pb-2">Reputation</th><th className="pb-2">Providers</th><th className="pb-2">Malware</th><th className="pb-2">Origin</th></tr></thead>
                <tbody>
                  {filtered.map((i) => (
                    <tr key={i.type + i.indicator} onClick={() => setSel(i.indicator)} className={cn("cursor-pointer border-t border-line/60 hover:bg-ink-800/50", current?.indicator === i.indicator && "bg-ink-800/70")}>
                      <td className="max-w-[260px] py-2 pr-3"><div className="truncate font-mono text-xs text-slate-100" title={i.indicator}>{i.indicator}</div><div className="text-[10.5px] text-slate-500">{i.type}</div></td>
                      <td className="pr-3"><CtiVerdictBadge verdict={i.verdict} /></td>
                      <td className="pr-3"><div className="flex gap-1">{Object.entries(i.providers).map(([p, r]: any) => <span key={p} title={`${p}: ${r.verdict}`} className="h-2.5 w-2.5 rounded-full" style={{ background: CTI_VERDICT_COLORS[r.verdict] }} />)}</div></td>
                      <td className="max-w-[160px] truncate pr-3 text-xs text-slate-400">{i.malware.join(", ") || "—"}</td>
                      <td>{i.origins.map((o: string) => <OriginBadge key={o} origin={o} />)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>
        <Card>
          <CardHeader title={current ? current.indicator : "Indicator detail"} subtitle={current ? `${current.type} · seen in ${current.incidents.length} incident(s)` : ""} icon={<Radar className="h-4 w-4" />} />
          {current ? (
            <div className="space-y-4">
              <div className="flex flex-wrap gap-1.5">{current.incidents.map((iid: string) => <Link key={iid} href={`/incidents/${iid}`}><Badge color="#60a5fa">{iid}</Badge></Link>)}</div>
              <div className="space-y-2">
                {Object.entries(current.providers).map(([p, r]: any) => (
                  <div key={p} className="rounded-xl border border-line bg-ink-900/60 p-3">
                    <div className="flex items-center justify-between"><span className="text-sm font-medium text-slate-100">{p}</span><div className="flex gap-1.5"><CtiVerdictBadge verdict={r.verdict} /><OriginBadge origin={r.data_origin} /></div></div>
                    <div className="mt-1.5 grid grid-cols-2 gap-x-4 text-[11px] text-slate-400">
                      <span>Status: <b className="text-slate-200">{r.status}</b></span>
                      <span>Confidence: <b className="text-slate-200">{r.confidence ?? "—"}</b></span>
                      <span>First seen: <b className="text-slate-200">{r.first_seen ?? "—"}</b></span>
                      <span>Last seen: <b className="text-slate-200">{r.last_seen ?? "—"}</b></span>
                      <span>Queried: <b className="text-slate-200">{fmtTime(r.queried_at, true)}</b></span>
                      <span>Latency: <b className="text-slate-200">{fmtMs(r.duration_ms)}</b></span>
                    </div>
                    {r.error && <div className="mt-1 text-[11px] text-rose-300">{r.error}</div>}
                    {r.references.map((ref: string) => <a key={ref} href={ref} target="_blank" rel="noreferrer" className="mt-1 block truncate text-[11px] text-cyan-300 hover:underline">{ref}</a>)}
                  </div>
                ))}
              </div>
              <KV k="Malware" v={current.malware.join(", ") || "—"} />
              <KV k="Threat actors" v={current.threat_actors.join(", ") || "—"} />
              <KV k="ATT&CK" v={current.mitre.map((m: any) => `${m.id} ${m.name}`).join(" · ") || "—"} />
              <KV k="Tags" v={current.tags.slice(0, 10).join(", ") || "—"} />
            </div>
          ) : <Empty title="Select an indicator" />}
        </Card>
      </div>

      <Card className="mt-5">
        <CardHeader title="Relationship graph" subtitle="Incidents → indicators → malware / actors / techniques, built only from provider responses" icon={<Users className="h-4 w-4" />} right={
          <select value={incident} onChange={(e) => setIncident(e.target.value)} className="rounded-lg border border-line bg-ink-900 px-2 py-1 text-xs text-slate-200">
            <option value="">All incidents</option>
            {incidents.map((i) => <option key={i} value={i}>{i}</option>)}
          </select>
        } />
        {graph ? <Graph graph={graph} /> : <Skeleton className="h-[520px]" />}
      </Card>
    </div>
  );
}
