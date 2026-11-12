"use client";

import { Background, Controls, Handle, MarkerType, Node, NodeProps, Position, ReactFlow, Edge } from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { CheckCircle2, CircleDashed, CircleSlash, Loader2, RotateCw, XCircle } from "lucide-react";
import { useMemo } from "react";
import { useStableFlowNodes } from "@/hooks/useStableFlowNodes";
import { fmtMs } from "@/lib/api";

export type PbNode = { id: string; name: string; stage: number; depends_on: string[]; when?: string | null; on_failure: string; milestone?: string | null };
export type TaskState = { status: string; duration_ms?: number | null; attempts?: number };

const COLORS: Record<string, string> = {
  pending: "#475569", running: "#22d3ee", completed: "#34d399", failed: "#fb7185", skipped: "#64748b", retrying: "#fb923c", cancelled: "#64748b",
};

function StatusIcon({ status }: { status: string }) {
  const cls = "h-3.5 w-3.5";
  if (status === "running") return <Loader2 className={`${cls} animate-spin`} />;
  if (status === "completed") return <CheckCircle2 className={cls} />;
  if (status === "failed") return <XCircle className={cls} />;
  if (status === "skipped" || status === "cancelled") return <CircleSlash className={cls} />;
  if (status === "retrying") return <RotateCw className={`${cls} animate-spin`} />;
  return <CircleDashed className={cls} />;
}

type Data = { node: PbNode; state?: TaskState; selected?: boolean; reverse?: boolean };

function TaskNode({ data }: NodeProps<Node<Data>>) {
  const status = data.state?.status ?? "pending";
  const c = COLORS[status] ?? "#475569";
  return (
    <div
      className="w-[200px] rounded-xl border bg-ink-850/95 px-3 py-2.5 text-left shadow-card backdrop-blur"
      style={{ borderColor: data.selected ? "#22d3ee" : `${c}55`, boxShadow: status === "running" ? `0 0 24px -4px ${c}` : undefined }}
    >
      <Handle type="target" position={data.reverse ? Position.Right : Position.Left} className="!h-2 !w-2 !border-0 !bg-slate-500" />
      <div className="flex items-center justify-between gap-2">
        <span className="font-mono text-[10px] text-slate-500">#{data.node.stage}</span>
        <span className="flex items-center gap-1 text-[10px] font-medium" style={{ color: c }}>
          <StatusIcon status={status} />
          {status}
        </span>
      </div>
      <div className="mt-1 text-[12.5px] font-medium leading-snug text-slate-100">{data.node.name}</div>
      <div className="mt-1 flex items-center justify-between text-[10px] text-slate-500">
        <span>{data.node.when ? `if ${data.node.when}` : data.node.on_failure === "continue" ? "continue on failure" : ""}</span>
        <span className="tabular-nums text-slate-400">{data.state?.duration_ms != null ? fmtMs(data.state.duration_ms) : ""}</span>
      </div>
      <Handle type="source" position={data.reverse ? Position.Left : Position.Right} className="!h-2 !w-2 !border-0 !bg-slate-500" />
    </div>
  );
}

const PER_ROW = 4;

const nodeTypes = { task: TaskNode };

export function PlaybookGraph({ nodes, states, selected, onSelect, height = 520 }: { nodes: PbNode[]; states?: Record<string, TaskState>; selected?: string | null; onSelect?: (id: string) => void; height?: number }) {
  const { rfNodes, rfEdges } = useMemo(() => {
    const byId = Object.fromEntries(nodes.map((n) => [n.id, n]));
    const depth: Record<string, number> = {};
    const d = (id: string): number => {
      if (depth[id] !== undefined) return depth[id];
      const deps = byId[id]?.depends_on ?? [];
      depth[id] = deps.length ? Math.max(...deps.map(d)) + 1 : 0;
      return depth[id];
    };
    nodes.forEach((n) => d(n.id));
    const cols: Record<number, PbNode[]> = {};
    nodes.forEach((n) => (cols[depth[n.id]] ||= []).push(n));
    // Snake layout: PER_ROW dependency levels per row, alternating direction, so long playbooks stay readable.
    // Row heights fit the tallest stack of parallel nodes in that row.
    const rowStack: number[] = [];
    Object.entries(cols).forEach(([c, list]) => {
      const r = Math.floor(Number(c) / PER_ROW);
      rowStack[r] = Math.max(rowStack[r] ?? 1, list.length);
    });
    const rowY: number[] = [];
    rowStack.forEach((n, r) => (rowY[r] = r === 0 ? 0 : rowY[r - 1] + (rowStack[r - 1] * 105) / 2 + (n * 105) / 2 + 60));
    const rfNodes: Node<Data>[] = [];
    Object.entries(cols).forEach(([colStr, list]) => {
      const col = Number(colStr);
      const row = Math.floor(col / PER_ROW);
      const reverse = row % 2 === 1;
      const pos = reverse ? PER_ROW - 1 - (col % PER_ROW) : col % PER_ROW;
      list.sort((a, b) => a.stage - b.stage);
      list.forEach((n, i) => {
        rfNodes.push({
          id: n.id,
          type: "task",
          position: { x: pos * 250, y: rowY[row] + (i - (list.length - 1) / 2) * 105 },
          data: { node: n, state: states?.[n.id], selected: selected === n.id, reverse },
        });
      });
    });
    const rfEdges: Edge[] = nodes.flatMap((n) =>
      n.depends_on.map((dep) => {
        const st = states?.[n.id]?.status;
        const c = st ? COLORS[st] : "#334155";
        return {
          id: `${dep}->${n.id}`,
          source: dep,
          target: n.id,
          type: "smoothstep",
          animated: st === "running",
          style: { stroke: c, strokeWidth: 1.5, opacity: st === "skipped" ? 0.4 : 0.9, strokeDasharray: n.when ? "5 4" : undefined },
          markerEnd: { type: MarkerType.ArrowClosed, color: c, width: 16, height: 16 },
        };
      }),
    );
    return { rfNodes, rfEdges };
  }, [nodes, states, selected]);

  const { nodes: flowNodes, onNodesChange } = useStableFlowNodes<Data>(rfNodes);
  return (
    <div style={{ height }} className="grid-bg overflow-hidden rounded-xl border border-line bg-ink-950/60">
      <ReactFlow
        nodes={flowNodes}
        edges={rfEdges}
        onNodesChange={onNodesChange}
        nodeTypes={nodeTypes}
        fitView
        fitViewOptions={{ padding: 0.15 }}
        nodesDraggable={false}
        nodesConnectable={false}
        proOptions={{ hideAttribution: true }}
        onNodeClick={(_, n) => onSelect?.(n.id)}
        minZoom={0.2}
      >
        <Background color="rgba(148,178,255,0.08)" gap={24} />
        <Controls showInteractive={false} />
      </ReactFlow>
    </div>
  );
}
