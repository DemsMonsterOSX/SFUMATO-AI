"use client";

import { AnimatePresence, motion } from "framer-motion";
import { Bot, Brain, CheckCircle2, CircleSlash, FileJson, Fingerprint, Gavel, ListChecks, Loader2, Network, Radar, ShieldCheck, XCircle } from "lucide-react";
import { InvEvent } from "@/hooks/useInvestigationStream";
import { fmtMs } from "@/lib/api";
import { cn } from "@/lib/utils";

export const MILESTONES = [
  { key: "json_received", label: "JSON received", node: "receive_incident", icon: FileJson },
  { key: "incident_validated", label: "Incident validated", node: "validate_json", icon: ShieldCheck },
  { key: "indicators_extracted", label: "Indicators extracted", node: "extract_indicators", icon: Fingerprint },
  { key: "cti_queried", label: "CTI providers queried", node: "query_cti", icon: Radar },
  { key: "cti_evidence_received", label: "CTI evidence received", node: "correlate_cti", icon: Network },
  { key: "soar_correlation_completed", label: "SOAR correlation completed", node: "generate_features", icon: ListChecks },
  { key: "ml_classification_completed", label: "ML classification completed", node: "ml_inference", icon: Brain },
  { key: "ai_investigation_completed", label: "AI investigation completed", node: "validate_agent_output", icon: Bot },
  { key: "final_verdict_generated", label: "Final verdict generated", node: "compute_verdict", icon: Gavel },
  { key: "recommended_actions_available", label: "Recommended actions available", node: "generate_actions", icon: CheckCircle2 },
];

type StageState = { status: "pending" | "running" | "completed" | "skipped" | "failed"; duration?: number; detail?: string; ts?: string };

export function stageStates(events: InvEvent[]): Record<string, StageState> {
  const byNode: Record<string, StageState> = {};
  for (const ev of events) {
    const node = ev.stage ?? "";
    if (ev.type === "task") {
      const cur = byNode[node] ?? { status: "pending" };
      byNode[node] = {
        ...cur,
        status: (ev.status as StageState["status"]) === ("retrying" as any) ? "running" : ((ev.status as StageState["status"]) ?? cur.status),
        duration: ev.data?.duration_ms ?? cur.duration,
        ts: ev.ts,
      };
    } else if ((ev.type === "log" || ev.type === "cti_result") && byNode[node]) {
      byNode[node].detail = ev.message;
    }
  }
  return byNode;
}

export function Pipeline({ events, incidentStatus }: { events: InvEvent[]; incidentStatus?: string }) {
  const states = stageStates(events);
  const reached = new Set(events.filter((e) => e.type === "milestone").map((e) => e.stage));
  const failed = incidentStatus === "failed";
  return (
    <div className="relative">
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-5">
        {MILESTONES.map((m, i) => {
          const st = states[m.node];
          let status: StageState["status"] = st?.status ?? "pending";
          if (reached.has(m.key)) status = "completed";
          const Icon = m.icon;
          const color =
            status === "completed" ? "#34d399" : status === "running" ? "#22d3ee" : status === "failed" ? "#fb7185" : status === "skipped" ? "#64748b" : "#334155";
          return (
            <motion.div
              key={m.key}
              initial={{ opacity: 0, y: 6 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: i * 0.03 }}
              className={cn(
                "relative overflow-hidden rounded-xl border bg-ink-900/70 p-3 transition-colors duration-500",
                status === "running" && "shadow-glow",
              )}
              style={{ borderColor: `${color}55` }}
            >
              {status === "running" && <div className="pointer-events-none absolute inset-0 animate-scan bg-gradient-to-b from-transparent via-cyan-400/10 to-transparent" />}
              <div className="flex items-center justify-between">
                <span className="font-mono text-[10px] text-slate-500">{String(i + 1).padStart(2, "0")}</span>
                <AnimatePresence mode="wait">
                  <motion.span key={status} initial={{ scale: 0.5, opacity: 0 }} animate={{ scale: 1, opacity: 1 }} style={{ color }}>
                    {status === "completed" ? (
                      <CheckCircle2 className="h-4 w-4" />
                    ) : status === "running" ? (
                      <Loader2 className="h-4 w-4 animate-spin" />
                    ) : status === "failed" ? (
                      <XCircle className="h-4 w-4" />
                    ) : status === "skipped" ? (
                      <CircleSlash className="h-4 w-4" />
                    ) : (
                      <span className="block h-2 w-2 rounded-full bg-slate-700" />
                    )}
                  </motion.span>
                </AnimatePresence>
              </div>
              <div className="mt-2 flex items-center gap-2">
                <Icon className="h-4 w-4 shrink-0" style={{ color: status === "pending" ? "#475569" : color }} />
                <span className={cn("text-[12.5px] font-medium leading-tight", status === "pending" ? "text-slate-500" : "text-slate-100")}>{m.label}</span>
              </div>
              <div className="mt-1.5 h-4 truncate text-[10.5px] text-slate-500" title={st?.detail}>
                {status === "skipped" ? "skipped by playbook condition" : status === "completed" ? fmtMs(st?.duration) : status === "running" ? st?.detail ?? "running…" : failed && status === "pending" ? "not executed" : ""}
              </div>
            </motion.div>
          );
        })}
      </div>
    </div>
  );
}
