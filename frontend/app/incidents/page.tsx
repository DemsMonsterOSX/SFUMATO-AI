"use client";

import { Search } from "lucide-react";
import Link from "next/link";
import { useState } from "react";
import { Card, Empty, ErrorNote, PageHeader, SeverityBadge, Skeleton, StatusBadge, VerdictBadge, Badge } from "@/components/ui";
import { useApi } from "@/hooks/useApi";
import { fmtMs, fmtTime } from "@/lib/api";
import { VERDICTS, cn } from "@/lib/utils";

export default function IncidentsPage() {
  const [q, setQ] = useState("");
  const [verdict, setVerdict] = useState("");
  const params = new URLSearchParams({ limit: "200" });
  if (q) params.set("q", q);
  if (verdict) params.set("verdict", verdict);
  const { data, error } = useApi<{ total: number; items: any[] }>(`incidents?${params}`, 3000);

  return (
    <div>
      <PageHeader kicker="Investigations" title="Incident investigations" description="Every incident submitted through the API or the simulator. Open one to replay its full execution history." />
      <Card className="mb-5 flex flex-wrap items-center gap-3 p-3">
        <div className="flex min-w-[240px] flex-1 items-center gap-2 rounded-xl border border-line bg-ink-950/60 px-3 py-2">
          <Search className="h-4 w-4 text-slate-500" />
          <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search by incident ID or alert name" className="w-full bg-transparent text-sm text-slate-100 outline-none placeholder:text-slate-500" />
        </div>
        <div className="flex flex-wrap gap-1">
          {["", ...Object.keys(VERDICTS)].map((v) => (
            <button key={v} onClick={() => setVerdict(v)} className={cn("rounded-lg px-3 py-1.5 text-xs", verdict === v ? "bg-ink-700 text-white" : "text-slate-400 hover:text-slate-100")}>
              {v ? VERDICTS[v as keyof typeof VERDICTS].label : "All"}
            </button>
          ))}
        </div>
      </Card>
      <ErrorNote error={error && !data ? error : null} />
      <Card className="p-0">
        {!data ? <Skeleton className="m-5 h-64" /> : data.items.length === 0 ? <div className="p-6"><Empty title="No incidents match" /></div> : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="label border-b border-line text-left">
                  <th className="px-5 py-3">Incident</th><th className="py-3 pr-3">Alert</th><th className="py-3 pr-3">Severity</th><th className="py-3 pr-3">Status</th>
                  <th className="py-3 pr-3">Verdict</th><th className="py-3 pr-3 text-right">Threat</th><th className="py-3 pr-3 text-right">Confidence</th><th className="py-3 pr-3">CTI mode</th><th className="py-3 pr-5 text-right">Duration</th>
                </tr>
              </thead>
              <tbody>
                {data.items.map((r) => (
                  <tr key={r.incident_id} className="border-t border-line/60 transition-colors hover:bg-ink-800/50">
                    <td className="px-5 py-3">
                      <Link href={`/incidents/${encodeURIComponent(r.incident_id)}`} className="font-mono text-xs text-cyan-300 hover:underline">{r.incident_id}</Link>
                      <div className="text-[11px] text-slate-500">{fmtTime(r.created_at, true)}</div>
                    </td>
                    <td className="max-w-[320px] pr-3"><div className="truncate text-slate-100">{r.alert_name}</div><div className="text-[11px] text-slate-500">{r.source} · {r.hostname ?? "—"} · {r.submitted_via}</div></td>
                    <td className="pr-3"><SeverityBadge severity={r.severity} /></td>
                    <td className="pr-3"><StatusBadge status={r.status} /></td>
                    <td className="pr-3"><VerdictBadge verdict={r.verdict} /></td>
                    <td className="pr-3 text-right font-mono tabular-nums">{r.threat_score ?? "—"}</td>
                    <td className="pr-3 text-right font-mono tabular-nums">{r.verdict_confidence ?? "—"}</td>
                    <td className="pr-3">{r.cti_mode === "demo" ? <Badge color="#a78bfa">demo</Badge> : <Badge color="#22d3ee">live</Badge>}</td>
                    <td className="pr-5 text-right text-xs text-slate-400">{fmtMs(r.duration_ms)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  );
}
