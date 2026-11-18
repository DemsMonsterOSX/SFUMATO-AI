"use client";

import { Bug, ShieldAlert, Siren, Target } from "lucide-react";
import Link from "next/link";
import { useEffect, useState } from "react";
import { Bar, BarChart, CartesianGrid, Legend, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { Badge, Card, CardHeader, Empty, ErrorNote, PageHeader, Skeleton, Stat } from "@/components/ui";
import { useApi } from "@/hooks/useApi";

const tooltipStyle = { background: "#08102a", border: "1px solid rgba(148,178,255,0.15)", borderRadius: 12, fontSize: 12 };
const SEV_COLORS: Record<string, string> = { CRITICAL: "#f43f5e", HIGH: "#fb923c", MEDIUM: "#fbbf24", LOW: "#60a5fa", UNSCORED: "#64748b" };

type Epss = { epss: number; percentile: number };
type Cve = { id: string; published: string; description: string; cvss: { score: number; severity: string } | null; kev: boolean; cwe: string[]; epss?: Epss };
type Kev = { id: string; vendor: string; product: string; name: string; added: string; due: string | null; ransomware: string | null; description: string; epss: Epss | null };
type Summary = {
  generated_at: string; window_days: number;
  kev: { total: number; added_in_window: number; ransomware_known: number; catalog_version: string; recent: Kev[] };
  nvd: { published_in_window: number; by_severity: Record<string, number>; scored_share: number; in_kev: number; per_day: Record<string, number | string>[]; top_cvss: Cve[] };
  epss: { top: Cve[]; fetched_for: number };
  sources: string[]; limitations: string[];
};
type Resp = { available: boolean; source: string | null; summary: Summary | null };
type Hit = { id: string; title: string; kev: boolean; added: string; cvss: number | null; epss: number | null };

const n = (v: number) => v.toLocaleString("en-US");

export default function CvePage() {
  const { data, error } = useApi<Resp>("cves/summary");
  const [q, setQ] = useState("");
  const [dq, setDq] = useState("");
  useEffect(() => { const t = setTimeout(() => setDq(q.trim()), 250); return () => clearTimeout(t); }, [q]);
  const { data: hits } = useApi<{ items: Hit[] }>(dq.length >= 2 ? `cves/search?q=${encodeURIComponent(dq)}` : null);
  const s = data?.summary;
  const sevKeys = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNSCORED"];

  return (
    <div>
      <PageHeader kicker="Vulnerability feed" title="CVE intelligence" description="Free public feeds collected into the project's bucket: CISA Known Exploited Vulnerabilities, the NIST NVD (recent CVEs and CVSS) and FIRST EPSS (probability of exploitation). A CVE listed in the KEV is being exploited now: it comes before any CVSS score." />
      <ErrorNote error={error} />
      {data && !data.available && <Empty title="No CVE feed published yet" icon={<Bug className="h-5 w-5" />}>Run <span className="font-mono">python bigdata/cve_ingest.py --bucket &lt;bucket&gt;</span>.</Empty>}
      {s && (
        <>
          <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
            <Stat label="KEV catalogue" value={n(s.kev.total)} sub={`+${s.kev.added_in_window} in ${s.window_days} days`} accent="#f43f5e" icon={<Siren className="h-4 w-4" />} />
            <Stat label="NVD CVEs published" value={n(s.nvd.published_in_window)} sub={`last ${s.window_days} days`} icon={<Bug className="h-4 w-4" />} />
            <Stat label="Critical (CVSS)" value={n(s.nvd.by_severity.CRITICAL ?? 0)} sub={`${Math.round(s.nvd.scored_share * 100)} % of CVEs scored yet`} accent="#fb923c" icon={<ShieldAlert className="h-4 w-4" />} />
            <Stat label="Ransomware-linked KEV" value={n(s.kev.ransomware_known)} sub="known campaign use" accent="#a78bfa" icon={<Target className="h-4 w-4" />} />
          </div>
          <p className="mt-2 text-[11px] text-slate-500">Data published {new Date(s.generated_at).toLocaleString()} · loaded from the {data?.source} · KEV catalogue {s.kev.catalog_version}. Triage guidance: <Link className="text-cyan-300 underline" href="/procedures">PROC-128 Known-exploited CVE triage</Link>.</p>

          <Card className="mt-5">
            <CardHeader title="CVEs published per day, by severity" subtitle="Unscored = no CVSS score yet (the NVD often needs days to analyse a new CVE)" />
            <div className="h-[300px]">
              <ResponsiveContainer>
                <BarChart data={s.nvd.per_day} margin={{ left: -5 }}>
                  <CartesianGrid stroke="rgba(148,178,255,0.06)" vertical={false} />
                  <XAxis dataKey="day" tickFormatter={(d: string) => d.slice(5)} interval="preserveStartEnd" tick={{ fill: "#94a3b8", fontSize: 10 }} axisLine={false} tickLine={false} />
                  <YAxis tick={{ fill: "#64748b", fontSize: 11 }} axisLine={false} tickLine={false} />
                  <Tooltip contentStyle={tooltipStyle} />
                  <Legend wrapperStyle={{ fontSize: 10 }} />
                  {sevKeys.map((k) => <Bar key={k} dataKey={k} stackId="a" fill={SEV_COLORS[k]} />)}
                </BarChart>
              </ResponsiveContainer>
            </div>
          </Card>

          <Card className="mt-5">
            <CardHeader title="Search the feed" subtitle="CVE id, vendor, product, keyword or CWE, among the KEV additions and the highest CVSS / EPSS entries" />
            <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="php, CVE-2026, cisco, CWE-79…" aria-label="Search CVEs"
              className="w-full rounded-xl border border-line bg-ink-900/70 px-3 py-2 text-sm text-slate-100 outline-none placeholder:text-slate-500 focus:border-cyan-400/50" />
            {dq.length >= 2 && (
              <ul className="mt-3 space-y-1.5">
                {!hits ? <Skeleton className="h-10" /> : hits.items.length === 0 ? <li className="text-xs text-slate-400">No match in the published lists.</li> : hits.items.map((h) => (
                  <li key={h.id} className="rounded-xl border border-line bg-ink-900/50 px-3 py-2 text-xs">
                    <div className="flex flex-wrap items-center gap-2">
                      <a className="font-mono text-cyan-300 underline" href={`https://nvd.nist.gov/vuln/detail/${h.id}`} target="_blank" rel="noreferrer">{h.id}</a>
                      {h.kev && <Badge color="#f43f5e">KEV</Badge>}{h.cvss != null && <Badge color="#fb923c">CVSS {h.cvss}</Badge>}{h.epss != null && <Badge color="#a78bfa">EPSS {h.epss.toFixed(2)}</Badge>}
                      <span className="text-slate-500">{h.added}</span>
                    </div>
                    <div className="mt-1 text-slate-300">{h.title}</div>
                  </li>
                ))}
              </ul>
            )}
          </Card>

          <div className="mt-5 grid gap-5 xl:grid-cols-2">
            <Card>
              <CardHeader title="Latest KEV additions" subtitle="Known to be exploited: patch by the due date" icon={<Siren className="h-4 w-4" />} />
              <ul className="max-h-[520px] space-y-1.5 overflow-y-auto pr-1">
                {s.kev.recent.slice(0, 30).map((v) => (
                  <li key={v.id} className="rounded-xl border border-line bg-ink-900/50 px-3 py-2 text-xs">
                    <div className="flex flex-wrap items-center gap-2">
                      <a className="font-mono text-cyan-300 underline" href={`https://nvd.nist.gov/vuln/detail/${v.id}`} target="_blank" rel="noreferrer">{v.id}</a>
                      <span className="text-slate-400">{v.vendor} · {v.product}</span>
                      {v.ransomware === "Known" && <Badge color="#a78bfa">ransomware</Badge>}
                      {v.epss && <Badge color="#fbbf24">EPSS {v.epss.epss.toFixed(2)}</Badge>}
                    </div>
                    <div className="mt-1 text-slate-200">{v.name}</div>
                    <div className="mt-0.5 text-slate-500">added {v.added}{v.due ? ` · due ${v.due}` : ""}</div>
                  </li>
                ))}
              </ul>
            </Card>
            <Card>
              <CardHeader title="Highest probability of exploitation (EPSS)" subtitle={`Among recent CVEs scored 7.0+ and KEV additions (${n(s.epss.fetched_for)} looked up)`} icon={<Target className="h-4 w-4" />} />
              <ul className="max-h-[520px] space-y-1.5 overflow-y-auto pr-1">
                {s.epss.top.map((c) => (
                  <li key={c.id} className="rounded-xl border border-line bg-ink-900/50 px-3 py-2 text-xs">
                    <div className="flex flex-wrap items-center gap-2">
                      <a className="font-mono text-cyan-300 underline" href={`https://nvd.nist.gov/vuln/detail/${c.id}`} target="_blank" rel="noreferrer">{c.id}</a>
                      <Badge color="#a78bfa">EPSS {c.epss?.epss.toFixed(3)}</Badge>
                      {c.cvss && <Badge color={SEV_COLORS[c.cvss.severity] ?? "#64748b"}>CVSS {c.cvss.score}</Badge>}
                      {c.kev && <Badge color="#f43f5e">KEV</Badge>}
                    </div>
                    <div className="mt-1 text-slate-300">{c.description.slice(0, 160)}{c.description.length > 160 ? "…" : ""}</div>
                  </li>
                ))}
              </ul>
            </Card>
          </div>

          <Card className="mt-5">
            <CardHeader title="Limits" />
            <ul className="list-disc space-y-1 pl-5 text-xs text-slate-300">{s.limitations.map((l) => <li key={l}>{l}</li>)}</ul>
            <p className="mt-2 text-[11px] text-slate-500">Sources: {s.sources.join(", ")}.</p>
          </Card>
        </>
      )}
      {!data && !error && <Skeleton className="h-64" />}
    </div>
  );
}
