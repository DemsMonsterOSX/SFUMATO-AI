"use client";

import { Bug, Database, FilePlus2, Gauge, Network } from "lucide-react";
import Link from "next/link";
import { useEffect, useState } from "react";
import { Badge, Button, Card, CardHeader, Empty, ErrorNote, JsonBlock, PageHeader, Skeleton, Tabs } from "@/components/ui";
import { useApi } from "@/hooks/useApi";
import { api } from "@/lib/api";

const n = (v: number) => v.toLocaleString("en-US");

/* ---------------------------------------------------------------- incidents */
type Scenario = { key: string; title?: string; name?: string };
function IncidentsTab() {
  const { data: scenarios } = useApi<Scenario[]>("scenarios");
  const [body, setBody] = useState("");
  const [key, setKey] = useState("");
  const [busy, setBusy] = useState(false);
  const [res, setRes] = useState<unknown>(null);
  const [err, setErr] = useState<string | null>(null);
  const { data: recent, reload } = useApi<any>("incidents?limit=8");

  async function load(k: string) {
    setKey(k);
    const s = await api<{ incident: unknown }>(`scenarios/${k}`);
    setBody(JSON.stringify(s.incident, null, 2));
  }
  useEffect(() => { if (scenarios?.length && !key) void load(scenarios[0].key); }, [scenarios]); // eslint-disable-line react-hooks/exhaustive-deps

  async function send() {
    setBusy(true); setErr(null); setRes(null);
    try {
      const payload = JSON.parse(body);
      setRes(await api("incidents?resubmit=true&via=api-console", { method: "POST", body: JSON.stringify(payload) }));
      reload();
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally { setBusy(false); }
  }
  const items: any[] = recent?.items ?? recent ?? [];
  return (
    <div className="grid gap-5 xl:grid-cols-2">
      <Card>
        <CardHeader title="Create an incident" subtitle="POST /api/v1/incidents: the same entry point as any external client" icon={<FilePlus2 className="h-4 w-4" />} />
        <div className="mb-2 flex flex-wrap gap-1.5">
          {(scenarios ?? []).map((s) => <button key={s.key} onClick={() => void load(s.key)} className={`rounded-lg border px-2 py-1 text-[11px] ${key === s.key ? "border-cyan-400/50 bg-cyan-400/10 text-white" : "border-line text-slate-400"}`}>{s.title ?? s.name ?? s.key}</button>)}
        </div>
        <textarea value={body} onChange={(e) => setBody(e.target.value)} spellCheck={false} aria-label="Incident JSON"
          className="h-72 w-full rounded-xl border border-line bg-ink-900/70 p-3 font-mono text-[11px] text-slate-200 outline-none focus:border-cyan-400/50" />
        <div className="mt-2 flex items-center gap-3">
          <Button onClick={send} disabled={busy || !body}>{busy ? "Sending…" : "Send to the API"}</Button>
          {err && <span className="text-xs text-red-300">{err}</span>}
        </div>
        {res !== null && (
          <div className="mt-3">
            <JsonBlock value={res} max="max-h-40" />
            {(res as { incident_id?: string }).incident_id && <Link className="mt-2 inline-block text-xs text-cyan-300 underline" href={`/incidents/${encodeURIComponent((res as { incident_id: string }).incident_id)}`}>Open the investigation</Link>}
          </div>
        )}
      </Card>
      <Card>
        <CardHeader title="Latest incidents" subtitle="GET /api/v1/incidents" />
        {!recent ? <Skeleton className="h-40" /> : items.length === 0 ? <Empty title="No incident yet" /> : (
          <ul className="space-y-1.5 text-xs">
            {items.slice(0, 8).map((i: any) => (
              <li key={i.incident_id ?? i.id} className="rounded-xl border border-line bg-ink-900/50 px-3 py-2">
                <Link className="font-mono text-cyan-300 underline" href={`/incidents/${encodeURIComponent(i.incident_id ?? i.id)}`}>{i.incident_id ?? i.id}</Link>
                <span className="ml-2 text-slate-400">{i.title ?? ""}</span> <Badge color="#64748b">{i.status}</Badge>
              </li>
            ))}
          </ul>
        )}
      </Card>
    </div>
  );
}

/* ---------------------------------------------------------------------- CVE */
function CveTab() {
  const [id, setId] = useState("CVE-2024-4577");
  const [res, setRes] = useState<any>(null);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  async function go() {
    setBusy(true); setErr(null); setRes(null);
    try { setRes(await api(`cves/lookup/${encodeURIComponent(id.trim())}`)); } catch (e) { setErr(e instanceof Error ? e.message : String(e)); } finally { setBusy(false); }
  }
  return (
    <Card>
      <CardHeader title="Fetch a CVE live" subtitle="GET /api/v1/cves/lookup/{id}: NIST NVD + CISA KEV + FIRST EPSS, cached 10 minutes, NVD calls rate-protected" icon={<Bug className="h-4 w-4" />} />
      <div className="flex flex-wrap gap-2">
        <input value={id} onChange={(e) => setId(e.target.value)} aria-label="CVE identifier" placeholder="CVE-2024-4577"
          className="min-w-[220px] flex-1 rounded-xl border border-line bg-ink-900/70 px-3 py-2 font-mono text-sm text-slate-100 outline-none focus:border-cyan-400/50" />
        <Button onClick={go} disabled={busy}>{busy ? "Fetching…" : "Fetch"}</Button>
      </div>
      {err && <p className="mt-2 text-xs text-red-300">{err}</p>}
      {res && (
        <div className="mt-3 space-y-2 text-xs text-slate-200">
          <div className="flex flex-wrap items-center gap-2">
            <span className="font-mono text-cyan-300">{res.id}</span>
            {res.cvss && <Badge color="#fb923c">CVSS {res.cvss.score} {res.cvss.severity}</Badge>}
            {res.epss && <Badge color="#a78bfa">EPSS {res.epss.epss.toFixed(3)}</Badge>}
            {res.kev ? <Badge color="#f43f5e">KEV · due {res.kev.due}{res.kev.ransomware === "Known" ? " · ransomware" : ""}</Badge> : <Badge color="#64748b">not in KEV</Badge>}
            <span className="text-slate-500">{res.status}</span>
          </div>
          <p className="leading-relaxed text-slate-300">{res.description}</p>
          <p className="text-slate-500">{res.cwe.join(", ")} · published {res.published?.slice(0, 10)} · modified {res.modified?.slice(0, 10)}</p>
          <JsonBlock value={res} max="max-h-56" />
        </div>
      )}
    </Card>
  );
}

/* ------------------------------------------------------------------ datasets */
type Root = { prefix: string; description: string };
type Listing = { roots: Root[]; available?: boolean; prefix?: string; items?: { name: string; size: number; kind: string; updated?: string }[]; prefixes?: string[] };
type Preview = { available?: boolean; error?: string; path?: string; size?: number; kind?: string; truncated?: boolean; bytes_read?: number; columns?: string[]; column_count?: number; rows?: any[]; text?: string; note?: string };
function DatasetsTab() {
  const [prefix, setPrefix] = useState<string | null>(null);
  const [file, setFile] = useState<string | null>(null);
  const { data: root } = useApi<Listing>("datasets");
  const { data: list } = useApi<Listing>(prefix ? `datasets?prefix=${encodeURIComponent(prefix)}` : null);
  const { data: pv, error: pvErr } = useApi<Preview>(file ? `datasets/preview?path=${encodeURIComponent(file)}&rows=15` : null);
  const mb = (b: number) => (b > 1e9 ? `${(b / 1e9).toFixed(2)} GB` : b > 1e6 ? `${(b / 1e6).toFixed(1)} MB` : `${(b / 1e3).toFixed(0)} KB`);
  return (
    <div className="grid gap-5 xl:grid-cols-[minmax(0,4fr)_minmax(0,7fr)]">
      <Card>
        <CardHeader title="Datasets in the bucket" subtitle="Read-only; only these locations are exposed" icon={<Database className="h-4 w-4" />} />
        {!root ? <Skeleton className="h-32" /> : (
          <ul className="space-y-1.5 text-xs">
            {root.roots.map((r) => (
              <li key={r.prefix}>
                <button onClick={() => { setPrefix(r.prefix); setFile(null); }} className={`w-full rounded-xl border px-3 py-2 text-left ${prefix === r.prefix ? "border-cyan-400/50 bg-cyan-400/10" : "border-line bg-ink-900/50"}`}>
                  <span className="font-mono text-cyan-300">{r.prefix}</span><div className="text-slate-400">{r.description}</div>
                </button>
              </li>
            ))}
          </ul>
        )}
        {list && prefix && (
          <div className="mt-3 border-t border-line pt-3">
            {!list.available && <p className="text-xs text-amber-200">The bucket is only readable from the deployed VM.</p>}
            <ul className="max-h-72 space-y-1 overflow-y-auto text-xs">
              {(list.prefixes ?? []).map((p) => <li key={p}><button className="font-mono text-slate-300 underline" onClick={() => setPrefix(p)}>{p}</button></li>)}
              {(list.items ?? []).map((i) => (
                <li key={i.name} className="flex items-center justify-between gap-2">
                  <button className="truncate text-left font-mono text-slate-200 hover:text-cyan-300" onClick={() => setFile(i.name)} title={i.name}>{i.name.split("/").pop()}</button>
                  <span className="shrink-0 text-slate-500">{mb(i.size)} · {i.kind}</span>
                </li>
              ))}
            </ul>
          </div>
        )}
      </Card>
      <Card>
        <CardHeader title="Preview" subtitle={file ?? "Select a file"} />
        <ErrorNote error={pvErr} />
        {!file ? <Empty title="No file selected">CSV files show their first rows (at most 256 KB are read, even for the 4 GB files).</Empty> : !pv ? <Skeleton className="h-48" /> : pv.error ? <p className="text-xs text-red-300">{pv.error}</p> : pv.note ? <p className="text-xs text-slate-300">{pv.note} ({mb(pv.size ?? 0)})</p> : (
          <div>
            <p className="mb-2 text-[11px] text-slate-500">{mb(pv.size ?? 0)} · read {mb(pv.bytes_read ?? 0)}{pv.truncated ? " (start of the file)" : ""}{pv.column_count ? ` · ${pv.column_count} columns` : ""}</p>
            {pv.columns ? (
              <div className="max-h-[420px] overflow-auto rounded-xl border border-line">
                <table className="min-w-full text-left text-[11px]">
                  <thead className="sticky top-0 bg-ink-900 text-slate-400"><tr>{pv.columns.map((c, i) => <th key={i} className="whitespace-nowrap px-2 py-1.5 font-medium">{c}</th>)}</tr></thead>
                  <tbody>{(pv.rows ?? []).map((r: string[], i: number) => <tr key={i} className="border-t border-line text-slate-200">{r.map((v, j) => <td key={j} className="whitespace-nowrap px-2 py-1 font-mono">{v}</td>)}</tr>)}</tbody>
                </table>
              </div>
            ) : pv.rows ? <JsonBlock value={pv.rows} /> : <pre className="max-h-[420px] overflow-auto whitespace-pre-wrap rounded-xl border border-line bg-ink-900/60 p-3 text-[11px] text-slate-200">{pv.text}</pre>}
          </div>
        )}
      </Card>
    </div>
  );
}

/* --------------------------------------------------------- load and distribution */
type Metrics = { rate_limit_per_minute?: number | null; window_s: number; requests: number; rps_window: number; rps_last_10s: number; p50_ms: number | null; p95_ms: number | null; p99_ms: number | null; errors_5xx: number;
  routes: { route: string; requests: number; errors: number; client_errors: number; p50_ms: number | null; p95_ms: number | null }[];
  uptime_s: number; load_average: number[] | null; memory: { total_mb: number; available_mb: number } | null; cpu_count: number | null };
type StreamOv = { active: boolean; scorers: { host: string; partitions: number[]; throughput_per_s: number; consumed: number; active: boolean; lag_by_partition: Record<string, number> }[]; totals: { throughput_per_s: number } };

type Probe = { concurrency: number; rps: number; p50: number; p95: number; errors: number; limited: number; requests: number };
const ENDPOINTS: Record<string, string> = { "health": "Liveness (no database, lightest)", "status": "Platform status (database + worker)", "cves/summary": "CVE summary (bucket read, cached)", "procedures?q=ransomware": "Procedure search (BM25)", "incidents?limit=5": "Incident list (database)" };

function LoadTab() {
  const { data: m } = useApi<Metrics>("metrics/api", 3000);
  const { data: st } = useApi<StreamOv>("stream/overview", 5000);
  const [ep, setEp] = useState("health");
  const [running, setRunning] = useState(false);
  const [probes, setProbes] = useState<Probe[]>([]);
  const [note, setNote] = useState<string | null>(null);

  async function run() {
    if (!window.confirm("Run the API load test from this browser?\n\nIt sends requests with 1, 2, 4, 8, 16 then 32 parallel connections for 8 seconds each (about a minute) and stops early if more than 5 % of the requests fail or are rate-limited. The dashboard VM is small (0.25 vCPU): other users may notice a slowdown.")) return;
    setRunning(true); setProbes([]); setNote(null);
    const out: Probe[] = [];
    for (const c of [1, 2, 4, 8, 16, 32]) {
      const lat: number[] = []; let errors = 0; let limited = 0; const t0 = performance.now(); const end = t0 + 8000;
      await Promise.all(Array.from({ length: c }, async () => {
        while (performance.now() < end) {
          const s = performance.now();
          try { const r = await fetch(`/api/backend/${ep}`, { cache: "no-store" }); await r.arrayBuffer(); if (r.status === 429) limited++; else if (!r.ok) errors++; } catch { errors++; }
          lat.push(performance.now() - s);
        }
      }));
      const dt = (performance.now() - t0) / 1000;
      lat.sort((a, b) => a - b);
      const p = { concurrency: c, requests: lat.length, rps: Math.round(lat.length / dt), p50: Math.round(lat[Math.floor(lat.length * 0.5)] ?? 0), p95: Math.round(lat[Math.floor(lat.length * 0.95)] ?? 0), errors, limited };
      out.push(p); setProbes([...out]);
      if (errors / Math.max(1, lat.length) > 0.05) { setNote(`Stopped at ${c} connections: more than 5 % of the requests failed.`); break; }
      if (limited / Math.max(1, lat.length) > 0.05) { setNote(`Stopped at ${c} connections: the API rate limiter answered 429 to more than 5 % of the requests. That is the configured policy, not a crash.`); break; }
    }
    setRunning(false);
  }
  const best = probes.reduce((a, b) => (b.errors / Math.max(1, b.requests) <= 0.05 && b.limited / Math.max(1, b.requests) <= 0.05 && b.rps > a ? b.rps : a), 0);
  return (
    <div className="space-y-5">
      <div className="grid gap-5 xl:grid-cols-2">
        <Card>
          <CardHeader title="API server load (last minute)" subtitle="Live from this API process" icon={<Gauge className="h-4 w-4" />} />
          {!m ? <Skeleton className="h-32" /> : (
            <div className="space-y-2 text-xs text-slate-200">
              <div className="grid grid-cols-2 gap-2 md:grid-cols-4">
                {[["req/s (10 s)", m.rps_last_10s], ["req/s (window)", m.rps_window], ["p50 ms", m.p50_ms ?? "—"], ["p95 ms", m.p95_ms ?? "—"]].map(([k, v]) => <div key={String(k)} className="rounded-xl border border-line bg-ink-900/50 p-2"><div className="text-slate-500">{k}</div><div className="font-mono text-base text-white">{v}</div></div>)}
              </div>
              <p className="text-slate-400">CPU load average {m.load_average?.map((x) => x.toFixed(2)).join(" / ") ?? "n/a"} on {m.cpu_count} vCPU{(m.cpu_count ?? 0) > 1 ? "s" : ""}{m.memory ? ` · memory ${m.memory.available_mb} of ${m.memory.total_mb} MB free` : ""} · {m.errors_5xx} server errors</p>
              <table className="w-full text-left"><thead className="text-slate-500"><tr><th className="py-1">Route</th><th>Req</th><th>p50</th><th>p95</th><th>5xx</th></tr></thead>
                <tbody>{m.routes.slice(0, 8).map((r) => <tr key={r.route} className="border-t border-line"><td className="py-1 font-mono">{r.route}</td><td>{r.requests}</td><td>{r.p50_ms}</td><td>{r.p95_ms}</td><td>{r.errors}</td></tr>)}</tbody></table>
            </div>
          )}
        </Card>
        <Card>
          <CardHeader title="Load distribution of the streaming cluster" subtitle={st?.active ? "Partitions shared by the scorers (live)" : "Cluster idle: start it with scripts\\gcp_stream.ps1 run"} icon={<Network className="h-4 w-4" />} />
          {!st ? <Skeleton className="h-32" /> : st.scorers.length === 0 ? <Empty title="No scorer state published" /> : (
            <ul className="space-y-2 text-xs">
              {st.scorers.map((s) => {
                const total = st.scorers.reduce((a, b) => a + (b.active ? b.throughput_per_s : 0), 0) || 1;
                return (
                  <li key={s.host} className="rounded-xl border border-line bg-ink-900/50 p-2">
                    <div className="flex justify-between"><span className="font-mono">{s.host}</span><span className="text-slate-400">partitions {s.partitions.join(", ") || "none"} · {s.active ? `${s.throughput_per_s}/s` : "stopped"}</span></div>
                    <div className="mt-1 h-1.5 rounded bg-ink-800"><div className="h-1.5 rounded bg-cyan-400" style={{ width: `${s.active ? (s.throughput_per_s / total) * 100 : 0}%` }} /></div>
                  </li>
                );
              })}
            </ul>
          )}
        </Card>
      </div>
      <Card>
        <CardHeader title="API load test (requests per second)" subtitle="Ramps the number of parallel connections from this browser and reports the throughput; compare with the server view above" icon={<Gauge className="h-4 w-4" />}
          right={<Button onClick={run} disabled={running}>{running ? "Running…" : "Run load test"}</Button>} />
        <div className="mb-3 flex flex-wrap gap-1.5">{Object.entries(ENDPOINTS).map(([k, v]) => <button key={k} onClick={() => setEp(k)} disabled={running} title={v} className={`rounded-lg border px-2 py-1 text-[11px] ${ep === k ? "border-cyan-400/50 bg-cyan-400/10 text-white" : "border-line text-slate-400"}`}>/{k}</button>)}</div>
        {probes.length > 0 && (
          <>
            <Badge color="#34d399">best sustained: {n(best)} requests/s</Badge>
            <table className="mt-3 w-full text-left text-xs"><thead className="text-slate-400"><tr>{["Connections", "Requests", "Req/s", "p50 ms", "p95 ms", "Errors", "Rate-limited (429)"].map((h) => <th key={h} className="px-2 py-2 font-medium">{h}</th>)}</tr></thead>
              <tbody>{probes.map((p) => <tr key={p.concurrency} className="border-t border-line text-slate-200"><td className="px-2 py-2 font-mono">{p.concurrency}</td><td className="px-2 py-2 font-mono">{n(p.requests)}</td><td className="px-2 py-2 font-mono">{n(p.rps)}</td><td className="px-2 py-2 font-mono">{p.p50}</td><td className="px-2 py-2 font-mono">{p.p95}</td><td className="px-2 py-2 font-mono">{p.errors}</td><td className="px-2 py-2 font-mono">{p.limited}</td></tr>)}</tbody></table>
          </>
        )}
        {note && <p className="mt-2 text-xs text-amber-200">{note}</p>}
        <p className="mt-3 text-[11px] text-slate-500">The API allows {m?.rate_limit_per_minute ? n(m.rate_limit_per_minute) : "a limited number of"} requests per minute per key and the whole team shares the dashboard key; answers 429 show the limiter working. /health is never rate-limited, so it measures raw capacity. The path measured is browser, internet, HTTPS proxy, dashboard proxy, API: it is the real user path, so it includes your own connection and the browser limit on parallel requests. It tests the small dashboard VM, not the streaming cluster.</p>
      </Card>
    </div>
  );
}

export default function ApiConsolePage() {
  return (
    <div>
      <PageHeader kicker="Developer console" title="API Console" description="Call the platform API from the browser: create incidents, fetch CVEs live, browse the datasets of the bucket, watch the load distribution and measure requests per second. Every call goes through the team login; nothing here is open to the Internet." />
      <Tabs defaultValue="incidents" tabs={[
        { value: "incidents", label: "Incidents", content: <IncidentsTab /> },
        { value: "cve", label: "CVE", content: <CveTab /> },
        { value: "datasets", label: "Datasets (CSV)", content: <DatasetsTab /> },
        { value: "load", label: "Load and performance", content: <LoadTab /> },
      ]} />
    </div>
  );
}
