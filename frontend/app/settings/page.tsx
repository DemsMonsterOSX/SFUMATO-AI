"use client";

import { CheckCircle2, KeyRound, Lock, ScrollText, Server } from "lucide-react";
import { useState } from "react";
import { Badge, Button, Card, CardHeader, KV, PageHeader, Skeleton } from "@/components/ui";
import { useApi } from "@/hooks/useApi";
import { api, fmtTime } from "@/lib/api";

const HELP: Record<string, string> = {
  abusech_auth_key: "Free key from https://auth.abuse.ch/ — enables ThreatFox and URLhaus live lookups.",
  otx_api_key: "Free account at https://otx.alienvault.com/ → Settings → API key.",
  opencti_url: "e.g. http://opencti:8080 in FULL mode, or your own OpenCTI instance.",
  opencti_token: "OpenCTI user API token (read access is enough).",
  anthropic_api_key: "Optional external LLM. Also set AI_ALLOW_EXTERNAL=true or AI_PROVIDER=anthropic.",
  openai_api_key: "Optional OpenAI-compatible LLM endpoint key.",
  ollama_url: "Local LLM, e.g. http://ollama:11434 (Docker) or http://127.0.0.1:11434.",
};

export default function SettingsPage() {
  const { data, reload } = useApi<any>("settings");
  const { data: audit } = useApi<any[]>("audit?limit=30", 8000);
  const [values, setValues] = useState<Record<string, string>>({});
  const [saved, setSaved] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);

  const save = async (name: string, value: string | null) => {
    setErr(null);
    try {
      await api("settings/credentials", { method: "PUT", body: JSON.stringify({ name, value }) });
      setValues((v) => ({ ...v, [name]: "" }));
      setSaved(name);
      reload();
      setTimeout(() => setSaved(null), 2500);
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    }
  };

  return (
    <div>
      <PageHeader kicker="Settings · first-run setup" title="Connect your intelligence sources" description="Everything works without credentials in reproducible demo mode. Live intelligence needs free API keys: enter them here once (stored encrypted, never displayed again) or put them in .env." />
      <div className="grid gap-5 xl:grid-cols-[1.4fr_1fr]">
        <Card>
          <CardHeader title="Optional credentials" subtitle="Write-only — the API only ever returns whether a value is configured" icon={<KeyRound className="h-4 w-4" />} />
          {err && <div className="mb-3 rounded-lg border border-rose-400/30 bg-rose-500/10 px-3 py-2 text-xs text-rose-200">{err}</div>}
          {!data ? <Skeleton className="h-80" /> : (
            <div className="space-y-3">
              {data.credentials.map((c: any) => (
                <div key={c.name} className="rounded-xl border border-line bg-ink-900/60 p-3">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div>
                      <div className="text-sm font-medium text-slate-100">{c.label}</div>
                      <div className="text-[11px] text-slate-500">{HELP[c.name]}</div>
                    </div>
                    {c.configured ? <Badge color="#34d399"><CheckCircle2 className="h-3 w-3" /> configured ({c.source === "setup_screen" ? "setup screen" : "environment"})</Badge> : <Badge className="border-line text-slate-400">not configured</Badge>}
                  </div>
                  <div className="mt-2 flex gap-2">
                    <input
                      type={c.name.endsWith("_url") ? "text" : "password"}
                      autoComplete="off"
                      value={values[c.name] ?? ""}
                      onChange={(e) => setValues((v) => ({ ...v, [c.name]: e.target.value }))}
                      placeholder={c.configured ? "•••••• (enter a new value to replace)" : c.name.endsWith("_url") ? "https://…" : "paste key"}
                      className="flex-1 rounded-lg border border-line bg-ink-950 px-3 py-1.5 font-mono text-xs text-slate-100 outline-none focus:border-cyan-400/40"
                    />
                    <Button variant="outline" onClick={() => save(c.name, values[c.name] ?? "")} disabled={!values[c.name]}>{saved === c.name ? "Saved" : "Save"}</Button>
                    {c.source === "setup_screen" && <Button variant="ghost" onClick={() => save(c.name, null)}>Clear</Button>}
                  </div>
                </div>
              ))}
            </div>
          )}
        </Card>
        <div className="space-y-5">
          <Card>
            <CardHeader title="Platform configuration" subtitle="Change these in .env and restart" icon={<Server className="h-4 w-4" />} />
            {data ? (
              <div>
                <KV k="Deployment mode" v={<Badge color="#22d3ee">{data.deployment_mode.toUpperCase()}</Badge>} />
                <KV k="Default CTI mode" v={data.cti_mode === "demo" ? "Reproducible demo (fixtures)" : "Live intelligence"} />
                <KV k="AI provider" v={data.ai_provider} />
                <KV k="Ollama model" v={data.ollama_model} mono />
                <KV k="External LLM allowed" v={data.ai_allow_external ? "yes" : "no"} />
                <KV k="Max request size" v={`${Math.round(data.limits.max_request_bytes / 1024)} KiB`} />
                <KV k="Rate limit" v={`${data.limits.rate_limit_per_minute} req/min`} />
              </div>
            ) : <Skeleton className="h-48" />}
          </Card>
          <Card>
            <CardHeader title="Safety guarantees" icon={<Lock className="h-4 w-4" />} />
            <ul className="space-y-1.5 text-xs text-slate-300">
              <li>• Read-only integrations: lookups only, no write calls to providers.</li>
              <li>• Private, internal, personal and documentation indicators never reach public CTI.</li>
              <li>• Commands found in incidents are decoded for analysis, never executed.</li>
              <li>• No automatic remediation: no blocking, isolation, account or firewall changes.</li>
              <li>• External LLMs only receive pseudonymised data, and only when explicitly enabled.</li>
            </ul>
          </Card>
        </div>
      </div>
      <Card className="mt-5">
        <CardHeader title="Audit log" subtitle="Recent security-relevant API actions" icon={<ScrollText className="h-4 w-4" />} />
        <div className="max-h-72 overflow-auto font-mono text-[11px]">
          {(audit ?? []).map((a, i) => (
            <div key={i} className="flex gap-3 border-b border-line/50 py-1.5 text-slate-300">
              <span className="w-36 text-slate-500">{fmtTime(a.ts, true)}</span>
              <span className="w-32 text-violet-300">{a.action}</span>
              <span className="w-40 truncate">{a.target}</span>
              <span className="w-28 text-slate-500">{a.actor}</span>
              <span className="text-slate-500">{a.client_ip}</span>
            </div>
          ))}
        </div>
      </Card>
    </div>
  );
}
