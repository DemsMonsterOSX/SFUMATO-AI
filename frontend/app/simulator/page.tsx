"use client";

import { motion } from "framer-motion";
import { FlaskConical, Globe, HardDrive, Loader2, Play, RotateCcw, Wand2 } from "lucide-react";
import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import { JsonEditor } from "@/components/json-editor";
import { Badge, Button, Card, CardHeader, PageHeader, Skeleton } from "@/components/ui";
import { useApi } from "@/hooks/useApi";
import { ApiError, api } from "@/lib/api";
import { cn } from "@/lib/utils";

type Scenario = { key: string; title: string; description: string; file: string };

export default function SimulatorPage() {
  const router = useRouter();
  const { data: scenarios } = useApi<Scenario[]>("scenarios");
  const { data: cti } = useApi<any>("cti/status");
  const [selected, setSelected] = useState<string | null>(null);
  const [text, setText] = useState("");
  const [original, setOriginal] = useState("");
  const [mode, setMode] = useState<"demo" | "live">("demo");
  const [busy, setBusy] = useState(false);
  const [errors, setErrors] = useState<{ msg: string; items?: { loc: string; msg: string }[] } | null>(null);

  const load = async (key: string) => {
    setSelected(key);
    setErrors(null);
    const s = await api<{ incident: any }>(`scenarios/${key}`);
    const t = JSON.stringify(s.incident, null, 2);
    setText(t);
    setOriginal(t);
  };
  useEffect(() => {
    if (scenarios?.length && !selected) load(scenarios[0].key);
  }, [scenarios]); // eslint-disable-line react-hooks/exhaustive-deps
  useEffect(() => {
    if (cti?.default_mode) setMode(cti.default_mode);
  }, [cti?.default_mode]);

  const submit = async () => {
    setErrors(null);
    let payload: unknown;
    try {
      payload = JSON.parse(text);
    } catch (e) {
      setErrors({ msg: `Invalid JSON: ${(e as Error).message}` });
      return;
    }
    setBusy(true);
    try {
      const res = await api<{ incident_id: string }>(`incidents?resubmit=true&via=simulator&cti_mode=${mode}`, { method: "POST", body: JSON.stringify(payload) });
      router.push(`/incidents/${encodeURIComponent(res.incident_id)}`);
    } catch (e) {
      const body = e instanceof ApiError ? (e.body as any) : null;
      setErrors({ msg: e instanceof Error ? e.message : String(e), items: body?.errors });
      setBusy(false);
    }
  };

  const configured = (cti?.providers ?? []).filter((p: any) => p.configured).map((p: any) => p.name);

  return (
    <div>
      <PageHeader
        kicker="Incident simulator"
        title="Craft an incident, watch it being investigated"
        description="The simulator submits to POST /api/v1/incidents — exactly the same pipeline as external API clients. Nothing is pre-computed: the verdict is produced live by the SOAR playbook."
      />
      <div className="grid gap-5 xl:grid-cols-[360px_1fr]">
        <div className="space-y-3">
          <div className="label px-1">Scenarios</div>
          {!scenarios && <Skeleton className="h-96" />}
          {scenarios?.map((s, i) => (
            <motion.button
              key={s.key}
              initial={{ opacity: 0, x: -8 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ delay: i * 0.04 }}
              onClick={() => load(s.key)}
              className={cn("glass glass-hover w-full p-4 text-left", selected === s.key && "border-cyan-400/40 shadow-glow")}
            >
              <div className="flex items-center gap-2">
                <span className="font-mono text-[10px] text-slate-500">{String(i + 1).padStart(2, "0")}</span>
                <span className="text-sm font-medium text-slate-100">{s.title}</span>
              </div>
              <p className="mt-1 text-xs leading-relaxed text-slate-400">{s.description}</p>
            </motion.button>
          ))}
        </div>
        <Card>
          <CardHeader
            title="Incident JSON"
            subtitle="Edit any field — the backend validates it against the strict incident schema"
            icon={<Wand2 className="h-4 w-4" />}
            right={<Button variant="ghost" onClick={() => setText(original)} disabled={text === original}><RotateCcw className="h-4 w-4" /> Reset</Button>}
          />
          {text ? <JsonEditor value={text} onChange={setText} height={520} /> : <Skeleton className="h-[520px]" />}

          <div className="mt-5 grid gap-3 md:grid-cols-2">
            <button onClick={() => setMode("demo")} className={cn("rounded-xl border p-3 text-left transition-colors", mode === "demo" ? "border-violet-400/50 bg-violet-500/10" : "border-line bg-ink-900/60 hover:border-violet-400/30")}>
              <div className="flex items-center gap-2 text-sm font-medium text-slate-100"><HardDrive className="h-4 w-4 text-violet-300" /> Reproducible demo mode</div>
              <p className="mt-1 text-xs text-slate-400">CTI answers come from local, clearly labelled fixtures. Works offline. Same SOAR / ML / decision pipeline.</p>
            </button>
            <button onClick={() => setMode("live")} className={cn("rounded-xl border p-3 text-left transition-colors", mode === "live" ? "border-cyan-400/50 bg-cyan-500/10" : "border-line bg-ink-900/60 hover:border-cyan-400/30")}>
              <div className="flex items-center gap-2 text-sm font-medium text-slate-100"><Globe className="h-4 w-4 text-cyan-300" /> Live intelligence mode</div>
              <p className="mt-1 text-xs text-slate-400">
                Real queries to configured providers{configured.length ? `: ${configured.join(", ")}` : " (none configured yet — see Settings)"}. Documentation IPs/domains are never sent.
              </p>
            </button>
          </div>

          {errors && (
            <div className="mt-4 rounded-xl border border-rose-400/30 bg-rose-500/10 p-3 text-sm text-rose-200">
              <div className="font-medium">{errors.msg}</div>
              {errors.items?.map((e, i) => <div key={i} className="mt-1 font-mono text-xs">{e.loc}: {e.msg}</div>)}
            </div>
          )}
          <div className="mt-5 flex flex-wrap items-center justify-between gap-3">
            <div className="flex items-center gap-2 text-xs text-slate-500">
              <FlaskConical className="h-4 w-4" /> A modified copy is stored under a new ID (…-R2, -R3) when the ID already exists.
            </div>
            <Button onClick={submit} disabled={busy || !text} className="px-6 py-2.5 text-[15px]">
              {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <Play className="h-4 w-4" />} Analyze Incident
            </Button>
          </div>
          <div className="mt-3 flex justify-end"><Badge className="border-line text-slate-500">Response actions remain display-only</Badge></div>
        </Card>
      </div>
    </div>
  );
}
