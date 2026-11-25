"use client";

import { Cloud, Cpu, Server, X } from "lucide-react";
import { useMemo, useState } from "react";
import { ArchitectureDiagram, buildDiagram, type NodeState } from "@/components/architecture-diagram";
import { Badge, Card, CardHeader, Dot, ErrorNote, PageHeader, Stat } from "@/components/ui";
import { useApi } from "@/hooks/useApi";

// Machines are read live from the Compute API (GET bigdata/architecture, every 20 s). The text below describes what each machine is built to
// run (scripts/ and deploy/): it is the design, not a probe of the machine's content.
type Role = { key: string; name: string; target: string; layer: string; role: string; contains: string[]; script: string };
type Live = { name: string; zone: string; status: string; machine_type: string; vcpus: number | null; gpu: string[]; provisioning: string; internal_ip: string | null; has_external_ip: boolean; disks_gb: number };
type Arch = { live: boolean; reason?: string; read_at?: number; vms?: Live[]; quotas?: Record<string, { limit: number; usage: number }>; running_vcpus?: number; running_count?: number };
type Service = { key: string; name: string; layer: string; role: string; contains: string[] };

const COLORS: Record<string, string> = { Application: "#22d3ee", Streaming: "#a78bfa", "Big Data": "#34d399", Support: "#fbbf24" };

const ROLES: Role[] = [
  { key: "dash", name: "sfumato", target: "e2-standard-4", layer: "Application", role: "The dashboard you are on", script: "scripts/gcp_vm.ps1",
    contains: ["Caddy: HTTPS (certificate for the sslip.io name) and the team login", "Next.js front end (this site), served on the internal network", "FastAPI back end + SOAR worker (uvicorn, 127.0.0.1:8000)", "SQLite database of the application (incidents, audit)", "Machine learning artifacts and the Big Data result files", "Reads the Compute API (read-only) for this page"] },
  { key: "k1", name: "sfumato-kafka-1", target: "e2-standard-4", layer: "Streaming", role: "Kafka broker 1 and the stress-test host", script: "scripts/gcp_stream.ps1",
    contains: ["Kafka 4.1.2 in KRaft mode: broker and controller", "Topics (replication 3): network-flows, conn-events, source-alerts, naive-alerts, flow-aggregates, rule-alerts, cve-events", "Flow producer and scorer (model-based)", "CVE bridge", "Stress-test controller used by the Live Stream page"] },
  { key: "k2", name: "sfumato-kafka-2", target: "e2-standard-2", layer: "Streaming", role: "Kafka broker 2 and a scorer", script: "scripts/gcp_stream.ps1",
    contains: ["Kafka 4.1.2 broker and KRaft voter", "Scorer in the shared consumer group", "CVE consumer"] },
  { key: "k3", name: "sfumato-kafka-3", target: "e2-standard-2", layer: "Streaming", role: "Kafka broker 3 and a scorer", script: "scripts/gcp_stream.ps1",
    contains: ["Kafka 4.1.2 broker and KRaft voter", "Scorer in the shared consumer group"] },
  { key: "flink", name: "sfumato-flink", target: "e2-standard-4", layer: "Streaming", role: "Flink: both jobs on one cluster", script: "scripts/gcp_flink.ps1 -SqlFile2",
    contains: ["Apache Flink 1.20.5, standalone: one JobManager, one TaskManager with 4 slots", "sfumato-flow-analytics: 10-second windows over network-flows, rate rules", "sfumato-source-rules: 60-second windows per source address over conn-events, rule 'concentrated source'", "Results reader that publishes to the bucket for the Live Stream page"] },
  { key: "qwen", name: "sfumato-qwen", target: "n1-standard-4 + NVIDIA T4", layer: "Support", role: "Da Vinci's local model, on GPU", script: "scripts/gcp_qwen.ps1 -Gpu",
    contains: ["Ollama 0.40.16 serving the models on the T4 (16 GB)", "qwen2.5:14b-instruct (default), qwen2.5:7b-instruct, qwen3.8:27b (too large for the card: part runs on the CPU)", "NVIDIA driver from the Deep Learning VM image", "No service account: no access to the project's data"] },
  { key: "elk", name: "sfumato-elk", target: "e2-standard-2", layer: "Support", role: "Logs", script: "scripts/gcp_elk.ps1",
    contains: ["Elasticsearch (2 GB heap): indexes the application and audit logs", "Logstash: receives the logs of the API and the streaming applications", "No Kibana: the Logs tab of this site replaces it"] },
  { key: "lg", name: "sfumato-lg", target: "e2-standard-8", layer: "Big Data", role: "Worker: load generator and raw traffic", script: "streaming/conn_replay.py, scripts/gcp_pcap.ps1",
    contains: ["Python environment (confluent-kafka, pandas, pyarrow) for the load tests", "conn_replay.py: replays the Zeek connection records into Kafka", "scale_test.py: ramps the flow rate against the scorers", "Raw PCAP to Zeek to Parquet steps, on demand"] },
];

const SERVICES: Service[] = [
  { key: "bucket", name: "Cloud Storage bucket", layer: "Big Data", role: "Everything durable", contains: ["Raw copy of the dataset (CSV, 6.9 GB)", "Parquet: clean flows, Zeek connection logs per day (14-16, 20-23 Feb)", "Signed model artifacts and the application package", "Result files of the Flink reader"] },
  { key: "spark", name: "Dataproc Serverless (Spark)", layer: "Big Data", role: "Batch jobs", contains: ["Preparation of the CSV set into Parquet", "MLlib models", "Run with 2, 3 and 4 executors for the scaling test (uses the project's vCPU quota)"] },
  { key: "bq", name: "BigQuery", layer: "Big Data", role: "SQL analytics", contains: ["External tables over the clean Parquet", "Attacks per day and hour, class balance, targeted ports"] },
  { key: "cve", name: "Cloud Run job + Scheduler", layer: "Support", role: "CVE feed", contains: ["Job sfumato-cve, run by Cloud Scheduler every 12 hours", "Feeds the CVE page"] },
];
const EXTRA: Record<string, { name: string; role: string; contains: string[] }> = {
  user: { name: "Users", role: "Reach the dashboard over HTTPS with a team login", contains: ["Team accounts managed by scripts/gcp_vm.ps1 team-add"] },
  ds: { name: "CSE-CIC-IDS2018", role: "Public dataset (Canadian Institute for Cybersecurity + CSE)", contains: ["Processed CSV: 10 files, 6.9 GB", "Raw PCAP: 486 GB, one archive per day", "Official attack table (attacker addresses and time slots)"] },
};

const FLOW = [
  ["1", "Acquire", "Public CIC bucket (CSV + raw PCAP) → project bucket"],
  ["2", "Prepare", "Spark on Dataproc (CSV) and Zeek on the worker (raw traffic) → Parquet"],
  ["3", "Analyse", "BigQuery SQL, per-source 60 s windows, open-set detector with abstention"],
  ["4", "Stream", "Load generator or producer → Kafka (3 brokers) → scorers and Flink jobs → alert topics"],
  ["5", "Respond", "Triage routes a window (attack, rule-confirmed, human queue) → incident → suggested procedure"],
];

const ramGb = (t: string): number | null => {
  if (t === "e2-medium") return 4; if (t === "e2-small") return 2; if (t === "e2-micro") return 1;
  let m = /^e2-standard-(\d+)$/.exec(t); if (m) return 4 * +m[1];
  m = /^n1-standard-(\d+)$/.exec(t); if (m) return +(3.75 * +m[1]).toFixed(1);
  return null;
};
const stateColor = (s?: string) => (s === "RUNNING" ? { ok: true } : s === "TERMINATED" || s === "STOPPED" ? {} : { warn: true });
const ago = (t?: number) => (t ? `${Math.max(0, Math.round(Date.now() / 1000 - t))} s ago` : "");

export default function ArchitecturePage() {
  const { data, error } = useApi<Arch>("bigdata/architecture", 20000);
  const [selected, setSelected] = useState<string | null>("dash");
  const live = !!data?.live;
  const byName = useMemo(() => new Map((data?.vms ?? []).map((v) => [v.name, v])), [data]);
  const known = new Set(ROLES.map((r) => r.name));
  const others = (data?.vms ?? []).filter((v) => !known.has(v.name));
  const q = data?.quotas ?? {};
  const cpu = q.CPUS_ALL_REGIONS, gpuq = q.GPUS_ALL_REGIONS, ips = q.IN_USE_ADDRESSES;
  const layers = ["Application", "Streaming", "Big Data", "Support"];

  const { definition } = useMemo(() => {
    const states: Record<string, NodeState> = {}; const labels: Record<string, string> = {};
    ROLES.forEach((r) => {
      const v = byName.get(r.name);
      states[r.key] = !live ? "unknown" : !v ? "stopped" : v.status === "RUNNING" ? "running" : "stopped";
      labels[r.key] = v ? `${v.machine_type}${v.gpu.length ? " + T4" : ""} · ${v.vcpus ?? "?"} vCPU` : r.target;
    });
    return { definition: buildDiagram(states, labels) };
  }, [byName, live]);

  const role = ROLES.find((r) => r.key === selected);
  const svc = SERVICES.find((s) => s.key === selected);
  const ex = selected ? EXTRA[selected] : undefined;
  const lv = role ? byName.get(role.name) : undefined;

  return (
    <div>
      <PageHeader kicker="Architecture" title="Machines and services" description="The diagram shows the project as deployed: green machines are running, grey ones are stopped. Click any box for its specification and what it contains."
        right={<Badge color={live ? "#34d399" : "#fbbf24"} title={data?.reason}>{live ? `live · read ${ago(data?.read_at)}` : "static description"}</Badge>} />
      <ErrorNote error={error} />
      {data && !live && <p className="mb-4 rounded-xl border border-amber-400/30 bg-amber-400/5 p-3 text-xs text-amber-200">The Compute API could not be read from this machine, so machine states are unknown and the designed layout is shown. {data.reason}</p>}

      <div className="mb-5 grid gap-3 md:grid-cols-4">
        <Stat label="Machines running" value={live ? `${data?.running_count} / ${ROLES.length}` : `${ROLES.length}`} sub={live ? "of the designed layout" : "designed layout"} icon={<Server className="h-4 w-4" />} />
        <Stat label="vCPU running" value={live && cpu ? `${data?.running_vcpus} / ${cpu.limit}` : "n/a"} sub="project quota, all regions" icon={<Cpu className="h-4 w-4" />} />
        <Stat label="GPU" value={live && gpuq ? `${gpuq.usage} / ${gpuq.limit}` : "1 T4"} sub="NVIDIA T4 for the local model" icon={<Cloud className="h-4 w-4" />} />
        <Stat label="External addresses" value={live && ips ? `${ips.usage} / ${ips.limit}` : "n/a"} sub="us-central1" />
      </div>

      <Card className="mb-5">
        <CardHeader title="Architecture diagram" subtitle="Click a machine or a service" right={<div className="flex gap-2 text-[10px] text-slate-400"><span className="flex items-center gap-1"><Dot ok />running</span><span className="flex items-center gap-1"><Dot />stopped</span></div>} />
        <div className="grid gap-4 p-4">
          <ArchitectureDiagram definition={definition} selected={selected} onSelect={setSelected} />
          <aside className="rounded-2xl border border-slate-700/40 bg-ink-900/40 p-4 text-sm" aria-live="polite">
            {!selected && <p className="text-slate-400">Select a box in the diagram.</p>}
            {role && (
              <div>
                <div className="mb-3 flex items-start justify-between gap-2">
                  <div><div className="font-mono text-sm text-slate-100">{role.name}</div><div className="text-xs text-slate-400">{role.role}</div></div>
                  <button onClick={() => setSelected(null)} aria-label="Close" className="rounded-lg p-1 text-slate-500 hover:text-slate-200"><X className="h-4 w-4" /></button>
                </div>
                <div className="mb-3 flex items-center gap-2 text-xs text-slate-300"><Dot {...stateColor(lv?.status)} />{live ? (lv ? lv.status.toLowerCase() : "not created") : "state unknown"}</div>
                <dl className="mb-4 grid grid-cols-2 gap-x-3 gap-y-2 text-xs">
                  <dt className="text-slate-500">Machine type</dt><dd className="text-slate-200">{lv ? lv.machine_type : role.target}{!lv && " (target)"}</dd>
                  <dt className="text-slate-500">vCPU</dt><dd className="text-slate-200">{lv?.vcpus ?? "n/a"}</dd>
                  <dt className="text-slate-500">Memory (type)</dt><dd className="text-slate-200">{lv && ramGb(lv.machine_type) ? `${ramGb(lv.machine_type)} GB` : "n/a"}</dd>
                  <dt className="text-slate-500">GPU</dt><dd className="text-slate-200">{lv?.gpu.length ? lv.gpu.join(", ") : role.key === "qwen" ? "1x NVIDIA T4 (target)" : "none"}</dd>
                  <dt className="text-slate-500">Boot disk</dt><dd className="text-slate-200">{lv ? `${lv.disks_gb} GB` : "n/a"}</dd>
                  <dt className="text-slate-500">Zone</dt><dd className="text-slate-200">{lv?.zone ?? "n/a"}</dd>
                  <dt className="text-slate-500">Provisioning</dt><dd className="text-slate-200">{lv ? lv.provisioning.toLowerCase() : "n/a"}</dd>
                  <dt className="text-slate-500">Internal address</dt><dd className="font-mono text-slate-200">{lv?.internal_ip ?? "n/a"}</dd>
                  <dt className="text-slate-500">External address</dt><dd className="text-slate-200">{lv ? (lv.has_external_ip ? "yes" : "no") : "n/a"}</dd>
                </dl>
                <div className="mb-1 text-xs font-medium text-slate-300">What it contains</div>
                <ul className="mb-3 list-disc space-y-1 pl-4 text-xs text-slate-400">{role.contains.map((c) => <li key={c}>{c}</li>)}</ul>
                <div className="text-[11px] text-slate-500">Created by <span className="font-mono">{role.script}</span></div>
              </div>
            )}
            {(svc || ex) && (
              <div>
                <div className="mb-3 flex items-start justify-between gap-2">
                  <div><div className="text-sm text-slate-100">{svc?.name ?? ex?.name}</div><div className="text-xs text-slate-400">{svc?.role ?? ex?.role}</div></div>
                  <button onClick={() => setSelected(null)} aria-label="Close" className="rounded-lg p-1 text-slate-500 hover:text-slate-200"><X className="h-4 w-4" /></button>
                </div>
                <div className="mb-1 text-xs font-medium text-slate-300">{svc ? "What it holds or does" : "About"}</div>
                <ul className="list-disc space-y-1 pl-4 text-xs text-slate-400">{(svc?.contains ?? ex?.contains ?? []).map((c) => <li key={c}>{c}</li>)}</ul>
                {svc && <div className="mt-3"><Badge color="#a78bfa">Managed service</Badge></div>}
              </div>
            )}
          </aside>
        </div>
      </Card>

      <Card className="mb-5">
        <CardHeader title="Data path" subtitle="From the public dataset to an incident" />
        <ol className="grid gap-3 p-4 md:grid-cols-5">
          {FLOW.map(([n, t, d]) => (
            <li key={n} className="rounded-xl border border-slate-700/40 p-3 text-sm"><div className="mb-1 text-xs text-slate-500">Step {n}</div><div className="font-medium text-slate-100">{t}</div><div className="mt-1 text-xs text-slate-400">{d}</div></li>
          ))}
        </ol>
      </Card>

      {layers.map((layer) => {
        const roles = ROLES.filter((v) => v.layer === layer);
        const services = SERVICES.filter((m) => m.layer === layer);
        return (
          <Card key={layer} className="mb-5">
            <CardHeader title={layer} subtitle={`${roles.length} machine${roles.length > 1 ? "s" : ""}${services.length ? ` + ${services.length} managed service${services.length > 1 ? "s" : ""}` : ""}`} right={<Badge color={COLORS[layer]}>{layer}</Badge>} />
            <div className="overflow-x-auto p-4">
              <table className="w-full min-w-[760px] text-left text-sm">
                <thead className="text-xs text-slate-500"><tr><th className="pb-2 pr-3">Machine</th><th className="pb-2 pr-3">State</th><th className="pb-2 pr-3">Type</th><th className="pb-2 pr-3">Role</th><th className="pb-2">Created by</th></tr></thead>
                <tbody>
                  {roles.map((r) => {
                    const v = byName.get(r.name);
                    const drift = v && !r.target.startsWith(v.machine_type);
                    return (
                      <tr key={r.key} onClick={() => setSelected(r.key)} className="cursor-pointer border-t border-slate-700/30 align-top hover:bg-ink-800/40">
                        <td className="py-2 pr-3 font-mono text-xs text-slate-100">{r.name}</td>
                        <td className="py-2 pr-3 text-slate-300">{live ? (v ? <span className="flex items-center gap-2"><Dot {...stateColor(v.status)} />{v.status.toLowerCase()}</span> : <span className="text-slate-500">not created</span>) : <span className="text-slate-500">unknown</span>}</td>
                        <td className="py-2 pr-3 text-slate-300">{v ? <>{v.machine_type}{v.gpu.length ? " + T4" : ""}<div className="text-xs text-slate-500">{v.provisioning.toLowerCase()} · {v.vcpus ?? "?"} vCPU</div>{drift && <div className="text-xs text-amber-300">target: {r.target}</div>}</> : <>{r.target}<div className="text-xs text-slate-500">target</div></>}</td>
                        <td className="py-2 pr-3 text-slate-200">{r.role}</td>
                        <td className="py-2 font-mono text-xs text-slate-400">{r.script}</td>
                      </tr>
                    );
                  })}
                  {services.map((m) => (
                    <tr key={m.key} onClick={() => setSelected(m.key)} className="cursor-pointer border-t border-slate-700/30 align-top hover:bg-ink-800/40">
                      <td className="py-2 pr-3 text-slate-100">{m.name}</td>
                      <td className="py-2 pr-3 text-slate-300">managed</td>
                      <td className="py-2 pr-3 text-slate-400" colSpan={3}>{m.role}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Card>
        );
      })}

      {live && others.length > 0 && (
        <Card className="mb-5">
          <CardHeader title="Other machines in the project" subtitle="Not part of the designed layout: temporary workers or machines to retire" />
          <div className="overflow-x-auto p-4">
            <table className="w-full min-w-[560px] text-left text-sm">
              <thead className="text-xs text-slate-500"><tr><th className="pb-2 pr-3">Machine</th><th className="pb-2 pr-3">State</th><th className="pb-2 pr-3">Type</th><th className="pb-2">Provisioning</th></tr></thead>
              <tbody>
                {others.map((v) => (
                  <tr key={v.name} className="border-t border-slate-700/30">
                    <td className="py-2 pr-3 font-mono text-xs text-slate-100">{v.name}</td>
                    <td className="py-2 pr-3 text-slate-300"><span className="flex items-center gap-2"><Dot {...stateColor(v.status)} />{v.status.toLowerCase()}</span></td>
                    <td className="py-2 pr-3 text-slate-300">{v.machine_type} · {v.vcpus ?? "?"} vCPU</td>
                    <td className="py-2 text-slate-400">{v.provisioning.toLowerCase()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      )}
    </div>
  );
}
