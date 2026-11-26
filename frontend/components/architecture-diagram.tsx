"use client";

import { useEffect, useRef, useState } from "react";

export type NodeState = "running" | "stopped" | "unknown";
export type Labels = Record<string, string>;

/** Mermaid source of the platform. `states` colours the machines (green running, grey stopped); `labels` carries the real machine type when it is known. */
export function buildDiagram(states: Record<string, NodeState>, labels: Labels): string {
  const L = (k: string, fallback: string) => labels[k] ?? fallback;
  const cls = (k: string) => (states[k] === "running" ? "run" : states[k] === "stopped" ? "stop" : "vm");
  return `flowchart TB
  user(["👤 Utilisateur<br/>jury, équipe"]):::ext
  ds[("Dataset public<br/>CSE-CIC-IDS2018")]:::ext

  subgraph app["Application"]
    direction LR
    dash["<b>sfumato</b><br/>${L("dash", "Dashboard")}<br/><i>Next.js · FastAPI · Caddy</i>"]:::${cls("dash")}
  end

  subgraph stream["Streaming · Kafka + Flink"]
    direction LR
    k1["<b>kafka-1</b><br/>${L("k1", "broker + stress test")}<br/><i>producteur · contrôleur</i>"]:::${cls("k1")}
    k2["<b>kafka-2</b><br/>${L("k2", "broker")}<br/><i>scorer · CVE</i>"]:::${cls("k2")}
    k3["<b>kafka-3</b><br/>${L("k3", "broker")}<br/><i>scorer</i>"]:::${cls("k3")}
    flink["<b>sfumato-flink</b><br/>${L("flink", "Flink")}<br/><i>2 jobs SQL</i>"]:::${cls("flink")}
  end

  subgraph ai["IA locale et logs"]
    direction LR
    qwen["<b>sfumato-qwen-clone</b><br/>${L("qwen", "GPU")}<br/><i>Ollama · Qwen</i>"]:::${cls("qwen")}
    elk["<b>sfumato-elk</b><br/>${L("elk", "logs")}<br/><i>Elasticsearch · Logstash</i>"]:::${cls("elk")}
    soar["<b>sfumato-soar</b><br/>${L("soar", "SOAR")}<br/><i>Shuffle · webhook</i>"]:::${cls("soar")}
  end

  subgraph work["Traitement"]
    direction LR
    lg["<b>sfumato-lg</b><br/>${L("lg", "worker")}<br/><i>charge · PCAP · Zeek</i>"]:::${cls("lg")}
  end

  subgraph gcp["Services gérés Google Cloud"]
    direction LR
    bucket[("Cloud Storage<br/>CSV · Parquet · modèles")]:::svc
    spark["Dataproc<br/>Spark serverless"]:::svc
    bq["BigQuery<br/>SQL analytique"]:::svc
    cve["Cloud Run + Scheduler<br/>flux CVE"]:::svc
  end

  user -->|HTTPS + connexion| dash
  ds -->|copie| bucket
  dash -->|questions Da Vinci| qwen
  dash -->|logs| elk
  dash -->|webhook fin d'enquête| soar
  dash -->|test de charge| k1
  dash -->|résultats, modèles| bucket
  cve -.->|toutes les 12 h| dash
  lg ==>|rejeu de connexions| k1
  lg -->|Zeek vers Parquet| bucket
  k1 ---|réplication x3| k2
  k2 --- k3
  k3 --- k1
  k1 -->|conn-events| flink
  flink -->|alertes| k3
  bucket <-->|lecture, écriture| spark
  bucket -->|tables externes| bq

  classDef vm fill:#0e1a38,stroke:#3b82f6,color:#e2e8f0,stroke-width:1.5px;
  classDef run fill:#0b2a26,stroke:#34d399,color:#e2e8f0,stroke-width:2px;
  classDef stop fill:#151c30,stroke:#64748b,color:#94a3b8,stroke-width:1.5px,stroke-dasharray:5 4;
  classDef svc fill:#1a1438,stroke:#a78bfa,color:#e2e8f0,stroke-width:1.5px;
  classDef ext fill:#2a1f0c,stroke:#fbbf24,color:#fde68a,stroke-width:1.5px;
`;
}

/** Renders the Mermaid diagram and makes every node clickable (mouse and keyboard). */
export function ArchitectureDiagram({ definition, selected, onSelect }: { definition: string; selected: string | null; onSelect: (key: string) => void }) {
  const host = useRef<HTMLDivElement>(null);
  const [error, setError] = useState<string | null>(null);
  const [full, setFull] = useState(false);
  const fullRef = useRef(false);
  fullRef.current = full;
  const applyZoom = () => {
    const el = host.current?.querySelector("svg");
    if (!el) return;
    const natural = Number(el.dataset.natural || 0);
    if (fullRef.current) { el.style.width = `${natural}px`; el.style.maxWidth = "none"; el.style.minWidth = ""; }
    else { el.style.width = "100%"; el.style.maxWidth = "100%"; el.style.minWidth = `${Math.min(natural, 1250)}px`; }
  };
  const cb = useRef(onSelect);
  cb.current = onSelect;

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const mermaid = (await import("mermaid")).default;
        mermaid.initialize({
          startOnLoad: false, theme: "base", securityLevel: "strict",
          flowchart: { curve: "basis", htmlLabels: true, padding: 14, nodeSpacing: 28, rankSpacing: 46 },
          themeVariables: {
            background: "transparent", primaryColor: "#0e1a38", primaryBorderColor: "#3b82f6", primaryTextColor: "#e2e8f0", lineColor: "#64748b",
            clusterBkg: "rgba(10,18,40,0.55)", clusterBorder: "#1e2a4d", edgeLabelBackground: "#0a1228", fontSize: "13px",
          },
        });
        const { svg } = await mermaid.render(`arch-${Date.now()}`, definition);
        if (cancelled || !host.current) return;
        host.current.innerHTML = svg;
        const el = host.current.querySelector("svg");
        if (el) { el.removeAttribute("height"); el.style.height = "auto"; el.dataset.natural = String(Math.round(el.viewBox.baseVal.width)); }
        applyZoom();
        host.current.querySelectorAll<SVGGElement>("g.node").forEach((n) => {
          const m = /flowchart-(.+)-\d+$/.exec(n.id);
          if (!m) return;
          const key = m[1];
          n.dataset.key = key;
          n.style.cursor = "pointer";
          n.setAttribute("tabindex", "0");
          n.setAttribute("role", "button");
          n.addEventListener("click", () => cb.current(key));
          n.addEventListener("keydown", (e) => { if ((e as KeyboardEvent).key === "Enter" || (e as KeyboardEvent).key === " ") { e.preventDefault(); cb.current(key); } });
        });
        setError(null);
      } catch (e) {
        if (!cancelled) setError(e instanceof Error ? e.message : String(e));
      }
    })();
    return () => { cancelled = true; };
  }, [definition]);

  useEffect(() => { applyZoom(); // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [full]);

  useEffect(() => {
    host.current?.querySelectorAll<SVGGElement>("g.node").forEach((n) => n.classList.toggle("arch-sel", n.dataset.key === selected));
  }, [selected, definition]);

  return (
    <div>
      <style>{`.arch-host .node.arch-sel rect, .arch-host .node.arch-sel path, .arch-host .node.arch-sel polygon { stroke: #22d3ee !important; stroke-width: 3px !important; filter: drop-shadow(0 0 8px rgba(34,211,238,0.55)); }
.arch-host .node { transition: filter .15s; } .arch-host .node:hover { filter: brightness(1.25); } .arch-host .node:focus-visible { outline: 2px solid #22d3ee; outline-offset: 3px; }`}</style>
      <div className="mb-2 flex justify-end">
        <button onClick={() => setFull((f) => !f)} className="rounded-lg border border-slate-700/50 px-2.5 py-1 text-[11px] text-slate-300 hover:border-cyan-400/50 hover:text-white">{full ? "Ajuster à la page" : "Taille réelle"}</button>
      </div>
      <div ref={host} className="arch-host overflow-x-auto" aria-label="Schéma de l'architecture, cliquer sur une machine pour son détail" />
      {error && <p className="p-3 text-xs text-amber-300">Le schéma n&apos;a pas pu être affiché ({error}). Le tableau ci-dessous donne les mêmes informations.</p>}
    </div>
  );
}
