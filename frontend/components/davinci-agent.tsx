"use client";

import { Send, X } from "lucide-react";
import { FormEvent, useEffect, useRef, useState } from "react";
import { Badge } from "@/components/ui";
import { useApi } from "@/hooks/useApi";
import { api } from "@/lib/api";

type Info = { suggestions: string[]; llm_available: boolean; provider: string; model: string; reason: string };
type Reply = { answer: string; sources: string[]; engine: string; model: string; note: string | null };
type Msg = { role: "user" | "agent"; text: string; meta?: Reply };

/** Floating pop-up assistant for the Big Data results. Rules always answer; an LLM (Gemini) rewrites when it is configured. */
export function DaVinciAgent() {
  const [open, setOpen] = useState(false);
  const [q, setQ] = useState("");
  const [busy, setBusy] = useState(false);
  const [useLlm, setUseLlm] = useState(true);
  const [msgs, setMsgs] = useState<Msg[]>([]);
  const { data: info } = useApi<Info>(open ? "bigdata/agent/info" : null);
  const end = useRef<HTMLDivElement>(null);

  useEffect(() => { end.current?.scrollIntoView({ behavior: "smooth" }); }, [msgs, busy]);

  async function ask(text: string) {
    const question = text.trim();
    if (!question || busy) return;
    setQ("");
    setMsgs((m) => [...m, { role: "user", text: question }]);
    setBusy(true);
    try {
      const r = await api<Reply>("bigdata/agent", { method: "POST", body: JSON.stringify({ question, use_llm: useLlm }) });
      setMsgs((m) => [...m, { role: "agent", text: r.answer, meta: r }]);
    } catch (e) {
      setMsgs((m) => [...m, { role: "agent", text: `Erreur : ${e instanceof Error ? e.message : String(e)}` }]);
    } finally {
      setBusy(false);
    }
  }
  const submit = (e: FormEvent) => { e.preventDefault(); void ask(q); };
  const engineLabel = (m?: Reply) => (m ? (m.engine === "rules" ? "règles" : `${m.engine} · ${m.model}`) : "");

  return (
    <>
      <button onClick={() => setOpen((o) => !o)} aria-label={open ? "Fermer Da Vinci AI" : "Ouvrir Da Vinci AI"}
        className="fixed bottom-5 right-5 z-50 flex items-center gap-2 rounded-full border border-cyan-400/40 bg-ink-950/90 py-1.5 pl-1.5 pr-4 text-sm font-medium text-white shadow-glow backdrop-blur transition hover:scale-[1.03]">
        {open ? (
          <span className="grid h-10 w-10 place-items-center rounded-full bg-ink-800"><X className="h-4 w-4" /></span>
        ) : (
          // eslint-disable-next-line @next/next/no-img-element
          <img src="/davinci/icon.webp" alt="" width={40} height={40} className="h-10 w-10 rounded-full ring-1 ring-cyan-400/50" />
        )}
        <span className="hidden sm:inline">Da Vinci <span className="bg-gradient-to-r from-cyan-300 to-violet-400 bg-clip-text font-semibold text-transparent">AI</span></span>
      </button>
      {open && (
        <div role="dialog" aria-label="Da Vinci AI"
          className="fixed bottom-20 right-3 z-50 flex h-[min(560px,calc(100vh-7rem))] w-[min(400px,calc(100vw-1.5rem))] flex-col overflow-hidden rounded-2xl border border-line bg-ink-950/95 shadow-2xl backdrop-blur-xl sm:right-5">
          <div className="flex items-center justify-between border-b border-line px-4 py-3">
            <div className="flex items-center gap-2">
              {/* eslint-disable-next-line @next/next/no-img-element */}
              <img src="/davinci/icon.webp" alt="" width={32} height={32} className="h-8 w-8 rounded-full ring-1 ring-cyan-400/40" />
              <div className="leading-tight">
                <div className="text-sm font-semibold text-white">Da Vinci AI</div>
                <div className="text-[10px] text-slate-400">Questions sur le projet : Big Data, CVE, procédures, flux, API</div>
              </div>
            </div>
            <label className="flex cursor-pointer items-center gap-1.5 text-[10px] text-slate-300"
              title={info ? (info.llm_available ? `${info.provider} · ${info.model}` : info.reason) : ""}>
              <input type="checkbox" checked={useLlm && !!info?.llm_available} disabled={!info?.llm_available}
                onChange={(e) => setUseLlm(e.target.checked)} className="accent-cyan-400" />
              {info?.llm_available ? `IA ${info.provider === "ollama" ? "Qwen" : info.provider}` : "Règles seules"}
            </label>
          </div>
          <div className="flex-1 space-y-3 overflow-y-auto px-4 py-3 text-sm">
            {msgs.length === 0 && (
              <div className="space-y-2">
                {/* eslint-disable-next-line @next/next/no-img-element */}
                <img src="/davinci/logo.webp" alt="Da Vinci AI" width={120} height={120} className="mx-auto h-28 w-28 object-contain" />
                <p className="text-xs leading-relaxed text-slate-400">
                  Je réponds à partir des résultats publiés, des procédures, du flux CVE, du bucket et de la documentation du projet, jamais à partir de ma mémoire. {info && !info.llm_available && "Aucune clé IA n'est configurée : j'utilise des règles déterministes."}
                </p>
                {(info?.suggestions ?? []).map((s) => (
                  <button key={s} onClick={() => void ask(s)} className="block w-full rounded-xl border border-line bg-ink-900/60 px-3 py-2 text-left text-xs text-slate-200 transition hover:border-cyan-400/40">{s}</button>
                ))}
              </div>
            )}
            {msgs.map((m, i) => (
              <div key={i} className={m.role === "user" ? "flex justify-end" : "flex justify-start"}>
                <div className={m.role === "user" ? "max-w-[85%] rounded-2xl rounded-br-sm bg-electric-500/30 px-3 py-2 text-slate-100" : "max-w-[92%] rounded-2xl rounded-bl-sm border border-line bg-ink-900/70 px-3 py-2 text-slate-200"}>
                  <p className="whitespace-pre-wrap leading-relaxed">{m.text}</p>
                  {m.meta && (
                    <div className="mt-2 flex flex-wrap items-center gap-1.5">
                      <Badge color={m.meta.engine === "rules" ? "#a78bfa" : "#22d3ee"}>{engineLabel(m.meta)}</Badge>
                      {m.meta.sources.map((s) => <span key={s} className="font-mono text-[10px] text-slate-500">{s}</span>)}
                      {m.meta.note && <span className="text-[10px] text-amber-300">{m.meta.note}</span>}
                    </div>
                  )}
                </div>
              </div>
            ))}
            {busy && <div className="text-xs text-slate-400">Da Vinci réfléchit…</div>}
            <div ref={end} />
          </div>
          <form onSubmit={submit} className="flex items-center gap-2 border-t border-line p-3">
            <input value={q} onChange={(e) => setQ(e.target.value)} maxLength={500} placeholder="Pose une question…"
              className="min-w-0 flex-1 rounded-xl border border-line bg-ink-900/70 px-3 py-2 text-sm text-slate-100 outline-none placeholder:text-slate-500 focus:border-cyan-400/50" />
            <button type="submit" disabled={busy || !q.trim()} aria-label="Envoyer"
              className="grid h-9 w-9 place-items-center rounded-xl bg-cyan-500/80 text-white transition disabled:opacity-40">
              <Send className="h-4 w-4" />
            </button>
          </form>
        </div>
      )}
    </>
  );
}
