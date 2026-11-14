"use client";

import { motion } from "framer-motion";
import { Activity, Brain, Database, FlaskConical, GitBranch, LayoutDashboard, Radar, Settings, ShieldHalf } from "lucide-react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { ReactNode } from "react";
import { useApi } from "@/hooks/useApi";
import { cn } from "@/lib/utils";
import { Dot } from "./ui";

const NAV = [
  { href: "/", label: "Command Center", icon: LayoutDashboard },
  { href: "/incidents", label: "Investigations", icon: Activity },
  { href: "/intel", label: "Threat Intelligence", icon: Radar },
  { href: "/playbooks", label: "SOAR Playbooks", icon: GitBranch },
  { href: "/observatory", label: "ML & AI Observatory", icon: Brain },
  { href: "/bigdata", label: "Big Data Lab", icon: Database },
  { href: "/simulator", label: "Incident Simulator", icon: FlaskConical },
  { href: "/settings", label: "Settings", icon: Settings },
];

type Status = {
  platform: { deployment_mode: string; cti_mode: string; version: string };
  soar: { queued: number; running: number; worker: { mode: string; id: string | null } };
  ml: { ready: boolean; model_name?: string };
  ai: { selected: string; model: string };
};

export function Shell({ children }: { children: ReactNode }) {
  const path = usePathname();
  const { data: status, error } = useApi<Status>("status", 8000);
  return (
    <div className="flex min-h-screen">
      <aside className="sticky top-0 hidden h-screen w-[248px] shrink-0 flex-col border-r border-line bg-ink-950/70 px-4 py-5 backdrop-blur-xl lg:flex">
        <Link href="/" className="mb-8 flex items-center gap-3 px-2">
          <div className="relative grid h-10 w-10 place-items-center rounded-xl bg-gradient-to-br from-cyan-400 via-electric-500 to-violet-500 shadow-glow">
            <ShieldHalf className="h-5 w-5 text-white" />
          </div>
          <div className="leading-tight">
            <div className="text-[15px] font-semibold tracking-tight text-white">Sfumato</div>
            <div className="text-[11px] text-slate-400">Autonomous SOC</div>
          </div>
        </Link>
        <nav className="flex flex-1 flex-col gap-1">
          {NAV.map(({ href, label, icon: Icon }) => {
            const active = href === "/" ? path === "/" : path.startsWith(href);
            return (
              <Link key={href} href={href} className={cn("relative flex items-center gap-3 rounded-xl px-3 py-2.5 text-sm transition-colors", active ? "text-white" : "text-slate-400 hover:bg-ink-800/60 hover:text-slate-100")}>
                {active && (
                  <motion.span layoutId="nav-active" className="absolute inset-0 rounded-xl border border-cyan-400/25 bg-gradient-to-r from-cyan-500/15 via-electric-500/10 to-transparent" transition={{ type: "spring", stiffness: 380, damping: 32 }} />
                )}
                <Icon className={cn("relative h-4 w-4", active && "text-cyan-300")} />
                <span className="relative">{label}</span>
              </Link>
            );
          })}
        </nav>
        <div className="mt-6 space-y-2 rounded-xl border border-line bg-ink-900/60 p-3 text-[11px]">
          <div className="flex items-center justify-between">
            <span className="text-slate-400">API</span>
            <span className="flex items-center gap-1.5 text-slate-200">
              <Dot ok={!error && !!status} pulse /> {error ? "unreachable" : status ? "online" : "…"}
            </span>
          </div>
          <div className="flex items-center justify-between">
            <span className="text-slate-400">Deployment</span>
            <span className="font-medium uppercase text-slate-200">{status?.platform.deployment_mode ?? "—"}</span>
          </div>
          <div className="flex items-center justify-between">
            <span className="text-slate-400">AI</span>
            <span className="max-w-[120px] truncate text-slate-200" title={status?.ai.model}>{status?.ai.selected ?? "—"}</span>
          </div>
        </div>
        <div className="mt-4 px-2 text-[10px] leading-relaxed text-slate-500">
          Created by Florian Payet, Damien Leclercq &amp; Adrien Scazzola
        </div>
      </aside>
      <div className="flex min-w-0 flex-1 flex-col">
        <header className="sticky top-0 z-30 flex items-center justify-between gap-4 border-b border-line bg-ink-950/60 px-5 py-3 backdrop-blur-xl md:px-8">
          <div className="flex items-center gap-2 lg:hidden">
            <ShieldHalf className="h-5 w-5 text-cyan-300" />
            <span className="font-semibold">Sfumato</span>
          </div>
          <div className="hidden items-center gap-2 text-xs text-slate-400 md:flex">
            <span className="h-1.5 w-1.5 rounded-full bg-cyan-400 shadow-[0_0_12px_#22d3ee]" />
            Autonomous investigation pipeline · display-only response recommendations
          </div>
          <div className="flex items-center gap-2 text-[11px]">
            {status && (
              <>
                <span className="rounded-full border border-line bg-ink-800/70 px-2.5 py-1 text-slate-300">
                  CTI default: <b className={status.platform.cti_mode === "live" ? "text-cyan-300" : "text-violet-300"}>{status.platform.cti_mode === "live" ? "LIVE INTELLIGENCE" : "REPRODUCIBLE DEMO"}</b>
                </span>
                <span className="hidden rounded-full border border-line bg-ink-800/70 px-2.5 py-1 text-slate-300 sm:inline">
                  Queue: <b className="text-white">{status.soar.queued}</b> · Running: <b className="text-cyan-300">{status.soar.running}</b>
                </span>
              </>
            )}
          </div>
        </header>
        <nav className="flex gap-1 overflow-x-auto border-b border-line px-3 py-2 lg:hidden">
          {NAV.map(({ href, label }) => (
            <Link key={href} href={href} className={cn("whitespace-nowrap rounded-lg px-3 py-1.5 text-xs", (href === "/" ? path === "/" : path.startsWith(href)) ? "bg-ink-700 text-white" : "text-slate-400")}>
              {label}
            </Link>
          ))}
        </nav>
        <main className="mx-auto w-full max-w-[1500px] flex-1 px-4 py-7 md:px-8">{children}</main>
      </div>
    </div>
  );
}
