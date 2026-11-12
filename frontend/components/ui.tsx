"use client";

import * as TabsPrimitive from "@radix-ui/react-tabs";
import { motion } from "framer-motion";
import { Loader2 } from "lucide-react";
import Link from "next/link";
import { ReactNode } from "react";
import { CTI_VERDICT_COLORS, POLARITY_COLORS, SEVERITY_COLORS, VERDICTS, VerdictKey, cn } from "@/lib/utils";

export function Card({ className, children, hover, delay = 0 }: { className?: string; children: ReactNode; hover?: boolean; delay?: number }) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.45, delay, ease: [0.22, 1, 0.36, 1] }}
      className={cn("glass p-5", hover && "glass-hover", className)}
    >
      {children}
    </motion.div>
  );
}

export function CardHeader({ title, subtitle, icon, right }: { title: ReactNode; subtitle?: ReactNode; icon?: ReactNode; right?: ReactNode }) {
  return (
    <div className="mb-4 flex items-start justify-between gap-3">
      <div className="flex items-start gap-3">
        {icon && <div className="mt-0.5 rounded-lg border border-line bg-ink-700/60 p-2 text-cyan-300">{icon}</div>}
        <div>
          <h3 className="text-[15px] font-semibold tracking-tight text-slate-100">{title}</h3>
          {subtitle && <p className="mt-0.5 text-xs text-slate-400">{subtitle}</p>}
        </div>
      </div>
      {right}
    </div>
  );
}

export function PageHeader({ title, kicker, description, right }: { title: string; kicker?: string; description?: ReactNode; right?: ReactNode }) {
  return (
    <div className="mb-7 flex flex-wrap items-end justify-between gap-4">
      <div>
        {kicker && <div className="label mb-2 text-cyan-300/80">{kicker}</div>}
        <h1 className="text-3xl font-semibold tracking-tight text-white md:text-[34px]">{title}</h1>
        {description && <p className="mt-2 max-w-3xl text-sm text-slate-400">{description}</p>}
      </div>
      {right}
    </div>
  );
}

export function Badge({ children, color, className, title }: { children: ReactNode; color?: string; className?: string; title?: string }) {
  return (
    <span
      title={title}
      className={cn("inline-flex items-center gap-1 whitespace-nowrap rounded-full border px-2 py-0.5 text-[11px] font-medium", className)}
      style={color ? { color, borderColor: `${color}40`, background: `${color}14` } : undefined}
    >
      {children}
    </span>
  );
}

export function VerdictBadge({ verdict, size = "sm" }: { verdict?: string | null; size?: "sm" | "lg" }) {
  if (!verdict) return <Badge className="border-line text-slate-400">pending</Badge>;
  const v = VERDICTS[verdict as VerdictKey];
  if (!v) return <Badge>{verdict}</Badge>;
  return (
    <Badge color={v.color} className={size === "lg" ? "px-3 py-1 text-sm" : ""}>
      <span className="h-1.5 w-1.5 rounded-full" style={{ background: v.color }} />
      {v.label}
    </Badge>
  );
}

export function SeverityBadge({ severity }: { severity: string }) {
  return <Badge color={SEVERITY_COLORS[severity] ?? "#94a3b8"}>{severity}</Badge>;
}

export function PolarityBadge({ polarity }: { polarity: string }) {
  return <Badge color={POLARITY_COLORS[polarity]}>{polarity}</Badge>;
}

export function CtiVerdictBadge({ verdict }: { verdict: string }) {
  return <Badge color={CTI_VERDICT_COLORS[verdict] ?? "#94a3b8"}>{verdict.replace("_", " ")}</Badge>;
}

export function OriginBadge({ origin }: { origin: string }) {
  if (origin === "demo_fixture")
    return (
      <Badge color="#a78bfa" title="Recorded demonstration fixture — not live threat intelligence">
        DEMO FIXTURE
      </Badge>
    );
  if (origin === "cache") return <Badge color="#60a5fa" title="Live result served from cache">LIVE · CACHED</Badge>;
  return <Badge color="#22d3ee" title="Real-time query to the provider">LIVE</Badge>;
}

const STATUS_COLORS: Record<string, string> = {
  queued: "#94a3b8",
  running: "#22d3ee",
  completed: "#34d399",
  needs_review: "#fbbf24",
  failed: "#fb7185",
  skipped: "#64748b",
  retrying: "#fb923c",
  pending: "#475569",
  cancelled: "#64748b",
};

export function StatusBadge({ status }: { status: string }) {
  const c = STATUS_COLORS[status] ?? "#94a3b8";
  return (
    <Badge color={c}>
      {status === "running" ? <Loader2 className="h-3 w-3 animate-spin" /> : <span className="h-1.5 w-1.5 rounded-full" style={{ background: c }} />}
      {status.replace("_", " ")}
    </Badge>
  );
}

export function Dot({ ok, warn, pulse }: { ok?: boolean; warn?: boolean; pulse?: boolean }) {
  const c = ok ? "#34d399" : warn ? "#fbbf24" : "#fb7185";
  return (
    <span className="relative inline-flex h-2 w-2">
      {pulse && <span className="absolute inline-flex h-full w-full animate-pulseRing rounded-full" style={{ background: c }} />}
      <span className="relative inline-flex h-2 w-2 rounded-full" style={{ background: c }} />
    </span>
  );
}

export function Stat({ label, value, sub, accent, icon, href, delay }: { label: string; value: ReactNode; sub?: ReactNode; accent?: string; icon?: ReactNode; href?: string; delay?: number }) {
  const inner = (
    <Card hover className="relative overflow-hidden p-4" delay={delay}>
      <div className="pointer-events-none absolute -right-10 -top-10 h-28 w-28 rounded-full opacity-20 blur-2xl" style={{ background: accent ?? "#22d3ee" }} />
      <div className="flex items-center justify-between">
        <span className="label">{label}</span>
        <span style={{ color: accent ?? "#67e8f9" }}>{icon}</span>
      </div>
      <div className="mt-3 text-3xl font-semibold tabular-nums tracking-tight text-white">{value}</div>
      {sub && <div className="mt-1 text-xs text-slate-400">{sub}</div>}
    </Card>
  );
  return href ? <Link href={href}>{inner}</Link> : inner;
}

export function Button({ children, onClick, disabled, variant = "primary", className, type = "button" }: { children: ReactNode; onClick?: () => void; disabled?: boolean; variant?: "primary" | "ghost" | "outline"; className?: string; type?: "button" | "submit" }) {
  return (
    <button
      type={type}
      onClick={onClick}
      disabled={disabled}
      className={cn(
        "inline-flex items-center justify-center gap-2 rounded-xl px-4 py-2 text-sm font-medium transition-all disabled:cursor-not-allowed disabled:opacity-50",
        variant === "primary" &&
          "bg-gradient-to-r from-cyan-500 via-electric-500 to-violet-500 text-white shadow-glow hover:brightness-110 active:scale-[0.98]",
        variant === "outline" && "border border-line bg-ink-800/60 text-slate-200 hover:border-cyan-400/40 hover:text-white",
        variant === "ghost" && "text-slate-300 hover:bg-ink-700/60 hover:text-white",
        className,
      )}
    >
      {children}
    </button>
  );
}

export function Tabs({ tabs, defaultValue, className }: { tabs: { value: string; label: ReactNode; content: ReactNode }[]; defaultValue?: string; className?: string }) {
  return (
    <TabsPrimitive.Root defaultValue={defaultValue ?? tabs[0]?.value} className={className}>
      <TabsPrimitive.List className="mb-5 flex flex-wrap gap-1 rounded-xl border border-line bg-ink-900/60 p-1">
        {tabs.map((t) => (
          <TabsPrimitive.Trigger
            key={t.value}
            value={t.value}
            className="rounded-lg px-3.5 py-1.5 text-sm text-slate-400 transition-colors hover:text-slate-100 data-[state=active]:bg-ink-700 data-[state=active]:text-white data-[state=active]:shadow-[inset_0_0_0_1px_rgba(34,211,238,0.25)]"
          >
            {t.label}
          </TabsPrimitive.Trigger>
        ))}
      </TabsPrimitive.List>
      {tabs.map((t) => (
        <TabsPrimitive.Content key={t.value} value={t.value} className="outline-none">
          {t.content}
        </TabsPrimitive.Content>
      ))}
    </TabsPrimitive.Root>
  );
}

export function Empty({ title, children, icon }: { title: string; children?: ReactNode; icon?: ReactNode }) {
  return (
    <div className="flex flex-col items-center justify-center rounded-xl border border-dashed border-line py-10 text-center">
      {icon && <div className="mb-3 text-slate-500">{icon}</div>}
      <div className="text-sm font-medium text-slate-300">{title}</div>
      {children && <div className="mt-1 max-w-md text-xs text-slate-500">{children}</div>}
    </div>
  );
}

export function Skeleton({ className }: { className?: string }) {
  return <div className={cn("animate-shimmer rounded-lg bg-[linear-gradient(90deg,rgba(255,255,255,0.03),rgba(255,255,255,0.08),rgba(255,255,255,0.03))] bg-[length:200%_100%]", className)} />;
}

export function ErrorNote({ error }: { error: string | null }) {
  if (!error) return null;
  return <div className="rounded-xl border border-rose-400/30 bg-rose-500/10 px-4 py-3 text-sm text-rose-200">{error}</div>;
}

export function JsonBlock({ value, className, max = "max-h-[520px]" }: { value: unknown; className?: string; max?: string }) {
  const text = typeof value === "string" ? value : JSON.stringify(value, null, 2);
  const html = text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/("(?:\\.|[^"\\])*")(\s*:)?|\b(true|false|null)\b|(-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)/g, (m, str, colon, kw, num) => {
      if (str) return colon ? `<span class="text-cyan-300">${str}</span>${colon}` : `<span class="text-emerald-300">${str}</span>`;
      if (kw) return `<span class="text-violet-300">${kw}</span>`;
      if (num) return `<span class="text-amber-300">${num}</span>`;
      return m;
    });
  return (
    <pre
      className={cn("overflow-auto rounded-xl border border-line bg-ink-950/80 p-4 font-mono text-[12px] leading-relaxed text-slate-300", max, className)}
      dangerouslySetInnerHTML={{ __html: html }}
    />
  );
}

export function KV({ k, v, mono }: { k: string; v: ReactNode; mono?: boolean }) {
  return (
    <div className="flex items-start justify-between gap-4 border-b border-line/60 py-2 last:border-0">
      <span className="text-xs text-slate-400">{k}</span>
      <span className={cn("text-right text-sm text-slate-200", mono && "font-mono text-xs")}>{v ?? "—"}</span>
    </div>
  );
}

export function EvidenceChip({ id }: { id: string }) {
  const color = id.startsWith("EV-CTI") ? "#22d3ee" : id.startsWith("EV-BEH") ? "#fb7185" : id.startsWith("EV-CTX") ? "#34d399" : id.startsWith("EV-ML") ? "#a78bfa" : "#fbbf24";
  return (
    <a href={`#${id}`} className="font-mono">
      <Badge color={color}>{id}</Badge>
    </a>
  );
}

export function Bar({ value, max = 100, color = "#22d3ee" }: { value: number; max?: number; color?: string }) {
  return (
    <div className="h-1.5 w-full overflow-hidden rounded-full bg-ink-700">
      <motion.div className="h-full rounded-full" style={{ background: color }} initial={{ width: 0 }} animate={{ width: `${Math.min(100, (value / max) * 100)}%` }} transition={{ duration: 0.8, ease: "easeOut" }} />
    </div>
  );
}
