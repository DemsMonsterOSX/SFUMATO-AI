"use client";

import { motion } from "framer-motion";
import { VERDICTS, VerdictKey } from "@/lib/utils";

export function Gauge({ value, label, color, size = 132 }: { value: number | null | undefined; label: string; color: string; size?: number }) {
  const r = size / 2 - 10;
  const c = 2 * Math.PI * r;
  const v = Math.max(0, Math.min(100, value ?? 0));
  return (
    <div className="relative grid place-items-center" style={{ width: size, height: size }}>
      <svg width={size} height={size} className="-rotate-90">
        <circle cx={size / 2} cy={size / 2} r={r} stroke="rgba(148,178,255,0.1)" strokeWidth={9} fill="none" />
        <motion.circle
          cx={size / 2}
          cy={size / 2}
          r={r}
          stroke={color}
          strokeWidth={9}
          fill="none"
          strokeLinecap="round"
          strokeDasharray={c}
          initial={{ strokeDashoffset: c }}
          animate={{ strokeDashoffset: value == null ? c : c * (1 - v / 100) }}
          transition={{ duration: 1.2, ease: [0.22, 1, 0.36, 1] }}
          style={{ filter: `drop-shadow(0 0 8px ${color}88)` }}
        />
      </svg>
      <div className="absolute text-center">
        <div className="text-3xl font-semibold tabular-nums text-white">{value ?? "—"}</div>
        <div className="label mt-0.5 text-[9.5px]">{label}</div>
      </div>
    </div>
  );
}

export function scoreColor(score?: number | null) {
  if (score == null) return "#475569";
  if (score >= 55) return "#fb7185";
  if (score > 25) return "#fbbf24";
  return "#34d399";
}

export function VerdictTitle({ verdict }: { verdict?: string | null }) {
  const v = verdict ? VERDICTS[verdict as VerdictKey] : null;
  return (
    <motion.div initial={{ opacity: 0, scale: 0.96 }} animate={{ opacity: 1, scale: 1 }} transition={{ duration: 0.5 }}>
      <div className="label">Final verdict</div>
      <div className="mt-1 text-3xl font-semibold tracking-tight md:text-4xl" style={{ color: v?.color ?? "#94a3b8", textShadow: v ? `0 0 30px ${v.color}55` : undefined }}>
        {v?.label ?? "Investigating…"}
      </div>
    </motion.div>
  );
}
