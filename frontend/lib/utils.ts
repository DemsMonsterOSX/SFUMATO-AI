import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export const VERDICTS = {
  TRUE_POSITIVE: { label: "True Positive", short: "TP", color: "#fb7185", tw: "text-verdict-tp", ring: "ring-rose-400/40", bg: "bg-rose-500/10" },
  FALSE_POSITIVE: { label: "False Positive", short: "FP", color: "#38bdf8", tw: "text-verdict-fp", ring: "ring-sky-400/40", bg: "bg-sky-500/10" },
  LEGITIMATE_ACTIVITY: { label: "Legitimate Activity", short: "LEGIT", color: "#34d399", tw: "text-verdict-legit", ring: "ring-emerald-400/40", bg: "bg-emerald-500/10" },
  INCONCLUSIVE: { label: "Inconclusive", short: "INC", color: "#fbbf24", tw: "text-verdict-inc", ring: "ring-amber-400/40", bg: "bg-amber-500/10" },
} as const;
export type VerdictKey = keyof typeof VERDICTS;

export const SEVERITY_COLORS: Record<string, string> = {
  informational: "#64748b",
  low: "#38bdf8",
  medium: "#fbbf24",
  high: "#fb923c",
  critical: "#f43f5e",
};

export const POLARITY_COLORS: Record<string, string> = {
  malicious: "#fb7185",
  suspicious: "#fbbf24",
  benign: "#34d399",
  neutral: "#94a3b8",
};

export const CTI_VERDICT_COLORS: Record<string, string> = {
  malicious: "#fb7185",
  suspicious: "#fbbf24",
  allowlisted: "#34d399",
  unknown: "#a78bfa",
  not_found: "#64748b",
};
