import type { Config } from "tailwindcss";

const config: Config = {
  content: ["./app/**/*.{ts,tsx}", "./components/**/*.{ts,tsx}", "./lib/**/*.{ts,tsx}", "./hooks/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        ink: { 950: "#03060f", 900: "#060b1a", 850: "#08102a", 800: "#0b1430", 700: "#111c3d", 600: "#1a2850" },
        line: "rgba(148, 178, 255, 0.10)",
        cyan: { 300: "#67e8f9", 400: "#22d3ee", 500: "#06b6d4" },
        electric: { 400: "#60a5fa", 500: "#3b82f6", 600: "#2563eb" },
        violet: { 400: "#a78bfa", 500: "#8b5cf6" },
        verdict: { tp: "#fb7185", fp: "#38bdf8", legit: "#34d399", inc: "#fbbf24" },
      },
      fontFamily: {
        sans: ["var(--font-geist-sans)", "ui-sans-serif", "system-ui"],
        mono: ["var(--font-geist-mono)", "ui-monospace", "SFMono-Regular"],
      },
      boxShadow: {
        glow: "0 0 0 1px rgba(34,211,238,0.25), 0 8px 40px -12px rgba(34,211,238,0.35)",
        card: "0 1px 0 0 rgba(255,255,255,0.04) inset, 0 20px 50px -30px rgba(0,0,0,0.8)",
      },
      keyframes: {
        shimmer: { "0%": { backgroundPosition: "-200% 0" }, "100%": { backgroundPosition: "200% 0" } },
        pulseRing: { "0%": { transform: "scale(0.8)", opacity: "0.8" }, "100%": { transform: "scale(2.2)", opacity: "0" } },
        scan: { "0%": { transform: "translateY(-100%)" }, "100%": { transform: "translateY(100%)" } },
      },
      animation: {
        shimmer: "shimmer 2.2s linear infinite",
        pulseRing: "pulseRing 1.6s cubic-bezier(0.2,0.6,0.4,1) infinite",
        scan: "scan 3s linear infinite",
      },
    },
  },
  plugins: [],
};
export default config;
