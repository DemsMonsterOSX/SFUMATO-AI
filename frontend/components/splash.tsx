"use client";

import { AnimatePresence, motion } from "framer-motion";
import { ArrowRight } from "lucide-react";
import { useCallback, useEffect, useState } from "react";

const KEY = "sfumato-splash-seen";
const DUST = Array.from({ length: 26 }, (_, i) => ({
  left: `${(i * 37 + 11) % 100}%`,
  size: 1 + ((i * 7) % 3),
  delay: (i % 9) * 0.7,
  duration: 9 + ((i * 5) % 8),
}));

/** Full-screen welcome shown once per browser session, before the dashboard: the logo comes out of a "sfumato" haze. */
export function Splash() {
  const [open, setOpen] = useState(true);
  const [ready, setReady] = useState(false);
  const [reduced, setReduced] = useState(false);

  useEffect(() => {
    try {
      if (sessionStorage.getItem(KEY)) setOpen(false);
    } catch {
      /* storage blocked: the splash simply shows on every load */
    }
    setReduced(window.matchMedia?.("(prefers-reduced-motion: reduce)").matches ?? false);
  }, []);

  useEffect(() => {
    if (!open) return;
    const t = setTimeout(() => setReady(true), reduced ? 0 : 2300);
    return () => clearTimeout(t);
  }, [open, reduced]);

  const enter = useCallback(() => {
    try {
      sessionStorage.setItem(KEY, "1");
    } catch {
      /* ignore */
    }
    setOpen(false);
  }, []);

  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Enter" || e.key === " " || e.key === "Escape") { e.preventDefault(); enter(); }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, enter]);

  const d = (s: number) => (reduced ? 0 : s);

  return (
    <AnimatePresence>
      {open && (
        <motion.div
          key="splash"
          role="dialog"
          aria-label="Bienvenue dans Sfumato AI"
          className="fixed inset-0 z-[100] flex flex-col items-center justify-center overflow-hidden bg-black"
          initial={{ opacity: 1 }}
          exit={{ opacity: 0, filter: "blur(14px)", scale: 1.04, transition: { duration: reduced ? 0 : 0.9, ease: "easeInOut" } }}
        >
          {/* the haze: three slow blurred masses, warm like the engraving */}
          {!reduced && (
            <>
              <motion.div className="absolute -left-1/4 top-1/4 h-[70vh] w-[70vh] rounded-full" style={{ background: "radial-gradient(circle, rgba(214,190,150,0.16), transparent 65%)", filter: "blur(40px)" }}
                animate={{ x: ["0%", "28%", "0%"], opacity: [0.5, 0.9, 0.5] }} transition={{ duration: 16, repeat: Infinity, ease: "easeInOut" }} />
              <motion.div className="absolute -right-1/4 top-1/3 h-[60vh] w-[60vh] rounded-full" style={{ background: "radial-gradient(circle, rgba(160,140,110,0.14), transparent 65%)", filter: "blur(50px)" }}
                animate={{ x: ["0%", "-30%", "0%"], opacity: [0.4, 0.8, 0.4] }} transition={{ duration: 19, repeat: Infinity, ease: "easeInOut" }} />
              <motion.div className="absolute left-1/4 bottom-[-20%] h-[55vh] w-[80vw] rounded-full" style={{ background: "radial-gradient(ellipse, rgba(34,211,238,0.07), transparent 70%)", filter: "blur(60px)" }}
                animate={{ y: ["0%", "-12%", "0%"] }} transition={{ duration: 14, repeat: Infinity, ease: "easeInOut" }} />
              {DUST.map((p, i) => (
                <motion.span key={i} className="absolute bottom-[-4%] rounded-full bg-[#e8dcc4]" style={{ left: p.left, width: p.size, height: p.size, opacity: 0 }}
                  animate={{ y: ["0vh", "-110vh"], opacity: [0, 0.55, 0] }} transition={{ duration: p.duration, delay: p.delay, repeat: Infinity, ease: "linear" }} />
              ))}
            </>
          )}

          {/* the logo comes out of the haze */}
          <motion.div
            className="relative w-[min(88vw,760px)]"
            initial={reduced ? false : { opacity: 0, filter: "blur(22px)", scale: 1.08 }}
            animate={{ opacity: 1, filter: "blur(0px)", scale: 1 }}
            transition={{ duration: d(2.2), ease: [0.22, 1, 0.36, 1] }}
          >
            {/* eslint-disable-next-line @next/next/no-img-element */}
            <img src="/brand/sfumato-logo.webp" alt="Sfumato AI, Autonomous SOC" className="h-auto w-full select-none" draggable={false} />
            {!reduced && (
              <motion.div aria-hidden className="pointer-events-none absolute inset-y-0 w-1/5"
                style={{ background: "linear-gradient(90deg, transparent, rgba(255,244,220,0.10), transparent)" }}
                initial={{ left: "-25%" }} animate={{ left: "115%" }} transition={{ duration: 2.6, delay: 1.2, ease: "easeInOut" }} />
            )}
          </motion.div>

          <motion.div className="mt-6 flex h-14 items-center justify-center" initial={{ opacity: 0, y: 8 }} animate={{ opacity: ready ? 1 : 0, y: ready ? 0 : 8 }} transition={{ duration: d(0.6) }}>
            <button onClick={enter} tabIndex={ready ? 0 : -1} autoFocus
              className="group flex items-center gap-3 whitespace-nowrap rounded-full border border-[#e8dcc4]/40 bg-[#e8dcc4]/5 px-5 py-3 text-xs font-medium tracking-[0.16em] sm:px-7 sm:text-sm sm:tracking-[0.18em] text-[#f1e8d4] uppercase backdrop-blur transition hover:border-[#e8dcc4]/80 hover:bg-[#e8dcc4]/10">
              Accéder au dashboard
              <ArrowRight className="h-4 w-4 transition-transform group-hover:translate-x-1" />
            </button>
          </motion.div>
          <motion.p className="mt-3 text-[11px] tracking-[0.2em] text-[#e8dcc4]/40 uppercase" initial={{ opacity: 0 }} animate={{ opacity: ready ? 1 : 0 }} transition={{ duration: d(0.8), delay: d(0.3) }}>
            ou appuie sur Entrée
          </motion.p>
        </motion.div>
      )}
    </AnimatePresence>
  );
}
