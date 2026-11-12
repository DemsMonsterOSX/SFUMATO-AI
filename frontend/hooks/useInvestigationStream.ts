"use client";

import { useEffect, useRef, useState } from "react";
import { API_BASE } from "@/lib/api";

export type InvEvent = {
  seq: number;
  ts: string;
  type: string;
  stage: string | null;
  status: string | null;
  message: string;
  data: Record<string, any> | null;
};

/**
 * Subscribes to the backend SSE stream of an investigation. Every event shown is a persisted backend
 * event. When an investigation is watched live, the reveal is paced slightly (≤ 0.35 s per milestone)
 * so each stage is perceptible on screen; the timestamps and durations displayed are always the real ones.
 */
export function useInvestigationStream(incidentId: string | null, pace: boolean) {
  const [events, setEvents] = useState<InvEvent[]>([]);
  const [ended, setEnded] = useState(false);
  const [connected, setConnected] = useState(false);
  const queue = useRef<InvEvent[]>([]);
  const seen = useRef<Set<number>>(new Set());

  useEffect(() => {
    if (!incidentId) return;
    setEvents([]);
    setEnded(false);
    queue.current = [];
    seen.current = new Set();
    const es = new EventSource(`${API_BASE}/incidents/${encodeURIComponent(incidentId)}/events/stream`);
    let streamEnded = false;
    es.onopen = () => setConnected(true);
    es.addEventListener("investigation", (e) => {
      const ev = JSON.parse((e as MessageEvent).data) as InvEvent;
      if (seen.current.has(ev.seq)) return;
      seen.current.add(ev.seq);
      queue.current.push(ev);
    });
    es.addEventListener("end", () => {
      streamEnded = true;
      es.close();
      setConnected(false);
    });
    es.onerror = () => {
      setConnected(false);
      if (streamEnded) es.close();
    };

    // Time-budget based (not one timer per event) so throttled background tabs still catch up.
    let timer: ReturnType<typeof setTimeout>;
    let lastMilestone = 0;
    const tick = () => {
      if (queue.current.length) {
        const batch: InvEvent[] = [];
        while (queue.current.length) {
          const ev = queue.current[0];
          if (pace && ev.type === "milestone") {
            if (Date.now() - lastMilestone < 350) break;
            lastMilestone = Date.now();
          }
          batch.push(queue.current.shift()!);
        }
        if (batch.length) setEvents((prev) => [...prev, ...batch]);
      } else if (streamEnded) {
        setEnded(true);
      }
      timer = setTimeout(tick, 80);
    };
    tick();
    return () => {
      clearTimeout(timer);
      es.close();
    };
  }, [incidentId, pace]);

  return { events, ended, connected };
}
