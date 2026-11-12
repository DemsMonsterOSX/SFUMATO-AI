"use client";

import { Node, NodeChange, applyNodeChanges } from "@xyflow/react";
import { useCallback, useEffect, useState } from "react";

/**
 * React Flow 12 hides nodes until they are measured. Re-creating node objects on every poll drops the
 * measurements, so nodes would stay invisible. This keeps nodes in state and merges new layout/data
 * into the existing objects, preserving `measured`.
 */
export function useStableFlowNodes<T extends Record<string, unknown>>(next: Node<T>[]) {
  const [nodes, setNodes] = useState<Node<T>[]>(next);
  const signature = JSON.stringify(next.map((n) => [n.id, n.position, n.data]));
  useEffect(() => {
    setNodes((prev) => {
      const byId = new Map(prev.map((n) => [n.id, n]));
      return next.map((n) => {
        const old = byId.get(n.id);
        return old ? { ...old, position: n.position, data: n.data, type: n.type } : n;
      });
    });
  }, [signature]); // eslint-disable-line react-hooks/exhaustive-deps
  const onNodesChange = useCallback((changes: NodeChange<Node<T>>[]) => setNodes((nds) => applyNodeChanges(changes, nds)), []);
  return { nodes, onNodesChange };
}
