"use client";

import Editor, { loader } from "@monaco-editor/react";
import { useEffect, useState } from "react";

// Load Monaco from the app itself (copied to /public at install time) so the editor works offline.
// Web workers resolve URLs against their own location, so the path must be absolute.
if (typeof window !== "undefined") {
  loader.config({ paths: { vs: `${window.location.origin}/monaco/vs` } });
}

export function JsonEditor({ value, onChange, readOnly, height = 520 }: { value: string; onChange?: (v: string) => void; readOnly?: boolean; height?: number }) {
  const [failed, setFailed] = useState(false);
  useEffect(() => {
    const t = setTimeout(() => {
      if (!document.querySelector(".monaco-editor")) setFailed(true);
    }, 8000);
    return () => clearTimeout(t);
  }, []);
  if (failed) {
    return (
      <textarea
        className="w-full rounded-xl border border-line bg-ink-950 p-4 font-mono text-xs text-slate-200 outline-none focus:border-cyan-400/40"
        style={{ height }}
        value={value}
        readOnly={readOnly}
        spellCheck={false}
        onChange={(e) => onChange?.(e.target.value)}
      />
    );
  }
  return (
    <div className="overflow-hidden rounded-xl border border-line">
      <Editor
        height={height}
        language="json"
        theme="sfumato"
        value={value}
        onChange={(v) => onChange?.(v ?? "")}
        beforeMount={(monaco) => {
          monaco.editor.defineTheme("sfumato", {
            base: "vs-dark",
            inherit: true,
            rules: [
              { token: "string.key.json", foreground: "67e8f9" },
              { token: "string.value.json", foreground: "6ee7b7" },
              { token: "number", foreground: "fcd34d" },
              { token: "keyword.json", foreground: "c4b5fd" },
            ],
            colors: { "editor.background": "#050a1a", "editor.lineHighlightBackground": "#0b1430", "editorLineNumber.foreground": "#334155" },
          });
        }}
        options={{
          readOnly,
          minimap: { enabled: false },
          fontSize: 12.5,
          fontFamily: "var(--font-geist-mono), ui-monospace, monospace",
          scrollBeyondLastLine: false,
          wordWrap: "on",
          tabSize: 2,
          padding: { top: 12 },
          renderLineHighlight: "line",
          smoothScrolling: true,
        }}
      />
    </div>
  );
}
