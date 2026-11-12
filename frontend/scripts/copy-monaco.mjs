// Copies Monaco's AMD build into public/ so the JSON editor works offline (no CDN at runtime).
import { cpSync, existsSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const src = join(root, "node_modules", "monaco-editor", "min", "vs");
const dest = join(root, "public", "monaco", "vs");
if (existsSync(src)) {
  mkdirSync(dest, { recursive: true });
  cpSync(src, dest, { recursive: true });
  console.log("monaco-editor copied to public/monaco/vs");
} else {
  console.warn("monaco-editor not installed; JSON editor will fall back to a textarea");
}
