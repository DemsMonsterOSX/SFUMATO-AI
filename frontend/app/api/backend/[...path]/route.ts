// Server-side proxy to the FastAPI backend. The API key is added here, so it never reaches the browser.
import { NextRequest } from "next/server";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

const BACKEND = process.env.BACKEND_URL ?? "http://localhost:8000";
const API_KEY = process.env.SFUMATO_API_KEY ?? (process.env.API_KEYS ?? "sfumato-dev-key-change-me").split(",")[0].trim();
const ALLOWED = /^(health|status|stats|incidents|cti|soar|ml|ai|observatory|scenarios|schema|settings|audit|knowledge)(\/|$)/;

async function proxy(req: NextRequest, ctx: { params: Promise<{ path: string[] }> }) {
  const { path } = await ctx.params;
  const sub = path.map(encodeURIComponent).join("/");
  if (!ALLOWED.test(sub)) {
    return Response.json({ detail: "Unknown API route" }, { status: 404 });
  }
  const url = `${BACKEND}/api/v1/${sub}${req.nextUrl.search}`;
  const headers: Record<string, string> = { "X-API-Key": API_KEY, Accept: req.headers.get("accept") ?? "*/*" };
  const ct = req.headers.get("content-type");
  if (ct) headers["Content-Type"] = ct;
  const fwd = req.headers.get("x-forwarded-for");
  if (fwd) headers["X-Forwarded-For"] = fwd;

  let res: Response;
  try {
    res = await fetch(url, {
      method: req.method,
      headers,
      body: req.method === "GET" || req.method === "HEAD" ? undefined : await req.text(),
      cache: "no-store",
      signal: req.signal,
    });
  } catch (e) {
    return Response.json(
      { detail: `Backend unreachable at ${BACKEND}. Is the API container running?`, error: String(e) },
      { status: 502 },
    );
  }
  const out = new Headers();
  out.set("content-type", res.headers.get("content-type") ?? "application/json");
  out.set("cache-control", "no-cache, no-transform");
  if ((res.headers.get("content-type") ?? "").includes("text/event-stream")) {
    out.set("connection", "keep-alive");
    out.set("x-accel-buffering", "no");
  }
  return new Response(res.body, { status: res.status, headers: out });
}

export { proxy as GET, proxy as POST, proxy as PUT };
