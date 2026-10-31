import { NextRequest, NextResponse } from "next/server";
import { getSessionUser } from "@/lib/auth/auth";
import { isSameOrigin, rateLimit, clientIp, NO_STORE } from "@/lib/security/security";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

import { backendUrl as BACKEND_URL } from "@/lib/env";

const json = (data: unknown, status = 200) =>
  NextResponse.json(data, { status, headers: NO_STORE });

export async function POST(req: NextRequest) {
  if (!isSameOrigin(req)) return json({ ok: false, error: "forbidden" }, 403);
  if (!rateLimit(`dumpfile:${clientIp(req)}`, 6, 60_000))
    return json({ ok: false, error: "too many requests" }, 429);

  const user = await getSessionUser();
  if (!user) return json({ ok: false, error: "unauthorized" }, 401);

  const body = (await req.json().catch(() => null)) as
    | { steam_hex?: unknown; name?: unknown }
    | null;
  const steamHex = typeof body?.steam_hex === "string" ? body.steam_hex.trim().toLowerCase() : "";
  const name     = typeof body?.name === "string" ? body.name.trim() : "";
  if (!steamHex || !/^[0-9a-f]{1,16}$/.test(steamHex))
    return json({ ok: false, error: "bad steam_hex" }, 400);
  if (!/^[A-Za-z0-9._-]{5,96}$/.test(name) || !/\.dmp$/i.test(name) || name.includes(".."))
    return json({ ok: false, error: "bad dump name" }, 400);

  const controller = new AbortController();
  const t = setTimeout(() => controller.abort(), 70_000);
  let upstream: Response;
  try {
    upstream = await fetch(`${BACKEND_URL}/v1/agent/dump-file`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ steam_hex: steamHex, name }),
      signal: controller.signal,
      cache: "no-store",
    });
  } catch (e) {
    clearTimeout(t);
    return json({ ok: false, error: "Backend non raggiungibile (" + (e as Error).message + ")" }, 503);
  }
  clearTimeout(t);

  const ct = upstream.headers.get("content-type") ?? "";
  if (upstream.ok && ct.startsWith("application/octet-stream")) {
    const buf = Buffer.from(await upstream.arrayBuffer());
    return new NextResponse(buf, {
      status: 200,
      headers: {
        ...NO_STORE,
        "content-type":        "application/octet-stream",
        "content-length":      String(buf.length),
        "content-disposition": `attachment; filename="${name}"`,
      },
    });
  }

  const raw = await upstream.text().catch(() => "");
  let data: { ok?: boolean; error?: string } | null = null;
  try { data = JSON.parse(raw) as { ok?: boolean; error?: string }; } catch { data = null; }
  const status = upstream.status === 404 ? 404
              : upstream.status === 504 ? 504
              : upstream.status === 502 ? 502
              : 500;
  return json({ ok: false, error: data?.error || "Download failed" }, status);
}
