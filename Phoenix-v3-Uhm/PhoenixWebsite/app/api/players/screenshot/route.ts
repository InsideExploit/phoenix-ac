import { NextRequest, NextResponse } from "next/server";
import { getSessionUser } from "@/lib/auth/auth";
import { isSameOrigin, rateLimit, clientIp, NO_STORE } from "@/lib/security/security";
import { postAdminWebhook } from "@/lib/webhooks/webhook";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

import { backendUrl as BACKEND_URL } from "@/lib/env";

const json = (data: unknown, status = 200) =>
  NextResponse.json(data, { status, headers: NO_STORE });

export async function POST(req: NextRequest) {
  if (!isSameOrigin(req)) return json({ ok: false, error: "forbidden" }, 403);

  const user = await getSessionUser();
  if (!user) return json({ ok: false, error: "unauthorized" }, 401);

  if (!rateLimit(`shot:${user.id ?? user.email ?? clientIp(req)}`, 300, 60_000))
    return json({ ok: false, error: "too many requests" }, 429);

  const body = (await req.json().catch(() => null)) as
    | { steam_hex?: unknown; method?: unknown }
    | null;
  const steamHex = typeof body?.steam_hex === "string" ? body.steam_hex.trim().toLowerCase() : "";
  if (!steamHex || !/^[0-9a-f]{1,16}$/.test(steamHex))
    return json({ ok: false, error: "bad steam_hex" }, 400);

  const rawMethod = typeof body?.method === "string" ? body.method.toLowerCase() : "";
  const method: "auto" | "nvidia" | "gdi" =
    rawMethod === "nvidia" ? "nvidia" : rawMethod === "gdi" ? "gdi" : "auto";

  const controller = new AbortController();
  const abortTimer = setTimeout(() => controller.abort(), 25_000);

  let upstream: Response;
  try {
    upstream = await fetch(`${BACKEND_URL}/v1/agent/screenshot`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ steam_hex: steamHex, method }),
      signal: controller.signal,
      cache: "no-store",
    });
  } catch (e) {
    clearTimeout(abortTimer);
    const msg = (e as Error).message || "unknown";
    console.error("[screenshot] backend fetch failed:", msg);
    return json({ ok: false, error: "Backend non raggiungibile (" + msg + ")" }, 503);
  }
  clearTimeout(abortTimer);

  type BackendReply = {
    ok?: boolean;
    path?: string;
    bytes?: number;
    error?: string;
    method?: string;
    fallback?: string;
    fallback_reason?: string;
  };
  const rawText = await upstream.text().catch(() => "");
  let data: BackendReply | null = null;
  try { data = JSON.parse(rawText) as BackendReply; } catch { data = null; }

  if (!data) {
    console.error("[screenshot] non-json backend reply", {
      status: upstream.status,
      preview: rawText.slice(0, 200),
    });
    return json(
      { ok: false, error: "Backend ha risposto in modo inatteso (" + upstream.status + ")" },
      500,
    );
  }

  if (data.ok && data.path) {
    try {
      const fields: { name: string; value: string; inline?: boolean }[] = [
        { name: "Steam HEX", value: "`" + steamHex + "`", inline: true },
        { name: "Requested", value: method,               inline: true },
        { name: "Used",      value: data.method ?? method, inline: true },
        { name: "Bytes",     value: String(data.bytes ?? "?"), inline: true },
      ];
      if (data.fallback) {
        fields.push({ name: "Fallback", value: `${method} → ${data.fallback}`, inline: true });
        if (data.fallback_reason)
          fields.push({ name: "Reason", value: "`" + data.fallback_reason.slice(0, 512) + "`" });
      }
      void postAdminWebhook({
        title: "Screenshot manuale acquisito",
        color: 0x3498db,
        actor: user,
        fields,
      });
    } catch (e) {
      console.warn("[screenshot] webhook error:", (e as Error).message);
    }
    return json({
      ok: true,
      path: data.path,
      method: data.method,
      ...(data.fallback ? { fallback: data.fallback, fallback_reason: data.fallback_reason } : {}),
    });
  }

  const backendMsg = data.error || "Screenshot fallito";
  const status = upstream.status === 404 ? 404
              : upstream.status === 504 ? 504
              : 500;
  return json({ ok: false, error: backendMsg }, status);
}
