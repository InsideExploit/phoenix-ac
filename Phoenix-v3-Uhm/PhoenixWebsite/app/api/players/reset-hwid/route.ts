import { NextRequest, NextResponse } from "next/server";
import { getSessionUser } from "@/lib/auth/auth";
import { isSameOrigin, rateLimit, clientIp, NO_STORE } from "@/lib/security/security";
import { postAdminWebhook } from "@/lib/webhooks/webhook";
import { resetPlayerHardwareId } from "@/lib/players/players";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const json = (data: unknown, status = 200) =>
  NextResponse.json(data, { status, headers: NO_STORE });

export async function POST(req: NextRequest) {
  if (!isSameOrigin(req)) return json({ ok: false, error: "forbidden" }, 403);
  if (!rateLimit(`reset-hwid:${clientIp(req)}`, 15, 60_000))
    return json({ ok: false, error: "too many requests" }, 429);

  const user = await getSessionUser();
  if (!user) return json({ ok: false, error: "unauthorized" }, 401);

  const body = (await req.json().catch(() => null)) as { steam_hex?: unknown } | null;
  const steamHex = typeof body?.steam_hex === "string" ? body.steam_hex.trim().toLowerCase() : "";
  if (!steamHex || !/^[0-9a-f]{1,16}$/.test(steamHex))
    return json({ ok: false, error: "bad steam_hex" }, 400);

  const actor = user.id || user.global_name || user.username || "admin";

  const result = await resetPlayerHardwareId(steamHex, actor);
  if (!result.ok) {
    return json(
      { ok: false, error: result.error || "Player not found." },
      result.error ? 500 : 404,
    );
  }

  try {
    void postAdminWebhook({
      title: "Hardware ID reset",
      color: 0x9b59b6,
      actor: user,
      fields: [{ name: "Steam HEX", value: "`" + steamHex + "`", inline: true }],
    });
  } catch { /* ignore */ }

  return json({ ok: true });
}
