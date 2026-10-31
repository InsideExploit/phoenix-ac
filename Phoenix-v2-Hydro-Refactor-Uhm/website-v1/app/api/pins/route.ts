import { NextRequest, NextResponse } from "next/server";
import { getSessionUser } from "@/lib/auth/auth";
import type { SessionUser } from "@/lib/auth/session";
import { createPin, getPins, deletePin } from "@/lib/players/players";
import { isSameOrigin, rateLimit, clientIp, NO_STORE } from "@/lib/security/security";
import { sealForUser } from "@/lib/crypto/api_crypto";
import { postAdminWebhook } from "@/lib/webhooks/webhook";

export const runtime = "nodejs";

const json = (data: unknown, status = 200) =>
  NextResponse.json(data, { status, headers: NO_STORE });

type GuardResult =
  | { ok: true; user: SessionUser }
  | { ok: false; res: NextResponse };

async function guard(req: NextRequest): Promise<GuardResult> {
  if (!isSameOrigin(req))
    return { ok: false, res: json({ ok: false, error: "forbidden" }, 403) };
  if (!rateLimit(`pins:${clientIp(req)}`, 60, 60_000))
    return {
      ok: false,
      res: json({ ok: false, error: "too many requests" }, 429),
    };
  const user = await getSessionUser();
  if (!user)
    return { ok: false, res: json({ ok: false, error: "unauthorized" }, 401) };
  return { ok: true, user };
}

export async function GET(req: NextRequest) {
  if (!rateLimit(`pins-get:${clientIp(req)}`, 120, 60_000))
    return json({ ok: false, error: "too many requests" }, 429);
  const user = await getSessionUser();
  if (!user) return json({ ok: false, error: "unauthorized" }, 401);

  const pins = await getPins();
  return new NextResponse(sealForUser(user.id, { pins }), {
    status: 200,
    headers: { ...NO_STORE, "Content-Type": "application/octet-stream" },
  });
}

export async function POST(req: NextRequest) {
  const g = await guard(req);
  if (!g.ok) return g.res;

  const result = await createPin(g.user.id);

  if (result.ok) {
    void postAdminWebhook({
      title: "PIN generato",
      color: 0x3498db,
      actor: g.user,
      fields: [
        { name: "Codice", value: "`" + result.code + "`", inline: true },
      ],
    });
  }

  return json(result, result.ok ? 201 : 400);
}

export async function DELETE(req: NextRequest) {
  const g = await guard(req);
  if (!g.ok) return g.res;

  const body = (await req.json().catch(() => null)) as { code?: string } | null;
  if (!body?.code) return json({ ok: false, error: "code mancante" }, 400);

  const result = await deletePin(body.code);

  if (result.ok) {
    void postAdminWebhook({
      title: "PIN eliminato",
      color: 0xe74c3c,
      actor: g.user,
      fields: [
        { name: "Codice", value: "`" + body.code + "`", inline: true },
      ],
    });
  }

  return json(result, result.ok ? 200 : 400);
}
