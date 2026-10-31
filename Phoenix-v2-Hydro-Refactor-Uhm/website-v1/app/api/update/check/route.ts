import { NextRequest, NextResponse } from "next/server";
import { rateLimit, clientIp, NO_STORE } from "@/lib/security/security";
import { config } from "@/lib/core/config";

export const runtime = "nodejs";

const APP_VERSION = config.app_version;

const json = (data: unknown, status = 200) =>
  NextResponse.json(data, { status, headers: NO_STORE });

export async function GET(req: NextRequest) {
  if (!rateLimit(`update-check:${clientIp(req)}`, 30, 60_000))
    return json({ ok: false, error: "too many requests" }, 429);

  const expectedKey = config.phoenix_api_key;
  if (expectedKey && req.headers.get("x-api-key") !== expectedKey)
    return json({ ok: false, error: "forbidden" }, 403);

  const clientVersion = req.nextUrl.searchParams.get("v") ?? "";
  const updateAvailable = clientVersion !== APP_VERSION;

  return json({
    ok: true,
    version: APP_VERSION,
    update_available: updateAvailable,
  });
}
