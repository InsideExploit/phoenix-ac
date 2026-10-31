import { NextRequest, NextResponse } from "next/server";
import { getSessionUser } from "@/lib/auth/auth";
import { rateLimit, clientIp, NO_STORE } from "@/lib/security/security";
import { encryptDash, isDashCryptoConfigured } from "@/lib/crypto/crypto";
import { getDetections } from "@/lib/detections/detections";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const json = (data: unknown, status = 200) =>
  NextResponse.json(data, { status, headers: NO_STORE });

function encDashJson(data: unknown, status = 200) {
  if (!isDashCryptoConfigured()) return json(data, status);
  const body = encryptDash(JSON.stringify(data));
  return new NextResponse(body, {
    status,
    headers: {
      ...NO_STORE,
      "Content-Type": "application/octet-stream",
      "X-Phoenix-Enc": "dash",
    },
  });
}

function parseDate(v: string | null): Date | null {
  if (!v) return null;
  const t = Date.parse(v);
  return Number.isFinite(t) ? new Date(t) : null;
}

export async function GET(req: NextRequest) {
  if (!rateLimit(`detections:${clientIp(req)}`, 240, 60_000))
    return json({ ok: false, error: "too many requests" }, 429);
  if (!(await getSessionUser()))
    return json({ ok: false, error: "unauthorized" }, 401);

  const sp = req.nextUrl.searchParams;
  const q        = (sp.get("q") ?? "").trim().slice(0, 128);
  const type     = (sp.get("type") ?? "").trim().slice(0, 64);
  const steam    = (sp.get("steam") ?? "").trim().slice(0, 32);
  const since    = parseDate(sp.get("since"));
  const until    = parseDate(sp.get("until"));
  const pageSize = Math.min(Math.max(Number(sp.get("pageSize") ?? 30) | 0, 1), 100);
  const page     = Math.max(Number(sp.get("page") ?? 0) | 0, 0);

  const result = await getDetections({ q, type, steam, since, until, page, pageSize });

  return encDashJson({
    ok:         true,
    detections: result.detections,
    total:      result.total,
    types:      result.types,
    page,
    pageSize,
  });
}
