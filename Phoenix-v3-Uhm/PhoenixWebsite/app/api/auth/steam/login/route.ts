import { NextRequest, NextResponse } from "next/server";
import { rateLimit, clientIp } from "@/lib/security/security";
import { buildAuthorizeUrl } from "@/lib/auth/steam";

export const runtime = "nodejs";

export function GET(req: NextRequest) {
  if (!rateLimit(`steam-login:${clientIp(req)}`, 30, 60_000)) {
    return NextResponse.redirect(new URL("/?steam=rate", req.nextUrl.origin));
  }
  return NextResponse.redirect(buildAuthorizeUrl());
}
