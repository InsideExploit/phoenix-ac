import { NextRequest, NextResponse } from "next/server";
import { SESSION_COOKIE } from "@/lib/auth/session";
import { publicUrl } from "@/lib/core/url";

export const runtime = "nodejs";

export function GET(req: NextRequest) {
  const res = NextResponse.redirect(publicUrl(req, "/dashboard"));
  res.cookies.delete(SESSION_COOKIE);
  return res;
}
