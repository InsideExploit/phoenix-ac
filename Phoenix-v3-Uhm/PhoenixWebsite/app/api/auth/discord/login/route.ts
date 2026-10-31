import crypto from "crypto";
import { NextRequest, NextResponse } from "next/server";
import { STATE_COOKIE } from "@/lib/auth/session";
import { rateLimit, clientIp } from "@/lib/security/security";
import { publicUrl, discordRedirectUri } from "@/lib/core/url";
import { config } from "@/lib/core/config";

export const runtime = "nodejs";

export function GET(req: NextRequest) {
  if (!rateLimit(`login:${clientIp(req)}`, 30, 60_000)) {
    return NextResponse.redirect(publicUrl(req, "/dashboard?error=rate"));
  }

  const clientId = config.discord_client_id;
  if (!clientId) {
    return NextResponse.redirect(publicUrl(req, "/dashboard?error=config"));
  }

  const redirectUri = discordRedirectUri();

  const state = crypto.randomBytes(16).toString("hex");

  const authorize = new URL("https://discord.com/api/oauth2/authorize");
  authorize.searchParams.set("client_id", clientId);
  authorize.searchParams.set("redirect_uri", redirectUri);
  authorize.searchParams.set("response_type", "code");
  authorize.searchParams.set("scope", "identify email");
  authorize.searchParams.set("state", state);
  authorize.searchParams.set("prompt", "consent");

  const res = NextResponse.redirect(authorize.toString());
  res.cookies.set(STATE_COOKIE, state, {
    httpOnly: true,
    sameSite: "lax",
    path: "/",
    maxAge: 600,
    secure: process.env.NODE_ENV === "production",
  });
  return res;
}
