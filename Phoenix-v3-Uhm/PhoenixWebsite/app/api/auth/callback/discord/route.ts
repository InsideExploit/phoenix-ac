import { NextRequest, NextResponse } from "next/server";
import { sign, isAllowed, SESSION_COOKIE, STATE_COOKIE } from "@/lib/auth/session";
import { rateLimit, clientIp } from "@/lib/security/security";
import { publicUrl, discordRedirectUri } from "@/lib/core/url";
import { config } from "@/lib/core/config";

export const runtime = "nodejs";

export async function GET(req: NextRequest) {
  const code = req.nextUrl.searchParams.get("code");
  const state = req.nextUrl.searchParams.get("state");
  const savedState = req.cookies.get(STATE_COOKIE)?.value;

  const fail = (reason: string) =>
    NextResponse.redirect(publicUrl(req, `/dashboard?error=${reason}`));

  if (!rateLimit(`callback:${clientIp(req)}`, 20, 60_000)) return fail("rate");

  if (!code || !state || !savedState || state !== savedState) {
    return fail("state");
  }

  const clientId = config.discord_client_id;
  const clientSecret = config.discord_client_secret;
  if (!clientId || !clientSecret) return fail("config");

  const redirectUri = discordRedirectUri();

  const tokenRes = await fetch("https://discord.com/api/oauth2/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: clientId,
      client_secret: clientSecret,
      grant_type: "authorization_code",
      code,
      redirect_uri: redirectUri,
    }),
  });
  if (!tokenRes.ok) return fail("token");
  const token = (await tokenRes.json()) as { access_token?: string };
  if (!token.access_token) return fail("token");

  const userRes = await fetch("https://discord.com/api/users/@me", {
    headers: { Authorization: `Bearer ${token.access_token}` },
  });
  if (!userRes.ok) return fail("user");
  const u = (await userRes.json()) as {
    id: string;
    username: string;
    global_name?: string | null;
    avatar: string | null;
    email?: string | null;
  };

  if (!(await isAllowed(u.id))) return fail("forbidden");

  const session = sign({
    id: u.id,
    username: u.username,
    global_name: u.global_name ?? null,
    avatar: u.avatar,
    email: u.email ?? null,
  });

  const res = NextResponse.redirect(publicUrl(req, "/dashboard"));
  res.cookies.set(SESSION_COOKIE, session, {
    httpOnly: true,
    sameSite: "lax",
    path: "/",
    maxAge: 60 * 60 * 24 * 7,
    secure: process.env.NODE_ENV === "production",
  });
  res.cookies.delete(STATE_COOKIE);
  return res;
}
