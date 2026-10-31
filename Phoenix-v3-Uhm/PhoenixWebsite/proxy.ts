import { NextRequest, NextResponse } from "next/server";
import { SESSION_COOKIE, SESSION_TOKEN_VERSION } from "@/lib/core/constants";

const isDev = process.env.NODE_ENV !== "production";

function harden(res: NextResponse): NextResponse {

  const scriptSrc = isDev
    ? "'self' 'unsafe-inline' 'unsafe-eval'"
    : "'self' 'unsafe-inline'";

  const csp = [
    "default-src 'self'",
    "base-uri 'self'",
    "object-src 'none'",
    "frame-ancestors 'none'",
    "img-src 'self' https://cdn.discordapp.com data:",
    "style-src 'self' 'unsafe-inline'",
    `script-src ${scriptSrc}`,
    "connect-src 'self' ws: wss:",
    "font-src 'self' data:",
    "form-action 'self' https://discord.com",
  ].join("; ");

  res.headers.set("Content-Security-Policy", csp);
  res.headers.set("X-Frame-Options", "DENY");
  res.headers.set("X-Content-Type-Options", "nosniff");
  res.headers.set("Referrer-Policy", "no-referrer");
  res.headers.set(
    "Permissions-Policy",
    "camera=(), microphone=(), geolocation=(), browsing-topics=()",
  );
  res.headers.set("X-DNS-Prefetch-Control", "off");
  res.headers.set(
    "Strict-Transport-Security",
    "max-age=63072000; includeSubDomains; preload",
  );
  return res;
}

function looksSealed(token: string | undefined): boolean {
  if (!token) return false;
  const p = token.split(".");
  return p.length === 4 && p[0] === SESSION_TOKEN_VERSION && p.every(Boolean);
}

export function proxy(req: NextRequest) {
  const { pathname } = req.nextUrl;
  const protectedApi =
    pathname.startsWith("/api/players") || pathname.startsWith("/api/pins");
  const sensitive = protectedApi || pathname.startsWith("/dashboard");

  if (protectedApi && !looksSealed(req.cookies.get(SESSION_COOKIE)?.value)) {
    const res = NextResponse.json(
      { ok: false, error: "unauthorized" },
      { status: 401 },
    );
    res.headers.set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0");
    return harden(res);
  }

  const res = NextResponse.next();
  if (sensitive) {
    res.headers.set(
      "Cache-Control",
      "no-store, no-cache, must-revalidate, max-age=0",
    );
  }
  return harden(res);
}

export const config = {

  matcher: ["/((?!_next/static|_next/image|favicon.ico|.*\\.(?:png|jpg|jpeg|svg|ico|webp)$).*)"],
};
