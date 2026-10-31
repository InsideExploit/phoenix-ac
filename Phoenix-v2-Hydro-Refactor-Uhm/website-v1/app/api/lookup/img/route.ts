import { NextRequest, NextResponse } from "next/server";
import { getSessionUser } from "@/lib/auth/auth";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const ALLOWED_HOSTS = [
  "avatars.steamstatic.com",
  "avatars.akamaihd.net",
  "cdn.discordapp.com",
  "cdn.akamai.steamstatic.com",
];

const imgCache = new Map<string, { buf: ArrayBuffer; ct: string; ts: number }>();
const IMG_CACHE_TTL = 10 * 60 * 1000;

export async function GET(req: NextRequest) {
  const user = await getSessionUser();
  if (!user) return new NextResponse(null, { status: 401 });

  const url = new URL(req.url).searchParams.get("url");
  if (!url) return new NextResponse(null, { status: 400 });

  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return new NextResponse(null, { status: 400 });
  }

  if (!ALLOWED_HOSTS.includes(parsed.hostname)) {
    return new NextResponse(null, { status: 403 });
  }

  const hit = imgCache.get(url);
  if (hit && Date.now() - hit.ts < IMG_CACHE_TTL) {
    return new NextResponse(hit.buf, {
      headers: {
        "Content-Type": hit.ct,
        "Cache-Control": "public, max-age=600",
      },
    });
  }

  try {
    const upstream = await fetch(url, {
      headers: { "User-Agent": "Mozilla/5.0" },
    });
    if (!upstream.ok) return new NextResponse(null, { status: 502 });

    const ct = upstream.headers.get("content-type") || "image/jpeg";
    if (!ct.startsWith("image/")) return new NextResponse(null, { status: 415 });

    const buf = await upstream.arrayBuffer();
    imgCache.set(url, { buf, ct, ts: Date.now() });

    return new NextResponse(buf, {
      headers: {
        "Content-Type": ct,
        "Cache-Control": "public, max-age=600",
      },
    });
  } catch {
    return new NextResponse(null, { status: 502 });
  }
}
