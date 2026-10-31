import { NextRequest, NextResponse } from 'next/server';

import { getSessionUser } from '@/lib/auth/auth';
import { hasElevatedAccess } from '@/lib/auth/session';
import { backendUrl as BACKEND_URL } from '@/lib/env';
import { NO_STORE } from '@/lib/security/security';

export const runtime = 'nodejs';

export const dynamic = 'force-dynamic';
const json = (data: unknown, status = 200) =>
  NextResponse.json(data, { status, headers: NO_STORE });

export async function POST(req: NextRequest) {
  const user = await getSessionUser();
  if (!user) return json({ ok: false, error: 'unauthorized' }, 401);
  if (!(await hasElevatedAccess(user.id))) return json({ ok: false, error: 'forbidden' }, 403);
  const body = (await req.json().catch(() => null)) as {
    steam_hex?: unknown;
    pid?: unknown;
    min_len?: unknown;
    detect_ansi?: unknown;
    detect_unicode?: unknown;
    extended?: unknown;
    private?: unknown;
    image?: unknown;
    mapped?: unknown;
    needle?: unknown;
    needle_ci?: unknown;
  } | null;
  const steamHex = typeof body?.steam_hex === 'string' ? body.steam_hex.trim().toLowerCase() : '';
  if (!steamHex || !/^[0-9a-f]{1,16}$/.test(steamHex))
    return json({ ok: false, error: 'bad steam_hex' }, 400);
  const payload = {
    steam_hex: steamHex,
    pid: Number(body?.pid) | 0,
    min_len: Math.max(2, Math.min(128, Number(body?.min_len) | 0 || 4)),
    detect_ansi: body?.detect_ansi !== false,
    detect_unicode: !!body?.detect_unicode,
    extended: !!body?.extended,
    private: body?.private !== false,
    image: !!body?.image,
    mapped: !!body?.mapped,
    needle: typeof body?.needle === 'string' ? body.needle.slice(0, 255) : '',
    needle_ci: body?.needle_ci !== false,
  };
  try {
    const upstream = await fetch(`${BACKEND_URL}/v1/agent/proc/strings`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(payload),
      cache: 'no-store',
    });
    const text = await upstream.text().catch(() => '');
    let data: {
      ok?: boolean;
      raw?: string;
      error?: string;
    } | null = null;
    try {
      data = JSON.parse(text);
    } catch {}
    if (!data) return json({ ok: false, error: 'backend bad response' }, 500);
    if (!data.ok || !data.raw)
      return json({ ok: false, error: data.error ?? 'strings failed' }, upstream.status || 500);
    let parsed: unknown = null;
    try {
      parsed = JSON.parse(data.raw);
    } catch {}
    if (!parsed) return json({ ok: false, error: 'bad strings payload' }, 500);
    return json({ ok: true, ...(parsed as object) });
  } catch (e) {
    return json({ ok: false, error: 'Backend unreachable (' + (e as Error).message + ')' }, 503);
  }
}
