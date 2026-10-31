import { NextRequest, NextResponse } from 'next/server';

import { getSessionUser } from '@/lib/auth/auth';
import { hasElevatedAccess } from '@/lib/auth/session';
import { backendUrl as BACKEND_URL } from '@/lib/env';
import { NO_STORE } from '@/lib/security/security';

export const runtime = 'nodejs';

export const dynamic = 'force-dynamic';
const json = (data: unknown, status = 200) =>
  NextResponse.json(data, { status, headers: NO_STORE });

export async function GET(req: NextRequest) {
  const user = await getSessionUser();
  if (!user) return json({ ok: false, error: 'unauthorized' }, 401);
  if (!(await hasElevatedAccess(user.id))) return json({ ok: false, error: 'forbidden' }, 403);
  const steamHex = (req.nextUrl.searchParams.get('steam_hex') ?? '').trim().toLowerCase();
  if (!steamHex || !/^[0-9a-f]{1,16}$/.test(steamHex))
    return json({ ok: false, error: 'bad steam_hex' }, 400);
  try {
    const url = new URL(`${BACKEND_URL}/v1/agent/proc/list`);
    url.searchParams.set('steam_hex', steamHex);
    const upstream = await fetch(url, { method: 'GET', cache: 'no-store' });
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
      return json({ ok: false, error: data.error ?? 'proc list failed' }, upstream.status || 500);
    let parsed: unknown = null;
    try {
      parsed = JSON.parse(data.raw);
    } catch {}
    if (!parsed) return json({ ok: false, error: 'bad proc payload' }, 500);
    return json({ ok: true, ...(parsed as object) });
  } catch (e) {
    return json({ ok: false, error: 'Backend unreachable (' + (e as Error).message + ')' }, 503);
  }
}
