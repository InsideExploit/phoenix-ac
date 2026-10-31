import { NextRequest, NextResponse } from 'next/server';

import { getSessionUser } from '@/lib/auth/auth';
import { hasElevatedAccess } from '@/lib/auth/session';
import { backendUrl as BACKEND_URL } from '@/lib/env';
import { isSameOrigin, NO_STORE } from '@/lib/security/security';

export const runtime = 'nodejs';

export const dynamic = 'force-dynamic';
const json = (data: unknown, status = 200) =>
  NextResponse.json(data, { status, headers: NO_STORE });

export async function POST(req: NextRequest) {
  if (!isSameOrigin(req)) return json({ ok: false, error: 'forbidden' }, 403);
  const user = await getSessionUser();
  if (!user) return json({ ok: false, error: 'unauthorized' }, 401);
  if (!(await hasElevatedAccess(user.id))) return json({ ok: false, error: 'forbidden' }, 403);
  const body = (await req.json().catch(() => null)) as {
    steam_hex?: unknown;
    scan_id?: unknown;
  } | null;
  const steamHex = typeof body?.steam_hex === 'string' ? body.steam_hex.trim().toLowerCase() : '';
  if (!steamHex || !/^[0-9a-f]{1,16}$/.test(steamHex))
    return json({ ok: false, error: 'bad steam_hex' }, 400);
  const scanIdRaw = typeof body?.scan_id === 'number' ? body.scan_id : Number(body?.scan_id);
  if (!Number.isFinite(scanIdRaw) || scanIdRaw <= 0 || scanIdRaw > 0xffffffff)
    return json({ ok: false, error: 'bad scan_id' }, 400);
  try {
    const upstream = await fetch(`${BACKEND_URL}/v1/agent/scan/cancel`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ steam_hex: steamHex, scan_id: Math.floor(scanIdRaw) }),
      cache: 'no-store',
    });
    const text = await upstream.text().catch(() => '');
    let data: {
      ok?: boolean;
      error?: string;
    } | null = null;
    try {
      data = JSON.parse(text);
    } catch {}
    if (!data) return json({ ok: false, error: 'backend bad response' }, 500);
    if (!data.ok)
      return json({ ok: false, error: data.error ?? 'cancel failed' }, upstream.status || 500);
    return json({ ok: true });
  } catch (e) {
    return json({ ok: false, error: 'Backend unreachable (' + (e as Error).message + ')' }, 503);
  }
}
