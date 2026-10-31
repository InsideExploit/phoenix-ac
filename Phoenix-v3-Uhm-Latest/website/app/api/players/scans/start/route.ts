import { NextRequest, NextResponse } from 'next/server';

import { getSessionUser } from '@/lib/auth/auth';
import { hasElevatedAccess } from '@/lib/auth/session';
import { backendUrl as BACKEND_URL } from '@/lib/env';
import { clientIp, isSameOrigin, NO_STORE, rateLimit } from '@/lib/security/security';
import { postAdminWebhook } from '@/lib/webhooks/webhook';

export const runtime = 'nodejs';

export const dynamic = 'force-dynamic';
const json = (data: unknown, status = 200) =>
  NextResponse.json(data, { status, headers: NO_STORE });

export async function POST(req: NextRequest) {
  if (!isSameOrigin(req)) return json({ ok: false, error: 'forbidden' }, 403);
  const user = await getSessionUser();
  if (!user) return json({ ok: false, error: 'unauthorized' }, 401);
  if (!(await hasElevatedAccess(user.id))) return json({ ok: false, error: 'forbidden' }, 403);
  if (!rateLimit(`scan-start:${user.id ?? user.email ?? clientIp(req)}`, 10, 60000))
    return json({ ok: false, error: 'too many requests' }, 429);
  const body = (await req.json().catch(() => null)) as {
    steam_hex?: unknown;
    scan_type?: unknown;
    include_signed?: unknown;
  } | null;
  const steamHex = typeof body?.steam_hex === 'string' ? body.steam_hex.trim().toLowerCase() : '';
  if (!steamHex || !/^[0-9a-f]{1,16}$/.test(steamHex))
    return json({ ok: false, error: 'bad steam_hex' }, 400);
  const scanTypeRaw =
    typeof body?.scan_type === 'number' ? body.scan_type : Number(body?.scan_type ?? 1);
  const scanType = Number.isFinite(scanTypeRaw) && scanTypeRaw > 0 ? Math.floor(scanTypeRaw) : 1;
  const includeSigned = !!body?.include_signed;
  let upstream: Response;
  try {
    upstream = await fetch(`${BACKEND_URL}/v1/agent/scan/start`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        steam_hex: steamHex,
        scan_type: scanType,
        include_signed: includeSigned,
      }),
      cache: 'no-store',
    });
  } catch (e) {
    return json({ ok: false, error: 'Backend unreachable (' + (e as Error).message + ')' }, 503);
  }
  const text = await upstream.text().catch(() => '');
  let data: {
    ok?: boolean;
    error?: string;
    scanId?: number;
  } | null = null;
  try {
    data = JSON.parse(text);
  } catch {}
  if (!data || !data.ok || typeof data.scanId !== 'number') {
    const status = upstream.status === 404 ? 404 : upstream.status === 409 ? 409 : 500;
    return json({ ok: false, error: data?.error ?? 'scan start failed' }, status);
  }
  try {
    void postAdminWebhook({
      title: 'Scan started',
      color: 0xf39c12,
      actor: user,
      fields: [
        { name: 'Steam HEX', value: '`' + steamHex + '`', inline: true },
        { name: 'Scan type', value: String(scanType), inline: true },
        { name: 'Include signed', value: includeSigned ? 'yes' : 'no', inline: true },
      ],
    });
  } catch {}
  return json({ ok: true, scanId: data.scanId });
}
