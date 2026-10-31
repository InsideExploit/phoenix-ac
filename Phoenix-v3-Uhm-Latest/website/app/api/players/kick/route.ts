import { NextRequest, NextResponse } from 'next/server';

import { getSessionUser } from '@/lib/auth/auth';
import { backendUrl as BACKEND_URL } from '@/lib/env';
import { clientIp, isSameOrigin, NO_STORE, rateLimit } from '@/lib/security/security';
import { postAdminWebhook } from '@/lib/webhooks/webhook';

export const runtime = 'nodejs';

export const dynamic = 'force-dynamic';
const json = (data: unknown, status = 200) =>
  NextResponse.json(data, { status, headers: NO_STORE });

export async function POST(req: NextRequest) {
  if (!isSameOrigin(req)) return json({ ok: false, error: 'forbidden' }, 403);
  if (!rateLimit(`kick:${clientIp(req)}`, 20, 60000))
    return json({ ok: false, error: 'too many requests' }, 429);
  const user = await getSessionUser();
  if (!user) return json({ ok: false, error: 'unauthorized' }, 401);
  const body = (await req.json().catch(() => null)) as {
    steam_hex?: unknown;
    reason?: unknown;
  } | null;
  const steamHex = typeof body?.steam_hex === 'string' ? body.steam_hex.trim().toLowerCase() : '';
  if (!steamHex || !/^[0-9a-f]{1,16}$/.test(steamHex))
    return json({ ok: false, error: 'bad steam_hex' }, 400);
  const reason = (typeof body?.reason === 'string' ? body.reason.trim() : '').slice(0, 200);
  const controller = new AbortController();
  const t = setTimeout(() => controller.abort(), 10000);
  let upstream: Response;
  try {
    upstream = await fetch(`${BACKEND_URL}/v1/admin/kick`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ steam_hex: steamHex, reason }),
      signal: controller.signal,
      cache: 'no-store',
    });
  } catch (e) {
    clearTimeout(t);
    return json(
      { ok: false, error: 'Backend non raggiungibile (' + (e as Error).message + ')' },
      503,
    );
  }
  clearTimeout(t);
  type BackendReply = {
    ok?: boolean;
    error?: string;
  };
  const raw = await upstream.text().catch(() => '');
  let data: BackendReply | null = null;
  try {
    data = JSON.parse(raw) as BackendReply;
  } catch {
    data = null;
  }
  if (!data)
    return json({ ok: false, error: 'Backend risposta inattesa (' + upstream.status + ')' }, 500);
  if (data.ok) {
    try {
      void postAdminWebhook({
        title: 'Player Kicked',
        color: 0xf39c12,
        actor: user,
        fields: [
          { name: 'Steam HEX', value: '`' + steamHex + '`', inline: true },
          { name: 'Reason', value: reason || '(none)', inline: false },
        ],
      });
    } catch {}
    return json({ ok: true });
  }
  const status = upstream.status === 404 ? 404 : 500;
  return json({ ok: false, error: data.error || 'Kick fallito' }, status);
}
