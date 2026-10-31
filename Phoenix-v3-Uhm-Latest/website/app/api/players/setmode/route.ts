import { NextRequest, NextResponse } from 'next/server';

import { getSessionUser } from '@/lib/auth/auth';
import { config } from '@/lib/core/config';
import { setPlayerAgentMode } from '@/lib/players/players';
import { clientIp, isSameOrigin, NO_STORE, rateLimit } from '@/lib/security/security';
import { postAdminWebhook } from '@/lib/webhooks/webhook';

export const runtime = 'nodejs';

export const dynamic = 'force-dynamic';
const json = (data: unknown, status = 200) =>
  NextResponse.json(data, { status, headers: NO_STORE });

export async function POST(req: NextRequest) {
  if (!isSameOrigin(req)) return json({ ok: false, error: 'forbidden' }, 403);
  if (!rateLimit(`setmode:${clientIp(req)}`, 20, 60000))
    return json({ ok: false, error: 'too many requests' }, 429);
  const user = await getSessionUser();
  if (!user) return json({ ok: false, error: 'unauthorized' }, 401);
  const body = (await req.json().catch(() => null)) as {
    steam_hex?: unknown;
    mode?: unknown;
  } | null;
  const steamHex = typeof body?.steam_hex === 'string' ? body.steam_hex.trim().toLowerCase() : '';
  const mode = body?.mode === 'kernel' || body?.mode === 'usermode' ? body.mode : null;
  if (!steamHex || !/^[0-9a-f]{1,16}$/.test(steamHex) || !mode)
    return json({ ok: false, error: 'bad request' }, 400);
  const actor = user.id || user.global_name || user.username || 'admin';
  const result = await setPlayerAgentMode(
    steamHex,
    mode,
    actor,
    config.phoenix_online_window_seconds,
  );
  if (!result.ok) {
    return json(
      { ok: false, error: result.error || 'Player not found.' },
      result.error?.includes('online') ? 409 : result.error ? 400 : 404,
    );
  }
  try {
    void postAdminWebhook({
      title: 'Set mode',
      color: mode === 'kernel' ? 0xe67e22 : 0x3498db,
      actor: user,
      fields: [
        { name: 'Steam HEX', value: '`' + steamHex + '`', inline: true },
        { name: 'Mode', value: mode, inline: true },
      ],
    });
  } catch {}
  return json({ ok: true, mode });
}
