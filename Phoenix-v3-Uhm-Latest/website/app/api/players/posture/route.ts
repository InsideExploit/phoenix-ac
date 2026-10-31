import { NextRequest, NextResponse } from 'next/server';

import { getSessionUser } from '@/lib/auth/auth';
import { setPlayerPostureExempt } from '@/lib/players/players';
import { clientIp, isSameOrigin, NO_STORE, rateLimit } from '@/lib/security/security';
import { postAdminWebhook } from '@/lib/webhooks/webhook';

export const runtime = 'nodejs';

export const dynamic = 'force-dynamic';
const json = (data: unknown, status = 200) =>
  NextResponse.json(data, { status, headers: NO_STORE });

export async function POST(req: NextRequest) {
  if (!isSameOrigin(req)) return json({ ok: false, error: 'forbidden' }, 403);
  if (!rateLimit(`posture:${clientIp(req)}`, 40, 60000))
    return json({ ok: false, error: 'too many requests' }, 429);
  const user = await getSessionUser();
  if (!user) return json({ ok: false, error: 'unauthorized' }, 401);
  const body = (await req.json().catch(() => null)) as {
    steam_hex?: unknown;
    allow_no_secure_boot?: unknown;
    allow_no_hvci?: unknown;
  } | null;
  const steamHex = typeof body?.steam_hex === 'string' ? body.steam_hex.trim().toLowerCase() : '';
  if (!steamHex || !/^[0-9a-f]{1,16}$/.test(steamHex))
    return json({ ok: false, error: 'bad request' }, 400);
  const patch: {
    allowNoSecureBoot?: boolean;
    allowNoHvci?: boolean;
  } = {};
  if (typeof body?.allow_no_secure_boot === 'boolean')
    patch.allowNoSecureBoot = body.allow_no_secure_boot;
  if (typeof body?.allow_no_hvci === 'boolean') patch.allowNoHvci = body.allow_no_hvci;
  if (patch.allowNoSecureBoot === undefined && patch.allowNoHvci === undefined)
    return json({ ok: false, error: 'bad request' }, 400);
  const actor = user.id || user.global_name || user.username || 'admin';
  const result = await setPlayerPostureExempt(steamHex, patch, actor);
  if (!result.ok) return json({ ok: false, error: result.error || 'Player not found.' }, 404);
  const label =
    patch.allowNoSecureBoot !== undefined
      ? `Secure Boot ${patch.allowNoSecureBoot ? 'off' : 'required'}`
      : `Core Isolation ${patch.allowNoHvci ? 'off' : 'required'}`;
  try {
    void postAdminWebhook({
      title: 'Posture exception',
      color: 0x95a5a6,
      actor: user,
      fields: [
        { name: 'Steam HEX', value: '`' + steamHex + '`', inline: true },
        { name: 'Change', value: label, inline: true },
      ],
    });
  } catch {}
  return json({ ok: true, ...patch });
}
