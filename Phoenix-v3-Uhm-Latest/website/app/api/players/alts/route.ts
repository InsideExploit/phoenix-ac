import { NextRequest, NextResponse } from 'next/server';

import { getSessionUser } from '@/lib/auth/auth';
import { getAltAccountsByPlayerHex } from '@/lib/players/altAccounts';
import { clientIp, NO_STORE, rateLimit } from '@/lib/security/security';

export const runtime = 'nodejs';

export const dynamic = 'force-dynamic';
const json = (data: unknown, status = 200) =>
  NextResponse.json(data, { status, headers: NO_STORE });

export async function GET(req: NextRequest) {
  if (!rateLimit(`alts:${clientIp(req)}`, 60, 60000))
    return json({ ok: false, error: 'too many requests' }, 429);
  const user = await getSessionUser();
  if (!user) return json({ ok: false, error: 'unauthorized' }, 401);
  const sp = req.nextUrl.searchParams;
  const steamHex = (sp.get('steam') || '').trim().toLowerCase();
  if (!steamHex || !/^[0-9a-f]{1,16}$/.test(steamHex))
    return json({ ok: false, error: 'bad steam' }, 400);
  const alts = await getAltAccountsByPlayerHex(steamHex);
  return json({ ok: true, alts });
}
