import { NextRequest, NextResponse } from 'next/server';

import { getSessionUser } from '@/lib/auth/auth';
import { getLauncherSha } from '@/lib/launcher/launcher_sha';
import { clientIp, NO_STORE, rateLimit } from '@/lib/security/security';

export const runtime = 'nodejs';
const json = (data: unknown, status = 200) =>
  NextResponse.json(data, { status, headers: NO_STORE });

export async function GET(req: NextRequest) {
  if (!rateLimit(`sha:${clientIp(req)}`, 60, 60000))
    return json({ ok: false, error: 'too many requests' }, 429);
  if (!(await getSessionUser())) return json({ ok: false, error: 'unauthorized' }, 401);
  const sha = await getLauncherSha();
  return json({ ok: true, sha: sha ?? null });
}
