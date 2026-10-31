import { NextRequest } from 'next/server';

import { getSessionUser } from '@/lib/auth/auth';
import { hasElevatedAccess } from '@/lib/auth/session';
import { backendUrl as BACKEND_URL } from '@/lib/env';

export const runtime = 'nodejs';

export const dynamic = 'force-dynamic';

export async function GET(req: NextRequest) {
  const user = await getSessionUser();
  if (!user) return new Response('unauthorized', { status: 401 });
  if (!(await hasElevatedAccess(user.id))) return new Response('forbidden', { status: 403 });
  const steamHex = (req.nextUrl.searchParams.get('steam_hex') ?? '').trim().toLowerCase();
  if (!steamHex || !/^[0-9a-f]{1,16}$/.test(steamHex))
    return new Response('bad steam_hex', { status: 400 });
  const scanIdRaw = req.nextUrl.searchParams.get('scan_id') ?? '';
  const scanId = Number(scanIdRaw);
  if (!Number.isFinite(scanId) || scanId <= 0 || scanId > 0xffffffff)
    return new Response('bad scan_id', { status: 400 });
  const url = new URL(`${BACKEND_URL}/v1/agent/scan/events`);
  url.searchParams.set('steam_hex', steamHex);
  url.searchParams.set('scan_id', String(Math.floor(scanId)));
  const controller = new AbortController();
  req.signal.addEventListener('abort', () => controller.abort());
  let upstream: Response;
  try {
    upstream = await fetch(url, { method: 'GET', cache: 'no-store', signal: controller.signal });
  } catch (e) {
    return new Response(`Backend unreachable (${(e as Error).message})`, { status: 503 });
  }
  if (!upstream.ok || !upstream.body) {
    return new Response(`backend ${upstream.status}`, { status: upstream.status || 502 });
  }
  return new Response(upstream.body, {
    status: 200,
    headers: {
      'content-type': 'text/event-stream',
      'cache-control': 'no-store, no-cache, must-revalidate, max-age=0',
      'x-accel-buffering': 'no',
      connection: 'keep-alive',
    },
  });
}
