import { NextRequest } from 'next/server';

import { getSessionUser } from '@/lib/auth/auth';
import { hasElevatedAccess } from '@/lib/auth/session';
import { backendUrl as BACKEND_URL } from '@/lib/env';
import { clientIp, rateLimit } from '@/lib/security/security';

export const runtime = 'nodejs';

export const dynamic = 'force-dynamic';

export async function GET(
  req: NextRequest,
  ctx: {
    params: Promise<{
      path: string[];
    }>;
  },
) {
  if (!rateLimit(`shot-get:${clientIp(req)}`, 60, 60000))
    return new Response('too many requests', { status: 429 });
  const user = await getSessionUser();
  if (!user) return new Response('unauthorized', { status: 401 });
  if (!(await hasElevatedAccess(user.id))) return new Response('forbidden', { status: 403 });
  const { path } = await ctx.params;
  if (!path || path.length === 0) return new Response('bad path', { status: 400 });
  const safe = path
    .map((p) => p.replace(/[^0-9a-zA-Z._-]/g, ''))
    .filter((p) => p && p !== '.' && p !== '..');
  if (safe.length === 0 || !safe[safe.length - 1].endsWith('.png'))
    return new Response('bad path', { status: 400 });
  const rel = safe.join('/');
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 8000);
  let upstream: Response;
  try {
    upstream = await fetch(`${BACKEND_URL}/v1/screenshots/${rel}`, {
      signal: controller.signal,
      cache: 'no-store',
    });
  } catch (e) {
    clearTimeout(timeout);
    console.error('[screenshots-proxy] backend unreachable:', (e as Error).message);
    return new Response('backend unreachable', { status: 503 });
  }
  clearTimeout(timeout);
  if (!upstream.ok) return new Response('not found', { status: upstream.status });
  const buf = await upstream.arrayBuffer();
  return new Response(buf, {
    status: 200,
    headers: {
      'content-type': 'image/png',
      'cache-control': 'private, max-age=60',
    },
  });
}
