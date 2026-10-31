import { NextRequest, NextResponse } from 'next/server';

import {
  signDownloadToken,
  STEAM_DL_COOKIE,
  steamId64ToHex,
  verifyOpenIdCallback,
} from '@/lib/auth/steam';
import { findPlayerBySteamHex } from '@/lib/players/players';
import { clientIp, rateLimit } from '@/lib/security/security';

export const runtime = 'nodejs';

function bridge(
  payload:
    | {
        ok: true;
      }
    | {
        ok: false;
        err: string;
      },
): string {
  const json = JSON.stringify({ source: 'phoenixac-steam', ...payload });
  const msgHtml = payload.ok
    ? 'Accesso Steam completato. Puoi chiudere questa finestra.'
    : 'Accesso Steam fallito. Puoi chiudere questa finestra.';
  return `<!doctype html><meta charset="utf-8"><title>Steam</title>
<style>body{margin:0;font-family:system-ui,sans-serif;background:#0a0a0a;color:#e5e5e5;display:flex;align-items:center;justify-content:center;min-height:100vh;padding:24px;text-align:center}</style>
<script>(function(){
  var msg = ${json};
  try {
    if (window.opener && !window.opener.closed) {
      window.opener.postMessage(msg, location.origin);
      window.close();
    }
  } catch(e){}
})();</script>
<p>${msgHtml}</p>`;
}

function htmlResponse(body: string, cookie?: string): NextResponse {
  const res = new NextResponse(body, {
    status: 200,
    headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' },
  });
  if (cookie) {
    res.cookies.set(STEAM_DL_COOKIE, cookie, {
      httpOnly: true,
      sameSite: 'lax',
      path: '/',
      maxAge: 10 * 60,
      secure: process.env.NODE_ENV === 'production',
    });
  }
  return res;
}

const fail = (err: string) => htmlResponse(bridge({ ok: false, err }));

export async function GET(req: NextRequest) {
  if (!rateLimit(`steam-cb:${clientIp(req)}`, 60, 60000)) return fail('rate');
  const verified = await verifyOpenIdCallback(req.nextUrl.searchParams);
  if (!verified.ok || !verified.steamId64) return fail('openid');
  const hex = steamId64ToHex(verified.steamId64);
  const player = await findPlayerBySteamHex(hex);
  if (!player) return fail('not-authorized');
  if (player.banned) return fail('banned');
  if (player.suspended) return fail('suspended');
  const token = signDownloadToken({ steamHex: hex, playerId: player.id });
  return htmlResponse(bridge({ ok: true }), token);
}
