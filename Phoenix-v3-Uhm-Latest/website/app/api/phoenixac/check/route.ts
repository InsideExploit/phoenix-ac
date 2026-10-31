import { NextRequest, NextResponse } from 'next/server';

import type { ResultSetHeader, RowDataPacket } from 'mysql2';

import { config } from '@/lib/core/config';
import { encrypt, isCryptoConfigured, tryDecrypt } from '@/lib/crypto/crypto';
import { pool } from '@/lib/database/pool';
import { getLauncherSha, shaEnforce } from '@/lib/launcher/launcher_sha';
import { clientIp, NO_STORE, rateLimit } from '@/lib/security/security';
import { postLoginWebhook } from '@/lib/webhooks/webhook';

export const runtime = 'nodejs';
type Body = {
  steam_hex?: string;
  disk_id?: string;
  sha256?: string;
};

type PlayerRow = RowDataPacket & {
  id: number;
  banned: number;
  was_online: number;
};

const ONLINE_WINDOW_SECONDS = 120;
const json = (data: unknown, status = 200) =>
  NextResponse.json(data, { status, headers: NO_STORE });

function encJson(data: unknown, status = 200, encOk = false) {
  if (!encOk) return json(data, status);
  const body = encrypt(JSON.stringify(data));
  return new NextResponse(body, {
    status,
    headers: {
      ...NO_STORE,
      'Content-Type': 'application/octet-stream',
      'X-Phoenix-Enc': '1',
    },
  });
}

const isHex = (s: string) => /^[0-9a-fA-F]{6,32}$/.test(s);
const isDiskId = (s: string) => /^[0-9a-fA-F]{4,32}$/.test(s);
const isSha256 = (s: string) => /^[0-9a-f]{64}$/i.test(s);
const DBG = config.phoenix_check_debug;
const dlog = (msg: string) => {
  if (DBG) console.log(`[check] ${msg}`);
};

export async function POST(req: NextRequest) {
  const ip = clientIp(req);
  if (!rateLimit(`phoenixac:${ip}`, 120, 60000)) {
    dlog(`ip=${ip} REJECT rate-limit`);
    return json({ ok: false, error: 'too many requests' }, 429);
  }
  const expectedKey = config.phoenix_api_key;
  if (expectedKey && req.headers.get('x-api-key') !== expectedKey) {
    dlog(`ip=${ip} REJECT bad-api-key (got=${req.headers.get('x-api-key')?.slice(0, 8)})`);
    return json({ ok: false, error: 'forbidden' }, 403);
  }
  const wantEnc = req.headers.get('x-phoenix-enc') === '1' && isCryptoConfigured();
  let body: Body | null = null;
  if (wantEnc) {
    const raw = await req.text();
    const dec = tryDecrypt(raw);
    if (!dec) {
      dlog(`ip=${ip} REJECT decrypt-fail rawlen=${raw.length}`);
      return json({ ok: false, error: 'envelope invalido' }, 400);
    }
    body = JSON.parse(dec) as Body;
  } else {
    body = (await req.json().catch(() => null)) as Body | null;
  }
  const hex = body?.steam_hex?.trim() ?? '';
  const diskId = body?.disk_id?.trim() ?? '';
  const clientSha = body?.sha256?.trim().toLowerCase() ?? '';
  if (!hex || !isHex(hex)) {
    dlog(`ip=${ip} REJECT bad-hex hex=${hex}`);
    return json({ ok: false, error: 'steam_hex invalido' }, 400);
  }
  if (diskId && !isDiskId(diskId)) {
    dlog(`ip=${ip} REJECT bad-diskid diskId=${diskId}`);
    return json({ ok: false, error: 'disk_id invalido' }, 400);
  }
  if (shaEnforce()) {
    const expectedSha = await getLauncherSha();
    if (expectedSha) {
      if (!clientSha || !isSha256(clientSha)) {
        dlog(`ip=${ip} hex=${hex} REJECT sha-missing (clientSha=${clientSha?.slice(0, 16)})`);
        return json({ ok: false, error: 'binary tampered' }, 403);
      }
      if (clientSha !== expectedSha) {
        dlog(
          `ip=${ip} hex=${hex} REJECT sha-mismatch client=${clientSha.slice(0, 16)} server=${expectedSha.slice(0, 16)}`,
        );
        return json({ ok: false, error: 'binary tampered' }, 403);
      }
    } else {
      dlog(`ip=${ip} hex=${hex} sha-skip (no expectedSha - file missing on server?)`);
    }
  }
  try {
    const [rows] = await pool.query<PlayerRow[]>(
      `SELECT id, banned,
              (last_seen IS NOT NULL AND last_seen > (NOW() - INTERVAL ? SECOND)) AS was_online
         FROM players
        WHERE steam_hex = ?
        LIMIT 1`,
      [ONLINE_WINDOW_SECONDS, hex],
    );
    const player = rows[0];
    if (!player) {
      dlog(`ip=${ip} hex=${hex} REJECT not-in-db`);
      return json({ ok: false, error: 'unauthorized' }, 401);
    }
    if (player.banned) {
      dlog(`ip=${ip} hex=${hex} REJECT banned`);
      return json({ ok: false, error: 'banned' }, 403);
    }
    await pool.query<ResultSetHeader>(`UPDATE players SET last_seen = NOW() WHERE id = ?`, [
      player.id,
    ]);
    dlog(`ip=${ip} hex=${hex} OK last_seen=NOW`);
    if (!player.was_online) {
      void postLoginWebhook({
        steamHex: hex,
        diskId,
        ip: clientIp(req),
      });
    }
    return encJson({ ok: true, phoenix_ac: true, ttl: 60 }, 200, wantEnc);
  } catch {
    return json({ ok: false, error: 'server error' }, 500);
  }
}
