import { NextRequest, NextResponse } from 'next/server';

import type { ResultSetHeader, RowDataPacket } from 'mysql2';

import { config } from '@/lib/core/config';
import { encrypt, isCryptoConfigured, tryDecrypt } from '@/lib/crypto/crypto';
import { verifyReplayAndSig } from '@/lib/crypto/replay';
import { pool } from '@/lib/database/pool';
import { clientIp, NO_STORE, rateLimit } from '@/lib/security/security';
import { postDetectionEvent, type DetectionEventType } from '@/lib/webhooks/webhook';

export const runtime = 'nodejs';
const ALLOWED_TYPES: ReadonlySet<DetectionEventType> = new Set([
  'detection',
  'sweep',
  'exit',
  'overlay',
  'internal',
  'mapper',
  'injection',
  'modfingerprint',
  'security',
]);

type Body = {
  type?: string;
  steam_hex?: string;
  pid?: number | string | null;
  exe?: string | null;
  host?: string | null;
  payload?: Record<string, unknown> | null;
};

type PlayerRow = RowDataPacket & {
  id: number;
};

const json = (data: unknown, status = 200) =>
  NextResponse.json(data, { status, headers: NO_STORE });

function encJson(data: unknown, status = 200, encOk = false) {
  if (!encOk) return json(data, status);
  try {
    const body = encrypt(JSON.stringify(data));
    return new NextResponse(body, {
      status,
      headers: {
        ...NO_STORE,
        'Content-Type': 'application/octet-stream',
        'X-Phoenix-Enc': '1',
      },
    });
  } catch {
    return json(data, status);
  }
}

const isHex = (s: string) => /^[0-9a-fA-F]{6,32}$/.test(s);
const isType = (t: unknown): t is DetectionEventType =>
  typeof t === 'string' && ALLOWED_TYPES.has(t as DetectionEventType);

const truncate = (s: string | null, max: number): string | null =>
  s == null ? null : s.length > max ? s.slice(0, max) : s;

export async function POST(req: NextRequest) {
  try {
    if (!rateLimit(`phoenixac-evt:${clientIp(req)}`, 300, 60000))
      return json({ ok: false, error: 'too many requests' }, 429);
    const expectedKey = config.phoenix_api_key;
    if (expectedKey && req.headers.get('x-api-key') !== expectedKey)
      return json({ ok: false, error: 'forbidden' }, 403);
    const cryptoOn = isCryptoConfigured();
    const encHdr = req.headers.get('x-phoenix-enc') === '1';
    if (cryptoOn && !encHdr) return json({ ok: false, error: 'encryption required' }, 400);
    const wantEnc = encHdr && cryptoOn;
    let body: Body | null = null;
    if (wantEnc) {
      const raw = await req.text();
      const rc = verifyReplayAndSig(
        req.headers.get('x-phoenix-ts'),
        req.headers.get('x-phoenix-nonce'),
        req.headers.get('x-phoenix-sig'),
        raw,
      );
      if (!rc.ok) return json({ ok: false, error: rc.reason }, rc.status);
      const dec = tryDecrypt(raw);
      if (!dec) return json({ ok: false, error: 'envelope invalido' }, 400);
      try {
        body = JSON.parse(dec) as Body;
      } catch {
        return json({ ok: false, error: 'json invalido' }, 400);
      }
    } else {
      body = (await req.json().catch(() => null)) as Body | null;
    }
    if (!body) return json({ ok: false, error: 'body invalido' }, 400);
    if (!isType(body.type)) return json({ ok: false, error: 'type invalido' }, 400);
    const hex = (body.steam_hex ?? '').trim();
    if (!hex || !isHex(hex)) return json({ ok: false, error: 'steam_hex invalido' }, 400);
    const type = body.type;
    const pidNum = body.pid == null ? null : Number(body.pid);
    const pid =
      pidNum != null && Number.isFinite(pidNum) && pidNum > 0 && pidNum <= 0xffffffff
        ? Math.floor(pidNum)
        : null;
    const exe = truncate((body.exe ?? '').trim() || null, 255);
    const host = truncate((body.host ?? '').trim() || null, 128);
    const ip = clientIp(req);
    const payload =
      body.payload && typeof body.payload === 'object' && !Array.isArray(body.payload)
        ? body.payload
        : {};
    const payloadJson = JSON.stringify(payload);
    if (payloadJson.length > 16000) return json({ ok: false, error: 'payload too large' }, 413);
    try {
      void postDetectionEvent({
        type,
        steamHex: hex,
        pid,
        exe,
        host,
        ip,
        payload,
      });
    } catch {}
    try {
      const [rows] = await pool.query<PlayerRow[]>(
        `SELECT id FROM players WHERE steam_hex = ? LIMIT 1`,
        [hex],
      );
      const playerId = rows[0]?.id ?? null;
      await pool.query<ResultSetHeader>(
        `INSERT INTO detections
           (player_id, steam_hex, type, pid, exe, host, client_ip, payload)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
        [playerId, hex, type, pid, exe, host, ip, payloadJson],
      );
    } catch {}
    return encJson({ ok: true }, 200, wantEnc);
  } catch {
    return json({ ok: false, error: 'server error' }, 500);
  }
}
