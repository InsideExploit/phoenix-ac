import { NextRequest, NextResponse } from 'next/server';

import type { RowDataPacket } from 'mysql2';

import { config } from '@/lib/core/config';
import { pool } from '@/lib/database/pool';
import { clientIp, NO_STORE, rateLimit } from '@/lib/security/security';

export const runtime = 'nodejs';
type Body = {
  steam_hex?: string;
};

type Row = RowDataPacket & {
  id: number;
  banned: number;
  suspended: number;
  launcher_open: number;
};

const ONLINE_WINDOW_SECONDS = config.phoenix_online_window_seconds;
const json = (data: unknown, status = 200) =>
  NextResponse.json(data, { status, headers: NO_STORE });

const isHex = (s: string) => /^[0-9a-fA-F]{6,32}$/.test(s);

export async function POST(req: NextRequest) {
  if (!rateLimit(`phoenixac-srv:${clientIp(req)}`, 600, 60000))
    return json({ ok: false, error: 'too many requests' }, 429);
  const expected = config.phoenix_server_key;
  if (expected && req.headers.get('x-server-key') !== expected)
    return json({ ok: false, error: 'forbidden' }, 403);
  const body = (await req.json().catch(() => null)) as Body | null;
  const hex = (body?.steam_hex ?? '').replace(/^steam:/i, '').trim();
  if (!hex || !isHex(hex)) return json({ ok: false, error: 'steam_hex invalido' }, 400);
  try {
    const [rows] = await pool.query<Row[]>(
      `SELECT id, banned, COALESCE(suspended, 0) AS suspended,
              (last_seen IS NOT NULL AND last_seen > (NOW() - INTERVAL ? SECOND)) AS launcher_open
         FROM players WHERE steam_hex = ? LIMIT 1`,
      [ONLINE_WINDOW_SECONDS, hex],
    );
    const player = rows[0];
    if (!player) return json({ ok: true, required: false });
    if (player.suspended) {
      return json({
        ok: true,
        required: false,
        banned: !!player.banned,
        launcher_open: false,
      });
    }
    return json({
      ok: true,
      required: true,
      banned: !!player.banned,
      launcher_open: !!player.launcher_open,
    });
  } catch {
    return json({ ok: false, error: 'server error' }, 500);
  }
}
