import { NextRequest, NextResponse } from 'next/server';

import type { ResultSetHeader } from 'mysql2';

import { config } from '@/lib/core/config';
import { pool } from '@/lib/database/pool';
import { clientIp, NO_STORE, rateLimit } from '@/lib/security/security';

export const runtime = 'nodejs';
type Identity = {
  steam_hex?: string | null;
  discord_id?: string | null;
  license?: string | null;
  token?: string | null;
  name?: string | null;
};

type Body = {
  killer?: Identity | null;
  victim?: Identity | null;
  weapon?: string | null;
};

const json = (data: unknown, status = 200) =>
  NextResponse.json(data, { status, headers: NO_STORE });

const isHex = (s: string) => /^[0-9a-fA-F]{6,32}$/.test(s);
const trim = (s: string | null | undefined, n: number) =>
  s == null ? null : String(s).slice(0, n);

export async function POST(req: NextRequest) {
  if (!rateLimit(`kill-evt:${clientIp(req)}`, 1000, 60000))
    return json({ ok: false, error: 'too many requests' }, 429);
  const expected = config.phoenix_server_key;
  if (expected && req.headers.get('x-server-key') !== expected)
    return json({ ok: false, error: 'forbidden' }, 403);
  const body = (await req.json().catch(() => null)) as Body | null;
  if (!body) return json({ ok: false, error: 'body invalido' }, 400);
  const k = body.killer ?? {};
  const v = body.victim ?? {};
  const killerHex = (k.steam_hex ?? '').replace(/^steam:/i, '').trim();
  if (!killerHex || !isHex(killerHex))
    return json({ ok: false, error: 'killer.steam_hex invalido' }, 400);
  const victimHex = (v.steam_hex ?? '').replace(/^steam:/i, '').trim() || null;
  if (victimHex && !isHex(victimHex))
    return json({ ok: false, error: 'victim.steam_hex invalido' }, 400);
  try {
    await pool.query<ResultSetHeader>(
      `INSERT INTO kills
        (killer_steam_hex, killer_discord_id, killer_license, killer_token, killer_name,
         victim_steam_hex, victim_discord_id, victim_license, victim_token, victim_name,
         weapon)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        killerHex,
        trim(k.discord_id, 32),
        trim(k.license, 80),
        trim(k.token, 128),
        trim(k.name, 128),
        victimHex,
        trim(v.discord_id, 32),
        trim(v.license, 80),
        trim(v.token, 128),
        trim(v.name, 128),
        trim(body.weapon, 64),
      ],
    );
    return json({ ok: true });
  } catch {
    return json({ ok: false, error: 'server error' }, 500);
  }
}
