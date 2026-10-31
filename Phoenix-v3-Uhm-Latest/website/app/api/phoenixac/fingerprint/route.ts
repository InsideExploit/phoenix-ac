import { NextRequest, NextResponse } from 'next/server';

import type { RowDataPacket } from 'mysql2';

import { config } from '@/lib/core/config';
import { pool } from '@/lib/database/pool';
import { clientIp, NO_STORE, rateLimit } from '@/lib/security/security';
import { postEvasionWebhook } from '@/lib/webhooks/webhook';

export const runtime = 'nodejs';
type Body = {
  steam_hex?: string;
  name?: string | null;
  discord_id?: string | null;
  license?: string | null;
  license2?: string | null;
  tokens?: string[] | null;
};

type FpRow = RowDataPacket & {
  steam_hex: string;
  name: string | null;
};

type FlagRow = RowDataPacket & {
  id: number;
};

const json = (data: unknown, status = 200) =>
  NextResponse.json(data, { status, headers: NO_STORE });

const isHex = (s: string) => /^[0-9a-fA-F]{6,32}$/.test(s);
const trim = (s: string | null | undefined, n: number): string | null =>
  s == null || s === '' ? null : String(s).slice(0, n);

type FpType = 'discord' | 'license' | 'license2' | 'token' | 'ip';

export async function POST(req: NextRequest) {
  const ip = clientIp(req);
  if (!rateLimit(`fp:${ip}`, 600, 60000))
    return json({ ok: false, error: 'too many requests' }, 429);
  const expected = config.phoenix_server_key;
  if (expected && req.headers.get('x-server-key') !== expected)
    return json({ ok: false, error: 'forbidden' }, 403);
  const body = (await req.json().catch(() => null)) as Body | null;
  if (!body) return json({ ok: false, error: 'body invalido' }, 400);
  const hex = (body.steam_hex ?? '').replace(/^steam:/i, '').trim();
  if (!hex || !isHex(hex)) return json({ ok: false, error: 'steam_hex invalido' }, 400);
  const name = trim(body.name, 128);
  const fps: {
    type: FpType;
    value: string;
  }[] = [];
  const push = (type: FpType, v: string | null | undefined, max: number) => {
    const t = trim(v, max);
    if (t) fps.push({ type, value: t });
  };
  push('discord', body.discord_id, 32);
  push('license', body.license, 80);
  push('license2', body.license2, 80);
  if (Array.isArray(body.tokens)) {
    for (const t of body.tokens.slice(0, 12)) {
      push('token', t, 255);
    }
  }
  if (fps.length === 0) return json({ ok: true, flags: 0 });
  let flagsCreated = 0;
  try {
    for (const fp of fps) {
      await pool.query(
        `INSERT INTO player_fingerprints (steam_hex, fp_type, fp_value, name)
         VALUES (?, ?, ?, ?)
         ON DUPLICATE KEY UPDATE last_seen = CURRENT_TIMESTAMP,
                                 name = COALESCE(VALUES(name), name)`,
        [hex, fp.type, fp.value, name],
      );
      const [matches] = await pool.query<FpRow[]>(
        `SELECT steam_hex, name FROM player_fingerprints
           WHERE fp_type = ? AND fp_value = ? AND steam_hex <> ?`,
        [fp.type, fp.value, hex],
      );
      for (const m of matches) {
        const [dups] = await pool.query<FlagRow[]>(
          `SELECT id FROM evasion_flags
             WHERE ((primary_hex = ? AND secondary_hex = ?)
                 OR (primary_hex = ? AND secondary_hex = ?))
               AND fp_type = ? AND fp_value = ?
               AND created_at > (NOW() - INTERVAL 1 HOUR)
             LIMIT 1`,
          [hex, m.steam_hex, m.steam_hex, hex, fp.type, fp.value],
        );
        if (dups.length > 0) continue;
        await pool.query(
          `INSERT INTO evasion_flags
            (primary_hex, secondary_hex, fp_type, fp_value,
             primary_name, secondary_name, client_ip)
           VALUES (?, ?, ?, ?, ?, ?, ?)`,
          [hex, m.steam_hex, fp.type, fp.value, name, m.name, ip],
        );
        flagsCreated++;
        void postEvasionWebhook({
          primaryHex: hex,
          secondaryHex: m.steam_hex,
          fpType: fp.type,
          fpValue: fp.value,
          primaryName: name,
          secondaryName: m.name,
          clientIp: ip,
        });
      }
    }
    return json({ ok: true, flags: flagsCreated });
  } catch {
    return json({ ok: false, error: 'server error' }, 500);
  }
}
