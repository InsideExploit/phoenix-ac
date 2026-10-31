import { NextRequest, NextResponse } from 'next/server';

import type { RowDataPacket } from 'mysql2';

import { getSessionUser } from '@/lib/auth/auth';
import { encryptDash, isDashCryptoConfigured } from '@/lib/crypto/crypto';
import { pool } from '@/lib/database/pool';
import { clientIp, NO_STORE, rateLimit } from '@/lib/security/security';

export const runtime = 'nodejs';

export const dynamic = 'force-dynamic';
const json = (data: unknown, status = 200) =>
  NextResponse.json(data, { status, headers: NO_STORE });

function encDashJson(data: unknown, status = 200) {
  if (!isDashCryptoConfigured()) return json(data, status);
  const body = encryptDash(JSON.stringify(data));
  return new NextResponse(body, {
    status,
    headers: {
      ...NO_STORE,
      'Content-Type': 'application/octet-stream',
      'X-Phoenix-Enc': 'dash',
    },
  });
}

type KillAggRow = RowDataPacket & {
  steam_hex: string;
  kills: number;
  discord_id: string | null;
  license: string | null;
  token: string | null;
  name: string | null;
  last_seen: string | null;
};

type DeathAggRow = RowDataPacket & {
  steam_hex: string;
  deaths: number;
  discord_id: string | null;
  license: string | null;
  token: string | null;
  name: string | null;
  last_seen: string | null;
};

type EventRow = RowDataPacket & {
  hex: string;
  kind: 'k' | 'd';
};

export async function GET(req: NextRequest) {
  if (!rateLimit(`stats:${clientIp(req)}`, 240, 60000))
    return json({ ok: false, error: 'too many requests' }, 429);
  if (!(await getSessionUser())) return json({ ok: false, error: 'unauthorized' }, 401);
  const sp = req.nextUrl.searchParams;
  const qRaw = (sp.get('q') ?? '').trim();
  const q = qRaw.replace(/[%_]/g, '\\$&');
  const like = q ? `%${q}%` : null;
  try {
    const killParams: unknown[] = [];
    let killWhere = '';
    if (like) {
      killWhere = `WHERE killer_steam_hex LIKE ?
                     OR killer_discord_id LIKE ?
                     OR killer_name      LIKE ?`;
      killParams.push(like, like, like);
    }
    const [killRows] = await pool.query<KillAggRow[]>(
      `SELECT killer_steam_hex                   AS steam_hex,
              COUNT(*)                           AS kills,
              MAX(killer_discord_id)             AS discord_id,
              MAX(killer_license)                AS license,
              MAX(killer_token)                  AS token,
              MAX(killer_name)                   AS name,
              MAX(created_at)                    AS last_seen
         FROM kills
         ${killWhere}
         GROUP BY killer_steam_hex`,
      killParams,
    );
    const deathParams: unknown[] = [];
    let deathWhere = '';
    if (like) {
      deathWhere = `WHERE victim_steam_hex LIKE ?
                      OR victim_discord_id LIKE ?
                      OR victim_name      LIKE ?`;
      deathParams.push(like, like, like);
    }
    const [deathRows] = await pool.query<DeathAggRow[]>(
      `SELECT victim_steam_hex                  AS steam_hex,
              COUNT(*)                          AS deaths,
              MAX(victim_discord_id)            AS discord_id,
              MAX(victim_license)               AS license,
              MAX(victim_token)                 AS token,
              MAX(victim_name)                  AS name,
              MAX(created_at)                   AS last_seen
         FROM kills
         WHERE victim_steam_hex IS NOT NULL AND victim_steam_hex <> ''
         ${like ? 'AND (victim_steam_hex LIKE ? OR victim_discord_id LIKE ? OR victim_name LIKE ?)' : ''}
         GROUP BY victim_steam_hex`,
      deathParams,
    );
    type Agg = {
      steamHex: string;
      discordId: string | null;
      license: string | null;
      token: string | null;
      name: string | null;
      kills: number;
      deaths: number;
      lastSeen: string | null;
    };
    const map = new Map<string, Agg>();
    for (const r of killRows) {
      map.set(r.steam_hex, {
        steamHex: r.steam_hex,
        discordId: r.discord_id,
        license: r.license,
        token: r.token,
        name: r.name,
        kills: Number(r.kills),
        deaths: 0,
        lastSeen: r.last_seen,
      });
    }
    for (const r of deathRows) {
      const existing = map.get(r.steam_hex);
      if (existing) {
        existing.deaths = Number(r.deaths);
        existing.discordId = existing.discordId ?? r.discord_id;
        existing.license = existing.license ?? r.license;
        existing.token = existing.token ?? r.token;
        existing.name = existing.name ?? r.name;
        if (r.last_seen && (!existing.lastSeen || r.last_seen > existing.lastSeen)) {
          existing.lastSeen = r.last_seen;
        }
      } else {
        map.set(r.steam_hex, {
          steamHex: r.steam_hex,
          discordId: r.discord_id,
          license: r.license,
          token: r.token,
          name: r.name,
          kills: 0,
          deaths: Number(r.deaths),
          lastSeen: r.last_seen,
        });
      }
    }
    const hexes = Array.from(map.keys());
    const streakMap = new Map<
      string,
      {
        current: number;
        max: number;
      }
    >();
    if (hexes.length > 0) {
      const placeholders = hexes.map(() => '?').join(',');
      const [events] = await pool.query<EventRow[]>(
        `(SELECT killer_steam_hex AS hex, 'k' AS kind, created_at
            FROM kills
            WHERE killer_steam_hex IN (${placeholders}))
         UNION ALL
         (SELECT victim_steam_hex AS hex, 'd' AS kind, created_at
            FROM kills
            WHERE victim_steam_hex IN (${placeholders}))
         ORDER BY hex, created_at ASC`,
        [...hexes, ...hexes],
      );
      const cur = new Map<
        string,
        {
          c: number;
          m: number;
        }
      >();
      for (const e of events) {
        const s = cur.get(e.hex) ?? { c: 0, m: 0 };
        if (e.kind === 'k') {
          s.c += 1;
          if (s.c > s.m) s.m = s.c;
        } else {
          s.c = 0;
        }
        cur.set(e.hex, s);
      }
      for (const [h, s] of cur) {
        streakMap.set(h, { current: s.c, max: s.m });
      }
    }
    const stats = Array.from(map.values())
      .map((a) => {
        const s = streakMap.get(a.steamHex) ?? { current: 0, max: 0 };
        const kd = a.deaths === 0 ? a.kills : Number((a.kills / a.deaths).toFixed(2));
        return {
          steamHex: a.steamHex,
          discordId: a.discordId,
          license: a.license,
          token: a.token,
          name: a.name,
          kills: a.kills,
          deaths: a.deaths,
          kd,
          currentStreak: s.current,
          maxStreak: s.max,
          lastSeen: a.lastSeen,
        };
      })
      .sort((x, y) => {
        if (y.kills !== x.kills) return y.kills - x.kills;
        return y.deaths - x.deaths;
      });
    return encDashJson({ ok: true, stats });
  } catch {
    return json({ ok: false, error: 'server error' }, 500);
  }
}
