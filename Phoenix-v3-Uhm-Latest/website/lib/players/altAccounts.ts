import type { ResultSetHeader, RowDataPacket } from 'mysql2';

import { pool } from '@/lib/database/pool';

export type AltAccountView = {
  kind: 'steam' | 'discord';
  externalId: string;
  username: string | null;
  avatar: string | null;
  namesFetchedAt: string | null;
  firstSeen: string | null;
  lastSeen: string | null;
};

type Row = RowDataPacket & {
  kind: 'steam' | 'discord';
  external_id: string;
  username: string | null;
  avatar: string | null;
  names_fetched_at: Date | string | null;
  first_seen: Date | string | null;
  last_seen: Date | string | null;
};

export async function getAltAccountsByPlayerHex(steamHex: string): Promise<AltAccountView[]> {
  try {
    const [rows] = await pool.query<Row[]>(
      `SELECT a.kind, a.external_id, a.username, a.avatar, a.names_fetched_at, a.first_seen, a.last_seen
         FROM alt_accounts a
         JOIN players p ON p.id = a.player_id
        WHERE p.steam_hex = ? AND a.kind IN ('steam','discord')
        ORDER BY a.kind, a.last_seen DESC`,
      [steamHex],
    );
    return rows.map((r) => ({
      kind: r.kind,
      externalId: r.external_id,
      username: r.username,
      avatar: r.avatar,
      namesFetchedAt: r.names_fetched_at ? new Date(r.names_fetched_at).toISOString() : null,
      firstSeen: r.first_seen ? new Date(r.first_seen).toISOString() : null,
      lastSeen: r.last_seen ? new Date(r.last_seen).toISOString() : null,
    }));
  } catch {
    return [];
  }
}

export async function updateAltAccountName(input: {
  steamHex: string;
  kind: 'steam' | 'discord';
  externalId: string;
  username: string | null;
  avatar: string | null;
}): Promise<void> {
  try {
    await pool.execute<ResultSetHeader>(
      `UPDATE alt_accounts a
          JOIN players p ON p.id = a.player_id
         SET a.username = ?,
             a.avatar   = ?,
             a.names_fetched_at = NOW()
        WHERE p.steam_hex = ? AND a.kind = ? AND a.external_id = ?`,
      [
        input.username ? input.username.slice(0, 128) : null,
        input.avatar ? input.avatar.slice(0, 512) : null,
        input.steamHex,
        input.kind,
        input.externalId,
      ],
    );
  } catch {}
}
