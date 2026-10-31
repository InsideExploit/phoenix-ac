import type { ResultSetHeader } from 'mysql2';
import { pool } from './pool.js';

export type AltKind = 'steam' | 'discord';

export interface AltAccountInput {
    kind:       AltKind;
    externalId: string;
    username:   string | null;
    avatar:     string | null;
}

export async function upsertAltAccounts(
    playerId: number,
    steamHex: string,
    entries: AltAccountInput[],
): Promise<{ inserted: number; updated: number }> {
    if (entries.length === 0) return { inserted: 0, updated: 0 };

    let inserted = 0;
    let updated  = 0;
    const conn = await pool.getConnection();
    try {
        for (const e of entries) {
            if (!e.externalId) continue;
            const kind    = e.kind === 'steam' ? 'steam' : 'discord';
            const extId   = e.externalId.slice(0, 256);
            const uname   = e.username ? e.username.slice(0, 128) : null;
            const avatar  = e.avatar   ? e.avatar.slice(0, 512)   : null;

            const [res] = await conn.execute<ResultSetHeader>(
                `INSERT INTO alt_accounts
                    (player_id, steam_hex, kind, external_id, username, avatar, first_seen, last_seen)
                 VALUES (?, ?, ?, ?, ?, ?, NOW(), NOW())
                 ON DUPLICATE KEY UPDATE
                    username  = COALESCE(VALUES(username),  username),
                    avatar    = COALESCE(VALUES(avatar),    avatar),
                    last_seen = NOW()`,
                [playerId, steamHex, kind, extId, uname, avatar],
            );
            if (res.affectedRows === 1) inserted++;
            else if (res.affectedRows === 2) updated++;
        }
    } finally {
        conn.release();
    }
    return { inserted, updated };
}
