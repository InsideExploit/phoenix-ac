import type { RowDataPacket } from 'mysql2';
import { pool } from './pool.js';

export interface PlayerRow extends RowDataPacket {
    id: number;
    steam_hex: string;
    discord_id: string | null;
    name: string | null;
    hardware_id: string | null;
    banned: number;
    suspended: number;
    ban_reason: string | null;
    banned_by: string | null;
    banned_at: Date | null;
    ban_category: string | null;
    ban_reason_public: number;
    suspend_reason: string | null;
    suspended_by: string | null;
    suspended_at: Date | null;
    added_by: string | null;
    last_edit_by: string | null;
    last_edit_at: Date | null;
    last_seen: Date | null;
    created_at: Date;
    updated_at: Date;
}

export const BAN_CATEGORIES = ['cheating', 'bug-abuse', 'toxicity', 'alt-account'] as const;
export type BanCategory = typeof BAN_CATEGORIES[number];

export function categoryLabel(c: string | null | undefined): string {
    switch (c) {
        case 'cheating':    return 'Cheating';
        case 'bug-abuse':   return 'Bug abuse';
        case 'toxicity':    return 'Toxicity';
        case 'alt-account': return 'Alt account';
        default:            return 'Banned';
    }
}

export async function findPlayerBySteamHex(steamHex: string): Promise<PlayerRow | null> {
    const [rows] = await pool.query<PlayerRow[]>(
        'SELECT * FROM players WHERE steam_hex = ? LIMIT 1',
        [steamHex],
    );
    return rows[0] ?? null;
}

export async function findPlayersBySteamHexBulk(steamHexes: string[]): Promise<Map<string, PlayerRow>> {
    const out = new Map<string, PlayerRow>();
    if (steamHexes.length === 0) return out;
    const [rows] = await pool.query<PlayerRow[]>(
        'SELECT * FROM players WHERE steam_hex IN (?)',
        [steamHexes],
    );
    for (const row of rows) out.set(row.steam_hex, row);
    return out;
}

export async function touchLastSeen(playerId: number): Promise<void> {
    await pool.execute(
        'UPDATE players SET last_seen = CURRENT_TIMESTAMP WHERE id = ?',
        [playerId],
    );
}

export async function bindPlayerHardwareId(playerId: number, hardwareId: string): Promise<void> {
    await pool.execute(
        'UPDATE players SET hardware_id = ? WHERE id = ? AND hardware_id IS NULL',
        [hardwareId, playerId],
    );
}

export async function banPlayerBySteamHex(
    steamHex: string,
    reason: string,
    bannedBy: string,
    category: string | null,
    reasonPublic: boolean,
): Promise<boolean> {
    const [res] = await pool.execute(
        `UPDATE players
         SET banned            = 1,
             ban_reason        = ?,
             banned_by         = ?,
             banned_at         = CURRENT_TIMESTAMP,
             ban_category      = ?,
             ban_reason_public = ?
         WHERE steam_hex = ?`,
        [
            reason.slice(0, 255),
            bannedBy.slice(0, 64),
            category ? category.slice(0, 32) : null,
            reasonPublic ? 1 : 0,
            steamHex,
        ],
    );
    return (res as { affectedRows?: number }).affectedRows ? true : false;
}

export async function updateBanBySteamHex(
    steamHex: string,
    reason: string,
    category: string | null,
    reasonPublic: boolean,
): Promise<boolean> {
    const [res] = await pool.execute(
        `UPDATE players
         SET ban_reason        = ?,
             ban_category      = ?,
             ban_reason_public = ?
         WHERE steam_hex = ? AND banned = 1`,
        [
            reason.slice(0, 255),
            category ? category.slice(0, 32) : null,
            reasonPublic ? 1 : 0,
            steamHex,
        ],
    );
    return (res as { affectedRows?: number }).affectedRows ? true : false;
}

export async function updateSuspendBySteamHex(
    steamHex: string,
    reason: string,
): Promise<boolean> {
    const trimmed = reason.trim().slice(0, 255);
    const [res] = await pool.execute(
        `UPDATE players
         SET suspend_reason = ?
         WHERE steam_hex = ? AND suspended = 1`,
        [trimmed || null, steamHex],
    );
    return (res as { affectedRows?: number }).affectedRows ? true : false;
}

export async function unbanPlayerBySteamHex(steamHex: string): Promise<boolean> {
    const [res] = await pool.execute(
        `UPDATE players
         SET banned            = 0,
             ban_reason        = NULL,
             banned_by         = NULL,
             banned_at         = NULL,
             ban_category      = NULL,
             ban_reason_public = 0
         WHERE steam_hex = ?`,
        [steamHex],
    );
    return (res as { affectedRows?: number }).affectedRows ? true : false;
}

export async function suspendPlayerBySteamHex(
    steamHex: string,
    reason: string,
    suspendedBy: string,
): Promise<boolean> {
    const trimmed = reason.trim().slice(0, 255);
    const [res] = await pool.execute(
        `UPDATE players
         SET suspended      = 1,
             suspend_reason = ?,
             suspended_by   = ?,
             suspended_at   = CURRENT_TIMESTAMP
         WHERE steam_hex = ?`,
        [trimmed || null, suspendedBy.slice(0, 64), steamHex],
    );
    return (res as { affectedRows?: number }).affectedRows ? true : false;
}

export async function unsuspendPlayerBySteamHex(steamHex: string): Promise<boolean> {
    const [res] = await pool.execute(
        `UPDATE players
         SET suspended      = 0,
             suspend_reason = NULL,
             suspended_by   = NULL,
             suspended_at   = NULL
         WHERE steam_hex = ?`,
        [steamHex],
    );
    return (res as { affectedRows?: number }).affectedRows ? true : false;
}
