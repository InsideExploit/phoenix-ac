import type { ResultSetHeader, RowDataPacket } from 'mysql2';
import { pool } from './pool.js';

export interface SessionStatusRow extends RowDataPacket {
    id: bigint;
    last_heartbeat: Date | null;
    started_at: Date;
    age_ms: number;
}

export async function getLiveSessionStatus(steamHex: string): Promise<SessionStatusRow | null> {
    const [rows] = await pool.query<SessionStatusRow[]>(
        `SELECT id, last_heartbeat, started_at,
                TIMESTAMPDIFF(MICROSECOND,
                    COALESCE(last_heartbeat, started_at),
                    CURRENT_TIMESTAMP(6)) DIV 1000 AS age_ms
           FROM sessions
          WHERE steam_hex = ? AND ended_at IS NULL
          ORDER BY id DESC LIMIT 1`,
        [steamHex],
    );
    return rows[0] ?? null;
}

export interface SessionStatusBulkRow extends RowDataPacket {
    steam_hex: string;
    id: bigint;
    last_heartbeat: Date | null;
    started_at: Date;
    age_ms: number;
}

export async function getLiveSessionStatusBulk(steamHexes: string[]): Promise<Map<string, SessionStatusBulkRow>> {
    const out = new Map<string, SessionStatusBulkRow>();
    if (steamHexes.length === 0) return out;
    const [rows] = await pool.query<SessionStatusBulkRow[]>(
        `SELECT s.steam_hex, s.id, s.last_heartbeat, s.started_at,
                TIMESTAMPDIFF(MICROSECOND,
                    COALESCE(s.last_heartbeat, s.started_at),
                    CURRENT_TIMESTAMP(6)) DIV 1000 AS age_ms
           FROM sessions s
           JOIN (
                SELECT steam_hex, MAX(id) AS max_id
                  FROM sessions
                 WHERE steam_hex IN (?) AND ended_at IS NULL
                 GROUP BY steam_hex
           ) latest ON latest.max_id = s.id`,
        [steamHexes],
    );
    for (const row of rows) out.set(row.steam_hex, row);
    return out;
}

export interface StartSessionInput {
    steamHex: string;
    playerId: number | null;
    hardwareId: string | null;
    hardwareDetails: string | null;
    clientIp: string;
    clientVersion: string | null;
}

export async function startSession(input: StartSessionInput): Promise<bigint> {
    const [res] = await pool.execute<ResultSetHeader>(
        `INSERT INTO sessions
            (steam_hex, player_id, hardware_id, hardware_details, client_ip, client_version, last_heartbeat)
         VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)`,
        [input.steamHex, input.playerId, input.hardwareId, input.hardwareDetails,
         input.clientIp, input.clientVersion],
    );
    return BigInt(res.insertId);
}

export async function bumpHeartbeat(sessionId: bigint): Promise<void> {
    await pool.execute(
        'UPDATE sessions SET last_heartbeat = CURRENT_TIMESTAMP WHERE id = ?',
        [sessionId],
    );
}

export async function endSession(sessionId: bigint, reason: string): Promise<void> {
    await pool.execute(
        `UPDATE sessions
            SET ended_at = CURRENT_TIMESTAMP, end_reason = ?
          WHERE id = ? AND ended_at IS NULL`,
        [reason.slice(0, 64), sessionId],
    );
}
