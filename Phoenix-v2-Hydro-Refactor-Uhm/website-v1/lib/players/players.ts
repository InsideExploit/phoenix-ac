import type { RowDataPacket, ResultSetHeader } from "mysql2";
import { pool } from "@/lib/database/pool";
import { config } from "@/lib/core/config";

export type PlayerView = {
  steam: string;
  discord: string;
  banned: boolean;
  online: boolean;
  lastSeen: string | null;
};

type PlayerRow = RowDataPacket & {
  steam_hex: string;
  discord_id: string | null;
  banned: number;
  online: number;
  last_seen: Date | null;
};

const errCode = (e: unknown): string | undefined =>
  (e as { code?: string } | null)?.code;

const ONLINE_WINDOW_SECONDS = config.phoenix_online_window_seconds;

export type GetPlayersOpts = {
  limit?: number;
  offset?: number;
  q?: string;
};

export type PlayersPage = {
  total: number;
  players: PlayerView[];
};

const MAX_LIMIT = 200;
const DEFAULT_LIMIT = 50;

export async function getPlayers(opts: GetPlayersOpts = {}): Promise<PlayersPage> {
  const limit = Math.min(
    Math.max(1, Math.floor(opts.limit ?? DEFAULT_LIMIT)),
    MAX_LIMIT,
  );
  const offset = Math.max(0, Math.floor(opts.offset ?? 0));
  const q = (opts.q ?? "").trim();

  let where = "";
  const params: (string | number)[] = [];
  if (q) {
    where = `WHERE steam_hex LIKE ? OR discord_id LIKE ?`;
    const like = `%${q}%`;
    params.push(like, like);
  }

  try {
    const [countRows] = await pool.query<(RowDataPacket & { n: number })[]>(
      `SELECT COUNT(*) AS n FROM players ${where}`,
      params,
    );
    const total = Number(countRows[0]?.n ?? 0);

    const [rows] = await pool.query<PlayerRow[]>(
      `SELECT steam_hex, discord_id, banned, last_seen,
              (last_seen IS NOT NULL AND last_seen > (NOW() - INTERVAL ? SECOND)) AS online
         FROM players
         ${where}
         ORDER BY id ASC
         LIMIT ? OFFSET ?`,
      [...params, ONLINE_WINDOW_SECONDS, limit, offset],
    );

    return {
      total,
      players: rows.map((r) => ({
        steam: r.steam_hex,
        discord: r.discord_id ?? "",
        banned: !!r.banned,
        online: !!r.online,
        lastSeen: r.last_seen ? new Date(r.last_seen).toISOString() : null,
      })),
    };
  } catch {
    return { total: 0, players: [] };
  }
}

type CreateResult = { ok: true } | { ok: false; error: string };

export async function createPlayer(input: {
  steam_hex?: string;
  discord_id?: string | null;
}): Promise<CreateResult> {
  const steam = (input.steam_hex ?? "").trim();
  if (!steam) return { ok: false, error: "Steam HEX obbligatorio" };

  const discord = input.discord_id?.trim() || null;

  try {
    await pool.query<ResultSetHeader>(
      `INSERT INTO players (steam_hex, discord_id) VALUES (?, ?)`,
      [steam, discord],
    );
    return { ok: true };
  } catch (err) {
    if (errCode(err) === "ER_DUP_ENTRY")
      return { ok: false, error: "Steam HEX già presente" };
    return { ok: false, error: "Errore database" };
  }
}

export async function updatePlayer(
  steam_hex: string,
  changes: {
    banned?: boolean;
    discord_id?: string | null;
  },
): Promise<{ ok: boolean; error?: string }> {
  const sets: string[] = [];
  const vals: (string | number | null)[] = [];

  if (typeof changes.banned === "boolean") {
    sets.push("banned = ?");
    vals.push(changes.banned ? 1 : 0);
  }
  if (changes.discord_id !== undefined) {
    sets.push("discord_id = ?");
    vals.push(changes.discord_id?.trim() || null);
  }
  if (!sets.length) return { ok: false, error: "Niente da aggiornare" };

  try {
    const [res] = await pool.query<ResultSetHeader>(
      `UPDATE players SET ${sets.join(", ")} WHERE steam_hex = ?`,
      [...vals, steam_hex],
    );
    return { ok: res.affectedRows > 0 };
  } catch {
    return { ok: false, error: "Errore database" };
  }
}

export async function deletePlayer(
  steam_hex: string,
): Promise<{ ok: boolean }> {
  try {
    const [res] = await pool.query<ResultSetHeader>(
      `DELETE FROM players WHERE steam_hex = ?`,
      [steam_hex],
    );
    return { ok: res.affectedRows > 0 };
  } catch {
    return { ok: false };
  }
}

export type PinView = {
  code: string;
  used: boolean;
  createdBy: string;
  createdAt: string;
  expiresAt: string | null;
  expired: boolean;
};

type PinRow = RowDataPacket & {
  code: string;
  used: number;
  created_by: string | null;
  created_at: string;
  expires_at: string | null;
  expired: number;
};

export async function getPins(): Promise<PinView[]> {
  try {
    const [rows] = await pool.query<PinRow[]>(
      `SELECT code, used, created_by,
              DATE_FORMAT(created_at, '%d/%m/%Y %H:%i') AS created_at,
              DATE_FORMAT(expires_at, '%d/%m/%Y %H:%i') AS expires_at,
              (expires_at IS NOT NULL AND expires_at < NOW()) AS expired
         FROM pins
        ORDER BY created_at DESC, id DESC`,
    );
    return rows.map((r) => ({
      code: r.code,
      used: !!r.used,
      createdBy: r.created_by ?? "",
      createdAt: r.created_at,
      expiresAt: r.expires_at,
      expired: !!r.expired,
    }));
  } catch {
    return [];
  }
}

export async function deletePin(code: string): Promise<{ ok: boolean }> {
  try {
    const [res] = await pool.query<ResultSetHeader>(
      `DELETE FROM pins WHERE code = ?`,
      [code],
    );
    return { ok: res.affectedRows > 0 };
  } catch {
    return { ok: false };
  }
}

export async function redeemPin(code: string): Promise<{ ok: boolean }> {
  const c = (code ?? "").trim();
  if (!c) return { ok: false };
  try {
    const [res] = await pool.query<ResultSetHeader>(
      `UPDATE pins SET used = 1
        WHERE code = ? AND used = 0
          AND (expires_at IS NULL OR expires_at > NOW())`,
      [c],
    );
    return { ok: res.affectedRows === 1 };
  } catch {
    return { ok: false };
  }
}

export async function createPin(
  createdBy: string,
): Promise<{ ok: true; code: string } | { ok: false; error: string }> {
  const CHARS = "ABCDEFGHJKMNPQRSTUVWXYZ23456789";
  for (let attempt = 0; attempt < 6; attempt++) {
    const code = Array.from(
      { length: 8 },
      () => CHARS[Math.floor(Math.random() * CHARS.length)],
    ).join("");
    try {
      await pool.query<ResultSetHeader>(
        `INSERT INTO pins (code, created_by, expires_at)
         VALUES (?, ?, DATE_ADD(NOW(), INTERVAL 1 DAY))`,
        [code, createdBy],
      );
      return { ok: true, code };
    } catch (err) {
      if (errCode(err) === "ER_DUP_ENTRY") continue;
      return { ok: false, error: "Errore database" };
    }
  }
  return { ok: false, error: "Impossibile generare un PIN univoco" };
}
