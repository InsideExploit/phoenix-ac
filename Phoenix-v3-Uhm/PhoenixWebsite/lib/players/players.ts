import type { RowDataPacket, ResultSetHeader } from "mysql2";
import { pool } from "@/lib/database/pool";
import { config } from "@/lib/core/config";

export type PlayerView = {
  steam: string;
  discord: string;
  banned: boolean;
  suspended: boolean;
  online: boolean;
  lastSeen: string | null;
  addedBy: string | null;
  createdAt: string | null;
  lastEditBy: string | null;
  lastEditAt: string | null;
  hardwareId: string | null;
  banReason: string | null;
  banCategory: string | null;
  banReasonPublic: boolean;
  bannedBy: string | null;
  bannedAt: string | null;
  suspendReason: string | null;
  suspendedBy: string | null;
  suspendedAt: string | null;
  steamName: string | null;
  discordName: string | null;
  steamAvatar: string | null;
  discordAvatar: string | null;
};

type PlayerRow = RowDataPacket & {
  steam_hex: string;
  discord_id: string | null;
  banned: number;
  suspended: number;
  online: number;
  last_seen: Date | null;
  added_by: string | null;
  created_at: string | null;
  last_edit_by: string | null;
  last_edit_at: string | null;
  hardware_id: string | null;
  ban_reason: string | null;
  ban_category: string | null;
  ban_reason_public: number;
  banned_by: string | null;
  banned_at: string | null;
  suspend_reason: string | null;
  suspended_by: string | null;
  suspended_at: string | null;
  steam_name: string | null;
  discord_name: string | null;
  steam_avatar: string | null;
  discord_avatar: string | null;
};

const errCode = (e: unknown): string | undefined =>
  (e as { code?: string } | null)?.code;

const ONLINE_WINDOW_SECONDS = config.phoenix_online_window_seconds;

export type GetPlayersOpts = {
  limit?: number;
  offset?: number;
  q?: string;
  all?: boolean;
};

export type PlayersPage = {
  total: number;
  players: PlayerView[];
};

const MAX_LIMIT = 200;
const DEFAULT_LIMIT = 50;

function mapPlayerRow(r: PlayerRow): PlayerView {
  return {
    steam: r.steam_hex,
    discord: r.discord_id ?? "",
    banned: !!r.banned,
    suspended: !!r.suspended,
    online: !!r.online,
    lastSeen: r.last_seen ? new Date(r.last_seen).toISOString() : null,
    addedBy: r.added_by ?? null,
    createdAt: r.created_at ?? null,
    lastEditBy: r.last_edit_by ?? null,
    lastEditAt: r.last_edit_at ?? null,
    hardwareId: r.hardware_id ?? null,
    banReason:       r.ban_reason ?? null,
    banCategory:     r.ban_category ?? null,
    banReasonPublic: !!r.ban_reason_public,
    bannedBy:        r.banned_by ?? null,
    bannedAt:        r.banned_at ?? null,
    suspendReason:   r.suspend_reason ?? null,
    suspendedBy:     r.suspended_by ?? null,
    suspendedAt:     r.suspended_at ?? null,
    steamName:       r.steam_name    ?? null,
    discordName:     r.discord_name  ?? null,
    steamAvatar:     r.steam_avatar  ?? null,
    discordAvatar:   r.discord_avatar?? null,
  };
}

export async function upsertCachedNames(input: {
  steamHex?: string | null;
  discordId?: string | null;
  steamName?: string;
  steamAvatar?: string;
  discordName?: string;
  discordAvatar?: string;
}): Promise<void> {
  const steamSet: string[] = [];
  const steamVals: (string | null)[] = [];
  if (input.steamName   !== undefined) { steamSet.push("steam_name = ?");   steamVals.push(input.steamName   || null); }
  if (input.steamAvatar !== undefined) { steamSet.push("steam_avatar = ?"); steamVals.push(input.steamAvatar || null); }

  const discordSet: string[] = [];
  const discordVals: (string | null)[] = [];
  if (input.discordName   !== undefined) { discordSet.push("discord_name = ?");   discordVals.push(input.discordName   || null); }
  if (input.discordAvatar !== undefined) { discordSet.push("discord_avatar = ?"); discordVals.push(input.discordAvatar || null); }

  try {
    if (input.steamHex && (steamSet.length || discordSet.length)) {
      const parts = [...steamSet, ...discordSet, "names_fetched_at = NOW()"];
      const vals  = [...steamVals, ...discordVals, input.steamHex];
      await pool.query(`UPDATE players SET ${parts.join(", ")} WHERE steam_hex = ?`, vals);
    }
    if (!input.steamHex && input.discordId && discordSet.length) {
      const parts = [...discordSet, "names_fetched_at = NOW()"];
      const vals  = [...discordVals, input.discordId];
      await pool.query(`UPDATE players SET ${parts.join(", ")} WHERE discord_id = ?`, vals);
    }
  } catch {
    /* cache write is best-effort */
  }
}

export async function getPlayers(opts: GetPlayersOpts = {}): Promise<PlayersPage> {
  const offset = Math.max(0, Math.floor(opts.offset ?? 0));
  const q = (opts.q ?? "").trim();
  const fetchAll = opts.all === true;

  let where = "";
  const params: (string | number)[] = [];
  if (q) {
    where = `WHERE steam_hex LIKE ? OR discord_id LIKE ? OR steam_name LIKE ? OR discord_name LIKE ?`;
    const like = `%${q}%`;
    params.push(like, like, like, like);
  }

  try {
    const [countRows] = await pool.query<(RowDataPacket & { n: number })[]>(
      `SELECT COUNT(*) AS n FROM players ${where}`,
      params,
    );
    const total = Number(countRows[0]?.n ?? 0);

    const selectSql = `SELECT steam_hex, discord_id, banned, suspended, last_seen,
              (last_seen IS NOT NULL AND last_seen > (NOW() - INTERVAL ? SECOND)) AS online,
              added_by,
              DATE_FORMAT(created_at,   '%d/%m/%Y %H:%i') AS created_at,
              last_edit_by,
              DATE_FORMAT(last_edit_at, '%d/%m/%Y %H:%i') AS last_edit_at,
              hardware_id,
              ban_reason, ban_category, ban_reason_public, banned_by,
              DATE_FORMAT(banned_at,    '%d/%m/%Y %H:%i') AS banned_at,
              suspend_reason, suspended_by,
              DATE_FORMAT(suspended_at, '%d/%m/%Y %H:%i') AS suspended_at,
              steam_name, discord_name, steam_avatar, discord_avatar
         FROM players
         ${where}
         ORDER BY id ASC`;

    if (fetchAll) {
      const [rows] = await pool.query<PlayerRow[]>(selectSql, [
        ...params,
        ONLINE_WINDOW_SECONDS,
      ]);
      return { total, players: rows.map(mapPlayerRow) };
    }

    const limit = Math.min(
      Math.max(1, Math.floor(opts.limit ?? DEFAULT_LIMIT)),
      MAX_LIMIT,
    );

    const [rows] = await pool.query<PlayerRow[]>(
      `${selectSql} LIMIT ? OFFSET ?`,
      [...params, ONLINE_WINDOW_SECONDS, limit, offset],
    );

    return { total, players: rows.map(mapPlayerRow) };
  } catch {
    return { total: 0, players: [] };
  }
}

type CreateResult = { ok: true } | { ok: false; error: string };

export async function createPlayer(input: {
  steam_hex?: string;
  discord_id?: string | null;
  added_by?: string | null;
}): Promise<CreateResult> {
  const steam = (input.steam_hex ?? "").trim();
  if (!steam) return { ok: false, error: "Steam HEX obbligatorio" };

  const discord = input.discord_id?.trim() || null;
  const addedBy = input.added_by?.trim() || null;

  try {
    await pool.query<ResultSetHeader>(
      `INSERT INTO players (steam_hex, discord_id, added_by) VALUES (?, ?, ?)`,
      [steam, discord, addedBy],
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
    suspended?: boolean;
    discord_id?: string | null;
    last_edit_by?: string | null;
  },
): Promise<{ ok: boolean; error?: string }> {
  const sets: string[] = [];
  const vals: (string | number | null)[] = [];

  if (typeof changes.banned === "boolean") {
    sets.push("banned = ?");
    vals.push(changes.banned ? 1 : 0);
  }
  if (typeof changes.suspended === "boolean") {
    sets.push("suspended = ?");
    vals.push(changes.suspended ? 1 : 0);
  }
  if (changes.discord_id !== undefined) {
    sets.push("discord_id = ?");
    vals.push(changes.discord_id?.trim() || null);
  }
  if (!sets.length) return { ok: false, error: "Niente da aggiornare" };

  if (changes.last_edit_by) {
    sets.push("last_edit_by = ?");
    vals.push(changes.last_edit_by);
    sets.push("last_edit_at = NOW()");
  }

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

export async function resetPlayerHardwareId(
  steam_hex: string,
  actor: string | null,
): Promise<{ ok: boolean; error?: string }> {
  try {
    const [res] = await pool.query<ResultSetHeader>(
      `UPDATE players
          SET hardware_id  = NULL,
              last_edit_by = COALESCE(?, last_edit_by),
              last_edit_at = NOW()
        WHERE steam_hex = ?`,
      [actor?.trim() || null, steam_hex],
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

export type PlayerLookup = {
  id: number;
  banned: boolean;
  suspended: boolean;
};

export async function findPlayerBySteamHex(steamHex: string): Promise<PlayerLookup | null> {
  try {
    const [rows] = await pool.query<(RowDataPacket & { id: number; banned: number; suspended: number })[]>(
      `SELECT id, banned, suspended FROM players WHERE steam_hex = ? LIMIT 1`,
      [steamHex],
    );
    const r = rows[0];
    if (!r) return null;
    return { id: Number(r.id), banned: !!r.banned, suspended: !!r.suspended };
  } catch {
    return null;
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
