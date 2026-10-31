import type { ResultSetHeader, RowDataPacket } from 'mysql2';

import fs from 'node:fs/promises';
import path from 'node:path';

import { config } from '@/lib/core/config';
import { pool } from '@/lib/database/pool';
import { getLauncherSha, shaEnforce } from '@/lib/launcher/launcher_sha';
import { parseEvent, payloadToJson, WireEventKind, wireEventTypeName } from '@/lib/net/wire';
import {
  postDetectionEvent,
  postLoginWebhook,
  type DetectionEventType,
} from '@/lib/webhooks/webhook';

const ONLINE_WINDOW_SECONDS = config.phoenix_online_window_seconds;
type PlayerRow = RowDataPacket & {
  id: number;
  banned: number;
  was_online: number;
};

const isHex = (s: string) => /^[0-9a-fA-F]{6,32}$/.test(s);
const isDiskId = (s: string) => /^[0-9a-fA-F]{4,32}$/.test(s);
const isSha256 = (s: string) => /^[0-9a-f]{64}$/i.test(s);

function readString(
  buf: Buffer,
  off: {
    v: number;
  },
): string {
  const len = buf.readUInt16LE(off.v);
  off.v += 2;
  const s = buf.subarray(off.v, off.v + len).toString('utf8');
  off.v += len;
  return s;
}

export async function handleAuthCheck(inner: Buffer, ip: string): Promise<Buffer> {
  const off = { v: 0 };
  const steamHex = readString(inner, off).trim();
  const diskId = readString(inner, off).trim();
  const clientSha = readString(inner, off).trim().toLowerCase();
  if (!steamHex || !isHex(steamHex)) return Buffer.from([0, 0, 0, 0]);
  if (diskId && !isDiskId(diskId)) return Buffer.from([0, 0, 0, 0]);
  if (shaEnforce()) {
    const expectedSha = await getLauncherSha();
    if (expectedSha) {
      if (!clientSha || !isSha256(clientSha)) return Buffer.from([0, 0, 0, 0]);
      if (clientSha !== expectedSha) return Buffer.from([0, 0, 0, 0]);
    }
  }
  const [rows] = await pool.query<PlayerRow[]>(
    `SELECT id, banned,
            (last_seen IS NOT NULL AND last_seen > (NOW() - INTERVAL ? SECOND)) AS was_online
       FROM players
      WHERE steam_hex = ?
      LIMIT 1`,
    [ONLINE_WINDOW_SECONDS, steamHex],
  );
  const player = rows[0];
  if (!player || player.banned) return Buffer.from([0, 0, 0, 0]);
  await pool.query<ResultSetHeader>(`UPDATE players SET last_seen = NOW() WHERE id = ?`, [
    player.id,
  ]);
  if (!player.was_online) {
    void postLoginWebhook({ steamHex, diskId, ip });
  }
  const rsp = Buffer.alloc(4);
  rsp[0] = 1;
  rsp[1] = 1;
  rsp.writeUInt16LE(config.phoenix_online_window_seconds, 2);
  return rsp;
}

export async function handleEvent(inner: Buffer, ip: string): Promise<Buffer> {
  const ev = parseEvent(inner);
  const typeName = wireEventTypeName[ev.kind];
  if (!typeName) return Buffer.from([0]);
  const payload = payloadToJson(ev.kind as WireEventKind, ev.payload);
  const pid = ev.pid > 0 ? ev.pid : null;
  try {
    void postDetectionEvent({
      type: typeName as DetectionEventType,
      steamHex: ev.steamHex,
      pid,
      exe: ev.exe || null,
      host: ev.host || null,
      ip,
      payload,
    });
  } catch {}
  try {
    type PlayerRowSmall = RowDataPacket & {
      id: number;
    };
    const [rows] = await pool.query<PlayerRowSmall[]>(
      `SELECT id FROM players WHERE steam_hex = ? LIMIT 1`,
      [ev.steamHex],
    );
    const playerId = rows[0]?.id ?? null;
    await pool.query<ResultSetHeader>(
      `INSERT INTO detections
         (player_id, steam_hex, type, pid, exe, host, client_ip, payload)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        playerId,
        ev.steamHex,
        typeName,
        pid,
        ev.exe || null,
        ev.host || null,
        ip,
        JSON.stringify(payload),
      ],
    );
  } catch {}
  return Buffer.from([1]);
}

export async function handleUpdateCheck(inner: Buffer): Promise<Buffer> {
  const off = { v: 0 };
  const clientVersion = readString(inner, off);
  const updateAvailable = clientVersion !== config.app_version;
  const rsp = Buffer.alloc(18);
  rsp[0] = 1;
  rsp[1] = updateAvailable ? 1 : 0;
  const ver = config.app_version.slice(0, 15);
  rsp.write(ver, 2, 16, 'utf8');
  return rsp;
}

export async function handleUpdateDownload(): Promise<{
  header: Buffer;
  file: Buffer | null;
}> {
  const updatePath = config.update_file || path.join(process.cwd(), 'private', 'AutoUpdate.exe');
  let file: Buffer;
  try {
    file = await fs.readFile(updatePath);
  } catch {
    return { header: Buffer.from([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]), file: null };
  }
  const hdr = Buffer.alloc(12);
  hdr[0] = 1;
  hdr.writeBigUInt64LE(BigInt(file.length), 4);
  return { header: hdr, file };
}
