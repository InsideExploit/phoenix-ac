import crypto from 'crypto';
import type { RowDataPacket } from 'mysql2';

import { config } from '@/lib/core/config';
import { SESSION_COOKIE, SESSION_TOKEN_VERSION, STATE_COOKIE } from '@/lib/core/constants';
import { pool } from '@/lib/database/pool';

export { SESSION_COOKIE, STATE_COOKIE };

const SECRET = config.session_secret;
const KEY = crypto.scryptSync(SECRET, 'phoenixac.session.key.v1', 32);
const MAX_AGE_MS = 7 * 24 * 60 * 60 * 1000;

export async function isAllowed(id: string | undefined | null): Promise<boolean> {
  if (!id) return false;
  try {
    const [rows] = await pool.query<RowDataPacket[]>(
      `SELECT 1 FROM admins WHERE discord_id = ? LIMIT 1`,
      [id],
    );
    return rows.length > 0;
  } catch (e) {
    console.error('[auth] isAllowed query failed:', e);
    return false;
  }
}

export async function hasElevatedAccess(id: string | undefined | null): Promise<boolean> {
  if (!id) return false;
  try {
    const [rows] = await pool.query<RowDataPacket[]>(
      `SELECT sec_level FROM admins WHERE discord_id = ? LIMIT 1`,
      [id],
    );
    if (rows.length === 0) return false;
    return (
      Number(
        (
          rows[0] as {
            sec_level?: number;
          }
        ).sec_level,
      ) > 0
    );
  } catch (e) {
    console.error('[auth] elevated access query failed:', e);
    return false;
  }
}

export type SessionUser = {
  id: string;
  username: string;
  global_name?: string | null;
  avatar: string | null;
  email?: string | null;
};

const b64u = (b: Buffer) => b.toString('base64url');
const fromB64u = (s: string) => Buffer.from(s, 'base64url');

export function sign(payload: SessionUser): string {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', KEY, iv);
  const plaintext = Buffer.from(
    JSON.stringify({
      id: payload.id,
      username: payload.username,
      global_name: payload.global_name ?? null,
      avatar: payload.avatar,
      email: payload.email ?? null,
      iat: Date.now(),
    }),
    'utf8',
  );
  const enc = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return [SESSION_TOKEN_VERSION, b64u(iv), b64u(enc), b64u(tag)].join('.');
}

export function verify(token: string | undefined | null): SessionUser | null {
  if (!token) return null;
  const parts = token.split('.');
  if (parts.length !== 4 || parts[0] !== SESSION_TOKEN_VERSION) return null;
  try {
    const iv = fromB64u(parts[1]);
    const enc = fromB64u(parts[2]);
    const tag = fromB64u(parts[3]);
    if (iv.length !== 12 || tag.length !== 16) return null;
    const decipher = crypto.createDecipheriv('aes-256-gcm', KEY, iv);
    decipher.setAuthTag(tag);
    const dec = Buffer.concat([decipher.update(enc), decipher.final()]);
    const obj = JSON.parse(dec.toString('utf8')) as SessionUser & {
      iat?: number;
    };
    if (!obj || typeof obj.id !== 'string') return null;
    if (typeof obj.iat === 'number' && Date.now() - obj.iat > MAX_AGE_MS) return null;
    return {
      id: obj.id,
      username: obj.username,
      global_name: obj.global_name ?? null,
      avatar: obj.avatar ?? null,
      email: obj.email ?? null,
    };
  } catch {
    return null;
  }
}

export function avatarUrl(user: SessionUser): string {
  if (user.avatar) {
    return `https://cdn.discordapp.com/avatars/${user.id}/${user.avatar}.png?size=128`;
  }
  const idx = (BigInt(user.id) >> 22n) % 6n;
  return `https://cdn.discordapp.com/embed/avatars/${idx}.png`;
}
