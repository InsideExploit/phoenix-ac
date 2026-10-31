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

type Row = RowDataPacket & {
  id: number;
  primary_hex: string;
  secondary_hex: string;
  fp_type: string;
  fp_value: string;
  primary_name: string | null;
  secondary_name: string | null;
  client_ip: string | null;
  created_at: string;
};

export async function GET(req: NextRequest) {
  if (!rateLimit(`evasion:${clientIp(req)}`, 120, 60000))
    return json({ ok: false, error: 'too many requests' }, 429);
  if (!(await getSessionUser())) return json({ ok: false, error: 'unauthorized' }, 401);
  const sp = req.nextUrl.searchParams;
  const qRaw = (sp.get('q') ?? '').trim();
  const limitRaw = Number(sp.get('limit') ?? '100');
  const offsetRaw = Number(sp.get('offset') ?? '0');
  const limit = Math.min(Math.max(Number.isFinite(limitRaw) ? limitRaw : 100, 1), 500);
  const offset = Math.max(Number.isFinite(offsetRaw) ? offsetRaw : 0, 0);
  const q = qRaw.replace(/[%_]/g, '\\$&');
  const like = q ? `%${q}%` : null;
  try {
    const params: unknown[] = [];
    let where = "WHERE fp_type <> 'ip'";
    if (like) {
      where += ` AND (primary_hex LIKE ? OR secondary_hex LIKE ?
                   OR fp_value LIKE ? OR primary_name LIKE ?
                   OR secondary_name LIKE ? OR client_ip LIKE ?)`;
      params.push(like, like, like, like, like, like);
    }
    const [rows] = await pool.query<Row[]>(
      `SELECT id, primary_hex, secondary_hex, fp_type, fp_value,
              primary_name, secondary_name, client_ip, created_at
         FROM evasion_flags
         ${where}
         ORDER BY created_at DESC
         LIMIT ${limit} OFFSET ${offset}`,
      params,
    );
    const flags = rows.map((r) => ({
      id: Number(r.id),
      primaryHex: r.primary_hex,
      secondaryHex: r.secondary_hex,
      fpType: r.fp_type,
      fpValue: r.fp_value,
      primaryName: r.primary_name,
      secondaryName: r.secondary_name,
      clientIp: r.client_ip,
      createdAt: r.created_at,
    }));
    return encDashJson({ ok: true, flags });
  } catch {
    return json({ ok: false, error: 'server error' }, 500);
  }
}
