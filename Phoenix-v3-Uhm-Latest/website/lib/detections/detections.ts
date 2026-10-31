import type { RowDataPacket } from 'mysql2';

import { pool } from '@/lib/database/pool';

export type DetectionView = {
  id: string;
  type: string;
  reason: string | null;
  offendingPath: string | null;
  steamHex: string;
  clientIp: string | null;
  hardwareId: string | null;
  sessionId: string | null;
  screenshotPath: string | null;
  extras: Record<string, unknown> | null;
  createdAt: string;
};

type DetectionRow = RowDataPacket & {
  id: string;
  type: string;
  reason: string | null;
  offending_path: string | null;
  steam_hex: string;
  client_ip: string | null;
  hardware_id: string | null;
  session_id: string | null;
  payload: string | Buffer | Record<string, unknown> | null;
  created_at: string;
};

function parsePayload(raw: string | Buffer | Record<string, unknown> | null): {
  shot: string | null;
  extras: Record<string, unknown> | null;
} {
  if (raw === null || raw === undefined) return { shot: null, extras: null };
  let parsed: {
    shot?: unknown;
    json?: unknown;
  } | null = null;
  if (typeof raw === 'string') {
    try {
      parsed = JSON.parse(raw) as {
        shot?: unknown;
        json?: unknown;
      };
    } catch {
      return { shot: null, extras: null };
    }
  } else if (Buffer.isBuffer(raw)) {
    try {
      parsed = JSON.parse(raw.toString('utf8')) as {
        shot?: unknown;
        json?: unknown;
      };
    } catch {
      return { shot: null, extras: null };
    }
  } else if (typeof raw === 'object') {
    parsed = raw as {
      shot?: unknown;
      json?: unknown;
    };
  }
  if (!parsed) return { shot: null, extras: null };
  const shotRaw = typeof parsed.shot === 'string' ? parsed.shot : null;
  let rel: string | null = null;
  if (shotRaw) {
    const cleaned = shotRaw.replace(/\\/g, '/');
    rel = cleaned.startsWith('screenshots/') ? cleaned.slice('screenshots/'.length) : cleaned;
  }
  let extras: Record<string, unknown> | null = null;
  const jField = parsed.json;
  let inner: {
    extras?: unknown;
  } | null = null;
  if (typeof jField === 'string') {
    try {
      inner = JSON.parse(jField) as {
        extras?: unknown;
      };
    } catch {
      inner = null;
    }
  } else if (jField && typeof jField === 'object') {
    inner = jField as {
      extras?: unknown;
    };
  }
  if (inner) {
    const e = inner.extras;
    if (typeof e === 'string') {
      try {
        extras = JSON.parse(e) as Record<string, unknown>;
      } catch {
        extras = null;
      }
    } else if (e && typeof e === 'object') {
      extras = e as Record<string, unknown>;
    }
  }
  return { shot: rel, extras };
}

function mapRow(r: DetectionRow): DetectionView {
  const { shot, extras } = parsePayload(r.payload);
  return {
    id: String(r.id),
    type: r.type,
    reason: r.reason ?? null,
    offendingPath: r.offending_path ?? null,
    steamHex: r.steam_hex,
    clientIp: r.client_ip ?? null,
    hardwareId: r.hardware_id ?? null,
    sessionId: r.session_id !== null ? String(r.session_id) : null,
    screenshotPath: shot,
    extras,
    createdAt: r.created_at,
  };
}

export type GetDetectionsOpts = {
  q?: string;
  type?: string;
  steam?: string;
  since?: Date | null;
  until?: Date | null;
  page?: number;
  pageSize?: number;
};

export type DetectionsPage = {
  detections: DetectionView[];
  total: number;
  types: {
    value: string;
    count: number;
  }[];
};

const MAX_PAGE_SIZE = 100;
const DEFAULT_PAGE_SIZE = 30;

function buildBaseClauses(opts: GetDetectionsOpts): {
  where: string;
  params: (string | Date)[];
} {
  const params: (string | Date)[] = [];
  const clauses: string[] = [];
  const q = (opts.q ?? '').trim();
  if (q) {
    clauses.push(`(steam_hex LIKE ? OR type LIKE ? OR reason LIKE ? OR offending_path LIKE ?)`);
    const like = `%${q}%`;
    params.push(like, like, like, like);
  }
  const steam = (opts.steam ?? '').trim().toLowerCase();
  if (steam) {
    clauses.push(`steam_hex = ?`);
    params.push(steam);
  }
  if (opts.since) {
    clauses.push(`created_at >= ?`);
    params.push(opts.since);
  }
  if (opts.until) {
    clauses.push(`created_at <  ?`);
    params.push(opts.until);
  }
  const where = clauses.length ? `WHERE ${clauses.join(' AND ')}` : '';
  return { where, params };
}

export async function getDetections(opts: GetDetectionsOpts = {}): Promise<DetectionsPage> {
  const pageSize = Math.min(
    Math.max(Math.floor(opts.pageSize ?? DEFAULT_PAGE_SIZE), 1),
    MAX_PAGE_SIZE,
  );
  const page = Math.max(Math.floor(opts.page ?? 0), 0);
  const offset = page * pageSize;
  const base = buildBaseClauses(opts);
  const type = (opts.type ?? '').trim();
  const listClauses: string[] = [];
  const listParams: (string | Date | number)[] = [...base.params];
  if (base.where) listClauses.push(base.where.slice(6));
  if (type) {
    listClauses.push(`type = ?`);
    listParams.push(type);
  }
  const listWhere = listClauses.length ? `WHERE ${listClauses.join(' AND ')}` : '';
  try {
    const [totalRows, typeRows, listRows] = await Promise.all([
      pool.query<
        (RowDataPacket & {
          n: number;
        })[]
      >(`SELECT COUNT(*) AS n FROM detections ${listWhere}`, listParams),
      pool.query<
        (RowDataPacket & {
          type: string;
          n: number;
        })[]
      >(
        `SELECT type, COUNT(*) AS n FROM detections ${base.where}
          GROUP BY type
          ORDER BY type ASC`,
        base.params,
      ),
      pool.query<DetectionRow[]>(
        `SELECT id, type, reason, offending_path,
                steam_hex, client_ip, hardware_id, session_id, payload,
                DATE_FORMAT(created_at, '%Y-%m-%dT%H:%i:%s') AS created_at
           FROM detections
          ${listWhere}
          ORDER BY created_at DESC, id DESC
          LIMIT ? OFFSET ?`,
        [...listParams, pageSize, offset],
      ),
    ]);
    const total = Number(totalRows[0][0]?.n ?? 0);
    const types = typeRows[0].map((r) => ({ value: r.type, count: Number(r.n) }));
    return { detections: listRows[0].map(mapRow), total, types };
  } catch {
    return { detections: [], total: 0, types: [] };
  }
}
