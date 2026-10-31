import { NextRequest, NextResponse } from 'next/server';

import { getSessionUser } from '@/lib/auth/auth';
import type { SessionUser } from '@/lib/auth/session';
import { encryptDash, isDashCryptoConfigured } from '@/lib/crypto/crypto';
import { createPlayer, deletePlayer, getPlayers, updatePlayer } from '@/lib/players/players';
import { clientIp, isSameOrigin, NO_STORE, rateLimit } from '@/lib/security/security';
import { postAdminWebhook } from '@/lib/webhooks/webhook';

export const runtime = 'nodejs';

export const dynamic = 'force-dynamic';
type Body = {
  steam_hex?: string;
  discord_id?: string | null;
  banned?: boolean;
  suspended?: boolean;
};

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

type GuardResult =
  | {
      ok: true;
      user: SessionUser;
    }
  | {
      ok: false;
      res: NextResponse;
    };

async function guard(req: NextRequest): Promise<GuardResult> {
  if (!isSameOrigin(req)) return { ok: false, res: json({ ok: false, error: 'forbidden' }, 403) };
  if (!rateLimit(`players:${clientIp(req)}`, 60, 60000))
    return {
      ok: false,
      res: json({ ok: false, error: 'too many requests' }, 429),
    };
  const user = await getSessionUser();
  if (!user) return { ok: false, res: json({ ok: false, error: 'unauthorized' }, 401) };
  return { ok: true, user };
}

async function readBody(req: NextRequest): Promise<Body | null> {
  return (await req.json().catch(() => null)) as Body | null;
}

export async function GET(req: NextRequest) {
  if (!rateLimit(`players-get:${clientIp(req)}`, 240, 60000))
    return json({ ok: false, error: 'too many requests' }, 429);
  if (!(await getSessionUser())) return json({ ok: false, error: 'unauthorized' }, 401);
  const sp = req.nextUrl.searchParams;
  const q = sp.get('q') ?? undefined;
  const all = sp.get('all') === '1';
  const limit = Number(sp.get('limit') ?? '50');
  const offset = Number(sp.get('offset') ?? '0');
  const page = await getPlayers({
    q,
    all,
    limit: Number.isFinite(limit) ? limit : 50,
    offset: Number.isFinite(offset) ? offset : 0,
  });
  return encDashJson({ ok: true, total: page.total, players: page.players });
}

export async function POST(req: NextRequest) {
  const g = await guard(req);
  if (!g.ok) return g.res;
  const body = await readBody(req);
  if (!body) return json({ ok: false, error: 'bad request' }, 400);
  const result = await createPlayer({
    steam_hex: body.steam_hex,
    discord_id: body.discord_id,
    added_by: g.user.id,
  });
  if (result.ok) {
    void postAdminWebhook({
      title: 'Player aggiunto',
      color: 0x36c25f,
      actor: g.user,
      fields: [
        {
          name: 'Steam HEX',
          value: '`' + (body.steam_hex ?? '?') + '`',
          inline: true,
        },
        {
          name: 'Discord ID',
          value: '`' + (body.discord_id || '-') + '`',
          inline: true,
        },
      ],
    });
  }
  return json(result, result.ok ? 201 : 400);
}

export async function PATCH(req: NextRequest) {
  const g = await guard(req);
  if (!g.ok) return g.res;
  const body = await readBody(req);
  if (!body?.steam_hex) return json({ ok: false, error: 'steam_hex mancante' }, 400);
  const result = await updatePlayer(body.steam_hex, {
    banned: body.banned,
    suspended: body.suspended,
    discord_id: body.discord_id,
    last_edit_by: g.user.id,
  });
  if (result.ok && typeof body.banned === 'boolean') {
    void postAdminWebhook({
      title: body.banned ? 'Player bannato' : 'Ban rimosso',
      color: body.banned ? 0xe74c3c : 0x36c25f,
      actor: g.user,
      fields: [
        {
          name: 'Steam HEX',
          value: '`' + body.steam_hex + '`',
          inline: true,
        },
      ],
    });
  }
  if (result.ok && typeof body.suspended === 'boolean') {
    void postAdminWebhook({
      title: body.suspended ? 'Player sospeso' : 'Sospensione rimossa',
      color: body.suspended ? 0xf39c12 : 0x36c25f,
      actor: g.user,
      fields: [
        {
          name: 'Steam HEX',
          value: '`' + body.steam_hex + '`',
          inline: true,
        },
      ],
    });
  }
  if (
    result.ok &&
    body.discord_id !== undefined &&
    typeof body.banned !== 'boolean' &&
    typeof body.suspended !== 'boolean'
  ) {
    void postAdminWebhook({
      title: 'Player aggiornato',
      color: 0x3498db,
      actor: g.user,
      fields: [
        {
          name: 'Steam HEX',
          value: '`' + body.steam_hex + '`',
          inline: true,
        },
        {
          name: 'Discord ID',
          value: '`' + (body.discord_id || '-') + '`',
          inline: true,
        },
      ],
    });
  }
  return json(result, result.ok ? 200 : 400);
}

export async function DELETE(req: NextRequest) {
  const g = await guard(req);
  if (!g.ok) return g.res;
  const body = await readBody(req);
  if (!body?.steam_hex) return json({ ok: false, error: 'steam_hex mancante' }, 400);
  const result = await deletePlayer(body.steam_hex);
  if (result.ok) {
    void postAdminWebhook({
      title: 'Player eliminato',
      color: 0xe74c3c,
      actor: g.user,
      fields: [
        {
          name: 'Steam HEX',
          value: '`' + body.steam_hex + '`',
          inline: true,
        },
      ],
    });
  }
  return json(result, result.ok ? 200 : 400);
}
