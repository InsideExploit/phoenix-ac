import { NextRequest, NextResponse } from 'next/server';

import { getSessionUser } from '@/lib/auth/auth';
import { config } from '@/lib/core/config';
import { updateAltAccountName } from '@/lib/players/altAccounts';
import { clientIp, isSameOrigin, NO_STORE, rateLimit } from '@/lib/security/security';

export const runtime = 'nodejs';

export const dynamic = 'force-dynamic';
const json = (data: unknown, status = 200) =>
  NextResponse.json(data, { status, headers: NO_STORE });

type Body = {
  steam_hex?: unknown;
  kind?: unknown;
  external_id?: unknown;
};

async function lookupSteam(id64: string): Promise<{
  username: string | null;
  avatar: string | null;
}> {
  if (!config.steam_api_key) return { username: null, avatar: null };
  try {
    const res = await fetch(
      `https://api.steampowered.com/ISteamUser/GetPlayerSummaries/v0002/?key=${config.steam_api_key}&steamids=${id64}`,
      { cache: 'no-store' },
    );
    if (!res.ok) return { username: null, avatar: null };
    const data = await res.json();
    const player = data?.response?.players?.[0];
    if (!player) return { username: null, avatar: null };
    const rawAvatar: string = player.avatarmedium || player.avatarfull || player.avatar || '';
    const avatar = rawAvatar ? `/api/lookup/img?url=${encodeURIComponent(rawAvatar)}` : null;
    const username: string | null = player.personaname ?? null;
    return { username, avatar };
  } catch {
    return { username: null, avatar: null };
  }
}

async function lookupDiscord(id: string): Promise<{
  username: string | null;
  avatar: string | null;
}> {
  if (!config.discord_bot_token) return { username: null, avatar: null };
  if (!/^\d{17,20}$/.test(id)) return { username: null, avatar: null };
  try {
    const res = await fetch(`https://discord.com/api/v10/users/${id}`, {
      headers: { Authorization: `Bot ${config.discord_bot_token}` },
      cache: 'no-store',
    });
    if (!res.ok) return { username: null, avatar: null };
    const data = await res.json();
    const username: string | null = data.username ?? null;
    const avatarHash = data.avatar;
    const rawAvatar = avatarHash
      ? `https://cdn.discordapp.com/avatars/${id}/${avatarHash}.png?size=64`
      : `https://cdn.discordapp.com/embed/avatars/${Number(BigInt(id) % 6n)}.png`;
    const avatar = `/api/lookup/img?url=${encodeURIComponent(rawAvatar)}`;
    return { username, avatar };
  } catch {
    return { username: null, avatar: null };
  }
}

export async function POST(req: NextRequest) {
  if (!isSameOrigin(req)) return json({ ok: false, error: 'forbidden' }, 403);
  if (!rateLimit(`alts-refresh:${clientIp(req)}`, 120, 60000))
    return json({ ok: false, error: 'too many requests' }, 429);
  const user = await getSessionUser();
  if (!user) return json({ ok: false, error: 'unauthorized' }, 401);
  const body = (await req.json().catch(() => null)) as Body | null;
  const steamHex = typeof body?.steam_hex === 'string' ? body.steam_hex.trim().toLowerCase() : '';
  const kind = body?.kind === 'steam' || body?.kind === 'discord' ? body.kind : '';
  const extId = typeof body?.external_id === 'string' ? body.external_id.trim() : '';
  if (!steamHex || !/^[0-9a-f]{1,16}$/.test(steamHex))
    return json({ ok: false, error: 'bad steam_hex' }, 400);
  if (!kind) return json({ ok: false, error: 'bad kind' }, 400);
  if (!extId || !/^[0-9]{1,20}$/.test(extId))
    return json({ ok: false, error: 'bad external_id' }, 400);
  const looked = kind === 'steam' ? await lookupSteam(extId) : await lookupDiscord(extId);
  await updateAltAccountName({
    steamHex,
    kind,
    externalId: extId,
    username: looked.username,
    avatar: looked.avatar,
  });
  return json({
    ok: true,
    username: looked.username,
    avatar: looked.avatar,
  });
}
