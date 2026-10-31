import { NextRequest, NextResponse } from 'next/server';

import { getSessionUser } from '@/lib/auth/auth';
import { config } from '@/lib/core/config';
import { upsertCachedNames } from '@/lib/players/players';

export const runtime = 'nodejs';

export const dynamic = 'force-dynamic';
type LookupResult = {
  steamName?: string;
  steamAvatar?: string;
  discordName?: string;
  discordAvatar?: string;
};

const serverCache = new Map<
  string,
  {
    data: LookupResult;
    ts: number;
  }
>();

const CACHE_TTL = 5 * 60 * 1000;

function hexToSteamId64(hex: string): string | null {
  try {
    const h = hex.replace(/^steam:/i, '').trim();
    if (!/^[0-9a-f]+$/i.test(h)) return null;
    return BigInt('0x' + h).toString();
  } catch {
    return null;
  }
}

async function lookupSteam(hex: string): Promise<{
  name?: string;
  avatar?: string;
}> {
  if (!config.steam_api_key) return {};
  const steamId = hexToSteamId64(hex);
  if (!steamId) return {};
  try {
    const res = await fetch(
      `https://api.steampowered.com/ISteamUser/GetPlayerSummaries/v0002/?key=${config.steam_api_key}&steamids=${steamId}`,
      { cache: 'no-store' },
    );
    if (!res.ok) return {};
    const data = await res.json();
    const player = data?.response?.players?.[0];
    if (!player) return {};
    const rawAvatar: string = player.avatarmedium || player.avatarfull || player.avatar || '';
    const avatar = rawAvatar ? `/api/lookup/img?url=${encodeURIComponent(rawAvatar)}` : undefined;
    return { name: player.personaname, avatar };
  } catch {
    return {};
  }
}

async function lookupDiscord(discordId: string): Promise<{
  name?: string;
  avatar?: string;
}> {
  if (!config.discord_bot_token) return {};
  if (!/^\d{17,20}$/.test(discordId)) return {};
  try {
    const res = await fetch(`https://discord.com/api/v10/users/${discordId}`, {
      headers: { Authorization: `Bot ${config.discord_bot_token}` },
      cache: 'no-store',
    });
    if (!res.ok) return {};
    const data = await res.json();
    const avatarHash = data.avatar;
    const rawAvatar = avatarHash
      ? `https://cdn.discordapp.com/avatars/${discordId}/${avatarHash}.png?size=64`
      : `https://cdn.discordapp.com/embed/avatars/${Number(BigInt(discordId) % BigInt(6))}.png`;
    const avatar = `/api/lookup/img?url=${encodeURIComponent(rawAvatar)}`;
    return { name: data.global_name || data.username, avatar };
  } catch {
    return {};
  }
}

export async function GET(req: NextRequest) {
  const user = await getSessionUser();
  if (!user) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  const { searchParams } = new URL(req.url);
  const steam = searchParams.get('steam') || undefined;
  const discord = searchParams.get('discord') || undefined;
  if (!steam && !discord) return NextResponse.json({});
  const cacheKey = `${steam ?? ''}|${discord ?? ''}`;
  const hit = serverCache.get(cacheKey);
  if (hit && Date.now() - hit.ts < CACHE_TTL) {
    return NextResponse.json(hit.data);
  }
  const empty: {
    name?: string;
    avatar?: string;
  } = {};
  const [steamRes, discordRes] = await Promise.all([
    steam ? lookupSteam(steam) : Promise.resolve(empty),
    discord ? lookupDiscord(discord) : Promise.resolve(empty),
  ]);
  const result: LookupResult = {};
  if (steamRes.name) result.steamName = steamRes.name;
  if (steamRes.avatar) result.steamAvatar = steamRes.avatar;
  if (discordRes.name) result.discordName = discordRes.name;
  if (discordRes.avatar) result.discordAvatar = discordRes.avatar;
  serverCache.set(cacheKey, { data: result, ts: Date.now() });
  if (steamRes.name || steamRes.avatar || discordRes.name || discordRes.avatar) {
    void upsertCachedNames({
      steamHex: steam ?? null,
      discordId: discord ?? null,
      steamName: steamRes.name,
      steamAvatar: steamRes.avatar,
      discordName: discordRes.name,
      discordAvatar: discordRes.avatar,
    });
  }
  return NextResponse.json(result);
}
