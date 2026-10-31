'use client';

import { Copy, Ellipsis, ExternalLink } from 'lucide-react';

import type { LookupResult, Player } from '../types';
import { PlayerStatus } from './player_status';

export function PlayerRow({
  player,
  info,
  addedByInfo,
  lastEditByInfo,
  index,
  onCopy,
  onMenu,
  onInfo,
}: {
  player: Player;
  info: LookupResult;
  addedByInfo: LookupResult;
  lastEditByInfo: LookupResult;
  index: number;
  onCopy: (v: string) => void;
  onMenu: (player: Player, e: React.MouseEvent<HTMLButtonElement>) => void;
  onInfo?: (p: Player) => void;
}) {
  const initial = player.banned
    ? 'B'
    : player.steam
        .replace(/[^a-z0-9]/gi, '')
        .charAt(0)
        .toUpperCase() || '1';
  const effInfo: LookupResult = {
    steamName: info.steamName ?? player.steamName ?? undefined,
    steamAvatar: info.steamAvatar ?? player.steamAvatar ?? undefined,
    discordName: info.discordName ?? player.discordName ?? undefined,
    discordAvatar: info.discordAvatar ?? player.discordAvatar ?? undefined,
  };
  const avatarSrc = effInfo.steamAvatar || effInfo.discordAvatar;
  const steamProfileUrl = (() => {
    const clean = player.steam.trim().toLowerCase().replace(/^0x/, '');
    if (!/^[0-9a-f]{1,16}$/.test(clean)) return null;
    try {
      return `https://steamcommunity.com/profiles/${BigInt('0x' + clean).toString()}`;
    } catch {
      return null;
    }
  })();
  return (
    <tr
      className="row-in border-b border-white/[0.04] transition-colors last:border-0 hover:bg-white/[0.02]"
      style={{ animationDelay: `${index * 28}ms` }}
    >
      <td className="px-4 py-3">
        <div className="flex items-center gap-2.5">
          {avatarSrc ? (
            <img
              src={avatarSrc}
              alt=""
              className="h-7 w-7 shrink-0 rounded-full object-cover"
            />
          ) : (
            <div className="flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-white/[0.05]">
              <span className="text-[11px] font-semibold text-white/50">{initial}</span>
            </div>
          )}
          <div className="min-w-0 flex-1">
            {effInfo.steamName && (
              <div className="flex w-fit max-w-full items-center gap-1">
                <p className="truncate text-[12.5px] font-medium text-white">{effInfo.steamName}</p>
                {steamProfileUrl && (
                  <a
                    href={steamProfileUrl}
                    target="_blank"
                    rel="noreferrer noopener"
                    className="text-white/25 hover:text-white"
                    aria-label="Open Steam profile"
                    title="Open Steam profile"
                  >
                    <ExternalLink className="h-3 w-3" />
                  </a>
                )}
              </div>
            )}
            <div className="flex w-fit max-w-full items-center gap-0.5">
              <span
                className={`truncate ${effInfo.steamName ? 'text-[10.5px] font-mono text-white/40' : 'text-[12.5px] text-white/75'}`}
              >
                {player.steam}
              </span>
              <button
                onClick={() => onCopy(player.steam)}
                className="ml-0.5 text-white/25 hover:text-white/70"
                aria-label="Copy Steam HEX"
              >
                <Copy className="h-3 w-3" />
              </button>
              {!effInfo.steamName && steamProfileUrl && (
                <a
                  href={steamProfileUrl}
                  target="_blank"
                  rel="noreferrer noopener"
                  className="ml-0.5 text-white/25 hover:text-white"
                  aria-label="Open Steam profile"
                  title="Open Steam profile"
                >
                  <ExternalLink className="h-3 w-3" />
                </a>
              )}
            </div>
          </div>
        </div>
      </td>

      <td className="hidden px-4 py-3 md:table-cell">
        {effInfo.discordAvatar || effInfo.discordName || player.discord ? (
          <div className="flex items-center gap-2">
            {effInfo.discordAvatar && (
              <img
                src={effInfo.discordAvatar}
                alt=""
                className="h-6 w-6 shrink-0 rounded-full object-cover"
              />
            )}
            <div className="min-w-0">
              {effInfo.discordName && (
                <p className="truncate text-[12.5px] text-white">{effInfo.discordName}</p>
              )}
              {player.discord && (
                <div className="flex items-center gap-0.5">
                  <span
                    className={`truncate font-mono ${effInfo.discordName ? 'text-[10.5px] text-white/35' : 'text-[12px] text-white/70'}`}
                  >
                    {player.discord}
                  </span>
                  <button
                    onClick={() => onCopy(player.discord)}
                    className="ml-0.5 text-white/25 hover:text-white/70"
                    aria-label="Copy Discord ID"
                  >
                    <Copy className="h-3 w-3" />
                  </button>
                </div>
              )}
            </div>
          </div>
        ) : (
          <span className="text-[12px] text-white/30">—</span>
        )}
      </td>

      <td className="hidden px-4 py-3 lg:table-cell">
        {player.hardwareId ? (
          <div className="flex min-w-0 items-center gap-1">
            <span
              className="truncate font-mono text-[10.5px] text-white/60"
              title={player.hardwareId}
            >
              {player.hardwareId.length > 16
                ? player.hardwareId.slice(0, 16) + '…'
                : player.hardwareId}
            </span>
            <button
              onClick={() => onCopy(player.hardwareId!)}
              className="ml-0.5 text-white/25 hover:text-white"
              aria-label="Copy Hardware ID"
            >
              <Copy className="h-3 w-3" />
            </button>
          </div>
        ) : (
          <span className="text-[11.5px] text-white/30">—</span>
        )}
      </td>

      <td className="hidden px-4 py-3 xl:table-cell">
        {player.addedBy ? (
          <div className="flex min-h-[24px] items-center gap-2">
            {addedByInfo.discordAvatar ? (
              <img
                src={addedByInfo.discordAvatar}
                alt=""
                className="h-5 w-5 shrink-0 rounded-full object-cover"
              />
            ) : (
              <div className="flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-white/[0.05]">
                <span className="text-[9px] font-semibold text-white/50">
                  {(addedByInfo.discordName || player.addedBy).charAt(0).toUpperCase()}
                </span>
              </div>
            )}
            <div className="min-w-0">
              <p className="truncate text-[11.5px] text-white/85">
                {addedByInfo.discordName || player.addedBy}
              </p>
              <p className="text-[10px] text-white/35">{player.createdAt ?? '—'}</p>
            </div>
          </div>
        ) : (
          <span className="text-[11.5px] text-white/40">{player.createdAt ?? '—'}</span>
        )}
      </td>

      <td className="hidden px-4 py-3 2xl:table-cell">
        {player.lastEditBy ? (
          <div className="flex min-h-[24px] items-center gap-2">
            {lastEditByInfo.discordAvatar ? (
              <img
                src={lastEditByInfo.discordAvatar}
                alt=""
                className="h-5 w-5 shrink-0 rounded-full object-cover"
              />
            ) : (
              <div className="flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-white/[0.05]">
                <span className="text-[9px] font-semibold text-white/50">
                  {(lastEditByInfo.discordName || player.lastEditBy).charAt(0).toUpperCase()}
                </span>
              </div>
            )}
            <div className="min-w-0">
              <p className="truncate text-[11.5px] text-white/85">
                {lastEditByInfo.discordName || player.lastEditBy}
              </p>
              {player.lastEditAt && (
                <p className="text-[10px] text-white/35">{player.lastEditAt}</p>
              )}
            </div>
          </div>
        ) : (
          <span className="text-[11.5px] text-white/30">—</span>
        )}
      </td>

      <td className="px-4 py-3">
        <PlayerStatus
          player={player}
          onInfo={onInfo}
        />
      </td>
      <td className="px-4 py-3 text-right">
        <button
          onClick={(e) => onMenu(player, e)}
          data-menu-anchor={player.steam}
          className="inline-flex h-6 w-6 items-center justify-center rounded-md text-white/40 hover:bg-white/[0.05] hover:text-white"
          aria-label="Player actions"
        >
          <Ellipsis className="h-3.5 w-3.5" />
        </button>
      </td>
    </tr>
  );
}
