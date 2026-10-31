'use client';

import { useMemo } from 'react';

import { Camera, UserPlus } from 'lucide-react';

import { FilterTabs } from '../common/filter_tabs';
import { SearchBar } from '../common/search_bar';
import { SectionCard } from '../common/section_card';
import { SkeletonRows } from '../common/skeleton_rows';
import { TablePagination } from '../common/table_pagination';
import { PlayerRow } from '../players/player_row';
import type { LookupResult, Player, PlayerFilter } from '../types';
import { PAGE_SIZE } from '../types';

const th =
  'px-4 py-2.5 text-left text-[10px] font-semibold uppercase tracking-[0.09em] text-white/40';

export function PlayersView({
  players,
  loading,
  query,
  setQuery,
  filter,
  setFilter,
  page,
  setPage,
  lookups,
  onAdd,
  onCopy,
  onMenu,
  onInfo,
  onScreenshotAll,
}: {
  players: Player[];
  loading: boolean;
  query: string;
  setQuery: (v: string) => void;
  filter: PlayerFilter;
  setFilter: (v: PlayerFilter) => void;
  page: number;
  setPage: (n: number) => void;
  lookups: Record<string, LookupResult>;
  onAdd: () => void;
  onCopy: (v: string) => void;
  onMenu: (player: Player, e: React.MouseEvent<HTMLButtonElement>) => void;
  onInfo: (p: Player) => void;
  onScreenshotAll?: () => void;
}) {
  const counts = useMemo(
    () => ({
      all: players.length,
      online: players.filter((p) => p.online && !p.banned && !p.suspended).length,
      offline: players.filter((p) => !p.online && !p.banned && !p.suspended).length,
      suspended: players.filter((p) => p.suspended && !p.banned).length,
      banned: players.filter((p) => p.banned).length,
    }),
    [players],
  );
  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return players.filter((p) => {
      if (filter === 'online' && !(p.online && !p.banned && !p.suspended)) return false;
      if (filter === 'offline' && !(!p.online && !p.banned && !p.suspended)) return false;
      if (filter === 'suspended' && !(p.suspended && !p.banned)) return false;
      if (filter === 'banned' && !p.banned) return false;
      if (!q) return true;
      const info = lookups[`${p.steam}|${p.discord}`] ?? {};
      const cachedSteamName = (info.steamName ?? p.steamName ?? '').toLowerCase();
      const cachedDiscordName = (info.discordName ?? p.discordName ?? '').toLowerCase();
      return (
        p.steam.toLowerCase().includes(q) ||
        p.discord.toLowerCase().includes(q) ||
        cachedSteamName.includes(q) ||
        cachedDiscordName.includes(q)
      );
    });
  }, [players, filter, query, lookups]);
  const pageSlice = filtered.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE);
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-3">
        <SearchBar
          value={query}
          onChange={setQuery}
          placeholder="Search Steam, Discord, name…"
        />
        <FilterTabs<PlayerFilter>
          value={filter}
          onChange={setFilter}
          options={[
            { value: 'all', label: 'All', count: counts.all },
            { value: 'online', label: 'Online', count: counts.online },
            { value: 'offline', label: 'Offline', count: counts.offline },
            { value: 'suspended', label: 'Suspended', count: counts.suspended },
            { value: 'banned', label: 'Banned', count: counts.banned },
          ]}
        />
        <div className="ml-auto flex items-center gap-2">
          {onScreenshotAll && (
            <button
              onClick={onScreenshotAll}
              disabled={counts.online === 0}
              className="inline-flex h-8 items-center gap-1.5 rounded-md border border-white/[0.10] bg-white/[0.03] px-3 text-[12px] text-white/85 hover:bg-white/[0.06] hover:text-white disabled:cursor-not-allowed disabled:opacity-40"
              title={
                counts.online === 0
                  ? 'No online players'
                  : `Capture all ${counts.online} online players`
              }
            >
              <Camera className="h-3.5 w-3.5" />
              Screenshot all
              <span className="ml-0.5 text-[10.5px] text-white/45">{counts.online}</span>
            </button>
          )}
          <button
            onClick={onAdd}
            className="inline-flex h-8 items-center gap-1.5 rounded-md bg-white px-3 text-[12px] font-medium text-black hover:bg-white/90"
          >
            <UserPlus className="h-3.5 w-3.5" />
            Add player
          </button>
        </div>
      </div>

      <SectionCard
        title="Players"
        meta={`${counts.online} online · ${counts.all} total`}
      >
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-white/[0.06]">
                <th className={th}>Player</th>
                <th className={`${th} hidden md:table-cell`}>Discord</th>
                <th className={`${th} hidden lg:table-cell`}>Hardware ID</th>
                <th className={`${th} hidden xl:table-cell`}>Added by</th>
                <th className={`${th} hidden 2xl:table-cell`}>Last edit</th>
                <th className={th}>Status</th>
                <th className={`${th} text-right`}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {loading && (
                <SkeletonRows
                  cols={6}
                  rows={9}
                />
              )}
              {!loading &&
                pageSlice.map((p, i) => (
                  <PlayerRow
                    key={p.steam}
                    player={p}
                    info={lookups[`${p.steam}|${p.discord}`] ?? {}}
                    addedByInfo={lookups[`|${p.addedBy}`] ?? {}}
                    lastEditByInfo={lookups[`|${p.lastEditBy}`] ?? {}}
                    index={i}
                    onCopy={onCopy}
                    onMenu={onMenu}
                    onInfo={onInfo}
                  />
                ))}
              {!loading && filtered.length === 0 && (
                <tr>
                  <td
                    colSpan={7}
                    className="px-4 py-14 text-center text-[12.5px] text-white/40"
                  >
                    No players found.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
        <TablePagination
          total={filtered.length}
          page={page}
          setPage={setPage}
        />
      </SectionCard>
    </div>
  );
}
