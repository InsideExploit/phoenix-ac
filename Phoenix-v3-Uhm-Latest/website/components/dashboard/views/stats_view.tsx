'use client';

import { RefreshCw } from 'lucide-react';

import { SearchBar } from '../common/search_bar';
import { SectionCard } from '../common/section_card';
import { SkeletonRows } from '../common/skeleton_rows';
import { TablePagination } from '../common/table_pagination';
import type { StatRow } from '../types';
import { PAGE_SIZE } from '../types';

const th =
  'px-4 py-2.5 text-left text-[10px] font-semibold uppercase tracking-[0.09em] text-white/40';

export function StatsView({
  stats,
  loading,
  query,
  setQuery,
  page,
  setPage,
  onSearch,
}: {
  stats: StatRow[];
  loading: boolean;
  query: string;
  setQuery: (v: string) => void;
  page: number;
  setPage: (n: number) => void;
  onSearch: (q: string) => void;
}) {
  const pageSlice = stats.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE);
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-3">
        <SearchBar
          value={query}
          onChange={setQuery}
          onSubmit={() => onSearch(query)}
          placeholder="Search Steam, Discord, name…"
        />
        <div className="ml-auto">
          <button
            onClick={() => onSearch(query)}
            disabled={loading}
            className="inline-flex h-8 items-center gap-1.5 rounded-md border border-white/[0.08] px-2.5 text-[12px] text-white/70 hover:bg-white/[0.04] hover:text-white disabled:opacity-40"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${loading ? 'animate-spin' : ''}`} />
            {loading ? 'Loading…' : 'Refresh'}
          </button>
        </div>
      </div>

      <SectionCard
        title="Player statistics"
        meta={`${stats.length} total`}
      >
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-white/[0.06]">
                <th className={th}>Name</th>
                <th className={th}>Steam</th>
                <th className={`${th} hidden md:table-cell`}>Discord</th>
                <th className={`${th} hidden lg:table-cell`}>License</th>
                <th className={`${th} hidden xl:table-cell`}>Token</th>
                <th className={`${th} text-right`}>K</th>
                <th className={`${th} text-right`}>D</th>
                <th className={`${th} text-right`}>K/D</th>
                <th className={`${th} text-right`}>Streak</th>
              </tr>
            </thead>
            <tbody>
              {loading && <SkeletonRows cols={9} />}
              {!loading && stats.length === 0 && (
                <tr>
                  <td
                    colSpan={9}
                    className="px-4 py-14 text-center text-[12.5px] text-white/40"
                  >
                    No data available.
                  </td>
                </tr>
              )}
              {!loading &&
                pageSlice.map((s, i) => (
                  <tr
                    key={s.steamHex}
                    className="row-in border-b border-white/[0.04] transition-colors last:border-0 hover:bg-white/[0.02]"
                    style={{ animationDelay: `${i * 28}ms` }}
                  >
                    <td className="px-4 py-3 text-[12.5px] text-white">{s.name || '—'}</td>
                    <td className="px-4 py-3 font-mono text-[11.5px] text-white/60">
                      {s.steamHex}
                    </td>
                    <td className="hidden px-4 py-3 font-mono text-[11.5px] text-white/60 md:table-cell">
                      {s.discordId || '—'}
                    </td>
                    <td className="hidden px-4 py-3 font-mono text-[10.5px] text-white/45 lg:table-cell">
                      {s.license
                        ? s.license.slice(0, 16) + (s.license.length > 16 ? '…' : '')
                        : '—'}
                    </td>
                    <td className="hidden px-4 py-3 font-mono text-[10.5px] text-white/45 xl:table-cell">
                      {s.token ? s.token.slice(0, 14) + (s.token.length > 14 ? '…' : '') : '—'}
                    </td>
                    <td className="px-4 py-3 text-right tabular-nums text-[12.5px] font-semibold text-emerald-400/90">
                      {s.kills}
                    </td>
                    <td className="px-4 py-3 text-right tabular-nums text-[12.5px] font-semibold text-red-400/85">
                      {s.deaths}
                    </td>
                    <td className="px-4 py-3 text-right tabular-nums text-[12.5px] text-white">
                      {s.kd}
                    </td>
                    <td className="px-4 py-3 text-right text-[11.5px] tabular-nums text-white/60">
                      <span className="text-white">{s.currentStreak}</span>
                      <span className="text-white/25"> / </span>
                      <span>{s.maxStreak}</span>
                    </td>
                  </tr>
                ))}
            </tbody>
          </table>
        </div>
        <TablePagination
          total={stats.length}
          page={page}
          setPage={setPage}
        />
      </SectionCard>
    </div>
  );
}
