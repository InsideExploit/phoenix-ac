"use client";

import { RefreshCw } from "lucide-react";
import type { EvasionFlag } from "../types";
import { PAGE_SIZE } from "../types";
import { SearchBar } from "../common/search_bar";
import { SkeletonRows } from "../common/skeleton_rows";
import { TablePagination } from "../common/table_pagination";
import { SectionCard } from "../common/section_card";

const th =
  "px-4 py-2.5 text-left text-[10px] font-semibold uppercase tracking-[0.09em] text-white/40";

export function EvasionView({
  flags,
  loading,
  query,
  setQuery,
  page,
  setPage,
  onSearch,
}: {
  flags: EvasionFlag[];
  loading: boolean;
  query: string;
  setQuery: (v: string) => void;
  page: number;
  setPage: (n: number) => void;
  onSearch: (q: string) => void;
}) {
  const pageSlice = flags.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE);

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-3">
        <SearchBar
          value={query}
          onChange={setQuery}
          onSubmit={() => onSearch(query)}
          placeholder="Search Steam, name, value…"
        />
        <div className="ml-auto">
          <button
            onClick={() => onSearch(query)}
            disabled={loading}
            className="inline-flex h-8 items-center gap-1.5 rounded-md border border-white/[0.08] px-2.5 text-[12px] text-white/70 hover:bg-white/[0.04] hover:text-white disabled:opacity-40"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${loading ? "animate-spin" : ""}`} />
            {loading ? "Loading…" : "Refresh"}
          </button>
        </div>
      </div>

      <SectionCard title="Detected flags" meta={`${flags.length} total`}>
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-white/[0.06]">
                <th className={th}>When</th>
                <th className={th}>Type</th>
                <th className={th}>Value</th>
                <th className={th}>Primary hex</th>
                <th className={th}>Secondary hex</th>
                <th className={`${th} hidden lg:table-cell`}>IP</th>
              </tr>
            </thead>
            <tbody>
              {loading && <SkeletonRows cols={6} />}
              {!loading && flags.length === 0 && (
                <tr>
                  <td colSpan={6} className="px-4 py-14 text-center text-[12.5px] text-white/40">
                    No active flags.
                  </td>
                </tr>
              )}
              {!loading && pageSlice.map((f, i) => (
                <tr
                  key={f.id}
                  className="row-in border-b border-white/[0.04] transition-colors last:border-0 hover:bg-white/[0.02]"
                  style={{ animationDelay: `${i * 28}ms` }}
                >
                  <td className="whitespace-nowrap px-4 py-3 text-[11.5px] text-white/55">
                    {new Date(f.createdAt).toLocaleString()}
                  </td>
                  <td className="px-4 py-3">
                    <span className="inline-flex items-center rounded-md border border-white/[0.10] bg-white/[0.03] px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wider text-white/75">
                      {f.fpType}
                    </span>
                  </td>
                  <td className="max-w-[260px] truncate px-4 py-3 font-mono text-[10.5px] text-white/50" title={f.fpValue}>
                    {f.fpValue}
                  </td>
                  <td className="px-4 py-3 font-mono text-[10.5px] text-white/60">
                    {f.primaryHex}
                    {f.primaryName && <div className="mt-0.5 font-sans text-[10.5px] text-white/40">{f.primaryName}</div>}
                  </td>
                  <td className="px-4 py-3 font-mono text-[10.5px] text-white/60">
                    {f.secondaryHex}
                    {f.secondaryName && <div className="mt-0.5 font-sans text-[10.5px] text-white/40">{f.secondaryName}</div>}
                  </td>
                  <td className="hidden px-4 py-3 font-mono text-[10.5px] text-white/50 lg:table-cell">{f.clientIp || "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <TablePagination total={flags.length} page={page} setPage={setPage} />
      </SectionCard>
    </div>
  );
}
