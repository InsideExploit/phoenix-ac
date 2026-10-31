"use client";

import { useMemo } from "react";
import { RefreshCw, Ticket } from "lucide-react";
import type { LookupResult, Pin, PinFilter } from "../types";
import { PAGE_SIZE } from "../types";
import { SearchBar } from "../common/search_bar";
import { FilterTabs } from "../common/filter_tabs";
import { SkeletonRows } from "../common/skeleton_rows";
import { TablePagination } from "../common/table_pagination";
import { SectionCard } from "../common/section_card";
import { PinRow } from "../pins/pin_row";

const th =
  "px-4 py-2.5 text-left text-[10px] font-semibold uppercase tracking-[0.09em] text-white/40";

export function PinsView({
  pins,
  loading,
  query,
  setQuery,
  filter,
  setFilter,
  page,
  setPage,
  busy,
  lookups,
  onRefresh,
  onGenerate,
  onCopyPin,
  onDeletePin,
}: {
  pins: Pin[];
  loading: boolean;
  query: string;
  setQuery: (v: string) => void;
  filter: PinFilter;
  setFilter: (v: PinFilter) => void;
  page: number;
  setPage: (n: number) => void;
  busy: boolean;
  lookups: Record<string, LookupResult>;
  onRefresh: () => void;
  onGenerate: () => void;
  onCopyPin: (code: string) => void;
  onDeletePin: (code: string) => void;
}) {
  const counts = useMemo(() => ({
    all:       pins.length,
    available: pins.filter((p) => !p.used && !p.expired).length,
    used:      pins.filter((p) => p.used).length,
    expired:   pins.filter((p) => !p.used && p.expired).length,
  }), [pins]);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return pins.filter((p) => {
      if (filter === "available" && (p.used || p.expired)) return false;
      if (filter === "used"      && !p.used)               return false;
      if (filter === "expired"   && (p.used || !p.expired))return false;
      if (!q) return true;
      const info = lookups[`|${p.createdBy}`] ?? {};
      return (
        p.code.toLowerCase().includes(q) ||
        (p.createdBy?.toLowerCase().includes(q) ?? false) ||
        (info.discordName?.toLowerCase().includes(q) ?? false)
      );
    });
  }, [pins, filter, query, lookups]);

  const pageSlice = filtered.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE);

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-3">
        <SearchBar value={query} onChange={setQuery} placeholder="Search code, creator…" />
        <FilterTabs<PinFilter>
          value={filter}
          onChange={setFilter}
          options={[
            { value: "all",       label: "All",       count: counts.all       },
            { value: "available", label: "Available", count: counts.available },
            { value: "used",      label: "Used",      count: counts.used      },
            { value: "expired",   label: "Expired",   count: counts.expired   },
          ]}
        />
        <div className="ml-auto flex items-center gap-2">
          <button
            onClick={onRefresh}
            disabled={loading}
            className="inline-flex h-8 items-center gap-1.5 rounded-md border border-white/[0.08] px-2.5 text-[12px] text-white/70 hover:bg-white/[0.04] hover:text-white disabled:opacity-40"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${loading ? "animate-spin" : ""}`} />
            {loading ? "Loading…" : "Refresh"}
          </button>
          <button
            onClick={onGenerate}
            disabled={busy}
            className="inline-flex h-8 items-center gap-1.5 rounded-md bg-white px-3 text-[12px] font-medium text-black hover:bg-white/90 disabled:opacity-40"
          >
            <Ticket className="h-3.5 w-3.5" />
            New PIN
          </button>
        </div>
      </div>

      <SectionCard
        title="Generated PINs"
        meta={`${filtered.length} / ${pins.length} total`}
      >
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-white/[0.06]">
                <th className={th}>PIN</th>
                <th className={th}>Status</th>
                <th className={`${th} hidden md:table-cell`}>Created by</th>
                <th className={`${th} hidden lg:table-cell`}>Created at</th>
                <th className={`${th} hidden xl:table-cell`}>Expires</th>
                <th className={`${th} text-right`}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {loading && <SkeletonRows cols={6} />}
              {!loading && pageSlice.map((p, i) => (
                <PinRow
                  key={p.code}
                  pin={p}
                  creatorInfo={lookups[`|${p.createdBy}`] ?? {}}
                  index={i}
                  onCopy={onCopyPin}
                  onDelete={onDeletePin}
                />
              ))}
              {!loading && filtered.length === 0 && (
                <tr>
                  <td colSpan={6} className="px-4 py-14 text-center text-[12.5px] text-white/40">
                    {pins.length === 0 ? "No PINs generated. Press New PIN." : "No PINs match your filters."}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
        <TablePagination total={filtered.length} page={page} setPage={setPage} />
      </SectionCard>
    </div>
  );
}
