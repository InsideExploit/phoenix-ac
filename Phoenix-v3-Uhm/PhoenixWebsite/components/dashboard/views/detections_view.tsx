"use client";

import { useMemo } from "react";
import { RefreshCw, User, X } from "lucide-react";
import type { Detection } from "../types";
import { SearchBar } from "../common/search_bar";
import { FilterTabs } from "../common/filter_tabs";
import { SectionCard } from "../common/section_card";
import { TablePagination } from "../common/table_pagination";
import { DetectionRow } from "../detections/detection_row";
import { prettyDetectionType } from "../detections/detection_labels";

type Group = { key: string; label: string; items: Detection[] };

function groupByDay(items: Detection[]): Group[] {
  const groups: Record<string, Detection[]> = {};
  for (const d of items) {
    const day = d.createdAt.slice(0, 10);
    (groups[day] ??= []).push(d);
  }
  const today     = new Date(); today.setHours(0, 0, 0, 0);
  const yesterday = new Date(today); yesterday.setDate(today.getDate() - 1);
  const fmtToday     = today.toISOString().slice(0, 10);
  const fmtYesterday = yesterday.toISOString().slice(0, 10);

  return Object.entries(groups)
    .sort(([a], [b]) => (a < b ? 1 : -1))
    .map(([key, list]) => {
      let label = key;
      if (key === fmtToday)     label = "Today";
      else if (key === fmtYesterday) label = "Yesterday";
      else {
        try {
          const d = new Date(key + "T00:00:00");
          label = d.toLocaleDateString(undefined, { weekday: "short", day: "2-digit", month: "short", year: "numeric" });
        } catch { /* fall through */ }
      }
      return { key, label, items: list };
    });
}

export function DetectionsView({
  detections,
  total,
  types,
  page,
  pageSize,
  setPage,
  loading,
  query,
  setQuery,
  typeFilter,
  setTypeFilter,
  steamFilter,
  onClearSteamFilter,
  onSearch,
  onRefresh,
  onOpen,
}: {
  detections: Detection[];
  total: number;
  types: { value: string; count: number }[];
  page: number;
  pageSize: number;
  setPage: (n: number) => void;
  loading: boolean;
  query: string;
  setQuery: (v: string) => void;
  typeFilter: string;
  setTypeFilter: (v: string) => void;
  steamFilter: string;
  onClearSteamFilter: () => void;
  onSearch: (q: string) => void;
  onRefresh: () => void;
  onOpen: (d: Detection) => void;
}) {
  const groups = useMemo(() => groupByDay(detections), [detections]);

  const totalAll = useMemo(
    () => types.reduce((n, t) => n + t.count, 0),
    [types],
  );

  const typeOptions = useMemo(() => {
    const opts: { value: string; label: string; count?: number }[] = [
      { value: "", label: "All", count: totalAll },
    ];
    for (const t of types) {
      opts.push({ value: t.value, label: prettyDetectionType(t.value), count: t.count });
    }
    return opts;
  }, [types, totalAll]);

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-3">
        <SearchBar
          value={query}
          onChange={setQuery}
          onSubmit={() => onSearch(query)}
          placeholder="Search Steam, type, reason, path…"
        />
        {steamFilter && (
          <span className="inline-flex items-center gap-1.5 rounded-md border border-sky-400/30 bg-sky-400/[0.06] py-1 pl-2 pr-1 text-[11px] text-sky-300/90">
            <User className="h-3 w-3" />
            <span>Player</span>
            <span className="font-mono text-sky-200/85">{steamFilter}</span>
            <button
              type="button"
              onClick={onClearSteamFilter}
              className="ml-0.5 inline-flex h-4 w-4 items-center justify-center rounded text-sky-200/60 hover:bg-sky-400/[0.12] hover:text-sky-100"
              aria-label="Clear player filter"
            >
              <X className="h-3 w-3" />
            </button>
          </span>
        )}
        <div className="ml-auto">
          <button
            onClick={onRefresh}
            disabled={loading}
            className="inline-flex h-8 items-center gap-1.5 rounded-md border border-white/[0.08] px-2.5 text-[12px] text-white/70 hover:bg-white/[0.04] hover:text-white disabled:opacity-40"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${loading ? "animate-spin" : ""}`} />
            {loading ? "Loading…" : "Refresh"}
          </button>
        </div>
      </div>

      {typeOptions.length > 1 && (
        <div className="overflow-x-auto">
          <FilterTabs<string>
            value={typeFilter}
            onChange={setTypeFilter}
            options={typeOptions}
          />
        </div>
      )}

      {loading && detections.length === 0 && (
        <SectionCard title="History">
          <div className="space-y-1.5 p-3">
            {Array.from({ length: 6 }).map((_, i) => (
              <div key={i} className="flex items-center gap-3 rounded-md border border-white/[0.05] bg-white/[0.015] px-3 py-3">
                <div className="h-8 w-8 shrink-0 rounded-md bg-white/[0.04]" />
                <div className="flex-1 space-y-1.5">
                  <div className="skel-bar" style={{ width: "45%" }} />
                  <div className="skel-bar" style={{ width: "70%" }} />
                </div>
              </div>
            ))}
          </div>
        </SectionCard>
      )}

      {!loading && detections.length === 0 && (
        <SectionCard title="History">
          <p className="px-4 py-14 text-center text-[12.5px] text-white/40">No detections match your filters.</p>
        </SectionCard>
      )}

      {!loading && groups.length > 0 && (
        <SectionCard
          title="History"
          meta={`Showing ${detections.length} of ${total}`}
        >
          <div className="space-y-4 p-3">
            {groups.map((g) => (
              <div key={g.key}>
                <div className="mb-1.5 flex items-baseline gap-2 px-1">
                  <span className="text-[11px] font-medium uppercase tracking-wider text-white/45">{g.label}</span>
                  <span className="text-[10px] text-white/30">· {g.items.length}</span>
                </div>
                <div className="space-y-1.5">
                  {g.items.map((d, i) => (
                    <DetectionRow key={d.id} detection={d} index={i} onOpen={onOpen} />
                  ))}
                </div>
              </div>
            ))}
          </div>
          <TablePagination total={total} page={page} setPage={setPage} pageSize={pageSize} />
        </SectionCard>
      )}
    </div>
  );
}
