import { ChevronLeft, ChevronRight } from 'lucide-react';

import { PAGE_SIZE } from '../types';

export function TablePagination({
  total,
  page,
  setPage,
  pageSize = PAGE_SIZE,
}: {
  total: number;
  page: number;
  setPage: (p: number) => void;
  pageSize?: number;
}) {
  const totalPages = Math.ceil(total / pageSize);
  if (totalPages <= 1) return null;
  const pages: (number | '…')[] = [];
  if (totalPages <= 7) {
    for (let i = 0; i < totalPages; i++) pages.push(i);
  } else {
    pages.push(0);
    if (page > 2) pages.push('…');
    for (let i = Math.max(1, page - 1); i <= Math.min(totalPages - 2, page + 1); i++) pages.push(i);
    if (page < totalPages - 3) pages.push('…');
    pages.push(totalPages - 1);
  }
  const btn =
    'inline-flex h-7 w-7 items-center justify-center rounded-md text-[11.5px] text-white/60 ' +
    'hover:bg-white/[0.04] hover:text-white disabled:pointer-events-none disabled:opacity-30';
  return (
    <div className="flex items-center justify-between border-t border-white/[0.05] px-4 py-2.5">
      <span className="text-[11px] tabular-nums text-white/45">
        {page * pageSize + 1}–{Math.min((page + 1) * pageSize, total)} of {total}
      </span>
      <div className="flex items-center gap-0.5">
        <button
          className={btn}
          disabled={page === 0}
          onClick={() => setPage(page - 1)}
          aria-label="Previous"
        >
          <ChevronLeft className="h-3.5 w-3.5" />
        </button>
        {pages.map((p, i) =>
          p === '…' ? (
            <span
              key={`e-${i}`}
              className="px-1 text-[11px] text-white/30"
            >
              …
            </span>
          ) : (
            <button
              key={p}
              onClick={() => setPage(p as number)}
              className={
                p === page
                  ? 'inline-flex h-7 w-7 items-center justify-center rounded-md bg-white/[0.06] text-[11.5px] font-medium text-white'
                  : btn
              }
            >
              {(p as number) + 1}
            </button>
          ),
        )}
        <button
          className={btn}
          disabled={page >= totalPages - 1}
          onClick={() => setPage(page + 1)}
          aria-label="Next"
        >
          <ChevronRight className="h-3.5 w-3.5" />
        </button>
      </div>
    </div>
  );
}
