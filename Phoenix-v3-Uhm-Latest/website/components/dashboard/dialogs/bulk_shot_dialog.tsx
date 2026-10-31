import { Ban, Camera, Loader2, RefreshCw, X } from 'lucide-react';

import { AnimatedDialog } from '@/components/ui/animated-dialog';

import type { BulkShotEntry, BulkShotState } from '../types';

export function BulkShotDialog({
  state,
  onClose,
  onRetry,
}: {
  state: BulkShotState;
  onClose: () => void;
  onRetry: (steam: string) => void;
}) {
  return (
    <AnimatedDialog
      open={!!state}
      onClose={onClose}
      panelClassName="max-w-6xl phx-dialog-in"
    >
      {(dismiss) =>
        state ? (
          <div className="flex max-h-[88vh] w-full flex-col overflow-hidden rounded-lg border border-white/[0.08] bg-[#111]">
            <div className="flex shrink-0 items-center justify-between border-b border-white/[0.06] px-4 py-3">
              <div className="flex items-center gap-2">
                <Camera className="h-3.5 w-3.5 text-white/60" />
                <div>
                  <h2 className="text-[13px] font-medium text-white">Bulk screenshot</h2>
                  <p className="mt-0.5 text-[10.5px] text-white/40">
                    {state.done} / {state.total} players · {state.method.toUpperCase()}
                  </p>
                </div>
              </div>
              <button
                type="button"
                onClick={dismiss}
                className="text-white/45 hover:text-white"
                aria-label="Close"
              >
                <X className="h-4 w-4" />
              </button>
            </div>

            <div className="min-h-0 flex-1 overflow-y-auto p-3">
              {Object.keys(state.entries).length === 0 ? (
                <p className="px-4 py-10 text-center text-[12px] text-white/40">
                  No online players to capture.
                </p>
              ) : (
                <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3 2xl:grid-cols-4">
                  {Object.values(state.entries).map((e) => (
                    <BulkTile
                      key={e.steam}
                      entry={e}
                      onRetry={onRetry}
                    />
                  ))}
                </div>
              )}
            </div>

            <div className="flex shrink-0 justify-end gap-2 border-t border-white/[0.06] px-4 py-3">
              <button
                onClick={dismiss}
                className="h-7 rounded-md bg-white/[0.08] px-3 text-[11.5px] font-medium text-white hover:bg-white/[0.14]"
              >
                Close
              </button>
            </div>
          </div>
        ) : null
      }
    </AnimatedDialog>
  );
}

function BulkTile({ entry, onRetry }: { entry: BulkShotEntry; onRetry: (steam: string) => void }) {
  const displayName = entry.displayName || entry.steam;
  return (
    <div className="flex flex-col overflow-hidden rounded-md border border-white/[0.06] bg-white/[0.02]">
      <div className="flex items-center gap-2 border-b border-white/[0.06] px-2.5 py-2">
        {entry.avatar ? (
          <img
            src={entry.avatar}
            alt=""
            className="h-6 w-6 shrink-0 rounded-sm object-cover"
          />
        ) : (
          <div className="h-6 w-6 shrink-0 rounded-sm bg-white/[0.06]" />
        )}
        <div className="min-w-0 flex-1">
          <p className="truncate text-[11.5px] font-medium text-white">{displayName}</p>
          <p className="truncate font-mono text-[9.5px] text-white/40">{entry.steam}</p>
        </div>
        {entry.state !== 'loading' && (
          <button
            onClick={() => onRetry(entry.steam)}
            className="shrink-0 text-white/35 hover:text-white/80"
            aria-label="Retry"
            title="Retry"
          >
            <RefreshCw className="h-3 w-3" />
          </button>
        )}
      </div>

      <div className="relative flex min-h-[160px] items-center justify-center overflow-hidden bg-black">
        {entry.state === 'loading' && (
          <div className="flex flex-col items-center gap-2 py-6 text-white/40">
            <Loader2 className="h-4 w-4 animate-spin" />
            <p className="text-[10.5px]">Capturing…</p>
          </div>
        )}
        {entry.state === 'ready' && entry.path && (
          <button
            type="button"
            onClick={() => window.open(`/api/screenshots/${entry.path}`, '_blank')}
            className="block h-full w-full"
            title="Open original"
          >
            <img
              src={`/api/screenshots/${entry.path}`}
              alt=""
              className="max-h-[220px] w-full object-contain"
            />
          </button>
        )}
        {entry.state === 'error' && (
          <div className="flex flex-col items-center gap-1.5 px-3 py-6 text-red-400/80">
            <Ban className="h-4 w-4" />
            <p className="text-center text-[10.5px] leading-snug">{entry.error ?? 'Error'}</p>
          </div>
        )}
      </div>
    </div>
  );
}
