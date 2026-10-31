import { Ban, Loader2, RefreshCw, Settings2, X } from 'lucide-react';

import { AnimatedDialog } from '@/components/ui/animated-dialog';

import type { ShotViewerState } from '../types';

export function ShotViewerDialog({
  state,
  onClose,
  onRetry,
  onRetryDifferent,
}: {
  state: ShotViewerState;
  onClose: () => void;
  onRetry: (steam: string) => void;
  onRetryDifferent: (steam: string) => void;
}) {
  return (
    <AnimatedDialog
      open={!!state}
      onClose={onClose}
      panelClassName="max-w-3xl phx-dialog-in"
    >
      {(dismiss) =>
        state ? (
          <div className="w-full rounded-lg border border-white/[0.08] bg-[#111] p-4">
            <div className="mb-3 flex items-center justify-between">
              <div className="min-w-0">
                <h2 className="text-[13px] font-medium text-white">Player screenshot</h2>
                <p className="mt-0.5 truncate font-mono text-[10.5px] text-white/40">
                  {state.steam}
                </p>
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

            <div className="flex min-h-[280px] items-center justify-center overflow-hidden rounded-md border border-white/[0.06] bg-black">
              {state.state === 'loading' && (
                <div className="flex flex-col items-center gap-2.5 py-14 text-white/45">
                  <Loader2 className="h-5 w-5 animate-spin" />
                  <p className="text-[11.5px]">Capturing on client…</p>
                </div>
              )}
              {state.state === 'ready' && state.path && (
                <img
                  src={`/api/screenshots/${state.path}`}
                  alt=""
                  className="max-h-[70vh] w-full object-contain"
                />
              )}
              {state.state === 'error' && (
                <div className="flex flex-col items-center gap-2 py-14 text-red-400/80">
                  <Ban className="h-5 w-5" />
                  <p className="text-[11.5px]">{state.error ?? 'Error'}</p>
                </div>
              )}
            </div>

            {state.state !== 'loading' && state.method && (
              <div className="mt-2 flex items-center gap-2 text-[10.5px] text-white/40">
                <span>Requested:</span>
                <span className="font-mono uppercase text-white/60">{state.method}</span>
                {state.usedMethod && state.usedMethod !== state.method && (
                  <>
                    <span>·</span>
                    <span>Used:</span>
                    <span className="font-mono uppercase text-amber-300/80">
                      {state.usedMethod}
                    </span>
                  </>
                )}
              </div>
            )}

            <div className="mt-3 flex flex-wrap justify-end gap-2">
              {state.state === 'ready' && state.path && (
                <button
                  onClick={() => window.open(`/api/screenshots/${state.path}`, '_blank')}
                  className="h-8 rounded-md border border-white/[0.08] px-3 text-[11.5px] text-white/70 hover:bg-white/[0.04] hover:text-white"
                >
                  Open original
                </button>
              )}
              {state.state !== 'loading' && (
                <>
                  <button
                    onClick={() => onRetryDifferent(state.steam)}
                    className="inline-flex h-8 items-center rounded-md border border-white/[0.08] px-3 text-[11.5px] text-white/70 hover:bg-white/[0.04] hover:text-white"
                  >
                    <Settings2 className="mr-1.5 h-3 w-3" />
                    Retry (change mode)
                  </button>
                  <button
                    onClick={() => onRetry(state.steam)}
                    className="inline-flex h-8 items-center rounded-md border border-white/[0.08] px-3 text-[11.5px] text-white/70 hover:bg-white/[0.04] hover:text-white"
                  >
                    <RefreshCw className="mr-1.5 h-3 w-3" />
                    Retry ({(state.method ?? 'auto').toUpperCase()})
                  </button>
                </>
              )}
              <button
                onClick={dismiss}
                className="h-8 rounded-md bg-white px-3 text-[11.5px] font-medium text-black hover:bg-white/90"
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
