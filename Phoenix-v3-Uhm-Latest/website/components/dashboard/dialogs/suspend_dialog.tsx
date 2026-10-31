'use client';

import { useEffect, useState } from 'react';

import { PauseCircle, X } from 'lucide-react';

import { AnimatedDialog } from '@/components/ui/animated-dialog';

import type { Player } from '../types';

export function SuspendDialog({
  target,
  mode = 'create',
  busy,
  onClose,
  onSubmit,
}: {
  target: Player | null;
  mode?: 'create' | 'edit';
  busy: boolean;
  onClose: () => void;
  onSubmit: (reason: string) => void;
}) {
  const [reason, setReason] = useState('');
  useEffect(() => {
    if (!target) return;
    setReason(mode === 'edit' ? (target.suspendReason ?? '') : '');
  }, [target, mode]);
  return (
    <AnimatedDialog
      open={!!target}
      onClose={() => !busy && onClose()}
      panelClassName="max-w-md phx-dialog-in"
    >
      {(dismiss) =>
        target ? (
          <form
            onSubmit={(e) => {
              e.preventDefault();
              if (busy) return;
              onSubmit(reason.trim());
            }}
            className="w-full rounded-lg border border-white/[0.08] bg-[#111] p-5"
          >
            <div className="mb-4 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <PauseCircle className="h-3.5 w-3.5 text-amber-400/85" />
                <h2 className="text-[14px] font-medium text-white">
                  {mode === 'edit' ? 'Edit suspend reason' : 'Suspend anticheat'}
                </h2>
              </div>
              <button
                type="button"
                onClick={dismiss}
                disabled={busy}
                className="text-white/45 hover:text-white disabled:opacity-30"
                aria-label="Close"
              >
                <X className="h-4 w-4" />
              </button>
            </div>

            <p className="mb-3 truncate font-mono text-[11px] text-white/45">{target.steam}</p>
            {mode === 'create' && (
              <p className="mb-4 text-[12.5px] leading-relaxed text-white/55">
                {target.steam} will be able to join the server without running PhoenixAC.
              </p>
            )}

            <label className="mb-5 block">
              <span className="mb-1.5 block text-[10.5px] font-medium uppercase tracking-wider text-white/40">
                Reason (optional)
              </span>
              <textarea
                autoFocus
                rows={3}
                value={reason}
                onChange={(e) => setReason(e.target.value)}
                placeholder="Why this player is exempted…"
                maxLength={255}
                disabled={busy}
                className="w-full resize-none rounded-md border border-white/[0.08] bg-black/40 px-3 py-2 text-[12.5px] leading-relaxed text-white placeholder:text-white/25 focus:border-white/20 focus:outline-none disabled:opacity-50"
              />
            </label>

            <div className="flex justify-end gap-2">
              <button
                type="button"
                onClick={dismiss}
                disabled={busy}
                className="h-8 rounded-md px-3 text-[12px] text-white/70 hover:bg-white/[0.04] hover:text-white disabled:opacity-40"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={busy}
                className="h-8 rounded-md bg-amber-500/85 px-3 text-[12px] font-medium text-black hover:bg-amber-500 disabled:opacity-40"
              >
                {busy ? 'Please wait…' : mode === 'edit' ? 'Save' : 'Suspend'}
              </button>
            </div>
          </form>
        ) : null
      }
    </AnimatedDialog>
  );
}
