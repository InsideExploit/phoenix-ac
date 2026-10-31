import { X } from 'lucide-react';

import { AnimatedDialog } from '@/components/ui/animated-dialog';

export type ReasonPromptPayload = {
  title: string;
  description: string;
  confirmLabel: string;
  destructive?: boolean;
  placeholder?: string;
  requireReason?: boolean;
  onConfirm: (reason: string) => void;
} | null;

export function ReasonPromptDialog({
  payload,
  reason,
  setReason,
  busy,
  onClose,
}: {
  payload: ReasonPromptPayload;
  reason: string;
  setReason: (v: string) => void;
  busy: boolean;
  onClose: () => void;
}) {
  return (
    <AnimatedDialog
      open={!!payload}
      onClose={() => !busy && onClose()}
      panelClassName="max-w-md phx-dialog-in"
    >
      {(dismiss) =>
        payload ? (
          <form
            onSubmit={(e) => {
              e.preventDefault();
              if (busy) return;
              if (payload.requireReason && reason.trim().length === 0) return;
              payload.onConfirm(reason.trim());
            }}
            className="w-full rounded-lg border border-white/[0.08] bg-[#111] p-5"
          >
            <div className="mb-4 flex items-center justify-between">
              <h2 className="text-[14px] font-medium text-white">{payload.title}</h2>
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
            <p className="mb-3 text-[12.5px] leading-relaxed text-white/55">
              {payload.description}
            </p>
            <label className="block">
              <span className="mb-1.5 block text-[10.5px] font-medium uppercase tracking-wider text-white/40">
                {payload.requireReason ? 'Reason (required)' : 'Reason (optional)'}
              </span>
              <textarea
                autoFocus
                rows={4}
                value={reason}
                onChange={(e) => setReason(e.target.value)}
                placeholder={payload.placeholder ?? 'Describe the reason…'}
                maxLength={255}
                disabled={busy}
                className="w-full resize-none rounded-md border border-white/[0.08] bg-black/40 px-3 py-2 text-[12.5px] leading-relaxed text-white placeholder:text-white/25 focus:border-white/20 focus:outline-none disabled:opacity-50"
              />
            </label>
            <div className="mt-5 flex justify-end gap-2">
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
                disabled={busy || (payload.requireReason && reason.trim().length === 0)}
                className={
                  'h-8 rounded-md px-3 text-[12px] font-medium transition-colors disabled:opacity-40 ' +
                  (payload.destructive
                    ? 'bg-red-500/85 text-white hover:bg-red-500'
                    : 'bg-white text-black hover:bg-white/90')
                }
              >
                {busy ? 'Please wait…' : payload.confirmLabel}
              </button>
            </div>
          </form>
        ) : null
      }
    </AnimatedDialog>
  );
}
