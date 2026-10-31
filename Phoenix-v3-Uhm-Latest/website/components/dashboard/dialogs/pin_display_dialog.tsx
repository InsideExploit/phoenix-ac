import { Copy, Ticket } from 'lucide-react';

import { AnimatedDialog } from '@/components/ui/animated-dialog';

export function PinDisplayDialog({
  code,
  onClose,
  onCopy,
}: {
  code: string | null;
  onClose: () => void;
  onCopy: (code: string) => void;
}) {
  return (
    <AnimatedDialog
      open={!!code}
      onClose={onClose}
      panelClassName="max-w-xs phx-dialog-in"
    >
      {(dismiss) =>
        code ? (
          <div className="w-full rounded-lg border border-white/[0.08] bg-[#111] p-5 text-center">
            <div className="mx-auto mb-4 flex h-10 w-10 items-center justify-center rounded-full bg-white/[0.05]">
              <Ticket className="h-4 w-4 text-white/70" />
            </div>
            <p className="text-[11px] uppercase tracking-wider text-white/40">
              PIN generated · valid 24h
            </p>
            <p className="mt-2 text-[28px] font-bold tracking-[0.14em] text-white">{code}</p>
            <div className="mt-5 flex gap-2">
              <button
                onClick={() => onCopy(code)}
                className="inline-flex flex-1 items-center justify-center gap-1.5 rounded-md border border-white/[0.08] px-3 py-1.5 text-[11.5px] text-white/70 hover:bg-white/[0.04] hover:text-white"
              >
                <Copy className="h-3 w-3" />
                Copy
              </button>
              <button
                onClick={dismiss}
                className="flex-1 rounded-md bg-white px-3 py-1.5 text-[11.5px] font-medium text-black hover:bg-white/90"
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
