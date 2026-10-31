import { AnimatedDialog } from '@/components/ui/animated-dialog';

export type ConfirmPayload = {
  title: string;
  description: string;
  confirmLabel?: string;
  destructive?: boolean;
  onConfirm: () => void;
} | null;

export function ConfirmDialog({
  payload,
  onClose,
}: {
  payload: ConfirmPayload;
  onClose: () => void;
}) {
  return (
    <AnimatedDialog
      open={!!payload}
      onClose={onClose}
      zIndex={80}
      panelClassName="max-w-sm phx-dialog-in"
    >
      {(dismiss) =>
        payload ? (
          <div className="w-full rounded-lg border border-white/[0.08] bg-[#111] p-5">
            <h2 className="text-[14px] font-medium text-white">{payload.title}</h2>
            <p className="mt-2 text-[12.5px] leading-relaxed text-white/60">
              {payload.description}
            </p>
            <div className="mt-5 flex justify-end gap-2">
              <button
                type="button"
                onClick={dismiss}
                className="h-8 rounded-md px-3 text-[12px] text-white/70 hover:bg-white/[0.04] hover:text-white"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={() => {
                  payload.onConfirm();
                  dismiss();
                }}
                className={
                  'h-8 rounded-md px-3 text-[12px] font-medium transition-colors ' +
                  (payload.destructive
                    ? 'bg-red-500/85 text-white hover:bg-red-500'
                    : 'bg-white text-black hover:bg-white/90')
                }
              >
                {payload.confirmLabel ?? 'Confirm'}
              </button>
            </div>
          </div>
        ) : null
      }
    </AnimatedDialog>
  );
}
