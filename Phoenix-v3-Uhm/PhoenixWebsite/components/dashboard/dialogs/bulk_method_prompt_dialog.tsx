import { Monitor, X, Zap } from "lucide-react";
import { AnimatedDialog } from "@/components/ui/animated-dialog";

export function BulkMethodPromptDialog({
  open,
  count,
  onPick,
  onClose,
}: {
  open: boolean;
  count: number;
  onPick: (method: "nvidia" | "gdi") => void;
  onClose: () => void;
}) {
  return (
    <AnimatedDialog open={open} onClose={onClose} panelClassName="max-w-xs phx-dialog-in" zIndex={70}>
      {(dismiss) => (
        <div className="w-full rounded-lg border border-white/[0.08] bg-[#111] p-4">
          <div className="mb-1 flex items-center justify-between">
            <h2 className="text-[12.5px] font-medium text-white">Bulk capture method</h2>
            <button
              type="button"
              onClick={dismiss}
              className="text-white/45 hover:text-white"
              aria-label="Close"
            >
              <X className="h-3.5 w-3.5" />
            </button>
          </div>
          <p className="mb-3 text-[10.5px] text-white/45">
            Will capture {count} online player{count === 1 ? "" : "s"}.
          </p>
          <div className="flex flex-col gap-1">
            <button
              type="button"
              onClick={() => { dismiss(); onPick("nvidia"); }}
              className="flex items-center gap-3 rounded-md border border-white/[0.06] bg-white/[0.015] px-3 py-2 text-left hover:border-white/15 hover:bg-white/[0.04]"
            >
              <Zap className="h-3.5 w-3.5 shrink-0 text-emerald-400" />
              <div className="min-w-0 flex-1">
                <div className="text-[12px] font-medium text-white">NVIDIA</div>
                <div className="text-[10.5px] text-white/45">Bypasses overlays &amp; display affinity</div>
              </div>
            </button>
            <button
              type="button"
              onClick={() => { dismiss(); onPick("gdi"); }}
              className="flex items-center gap-3 rounded-md border border-white/[0.06] bg-white/[0.015] px-3 py-2 text-left hover:border-white/15 hover:bg-white/[0.04]"
            >
              <Monitor className="h-3.5 w-3.5 shrink-0 text-sky-400" />
              <div className="min-w-0 flex-1">
                <div className="text-[12px] font-medium text-white">GDI</div>
                <div className="text-[10.5px] text-white/45">Universal, works anywhere</div>
              </div>
            </button>
          </div>
        </div>
      )}
    </AnimatedDialog>
  );
}
