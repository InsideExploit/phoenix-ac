import { X } from 'lucide-react';

import { AnimatedDialog } from '@/components/ui/animated-dialog';

export function AddPlayerDialog({
  open,
  form,
  setForm,
  busy,
  onClose,
  onSubmit,
}: {
  open: boolean;
  form: {
    steam: string;
    discord: string;
  };
  setForm: (v: { steam: string; discord: string }) => void;
  busy: boolean;
  onClose: () => void;
  onSubmit: () => void;
}) {
  return (
    <AnimatedDialog
      open={open}
      onClose={() => !busy && onClose()}
      panelClassName="max-w-md phx-dialog-in"
    >
      {(dismiss) => (
        <form
          onSubmit={(e) => {
            e.preventDefault();
            if (!form.steam.trim()) return;
            onSubmit();
          }}
          className="w-full rounded-lg border border-white/[0.08] bg-[#111] p-5"
        >
          <div className="mb-4 flex items-center justify-between">
            <h2 className="text-[14px] font-medium text-white">Add player</h2>
            <button
              type="button"
              onClick={dismiss}
              className="text-white/45 hover:text-white"
              aria-label="Close"
            >
              <X className="h-4 w-4" />
            </button>
          </div>

          <div className="space-y-3.5">
            <Field label="Steam HEX">
              <input
                autoFocus
                value={form.steam}
                onChange={(e) => setForm({ ...form, steam: e.target.value })}
                placeholder="Steam hex"
                className="h-9 w-full rounded-md border border-white/[0.08] bg-black/40 px-2.5 text-[12.5px] text-white placeholder:text-white/25 focus:border-white/20 focus:outline-none"
              />
            </Field>
            <Field label="Discord ID (optional)">
              <input
                value={form.discord}
                onChange={(e) => setForm({ ...form, discord: e.target.value })}
                placeholder="Discord user ID"
                className="h-9 w-full rounded-md border border-white/[0.08] bg-black/40 px-2.5 text-[12.5px] text-white placeholder:text-white/25 focus:border-white/20 focus:outline-none"
              />
            </Field>
            <p className="text-[11px] leading-relaxed text-white/45">
              Online/offline is derived from the launcher heartbeat automatically.
            </p>
          </div>

          <div className="mt-5 flex justify-end gap-2">
            <button
              type="button"
              onClick={dismiss}
              className="h-8 rounded-md px-3 text-[12px] text-white/70 hover:bg-white/[0.04] hover:text-white"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={busy || !form.steam.trim()}
              className="h-8 rounded-md bg-white px-3 text-[12px] font-medium text-black hover:bg-white/90 disabled:opacity-40"
            >
              {busy ? 'Saving…' : 'Save'}
            </button>
          </div>
        </form>
      )}
    </AnimatedDialog>
  );
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <label className="block">
      <span className="mb-1.5 block text-[10.5px] font-medium uppercase tracking-wider text-white/40">
        {label}
      </span>
      {children}
    </label>
  );
}
