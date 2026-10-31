"use client";

import { useEffect, useState } from "react";
import { Ban, Eye, EyeOff, X } from "lucide-react";
import { AnimatedDialog } from "@/components/ui/animated-dialog";
import { BAN_CATEGORIES, type BanCategoryValue, type Player } from "../types";

export function BanDialog({
  target,
  mode = "create",
  busy,
  onClose,
  onSubmit,
}: {
  target: Player | null;
  mode?: "create" | "edit";
  busy: boolean;
  onClose: () => void;
  onSubmit: (opts: { category: BanCategoryValue; reason: string; reasonPublic: boolean }) => void;
}) {
  const [category, setCategory] = useState<BanCategoryValue>("cheating");
  const [reason, setReason] = useState("");
  const [reasonPublic, setReasonPublic] = useState(false);

  useEffect(() => {
    if (!target) return;
    if (mode === "edit") {
      const validCats: BanCategoryValue[] = ["cheating", "bug-abuse", "toxicity", "alt-account"];
      const initCat = validCats.includes(target.banCategory as BanCategoryValue)
        ? (target.banCategory as BanCategoryValue)
        : "cheating";
      setCategory(initCat);
      setReason(target.banReason ?? "");
      setReasonPublic(target.banReasonPublic);
    } else {
      setCategory("cheating");
      setReason("");
      setReasonPublic(false);
    }
  }, [target, mode]);

  return (
    <AnimatedDialog open={!!target} onClose={() => !busy && onClose()} panelClassName="max-w-md phx-dialog-in">
      {(dismiss) => target ? (
        <form
          onSubmit={(e) => {
            e.preventDefault();
            if (busy || reason.trim().length === 0) return;
            onSubmit({ category, reason: reason.trim(), reasonPublic });
          }}
          className="w-full rounded-lg border border-white/[0.08] bg-[#111] p-5"
        >
          <div className="mb-4 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Ban className="h-3.5 w-3.5 text-red-400/85" />
              <h2 className="text-[14px] font-medium text-white">
                {mode === "edit" ? "Edit ban" : "Ban player"}
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

          <p className="mb-4 truncate font-mono text-[11px] text-white/45">{target.steam}</p>

          <label className="mb-4 block">
            <span className="mb-1.5 block text-[10.5px] font-medium uppercase tracking-wider text-white/40">Category</span>
            <div className="grid grid-cols-2 gap-1.5">
              {BAN_CATEGORIES.map((c) => {
                const active = category === c.value;
                return (
                  <button
                    key={c.value}
                    type="button"
                    disabled={busy}
                    onClick={() => setCategory(c.value)}
                    className={
                      "rounded-md border px-2.5 py-1.5 text-left text-[12px] transition-colors " +
                      (active
                        ? "border-red-400/50 bg-red-400/[0.06] text-white"
                        : "border-white/[0.08] bg-white/[0.015] text-white/65 hover:border-white/15 hover:text-white/90")
                    }
                  >
                    {c.label}
                  </button>
                );
              })}
            </div>
          </label>

          <label className="mb-4 block">
            <span className="mb-1.5 block text-[10.5px] font-medium uppercase tracking-wider text-white/40">
              Reason (required)
            </span>
            <textarea
              autoFocus
              rows={3}
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              placeholder="Detailed reason, evidence, links…"
              maxLength={255}
              disabled={busy}
              className="w-full resize-none rounded-md border border-white/[0.08] bg-black/40 px-3 py-2 text-[12.5px] leading-relaxed text-white placeholder:text-white/25 focus:border-white/20 focus:outline-none disabled:opacity-50"
            />
          </label>

          <button
            type="button"
            disabled={busy}
            onClick={() => setReasonPublic((v) => !v)}
            className={
              "mb-4 flex w-full items-start gap-2.5 rounded-md border px-3 py-2.5 text-left transition-colors " +
              (reasonPublic
                ? "border-sky-400/40 bg-sky-400/[0.05]"
                : "border-white/[0.08] bg-white/[0.02] hover:border-white/15")
            }
          >
            <div className="mt-0.5 shrink-0">
              {reasonPublic
                ? <Eye    className="h-3.5 w-3.5 text-sky-400" />
                : <EyeOff className="h-3.5 w-3.5 text-white/40" />}
            </div>
            <div className="flex-1">
              <div className="text-[12px] font-medium text-white">
                {reasonPublic ? "Show detailed reason to player" : "Show category only to player"}
              </div>
              <div className="mt-0.5 text-[10.5px] leading-snug text-white/45">
                {reasonPublic
                  ? "The player will see your exact reason in the kick dialog."
                  : "The player will only see the category label (e.g. “Cheating”)."}
              </div>
            </div>
          </button>

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
              disabled={busy || reason.trim().length === 0}
              className="h-8 rounded-md bg-red-500/85 px-3 text-[12px] font-medium text-white hover:bg-red-500 disabled:opacity-40"
            >
              {busy ? "Please wait…" : mode === "edit" ? "Save" : "Ban"}
            </button>
          </div>
        </form>
      ) : null}
    </AnimatedDialog>
  );
}
