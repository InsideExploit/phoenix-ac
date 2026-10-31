"use client";

import { Copy, Trash } from "lucide-react";
import type { LookupResult, Pin } from "../types";
import { splitDateTime } from "../data";

export function PinRow({
  pin,
  creatorInfo,
  index,
  onCopy,
  onDelete,
}: {
  pin: Pin;
  creatorInfo: LookupResult;
  index: number;
  onCopy: (code: string) => void;
  onDelete: (code: string) => void;
}) {
  const state = pin.used
    ? { label: "Used",      textCls: "text-white/45",       dot: "bg-white/30" }
    : pin.expired
      ? { label: "Expired",   textCls: "text-amber-400/85",   dot: "bg-amber-400/70" }
      : { label: "Available", textCls: "text-emerald-400/85", dot: "bg-emerald-400" };

  const createdAt = splitDateTime(pin.createdAt);
  const expiresAt = splitDateTime(pin.expiresAt);

  return (
    <tr
      className="row-in border-b border-white/[0.04] transition-colors last:border-0 hover:bg-white/[0.02]"
      style={{ animationDelay: `${index * 28}ms` }}
    >
      <td className="px-4 py-3">
        <div className="flex items-center gap-1.5">
          <span className="font-mono text-[12.5px] font-semibold tracking-[0.06em] text-white">{pin.code}</span>
          <button
            onClick={() => onCopy(pin.code)}
            className="text-white/25 hover:text-white/70"
            aria-label="Copy PIN"
          >
            <Copy className="h-3 w-3" />
          </button>
        </div>
      </td>

      <td className="px-4 py-3">
        <span className={`inline-flex items-center gap-1.5 text-[11.5px] font-medium ${state.textCls}`}>
          <span className={`h-1.5 w-1.5 shrink-0 rounded-full ${state.dot}`} />
          {state.label}
        </span>
      </td>

      <td className="hidden px-4 py-3 md:table-cell">
        <div className="flex min-h-[24px] items-center gap-2">
          {creatorInfo.discordAvatar ? (
            <img src={creatorInfo.discordAvatar} alt="" className="h-6 w-6 shrink-0 rounded-full object-cover" />
          ) : (
            <div className="flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-white/[0.05]">
              <span className="text-[10px] font-semibold text-white/50">
                {(creatorInfo.discordName || pin.createdBy || "?").charAt(0).toUpperCase()}
              </span>
            </div>
          )}
          <div className="min-w-0">
            <p className="truncate text-[12px] font-medium text-white">
              {creatorInfo.discordName || pin.createdBy || "—"}
            </p>
            {creatorInfo.discordName && pin.createdBy && (
              <p className="truncate font-mono text-[10px] text-white/35">{pin.createdBy}</p>
            )}
          </div>
        </div>
      </td>

      <td className="hidden px-4 py-3 lg:table-cell">
        {createdAt ? (
          <div>
            <p className="text-[11.5px] text-white/85">{createdAt.date}</p>
            {createdAt.time && <p className="text-[10px] text-white/35">{createdAt.time}</p>}
          </div>
        ) : (
          <span className="text-[11.5px] text-white/30">—</span>
        )}
      </td>

      <td className="hidden px-4 py-3 xl:table-cell">
        {expiresAt ? (
          <div>
            <p className={`text-[11.5px] ${pin.expired ? "text-amber-400/85" : "text-white/85"}`}>
              {expiresAt.date}
            </p>
            {expiresAt.time && <p className="text-[10px] text-white/35">{expiresAt.time}</p>}
          </div>
        ) : (
          <span className="text-[11.5px] text-white/30">—</span>
        )}
      </td>

      <td className="px-4 py-3 text-right">
        <button
          onClick={() => onDelete(pin.code)}
          disabled={pin.used}
          className="inline-flex h-6 w-6 items-center justify-center rounded-md text-white/40 hover:bg-red-400/[0.08] hover:text-red-400 disabled:pointer-events-none disabled:opacity-25"
          aria-label="Delete PIN"
        >
          <Trash className="h-3.5 w-3.5" />
        </button>
      </td>
    </tr>
  );
}
