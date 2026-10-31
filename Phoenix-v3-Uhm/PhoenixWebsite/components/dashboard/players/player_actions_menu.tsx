"use client";

import { useEffect, useLayoutEffect, useRef, useState } from "react";
import {
  Ban, Camera, Fingerprint, History, Info, Pencil, PauseCircle, PlayCircle, Trash, UserX, Users, Wrench,
} from "lucide-react";
import type { MenuState, Player } from "../types";

export function PlayerActionsMenu({
  menu,
  onClose,
  onEdit,
  onScreenshot,
  onKick,
  onToggleSuspend,
  onToggleBan,
  onDelete,
  onDetectionHistory,
  onResetHwid,
  onSystemInfo,
  onTools,
  onAltAccounts,
}: {
  menu: MenuState;
  onClose: () => void;
  onEdit: (p: Player) => void;
  onScreenshot: (p: Player) => void;
  onKick: (p: Player) => void;
  onToggleSuspend: (p: Player) => void;
  onToggleBan: (p: Player) => void;
  onDelete: (p: Player) => void;
  onDetectionHistory: (p: Player) => void;
  onResetHwid: (p: Player) => void;
  onSystemInfo: (p: Player) => void;
  onTools: (p: Player) => void;
  onAltAccounts: (p: Player) => void;
}) {
  const rootRef = useRef<HTMLDivElement | null>(null);
  const [top, setTop] = useState<number | null>(null);

  useLayoutEffect(() => {
    if (!menu) { setTop(null); return; }
    const el = rootRef.current;
    if (!el) { setTop(menu.top); return; }
    const h = el.offsetHeight;
    const margin = 8;
    const vh = window.innerHeight;
    const anchorGap = 4;
    const anchorTop = menu.top - anchorGap;
    let next = menu.top;
    if (menu.top + h + margin > vh) {
      next = Math.max(margin, anchorTop - h);
    }
    setTop(next);
  }, [menu]);

  useEffect(() => {
    if (!menu) return;
    const anchorId = menu.player.steam;
    const handler = (e: MouseEvent) => {
      if (rootRef.current && rootRef.current.contains(e.target as Node)) return;
      const anchor = (e.target as HTMLElement | null)?.closest?.("[data-menu-anchor]") as HTMLElement | null;
      if (anchor && anchor.dataset.menuAnchor === anchorId) return;
      onClose();
    };
    const kbd = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    document.addEventListener("mousedown", handler);
    document.addEventListener("keydown", kbd);
    return () => {
      document.removeEventListener("mousedown", handler);
      document.removeEventListener("keydown", kbd);
    };
  }, [menu, onClose]);

  if (!menu) return null;

  const run = (fn: () => void) => { onClose(); fn(); };
  const p = menu.player;

  const item =
    "flex w-full items-center gap-2 rounded px-2 py-[5px] text-left text-[11.5px] leading-tight transition-colors duration-100";
  const groupLabel =
    "px-2 pt-1.5 pb-0.5 text-[9.5px] font-semibold uppercase tracking-wider text-white/30";

  const showLive = p.online && !p.banned;

  return (
    <div
      ref={rootRef}
      style={{ top: top ?? menu.top, right: menu.right, visibility: top === null ? "hidden" : "visible" }}
      className="phx-menu-in fixed z-[60] w-[176px] rounded-md border border-white/[0.08] bg-[#111] p-1 shadow-2xl shadow-black/60"
    >
      <p className={groupLabel}>Manage</p>
      <button className={`${item} text-white/85 hover:bg-white/[0.05] hover:text-white`} onClick={() => run(() => onEdit(p))}>
        <Pencil className="h-3 w-3" /> Edit
      </button>
      <button className={`${item} text-white/85 hover:bg-white/[0.05] hover:text-white`} onClick={() => run(() => onDetectionHistory(p))}>
        <History className="h-3 w-3" /> Detection history
      </button>
      <button className={`${item} text-white/85 hover:bg-white/[0.05] hover:text-white`} onClick={() => run(() => onAltAccounts(p))}>
        <Users className="h-3 w-3" /> Alt accounts
      </button>

      {showLive && (
        <>
          <div className="my-1 h-px bg-white/[0.05]" />
          <p className={groupLabel}>Live</p>
          <button className={`${item} text-white/85 hover:bg-white/[0.05] hover:text-white`} onClick={() => run(() => onSystemInfo(p))}>
            <Info className="h-3 w-3" /> System info
          </button>
          <button className={`${item} text-white/85 hover:bg-white/[0.05] hover:text-white`} onClick={() => run(() => onTools(p))}>
            <Wrench className="h-3 w-3" /> Tools
          </button>
          {!p.suspended && (
            <button className={`${item} text-white/85 hover:bg-white/[0.05] hover:text-white`} onClick={() => run(() => onScreenshot(p))}>
              <Camera className="h-3 w-3" /> Screenshot
            </button>
          )}
          <button className={`${item} text-amber-400/85 hover:bg-amber-400/[0.08] hover:text-amber-400`} onClick={() => run(() => onKick(p))}>
            <UserX className="h-3 w-3" /> Kick
          </button>
        </>
      )}

      <div className="my-1 h-px bg-white/[0.05]" />
      <p className={groupLabel}>Enforcement</p>
      <button className={`${item} text-white/85 hover:bg-white/[0.05] hover:text-white`} onClick={() => run(() => onToggleSuspend(p))}>
        {p.suspended ? <PlayCircle className="h-3 w-3" /> : <PauseCircle className="h-3 w-3" />}
        {p.suspended ? "Resume AC" : "Suspend AC"}
      </button>
      <button className={`${item} text-white/85 hover:bg-white/[0.05] hover:text-white`} onClick={() => run(() => onResetHwid(p))}>
        <Fingerprint className="h-3 w-3" /> Reset hardware ID
      </button>
      <button className={`${item} text-red-400/85 hover:bg-red-400/[0.08] hover:text-red-400`} onClick={() => run(() => onToggleBan(p))}>
        <Ban className="h-3 w-3" /> {p.banned ? "Unban" : "Ban"}
      </button>

      <div className="my-1 h-px bg-white/[0.05]" />
      <p className={groupLabel}>Danger</p>
      <button className={`${item} text-red-400/85 hover:bg-red-400/[0.08] hover:text-red-400`} onClick={() => run(() => onDelete(p))}>
        <Trash className="h-3 w-3" /> Delete player
      </button>
    </div>
  );
}
