import { Ban, Info, PauseCircle, WifiOff } from "lucide-react";
import type { Player } from "../types";

export function PlayerStatus({
  player,
  onInfo,
}: {
  player: Player;
  onInfo?: (p: Player) => void;
}) {
  if (player.banned) {
    return (
      <span className="inline-flex items-center gap-1.5 text-[11px] font-medium text-red-400/85">
        <Ban className="h-2.5 w-2.5" /> Banned
        {onInfo && <InfoBtn onClick={() => onInfo(player)} />}
      </span>
    );
  }
  if (player.suspended) {
    return (
      <span className="inline-flex items-center gap-1.5 text-[11px] font-medium text-amber-400/85">
        <PauseCircle className="h-2.5 w-2.5" /> Suspended
        {onInfo && <InfoBtn onClick={() => onInfo(player)} />}
      </span>
    );
  }
  if (player.online) {
    return (
      <span className="inline-flex items-center gap-1.5 text-[11px] font-medium text-emerald-400/90">
        <span className="relative flex h-1.5 w-1.5">
          <span className="absolute inset-0 rounded-full bg-emerald-400/60 blur-[3px]" />
          <span className="relative h-1.5 w-1.5 rounded-full bg-emerald-400" />
        </span>
        Online
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-1.5 text-[11px] font-medium text-white/45">
      <WifiOff className="h-2.5 w-2.5" /> Offline
    </span>
  );
}

function InfoBtn({ onClick }: { onClick: () => void }) {
  return (
    <button
      type="button"
      onClick={onClick}
      className="ml-0.5 inline-flex h-3.5 w-3.5 items-center justify-center rounded-full text-white/40 hover:bg-white/[0.08] hover:text-white"
      aria-label="View reason"
      title="View reason"
    >
      <Info className="h-2.5 w-2.5" />
    </button>
  );
}
