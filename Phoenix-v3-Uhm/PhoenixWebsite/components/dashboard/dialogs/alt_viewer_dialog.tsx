"use client";

import { useEffect, useState } from "react";
import { Copy, ExternalLink, Users, X } from "lucide-react";
import { AnimatedDialog } from "@/components/ui/animated-dialog";
import type { Player } from "../types";

type Alt = {
  kind: "steam" | "discord";
  externalId: string;
  username: string | null;
  avatar: string | null;
  namesFetchedAt: string | null;
  firstSeen: string | null;
  lastSeen: string | null;
};

const NAME_TTL_MS = 24 * 60 * 60 * 1000;

function steamId64ToHex(id64: string): string {
  try { return BigInt(id64).toString(16); } catch { return ""; }
}

function discordCdnAvatar(id: string, hashOrUrl: string | null): string | undefined {
  if (!hashOrUrl) {
    try {
      const idx = Number(BigInt(id) % 6n);
      const raw = `https://cdn.discordapp.com/embed/avatars/${idx}.png`;
      return `/api/lookup/img?url=${encodeURIComponent(raw)}`;
    } catch { return undefined; }
  }
  if (hashOrUrl.startsWith("/") || hashOrUrl.startsWith("http")) return hashOrUrl;
  const raw = `https://cdn.discordapp.com/avatars/${id}/${hashOrUrl}.png?size=64`;
  return `/api/lookup/img?url=${encodeURIComponent(raw)}`;
}

function needsRefresh(alt: Alt): boolean {
  if (!alt.namesFetchedAt) return true;
  const t = Date.parse(alt.namesFetchedAt);
  if (!Number.isFinite(t)) return true;
  return Date.now() - t > NAME_TTL_MS;
}

export function AltViewerDialog({
  player,
  onClose,
  onCopy,
}: {
  player: Player | null;
  onClose: () => void;
  onCopy: (v: string) => void;
}) {
  const [state, setState] = useState<"loading" | "ready" | "error">("loading");
  const [error, setError] = useState<string | null>(null);
  const [alts, setAlts] = useState<Alt[]>([]);
  const [resolvingKeys, setResolvingKeys] = useState<Set<string>>(new Set());

  useEffect(() => {
    if (!player) return;
    let cancelled = false;
    setState("loading");
    setError(null);
    setAlts([]);
    setResolvingKeys(new Set());

    (async () => {
      try {
        const res = await fetch(`/api/players/alts?steam=${encodeURIComponent(player.steam)}`, {
          cache: "no-store",
        });
        const data = (await res.json().catch(() => null)) as
          | { ok: boolean; alts?: Alt[]; error?: string } | null;
        if (cancelled) return;
        if (!data?.ok) {
          setState("error");
          setError(data?.error ?? "Failed to load alt accounts");
          return;
        }
        const list = data.alts ?? [];
        setAlts(list);
        setState("ready");

        const stale = list.filter(needsRefresh);
        if (stale.length === 0) return;

        const keyOf = (a: Alt) => `${a.kind}:${a.externalId}`;
        setResolvingKeys(new Set(stale.map(keyOf)));

        const BATCH = 6;
        for (let i = 0; i < stale.length; i += BATCH) {
          const batch = stale.slice(i, i + BATCH);
          const results = await Promise.all(
            batch.map(async (a) => {
              try {
                const r = await fetch(`/api/players/alts/refresh`, {
                  method: "POST",
                  headers: { "content-type": "application/json" },
                  cache: "no-store",
                  body: JSON.stringify({
                    steam_hex: player.steam,
                    kind: a.kind,
                    external_id: a.externalId,
                  }),
                });
                const j = (await r.json().catch(() => null)) as
                  | { ok: boolean; username: string | null; avatar: string | null } | null;
                if (!j?.ok) return null;
                return {
                  key: keyOf(a),
                  externalId: a.externalId,
                  kind: a.kind,
                  username: j.username,
                  avatar: j.avatar,
                };
              } catch {
                return null;
              }
            }),
          );
          if (cancelled) return;

          setAlts((prev) => {
            const next = prev.slice();
            for (const r of results) {
              if (!r) continue;
              const ix = next.findIndex((x) => x.kind === r.kind && x.externalId === r.externalId);
              if (ix < 0) continue;
              const cur = next[ix];
              next[ix] = {
                ...cur,
                username: r.username ?? cur.username,
                avatar: r.avatar ?? cur.avatar,
                namesFetchedAt: new Date().toISOString(),
              };
            }
            return next;
          });
          setResolvingKeys((prev) => {
            const nxt = new Set(prev);
            for (const r of results) if (r) nxt.delete(r.key);
            return nxt;
          });
        }
      } catch (e) {
        if (cancelled) return;
        setState("error");
        setError((e as Error).message);
      }
    })();

    return () => { cancelled = true; };
  }, [player]);

  const steamAlts   = alts.filter((a) => a.kind === "steam");
  const discordAlts = alts.filter((a) => a.kind === "discord");

  return (
    <AnimatedDialog open={!!player} onClose={onClose} panelClassName="max-w-lg phx-dialog-in">
      {(dismiss) => player ? (
        <div className="flex max-h-[85vh] w-full flex-col overflow-hidden rounded-lg border border-white/[0.08] bg-[#111]">
          <div className="flex shrink-0 items-center justify-between border-b border-white/[0.06] px-4 py-3">
            <div className="flex items-center gap-2">
              <Users className="h-4 w-4 text-white/70" />
              <h2 className="text-[13px] font-medium text-white">Alt accounts</h2>
            </div>
            <button
              type="button"
              onClick={dismiss}
              className="text-white/45 hover:text-white"
              aria-label="Close"
            >
              <X className="h-4 w-4" />
            </button>
          </div>

          <div className="border-b border-white/[0.05] bg-white/[0.02] px-4 py-2">
            <div className="flex items-center gap-1.5">
              <span className="truncate font-mono text-[10.5px] text-white/50">{player.steam}</span>
              <button
                onClick={() => onCopy(player.steam)}
                className="text-white/25 hover:text-white/70"
                aria-label="Copy Steam HEX"
              >
                <Copy className="h-3 w-3" />
              </button>
            </div>
          </div>

          <div className="min-h-0 flex-1 overflow-y-auto p-4">
            {state === "loading" && (
              <p className="text-center text-[12px] text-white/45">Loading alt accounts…</p>
            )}

            {state === "error" && (
              <p className="text-center text-[12px] text-red-400/90">{error}</p>
            )}

            {state === "ready" && alts.length === 0 && (
              <p className="text-center text-[12px] text-white/45">
                No alt accounts recorded yet. They are collected the next time this player launches PhoenixAC.
              </p>
            )}

            {state === "ready" && alts.length > 0 && (
              <div className="space-y-3">
                <Group
                  title="Steam accounts"
                  count={steamAlts.length}
                  accent="text-sky-300/90"
                  empty="No Steam accounts detected."
                >
                  {steamAlts.map((a) => {
                    const hex = steamId64ToHex(a.externalId);
                    const key = `steam:${a.externalId}`;
                    const resolving = resolvingKeys.has(key) && !a.username && !a.avatar;
                    return (
                      <AltRow
                        key={key}
                        avatar={a.avatar ?? undefined}
                        name={a.username || (resolving ? "Resolving…" : hex)}
                        id={hex}
                        profileUrl={`https://steamcommunity.com/profiles/${a.externalId}`}
                        resolving={resolving}
                        onCopy={onCopy}
                      />
                    );
                  })}
                </Group>

                <Group
                  title="Discord accounts"
                  count={discordAlts.length}
                  accent="text-indigo-300/90"
                  empty="No Discord accounts detected."
                >
                  {discordAlts.map((a) => {
                    const key = `discord:${a.externalId}`;
                    const resolving = resolvingKeys.has(key) && !a.username;
                    const avatar = discordCdnAvatar(a.externalId, a.avatar);
                    return (
                      <AltRow
                        key={key}
                        avatar={avatar}
                        name={a.username || (resolving ? "Resolving…" : a.externalId)}
                        id={a.externalId}
                        resolving={resolving}
                        onCopy={onCopy}
                      />
                    );
                  })}
                </Group>
              </div>
            )}
          </div>

          <div className="flex shrink-0 justify-end border-t border-white/[0.06] px-4 py-3">
            <button
              onClick={dismiss}
              className="h-7 rounded-md bg-white/[0.08] px-3 text-[11.5px] font-medium text-white hover:bg-white/[0.14]"
            >
              Close
            </button>
          </div>
        </div>
      ) : null}
    </AnimatedDialog>
  );
}

function Group({
  title,
  count,
  accent,
  empty,
  children,
}: {
  title: string;
  count: number;
  accent: string;
  empty: string;
  children: React.ReactNode;
}) {
  return (
    <div className="overflow-hidden rounded-md border border-white/[0.06] bg-white/[0.015]">
      <div className="flex items-center justify-between border-b border-white/[0.05] bg-white/[0.02] px-3 py-2">
        <p className={`text-[11.5px] font-medium ${accent}`}>{title}</p>
        <span className="rounded border border-white/[0.10] bg-white/[0.03] px-1.5 py-[1px] text-[10px] font-medium text-white/70">
          {count}
        </span>
      </div>
      {count === 0 ? (
        <p className="px-3 py-3 text-[11.5px] text-white/40">{empty}</p>
      ) : (
        <div className="divide-y divide-white/[0.04]">{children}</div>
      )}
    </div>
  );
}

function AltRow({
  avatar,
  name,
  id,
  profileUrl,
  resolving,
  onCopy,
}: {
  avatar: string | undefined;
  name: string;
  id: string;
  profileUrl?: string;
  resolving?: boolean;
  onCopy: (v: string) => void;
}) {
  const initial = name.charAt(0).toUpperCase();
  return (
    <div className="flex items-center gap-3 px-3 py-2" title={id}>
      {avatar ? (
        <img src={avatar} alt="" className="h-7 w-7 shrink-0 rounded-full object-cover" />
      ) : resolving ? (
        <div className="h-7 w-7 shrink-0 animate-pulse rounded-full bg-white/[0.06]" />
      ) : (
        <div className="flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-white/[0.06]">
          <span className="text-[10px] font-semibold text-white/60">{initial}</span>
        </div>
      )}
      <div className="min-w-0 flex-1">
        <p className={`truncate text-[12.5px] font-medium ${resolving ? "text-white/40" : "text-white"}`}>
          {name}
        </p>
        <p className="truncate font-mono text-[10px] text-white/40">{id}</p>
      </div>
      <div className="flex shrink-0 items-center gap-1.5">
        {profileUrl && (
          <a
            href={profileUrl}
            target="_blank"
            rel="noreferrer noopener"
            className="text-white/30 hover:text-white/80"
            aria-label="Open profile"
            title="Open profile"
          >
            <ExternalLink className="h-3.5 w-3.5" />
          </a>
        )}
        <button
          onClick={() => onCopy(id)}
          className="text-white/30 hover:text-white/80"
          aria-label={`Copy ${id}`}
          title={`Copy ${id}`}
        >
          <Copy className="h-3.5 w-3.5" />
        </button>
      </div>
    </div>
  );
}
