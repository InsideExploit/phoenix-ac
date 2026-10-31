import { tryDecryptDash } from "@/lib/crypto/crypto_client";
import type { LookupResult, Player } from "./types";

export const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));
export const MIN_LOAD = 1400;

export async function fetchPlayersDecrypted(url: string): Promise<{
  ok: boolean;
  players?: Player[];
  total?: number;
} | null> {
  const res = await fetch(url, { cache: "no-store" });
  if (!res.ok) return null;
  const encHeader = res.headers.get("X-Phoenix-Enc");
  if (encHeader === "dash") {
    const b64 = await res.text();
    const plain = await tryDecryptDash(b64);
    if (!plain) return null;
    try { return JSON.parse(plain); } catch { return null; }
  }
  try { return await res.json(); } catch { return null; }
}

export async function decryptSealed<T>(keyB64: string, sealed: string): Promise<T> {
  const b2u = (s: string) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
  const keyBytes = b2u(keyB64);
  const raw = b2u(sealed);
  const iv = raw.slice(1, 13);
  const body = raw.slice(13);
  const key = await crypto.subtle.importKey("raw", keyBytes, "AES-GCM", false, ["decrypt"]);
  const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, body);
  return JSON.parse(new TextDecoder().decode(pt)) as T;
}

export function playersEqual(a: Player[], b: Player[]): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    const x = a[i];
    const y = b[i];
    if (
      x.steam !== y.steam ||
      x.discord !== y.discord ||
      x.banned !== y.banned ||
      x.suspended !== y.suspended ||
      x.online !== y.online ||
      x.lastSeen !== y.lastSeen ||
      x.banReason !== y.banReason ||
      x.banCategory !== y.banCategory ||
      x.banReasonPublic !== y.banReasonPublic ||
      x.suspendReason !== y.suspendReason ||
      x.hardwareId !== y.hardwareId
    ) return false;
  }
  return true;
}

const clientLookupCache = new Map<string, { data: LookupResult; ts: number }>();
const CLIENT_CACHE_TTL = 5 * 60 * 1000;

export async function fetchLookup(steam?: string, discord?: string): Promise<LookupResult> {
  const key = `${steam ?? ""}|${discord ?? ""}`;
  const hit = clientLookupCache.get(key);
  if (hit && Date.now() - hit.ts < CLIENT_CACHE_TTL) return hit.data;
  try {
    const params = new URLSearchParams();
    if (steam) params.set("steam", steam);
    if (discord) params.set("discord", discord);
    const res = await fetch(`/api/lookup?${params.toString()}`);
    if (!res.ok) return {};
    const data: LookupResult = await res.json();
    clientLookupCache.set(key, { data, ts: Date.now() });
    return data;
  } catch { return {}; }
}

export async function prefetchPlayerLookups(players: Player[]): Promise<Record<string, LookupResult>> {
  const keys = new Map<string, { steam?: string; discord?: string }>();
  const addDiscord = (id: string | null | undefined) => {
    if (!id) return;
    const k = `|${id}`;
    if (!keys.has(k)) keys.set(k, { discord: id });
  };
  for (const p of players) {
    const key = `${p.steam}|${p.discord}`;
    if (!keys.has(key)) keys.set(key, { steam: p.steam || undefined, discord: p.discord || undefined });
    addDiscord(p.addedBy);
    addDiscord(p.lastEditBy);
    addDiscord(p.bannedBy);
    addDiscord(p.suspendedBy);
  }

  const out: Record<string, LookupResult> = {};
  const pending: { key: string; steam?: string; discord?: string }[] = [];

  for (const [key, ids] of keys) {
    const hit = clientLookupCache.get(key);
    if (hit && Date.now() - hit.ts < CLIENT_CACHE_TTL) out[key] = hit.data;
    else pending.push({ key, ...ids });
  }

  const BATCH = 10;
  for (let i = 0; i < pending.length; i += BATCH) {
    const batch = pending.slice(i, i + BATCH);
    const results = await Promise.all(
      batch.map(async ({ key, steam, discord }) => {
        const data = await fetchLookup(steam, discord);
        return [key, data] as const;
      }),
    );
    for (const [key, data] of results) out[key] = data;
  }
  return out;
}

export function mergeLookups(
  prev: Record<string, LookupResult>,
  next: Record<string, LookupResult>,
): Record<string, LookupResult> {
  if (Object.keys(next).length === 0) return prev;
  let changed = false;
  const merged = { ...prev };
  for (const [k, v] of Object.entries(next)) {
    const e = prev[k];
    if (e &&
        e.steamName    === v.steamName    &&
        e.steamAvatar  === v.steamAvatar  &&
        e.discordName  === v.discordName  &&
        e.discordAvatar=== v.discordAvatar) continue;
    merged[k] = v;
    changed = true;
  }
  return changed ? merged : prev;
}

export function splitDateTime(raw: string | null): { date: string; time: string } | null {
  if (!raw) return null;
  const parts = raw.trim().split(" ");
  if (parts.length >= 2) return { date: parts[0], time: parts[1] };
  return { date: raw, time: "" };
}
