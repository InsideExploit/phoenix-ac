"use client";

import Image from "next/image";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  UsersRound,
  X,
  Menu,
  Search,
  UserPlus,
  Ticket,
  WifiOff,
  Wifi,
  Ban,
  Ellipsis,
  LogOut,
  Trash,
  Copy,
  TrendingUp,
  ScanFace,
  RefreshCw,
  ChevronLeft,
  ChevronRight,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";
import { tryDecryptDash } from "@/lib/crypto/crypto_client";

const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));
const MIN_LOAD = 700;

async function fetchPlayersDecrypted(url: string): Promise<{
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
    try {
      return JSON.parse(plain);
    } catch {
      return null;
    }
  }
  try {
    return await res.json();
  } catch {
    return null;
  }
}

type Player = {
  steam: string;
  discord: string;
  banned: boolean;
  online: boolean;
  lastSeen: string | null;
};
type View = "players" | "pins" | "stats" | "evasion";
type Pin = {
  code: string;
  used: boolean;
  createdBy: string;
  createdAt: string;
  expiresAt: string | null;
  expired: boolean;
};
type StatRow = {
  steamHex: string;
  discordId: string | null;
  license: string | null;
  token: string | null;
  name: string | null;
  kills: number;
  deaths: number;
  kd: number;
  currentStreak: number;
  maxStreak: number;
  lastSeen: string | null;
};
type EvasionFlag = {
  id: number;
  primaryHex: string;
  secondaryHex: string;
  fpType: string;
  fpValue: string;
  primaryName: string | null;
  secondaryName: string | null;
  clientIp: string | null;
  createdAt: string;
};

const FILTERS = ["Tutti", "Online", "Offline", "Bannati"] as const;
type Filter = (typeof FILTERS)[number];

const STATUS_MATCH: Record<Filter, (p: Player) => boolean> = {
  Tutti: () => true,
  Online: (p) => p.online && !p.banned,
  Offline: (p) => !p.online && !p.banned,
  Bannati: (p) => p.banned,
};

async function decryptSealed<T>(keyB64: string, sealed: string): Promise<T> {
  const b2u = (s: string) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
  const keyBytes = b2u(keyB64);
  const raw = b2u(sealed);
  const iv = raw.slice(1, 13);
  const body = raw.slice(13);
  const key = await crypto.subtle.importKey("raw", keyBytes, "AES-GCM", false, ["decrypt"]);
  const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, body);
  return JSON.parse(new TextDecoder().decode(pt)) as T;
}

type MenuState = { player: Player; top: number; right: number } | null;

const PAGE_SIZE = 15;
const SKEL_W = [72, 55, 85, 48, 68, 40, 78, 60, 52];

type LookupResult = {
  steamName?: string;
  steamAvatar?: string;
  discordName?: string;
  discordAvatar?: string;
};

const clientLookupCache = new Map<string, { data: LookupResult; ts: number }>();
const CLIENT_CACHE_TTL = 5 * 60 * 1000;

async function fetchLookup(steam?: string, discord?: string): Promise<LookupResult> {
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
  } catch {
    return {};
  }
}

function SkeletonRows({ cols, rows = 7 }: { cols: number; rows?: number }) {
  return (
    <>
      {Array.from({ length: rows }).map((_, i) => (
        <tr key={i} className="border-b border-border last:border-0">
          {Array.from({ length: cols }).map((_, j) => (
            <td key={j} className="px-5 py-[14px]">
              <div
                className="h-3.5 animate-pulse rounded-md bg-muted"
                style={{ width: `${SKEL_W[(i * cols + j) % SKEL_W.length]}%` }}
              />
            </td>
          ))}
        </tr>
      ))}
    </>
  );
}

function TablePagination({
  total,
  page,
  setPage,
}: {
  total: number;
  page: number;
  setPage: (p: number) => void;
}) {
  const totalPages = Math.ceil(total / PAGE_SIZE);
  if (totalPages <= 1) return null;

  const pages: (number | "…")[] = [];
  if (totalPages <= 7) {
    for (let i = 0; i < totalPages; i++) pages.push(i);
  } else {
    pages.push(0);
    if (page > 2) pages.push("…");
    for (let i = Math.max(1, page - 1); i <= Math.min(totalPages - 2, page + 1); i++) pages.push(i);
    if (page < totalPages - 3) pages.push("…");
    pages.push(totalPages - 1);
  }

  return (
    <div className="flex items-center justify-between border-t border-border px-5 py-3">
      <span className="text-[12px] text-muted-foreground">
        {page * PAGE_SIZE + 1}–{Math.min((page + 1) * PAGE_SIZE, total)} di {total}
      </span>
      <div className="flex items-center gap-1">
        <Button
          variant="ghost"
          size="sm"
          onClick={() => setPage(page - 1)}
          disabled={page === 0}
          className="h-7 w-7 p-0"
        >
          <ChevronLeft className="h-3.5 w-3.5" />
        </Button>
        {pages.map((p, i) =>
          p === "…" ? (
            <span key={`ellipsis-${i}`} className="px-1 text-[12px] text-muted-foreground">…</span>
          ) : (
            <Button
              key={p}
              variant={p === page ? "secondary" : "ghost"}
              size="sm"
              onClick={() => setPage(p as number)}
              className="h-7 w-7 p-0 text-[12px]"
            >
              {(p as number) + 1}
            </Button>
          ),
        )}
        <Button
          variant="ghost"
          size="sm"
          onClick={() => setPage(page + 1)}
          disabled={page >= totalPages - 1}
          className="h-7 w-7 p-0"
        >
          <ChevronRight className="h-3.5 w-3.5" />
        </Button>
      </div>
    </div>
  );
}

function ConfirmDialog({
  title,
  description,
  confirmLabel = "Conferma",
  destructive = false,
  onConfirm,
  onCancel,
}: {
  title: string;
  description: string;
  confirmLabel?: string;
  destructive?: boolean;
  onConfirm: () => void;
  onCancel: () => void;
}) {
  return (
    <div
      className="dialog-overlay fixed inset-0 z-[70] flex items-center justify-center bg-black/70 p-4 backdrop-blur-sm"
      onClick={onCancel}
    >
      <div
        onClick={(e) => e.stopPropagation()}
        className="dialog-content w-full max-w-sm rounded-2xl border border-border bg-card p-6 shadow-2xl shadow-black/60"
      >
        <h2 className="text-[16px] font-semibold text-foreground">{title}</h2>
        <p className="mt-2.5 text-[13px] leading-relaxed text-muted-foreground">{description}</p>
        <div className="mt-7 flex justify-end gap-2.5">
          <Button type="button" variant="ghost" className="h-9 px-4 text-[13px]" onClick={onCancel}>
            Annulla
          </Button>
          <Button
            type="button"
            className={`h-9 px-4 text-[13px] ${destructive ? "bg-red-500/90 hover:bg-red-500 text-white" : ""}`}
            onClick={onConfirm}
          >
            {confirmLabel}
          </Button>
        </div>
      </div>
    </div>
  );
}

const NAV_ITEMS: { view: View; icon: React.ElementType; label: string }[] = [
  { view: "players", icon: UsersRound, label: "Players" },
  { view: "pins", icon: Ticket, label: "Codici" },
  { view: "stats", icon: TrendingUp, label: "Statistiche" },
  { view: "evasion", icon: ScanFace, label: "Ban Evading" },
];

export default function DashboardClient({
  name,
  username,
  avatar,
  players: initialPlayers,
  apiKey,
}: {
  name: string;
  username: string;
  avatar: string;
  players: Player[];
  apiKey: string;
}) {
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [view, setView] = useState<View>("players");
  const [fading, setFading] = useState(false);
  const [query, setQuery] = useState("");
  const [filter, setFilter] = useState<Filter>("Tutti");

  const [players, setPlayers] = useState<Player[]>(initialPlayers);

  const [pins, setPins] = useState<Pin[]>([]);
  const [pinsLoading, setPinsLoading] = useState(false);

  const [stats, setStats] = useState<StatRow[]>([]);
  const [statsLoading, setStatsLoading] = useState(false);
  const [statsQuery, setStatsQuery] = useState("");

  const [evasion, setEvasion] = useState<EvasionFlag[]>([]);
  const [evasionLoading, setEvasionLoading] = useState(false);
  const [evasionQuery, setEvasionQuery] = useState("");

  const [playersPage, setPlayersPage] = useState(0);
  const [pinsPage, setPinsPage] = useState(0);
  const [statsPage, setStatsPage] = useState(0);
  const [evasionPage, setEvasionPage] = useState(0);
  const [dataKey, setDataKey] = useState(0);
  const bumpKey = () => setDataKey((k) => k + 1);

  const [busy, setBusy] = useState(false);
  const [toast, setToast] = useState<string | null>(null);
  const [showAdd, setShowAdd] = useState(false);
  const [form, setForm] = useState<{ steam: string; discord: string }>({ steam: "", discord: "" });
  const [pin, setPin] = useState<string | null>(null);
  const [menu, setMenu] = useState<MenuState>(null);
  const [confirm, setConfirm] = useState<{
    title: string;
    description: string;
    confirmLabel?: string;
    destructive?: boolean;
    onConfirm: () => void;
  } | null>(null);
  const toastTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  const flash = (msg: string) => {
    setToast(msg);
    if (toastTimer.current) clearTimeout(toastTimer.current);
    toastTimer.current = setTimeout(() => setToast(null), 2800);
  };

  const filtered = useMemo(() => {
    setPlayersPage(0);
    const q = query.trim().toLowerCase();
    return players.filter(
      (p) =>
        STATUS_MATCH[filter](p) &&
        (q === "" || p.steam.toLowerCase().includes(q) || p.discord.toLowerCase().includes(q)),
    );
  }, [players, query, filter]);

  const filteredPage = filtered.slice(playersPage * PAGE_SIZE, (playersPage + 1) * PAGE_SIZE);
  const pinsPage_ = pins.slice(pinsPage * PAGE_SIZE, (pinsPage + 1) * PAGE_SIZE);
  const statsPage_ = stats.slice(statsPage * PAGE_SIZE, (statsPage + 1) * PAGE_SIZE);
  const evasionPage_ = evasion.slice(evasionPage * PAGE_SIZE, (evasionPage + 1) * PAGE_SIZE);

  const onlineCount = players.filter((p) => p.online && !p.banned).length;
  const filterIndex = FILTERS.indexOf(filter);

  async function callApi(method: string, body: Record<string, unknown>) {
    setBusy(true);
    try {
      const res = await fetch("/api/players", {
        method,
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok || data.ok === false) {
        flash(data.error || "Operazione fallita");
        return false;
      }
      try {
        const j = await fetchPlayersDecrypted("/api/players");
        if (j && j.ok && Array.isArray(j.players)) setPlayers(j.players);
      } catch {}
      return true;
    } catch {
      flash("Errore di rete");
      return false;
    } finally {
      setBusy(false);
    }
  }

  async function submitAdd(e: React.FormEvent) {
    e.preventDefault();
    if (!form.steam.trim()) return;
    const ok = await callApi("POST", { steam_hex: form.steam, discord_id: form.discord });
    if (ok) {
      setShowAdd(false);
      setForm({ steam: "", discord: "" });
      flash("Giocatore aggiunto");
    }
  }

  async function _generatePin() {
    setBusy(true);
    try {
      const res = await fetch("/api/pins", { method: "POST" });
      const data = await res.json().catch(() => ({}));
      if (res.ok && data.ok) {
        setPin(data.code);
        loadPins();
      } else flash(data.error || "Errore nella generazione del PIN");
    } catch {
      flash("Errore di rete");
    } finally {
      setBusy(false);
    }
  }

  const generatePin = () => {
    setConfirm({
      title: "Genera PIN",
      description: "Verrà generato un nuovo PIN valido 24 ore. Vuoi continuare?",
      confirmLabel: "Genera",
      destructive: false,
      onConfirm: () => { setConfirm(null); _generatePin(); },
    });
  };

  async function loadPins() {
    setPinsLoading(true);
    try {
      const [res] = await Promise.all([fetch("/api/pins"), sleep(MIN_LOAD)]);
      if (!res.ok) {
        const data = await res.json().catch(() => ({}));
        flash(data.error || "Errore nel caricamento dei PIN");
        return;
      }
      const sealed = (await res.text()).trim();
      const payload = await decryptSealed<{ pins: Pin[] }>(apiKey, sealed);
      setPins(payload.pins ?? []);
      setPinsPage(0);
      bumpKey();
    } catch {
      flash("Errore di rete");
    } finally {
      setPinsLoading(false);
    }
  }

  async function _deletePinRow(code: string) {
    setBusy(true);
    try {
      const res = await fetch("/api/pins", {
        method: "DELETE",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ code }),
      });
      const data = await res.json().catch(() => ({}));
      if (res.ok && data.ok) {
        setPins((prev) => prev.filter((p) => p.code !== code));
        flash("PIN eliminato");
      } else flash(data.error || "Operazione fallita");
    } catch {
      flash("Errore di rete");
    } finally {
      setBusy(false);
    }
  }

  const deletePinRow = useCallback((code: string) => {
    setConfirm({
      title: "Elimina PIN",
      description: `Vuoi eliminare il PIN ${code}? L'azione non è reversibile.`,
      confirmLabel: "Elimina",
      destructive: true,
      onConfirm: () => { setConfirm(null); _deletePinRow(code); },
    });
  }, []);

  const copyPin = (code: string) => {
    navigator.clipboard?.writeText(code);
    flash("PIN copiato");
  };

  async function loadStats(q?: string) {
    setStatsLoading(true);
    try {
      const url = "/api/stats" + (q && q.trim() ? "?q=" + encodeURIComponent(q.trim()) : "");
      const [payload] = await Promise.all([
        fetchPlayersDecrypted(url) as Promise<{ ok: boolean; stats?: StatRow[] } | null>,
        sleep(MIN_LOAD),
      ]);
      if (!payload || !payload.ok) { flash("Errore nel caricamento statistiche"); return; }
      setStats(payload.stats ?? []);
      setStatsPage(0);
      bumpKey();
    } catch {
      flash("Errore di rete");
    } finally {
      setStatsLoading(false);
    }
  }

  async function loadEvasion(q?: string) {
    setEvasionLoading(true);
    try {
      const url = "/api/evasion-flags" + (q && q.trim() ? "?q=" + encodeURIComponent(q.trim()) : "");
      const [payload] = await Promise.all([
        fetchPlayersDecrypted(url) as Promise<{ ok: boolean; flags?: EvasionFlag[] } | null>,
        sleep(MIN_LOAD),
      ]);
      if (!payload || !payload.ok) { flash("Errore nel caricamento ban evasion"); return; }
      setEvasion(payload.flags ?? []);
      setEvasionPage(0);
      bumpKey();
    } catch {
      flash("Errore di rete");
    } finally {
      setEvasionLoading(false);
    }
  }

  const goView = (v: View) => {
    if (v === view) { setSidebarOpen(false); return; }
    setSidebarOpen(false);
    setFading(true);
    setTimeout(() => {
      setView(v);
      setFading(false);
      if (v === "pins") loadPins();
      if (v === "stats") loadStats(statsQuery);
      if (v === "evasion") loadEvasion(evasionQuery);
    }, 160);
  };

  const toggleBan = useCallback((p: Player) => {
    setConfirm({
      title: p.banned ? "Rimuovi ban" : "Banna giocatore",
      description: p.banned
        ? `Vuoi rimuovere il ban per ${p.steam}?`
        : `Vuoi bannare ${p.steam}? Verrà bloccato immediatamente.`,
      confirmLabel: p.banned ? "Rimuovi ban" : "Banna",
      destructive: !p.banned,
      onConfirm: () => { setConfirm(null); callApi("PATCH", { steam_hex: p.steam, banned: !p.banned }); },
    });
  }, []);

  const remove = useCallback((steam: string) => {
    setConfirm({
      title: "Elimina giocatore",
      description: `Vuoi eliminare definitivamente ${steam} dal database?`,
      confirmLabel: "Elimina",
      destructive: true,
      onConfirm: () => { setConfirm(null); callApi("DELETE", { steam_hex: steam }); },
    });
  }, []);

  const openMenu = (player: Player, e: React.MouseEvent<HTMLButtonElement>) => {
    const r = e.currentTarget.getBoundingClientRect();
    setMenu({ player, top: r.bottom + 6, right: window.innerWidth - r.right });
  };
  const runMenu = (fn: () => void) => { setMenu(null); fn(); };

  useEffect(() => {
    return () => { if (toastTimer.current) clearTimeout(toastTimer.current); };
  }, []);

  useEffect(() => {
    if (view !== "players") return;
    let cancelled = false;
    const refetch = async () => {
      try {
        const data = await fetchPlayersDecrypted("/api/players");
        if (!cancelled && data && data.ok && Array.isArray(data.players)) { setPlayers(data.players); bumpKey(); }
      } catch {}
    };
    refetch();
    const id = setInterval(refetch, 5000);
    return () => { cancelled = true; clearInterval(id); };
  }, [view]);

  const viewTitle: Record<View, string> = {
    players: "Players",
    pins: "Pin",
    stats: "Statistiche",
    evasion: "AntiBanEvading",
  };

  return (
    <div className="flex h-screen overflow-hidden bg-background text-foreground">
      <aside
        className={`fixed inset-y-0 left-0 z-40 flex w-[240px] flex-col border-r border-border bg-card transition-transform duration-300 lg:translate-x-0 ${
          sidebarOpen ? "translate-x-0" : "-translate-x-full lg:translate-x-0"
        }`}
      >
        <div className="flex h-[60px] shrink-0 items-center gap-3 border-b border-border px-4">
          <Image src="/logo.png" alt="PhoenixAC" width={32} height={32} className="shrink-0" />
          <div className="min-w-0 flex-1">
            <p className="text-[13px] font-semibold leading-none text-foreground">PhoenixAC</p>
            <p className="mt-1 text-[11px] text-muted-foreground">Dashboard</p>
          </div>
          <Button
            variant="ghost"
            size="icon"
            onClick={() => setSidebarOpen(false)}
            className="h-7 w-7 shrink-0 lg:hidden"
            aria-label="Chiudi menu"
          >
            <X className="h-4 w-4" />
          </Button>
        </div>

        <nav className="flex flex-1 flex-col gap-0.5 overflow-y-auto px-2 py-3">
          {NAV_ITEMS.map(({ view: v, icon: Icon, label }) => (
            <Button
              key={v}
              variant={view === v ? "secondary" : "ghost"}
              className={`group h-9 w-full justify-start gap-3 text-[13px] font-medium transition-all duration-150 ${
                view === v ? "text-foreground" : "text-muted-foreground"
              }`}
              onClick={() => goView(v)}
            >
              <Icon className="h-4 w-4 shrink-0 transition-transform duration-150 group-hover:scale-110" />
              {label}
            </Button>
          ))}
        </nav>

        <Separator />
        <div className="shrink-0 px-2 py-3">
          <div className="flex items-center gap-2.5 rounded-lg px-2 py-1.5">
            <div className="flex h-7 w-7 shrink-0 items-center justify-center overflow-hidden rounded-full bg-[#5865F2]">
              <img src={avatar} alt={username} className="h-full w-full object-cover" />
            </div>
            <div className="min-w-0 flex-1">
              <p className="truncate text-[12px] font-medium leading-none text-foreground">{name}</p>
              <p className="mt-0.5 truncate text-[10px] text-muted-foreground">Discord</p>
            </div>
            <Button
              variant="ghost"
              size="icon"
              className="h-7 w-7 shrink-0 text-muted-foreground hover:bg-destructive/10 hover:text-destructive"
              nativeButton={false}
              render={<a href="/api/auth/logout" aria-label="Disconnetti sessione" />}
            >
              <LogOut className="h-3.5 w-3.5" />
            </Button>
          </div>
        </div>
      </aside>

      {sidebarOpen && (
        <div
          className="fixed inset-0 z-30 bg-black/60 lg:hidden"
          onClick={() => setSidebarOpen(false)}
        />
      )}

      <div className="flex min-w-0 flex-1 flex-col lg:ml-[240px]">
        <header className="flex h-[60px] shrink-0 items-center justify-between border-b border-border bg-card px-4 lg:px-6">
          <div className="flex items-center gap-3">
            <Button
              variant="ghost"
              size="icon"
              onClick={() => setSidebarOpen(true)}
              className="h-8 w-8 lg:hidden"
              aria-label="Apri menu"
            >
              <Menu className="h-4 w-4" />
            </Button>
            <div>
              <h1 className="text-[14px] font-semibold leading-none text-foreground">{viewTitle[view]}</h1>
              <p className="mt-[3px] text-[11px] text-muted-foreground">Gestione</p>
            </div>
          </div>
        </header>

        <main
          className={`flex-1 overflow-x-hidden overflow-y-auto p-4 lg:p-6 transition-opacity duration-150 ${fading ? "opacity-0" : "opacity-100"}`}
        >
          {view === "players" && (
            <div className="space-y-4">
              <div className="flex flex-col gap-3 sm:flex-row sm:items-center">
                <div className="relative w-full sm:max-w-xs sm:flex-1">
                  <Search className="absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
                  <Input
                    value={query}
                    onChange={(e) => setQuery(e.target.value)}
                    placeholder="Cerca per Steam HEX, Discord…"
                    className="h-9 pl-9 text-[13px]"
                  />
                </div>
                <div className="flex items-center gap-2 sm:ml-auto">
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => setShowAdd(true)}
                    className="h-9 gap-2 px-3 text-[13px]"
                  >
                    <UserPlus className="h-3.5 w-3.5" />
                    Aggiungi
                  </Button>
                </div>
              </div>

              <div className="rounded-xl border border-border bg-card">
                <div className="flex items-center justify-between gap-4 border-b border-border px-5 py-3.5">
                  <p className="shrink-0 text-[13px] font-semibold text-foreground">Giocatori</p>
                  <div className="ml-auto flex items-center gap-3">
                    <div className="relative flex items-center rounded-lg border border-border bg-muted/50 p-0.5">
                      <div
                        className="pointer-events-none absolute bottom-0.5 top-0.5 rounded-md bg-accent transition-all duration-200 ease-out"
                        style={{ left: `calc(${filterIndex * 25}% + 2px)`, width: "calc(25% - 4px)" }}
                      />
                      {FILTERS.map((f) => (
                        <button
                          key={f}
                          onClick={() => setFilter(f)}
                          className={`relative z-10 w-[58px] cursor-pointer py-1 text-[11px] font-medium transition-colors duration-200 ${
                            filter === f ? "text-foreground" : "text-muted-foreground hover:text-foreground"
                          }`}
                        >
                          {f}
                        </button>
                      ))}
                    </div>
                    <span className="shrink-0 text-[11px] text-muted-foreground">
                      {onlineCount} online · {players.length} totali
                    </span>
                  </div>
                </div>

                <div className="overflow-x-auto">
                  <table className="w-full">
                    <thead>
                      <tr className="border-b border-border">
                        <th className="px-5 py-3 text-left text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">Steam Hex</th>
                        <th className="hidden px-5 py-3 text-left text-[11px] font-semibold uppercase tracking-wider text-muted-foreground md:table-cell">Discord</th>
                        <th className="px-5 py-3 text-left text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">Status</th>
                        <th className="px-5 py-3 text-right text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">Azioni</th>
                      </tr>
                    </thead>
                    <tbody>
                      {filteredPage.map((p, i) => (
                        <PlayerRow key={`${dataKey}-${p.steam}`} player={p} onMenu={openMenu} index={i} />
                      ))}
                      {filtered.length === 0 && (
                        <tr>
                          <td colSpan={4} className="px-5 py-12 text-center text-[13px] text-muted-foreground">
                            Nessun giocatore trovato.
                          </td>
                        </tr>
                      )}
                    </tbody>
                  </table>
                </div>
                <TablePagination total={filtered.length} page={playersPage} setPage={setPlayersPage} />
              </div>
            </div>
          )}

          {view === "pins" && (
            <div className="space-y-4">
              <div className="flex flex-col gap-3 sm:flex-row sm:items-center">
                <p className="text-[13px] text-muted-foreground">I PIN sono validi 24h dalla generazione.</p>
                <div className="flex items-center gap-2 sm:ml-auto">
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={loadPins}
                    disabled={pinsLoading}
                    className="h-9 gap-2 px-3 text-[13px]"
                  >
                    <RefreshCw className={`h-3.5 w-3.5 ${pinsLoading ? "animate-spin" : ""}`} />
                    Aggiorna
                  </Button>
                  <Button
                    size="sm"
                    onClick={generatePin}
                    disabled={busy}
                    className="h-9 gap-2 px-3 text-[13px]"
                  >
                    <Ticket className="h-3.5 w-3.5" />
                    Genera PIN
                  </Button>
                </div>
              </div>

              <div className="rounded-xl border border-border bg-card">
                <div className="flex items-center justify-between gap-4 border-b border-border px-5 py-3.5">
                  <p className="shrink-0 text-[13px] font-semibold text-foreground">PIN generati</p>
                  <span className="text-[11px] text-muted-foreground">{pins.length} totali</span>
                </div>
                <div className="overflow-x-auto">
                  <table className="w-full">
                    <thead>
                      <tr className="border-b border-border">
                        <th className="px-5 py-3 text-left text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">PIN</th>
                        <th className="px-5 py-3 text-left text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">Stato</th>
                        <th className="hidden px-5 py-3 text-left text-[11px] font-semibold uppercase tracking-wider text-muted-foreground md:table-cell">Creato da</th>
                        <th className="hidden px-5 py-3 text-left text-[11px] font-semibold uppercase tracking-wider text-muted-foreground lg:table-cell">Creato il</th>
                        <th className="hidden px-5 py-3 text-left text-[11px] font-semibold uppercase tracking-wider text-muted-foreground xl:table-cell">Scadenza</th>
                        <th className="px-5 py-3 text-right text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">Azioni</th>
                      </tr>
                    </thead>
                    <tbody>
                      {pinsLoading && <SkeletonRows cols={6} />}
                      {!pinsLoading && pins.length === 0 && (
                        <tr>
                          <td colSpan={6} className="px-5 py-12 text-center text-[13px] text-muted-foreground">
                            Nessun PIN generato. Premi &ldquo;Genera PIN&rdquo;.
                          </td>
                        </tr>
                      )}
                      {!pinsLoading && pinsPage_.map((p, i) => (
                        <PinRow key={`${dataKey}-${p.code}`} pin={p} onCopy={copyPin} onDelete={deletePinRow} index={i} />
                      ))}
                    </tbody>
                  </table>
                </div>
                <TablePagination total={pins.length} page={pinsPage} setPage={setPinsPage} />
              </div>
            </div>
          )}

          {view === "stats" && (
            <div className="space-y-4">
              <div className="flex flex-col gap-3 sm:flex-row sm:items-center">
                <p className="text-[13px] text-muted-foreground">Kill / death tracker. Filtra per Steam hex, Discord ID, nome.</p>
                <div className="flex items-center gap-2 sm:ml-auto">
                  <div className="relative">
                    <Search className="absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground pointer-events-none" />
                    <Input
                      value={statsQuery}
                      onChange={(e) => setStatsQuery(e.target.value)}
                      onKeyDown={(e) => { if (e.key === "Enter") loadStats(statsQuery); }}
                      placeholder="hex / discord / nome…"
                      className="h-9 pl-9 text-[13px] w-52"
                    />
                  </div>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => loadStats(statsQuery)}
                    disabled={statsLoading}
                    className="h-9 gap-2 px-3 text-[13px]"
                  >
                    <RefreshCw className={`h-3.5 w-3.5 ${statsLoading ? "animate-spin" : ""}`} />
                    {statsLoading ? "Caricamento…" : "Aggiorna"}
                  </Button>
                </div>
              </div>

              <div className="rounded-xl border border-border bg-card">
                <div className="flex items-center justify-between gap-4 border-b border-border px-5 py-3.5">
                  <p className="shrink-0 text-[13px] font-semibold text-foreground">Statistiche giocatori</p>
                  <span className="text-[11px] text-muted-foreground">{stats.length} totali</span>
                </div>
                <div className="overflow-x-auto">
                  <table className="w-full">
                    <thead>
                      <tr className="border-b border-border">
                        <th className="px-5 py-3 text-left text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">Nome</th>
                        <th className="px-5 py-3 text-left text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">Steam Hex</th>
                        <th className="hidden px-5 py-3 text-left text-[11px] font-semibold uppercase tracking-wider text-muted-foreground md:table-cell">Discord</th>
                        <th className="hidden px-5 py-3 text-left text-[11px] font-semibold uppercase tracking-wider text-muted-foreground lg:table-cell">License</th>
                        <th className="hidden px-5 py-3 text-left text-[11px] font-semibold uppercase tracking-wider text-muted-foreground xl:table-cell">Token</th>
                        <th className="px-5 py-3 text-right text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">K</th>
                        <th className="px-5 py-3 text-right text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">D</th>
                        <th className="px-5 py-3 text-right text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">K/D</th>
                        <th className="px-5 py-3 text-right text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">Streak</th>
                      </tr>
                    </thead>
                    <tbody>
                      {statsLoading && <SkeletonRows cols={9} />}
                      {!statsLoading && stats.length === 0 && (
                        <tr><td colSpan={9} className="px-5 py-12 text-center text-[13px] text-muted-foreground">Nessun dato disponibile.</td></tr>
                      )}
                      {!statsLoading && statsPage_.map((s, i) => (
                        <tr key={`${dataKey}-${s.steamHex}`} className="row-in border-b border-border last:border-0 hover:bg-muted/30" style={{ animationDelay: `${i * 35}ms` }}>
                          <td className="px-5 py-3 text-[13px] text-foreground">{s.name || "-"}</td>
                          <td className="px-5 py-3 text-[12px] text-muted-foreground">{s.steamHex}</td>
                          <td className="hidden px-5 py-3 text-[12px] text-muted-foreground md:table-cell">{s.discordId || "-"}</td>
                          <td className="hidden px-5 py-3 text-[11px] text-muted-foreground lg:table-cell">{s.license ? s.license.slice(0, 16) + (s.license.length > 16 ? "…" : "") : "-"}</td>
                          <td className="hidden px-5 py-3 text-[11px] text-muted-foreground xl:table-cell">{s.token ? s.token.slice(0, 14) + (s.token.length > 14 ? "…" : "") : "-"}</td>
                          <td className="px-5 py-3 text-right text-[13px] font-semibold text-emerald-400">{s.kills}</td>
                          <td className="px-5 py-3 text-right text-[13px] font-semibold text-red-400">{s.deaths}</td>
                          <td className="px-5 py-3 text-right text-[13px] text-foreground">{s.kd}</td>
                          <td className="px-5 py-3 text-right text-[12px] text-muted-foreground">
                            <span className="text-primary">{s.currentStreak}</span>
                            <span className="text-muted-foreground"> / </span>
                            <span>{s.maxStreak}</span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
                <TablePagination total={stats.length} page={statsPage} setPage={setStatsPage} />
              </div>
            </div>
          )}

          {view === "evasion" && (
            <div className="space-y-4">
              <div className="flex flex-col gap-3 sm:flex-row sm:items-center">
                <p className="text-[13px] text-muted-foreground">
                  Account flaggati per ban evasion. Solo audit — nessun ban automatico.
                </p>
                <div className="flex items-center gap-2 sm:ml-auto">
                  <div className="relative">
                    <Search className="absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground pointer-events-none" />
                    <Input
                      value={evasionQuery}
                      onChange={(e) => setEvasionQuery(e.target.value)}
                      onKeyDown={(e) => { if (e.key === "Enter") loadEvasion(evasionQuery); }}
                      placeholder="hex / nome / valore…"
                      className="h-9 pl-9 text-[13px] w-52"
                    />
                  </div>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => loadEvasion(evasionQuery)}
                    disabled={evasionLoading}
                    className="h-9 gap-2 px-3 text-[13px]"
                  >
                    <RefreshCw className={`h-3.5 w-3.5 ${evasionLoading ? "animate-spin" : ""}`} />
                    {evasionLoading ? "Caricamento…" : "Aggiorna"}
                  </Button>
                </div>
              </div>

              <div className="rounded-xl border border-border bg-card">
                <div className="flex items-center justify-between gap-4 border-b border-border px-5 py-3.5">
                  <p className="shrink-0 text-[13px] font-semibold text-foreground">Flag rilevati</p>
                  <span className="text-[11px] text-muted-foreground">{evasion.length} totali</span>
                </div>
                <div className="overflow-x-auto">
                  <table className="w-full">
                    <thead>
                      <tr className="border-b border-border">
                        <th className="px-5 py-3 text-left text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">Quando</th>
                        <th className="px-5 py-3 text-left text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">Tipo</th>
                        <th className="px-5 py-3 text-left text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">Valore</th>
                        <th className="px-5 py-3 text-left text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">Hex #1</th>
                        <th className="px-5 py-3 text-left text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">Hex #2</th>
                        <th className="hidden px-5 py-3 text-left text-[11px] font-semibold uppercase tracking-wider text-muted-foreground lg:table-cell">IP</th>
                      </tr>
                    </thead>
                    <tbody>
                      {evasionLoading && <SkeletonRows cols={6} />}
                      {!evasionLoading && evasion.length === 0 && (
                        <tr><td colSpan={6} className="px-5 py-12 text-center text-[13px] text-muted-foreground">Nessun flag attivo.</td></tr>
                      )}
                      {!evasionLoading && evasionPage_.map((f, i) => (
                        <tr key={`${dataKey}-${f.id}`} className="row-in border-b border-border last:border-0 hover:bg-muted/30" style={{ animationDelay: `${i * 35}ms` }}>
                          <td className="px-5 py-3 text-[12px] text-muted-foreground whitespace-nowrap">{new Date(f.createdAt).toLocaleString("it-IT")}</td>
                          <td className="px-5 py-3">
                            <Badge variant="outline" className="text-[10px] font-semibold uppercase text-primary border-primary/30">
                              {f.fpType}
                            </Badge>
                          </td>
                          <td className="px-5 py-3 text-[11px] text-muted-foreground max-w-[260px] truncate" title={f.fpValue}>{f.fpValue}</td>
                          <td className="px-5 py-3 text-[11px] text-muted-foreground">
                            {f.primaryHex}
                            {f.primaryName && <div className="text-[10px] text-muted-foreground">{f.primaryName}</div>}
                          </td>
                          <td className="px-5 py-3 text-[11px] text-muted-foreground">
                            {f.secondaryHex}
                            {f.secondaryName && <div className="text-[10px] text-muted-foreground">{f.secondaryName}</div>}
                          </td>
                          <td className="hidden px-5 py-3 text-[11px] text-muted-foreground lg:table-cell">{f.clientIp || "-"}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
                <TablePagination total={evasion.length} page={evasionPage} setPage={setEvasionPage} />
              </div>
            </div>
          )}
        </main>
      </div>

      {menu && (
        <>
          <div className="fixed inset-0 z-50" onClick={() => setMenu(null)} />
          <div
            className="menu-in fixed z-50 w-44 rounded-xl border border-border bg-popover p-1 shadow-2xl shadow-black/50"
            style={{ top: menu.top, right: menu.right }}
          >
            <Button
              variant="ghost"
              size="sm"
              className="h-8 w-full justify-start gap-2.5 px-2.5 text-[13px] text-red-400/80 hover:bg-red-400/[0.08] hover:text-red-400"
              onClick={() => runMenu(() => toggleBan(menu.player))}
            >
              <Ban className="h-3.5 w-3.5" />
              {menu.player.banned ? "Rimuovi ban" : "Banna"}
            </Button>
            <Button
              variant="ghost"
              size="sm"
              className="h-8 w-full justify-start gap-2.5 px-2.5 text-[13px] text-red-400/80 hover:bg-red-400/[0.08] hover:text-red-400"
              onClick={() => runMenu(() => remove(menu.player.steam))}
            >
              <Trash className="h-3.5 w-3.5" />
              Elimina
            </Button>
          </div>
        </>
      )}

      {showAdd && (
        <div
          className="dialog-overlay fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4 backdrop-blur-sm"
          onClick={() => !busy && setShowAdd(false)}
        >
          <form
            onClick={(e) => e.stopPropagation()}
            onSubmit={submitAdd}
            className="dialog-content w-full max-w-sm rounded-2xl border border-border bg-card p-6"
          >
            <div className="mb-6 flex items-center justify-between">
              <h2 className="text-[16px] font-semibold text-foreground">Aggiungi giocatore</h2>
              <Button
                type="button"
                variant="ghost"
                size="icon"
                onClick={() => setShowAdd(false)}
                className="h-8 w-8"
                aria-label="Chiudi"
              >
                <X className="h-4 w-4" />
              </Button>
            </div>

            <div className="space-y-4">
              <Field label="Steam HEX">
                <Input
                  value={form.steam}
                  onChange={(e) => setForm({ ...form, steam: e.target.value })}
                  autoFocus
                  placeholder="110000102766681"
                  className="h-10 text-[13px]"
                />
              </Field>
              <Field label="Discord ID (opzionale)">
                <Input
                  value={form.discord}
                  onChange={(e) => setForm({ ...form, discord: e.target.value })}
                  placeholder="1236057399958175885"
                  className="h-10 text-[13px]"
                />
              </Field>
              <p className="text-[12px] leading-relaxed text-muted-foreground">
                Lo stato online/offline è automatico: dipende dall&apos;heartbeat del launcher.
              </p>
            </div>

            <div className="mt-7 flex justify-end gap-2.5">
              <Button type="button" variant="ghost" className="h-9 px-4 text-[13px]" onClick={() => setShowAdd(false)}>
                Annulla
              </Button>
              <Button type="submit" className="h-9 px-4 text-[13px]" disabled={busy || !form.steam.trim()}>
                {busy ? "Salvataggio…" : "Salva"}
              </Button>
            </div>
          </form>
        </div>
      )}

      {pin && (
        <div
          className="dialog-overlay fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4 backdrop-blur-sm"
          onClick={() => setPin(null)}
        >
          <div
            onClick={(e) => e.stopPropagation()}
            className="dialog-content w-full max-w-xs rounded-2xl border border-border bg-card p-6 text-center"
          >
            <div className="mx-auto mb-4 flex h-11 w-11 items-center justify-center rounded-full bg-primary/15">
              <Ticket className="h-5 w-5 text-primary" />
            </div>
            <p className="text-[12px] text-muted-foreground">PIN generato · valido 24h</p>
            <p className="mt-2 text-[32px] font-bold tracking-[0.12em] text-foreground">{pin}</p>
            <div className="mt-5 flex gap-2">
              <Button
                variant="outline"
                className="flex-1 gap-1.5 text-[12px]"
                onClick={() => { navigator.clipboard?.writeText(pin); flash("PIN copiato"); }}
              >
                <Copy className="h-3.5 w-3.5" />
                Copia
              </Button>
              <Button className="flex-1 text-[12px]" onClick={() => setPin(null)}>
                Chiudi
              </Button>
            </div>
          </div>
        </div>
      )}

      {confirm && (
        <ConfirmDialog
          title={confirm.title}
          description={confirm.description}
          confirmLabel={confirm.confirmLabel}
          destructive={confirm.destructive}
          onConfirm={confirm.onConfirm}
          onCancel={() => setConfirm(null)}
        />
      )}

      {toast && (
        <div className="menu-in fixed bottom-5 left-1/2 z-50 -translate-x-1/2 rounded-lg border border-border bg-popover px-4 py-2.5 text-[13px] font-medium text-foreground shadow-2xl shadow-black/50">
          {toast}
        </div>
      )}
    </div>
  );
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <label className="block">
      <span className="mb-1.5 block text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
        {label}
      </span>
      {children}
    </label>
  );
}

function PlayerRow({
  player,
  onMenu,
  index = 0,
}: {
  player: Player;
  onMenu: (player: Player, e: React.MouseEvent<HTMLButtonElement>) => void;
  index?: number;
}) {
  const [info, setInfo] = useState<LookupResult>({});

  useEffect(() => {
    let cancelled = false;
    fetchLookup(player.steam || undefined, player.discord || undefined).then((d) => {
      if (!cancelled) setInfo(d);
    });
    return () => { cancelled = true; };
  }, [player.steam, player.discord]);

  const initial = player.banned
    ? "B"
    : player.steam.replace(/[^a-z0-9]/gi, "").charAt(0).toUpperCase() || "1";
  const avatarSrc = info.steamAvatar || info.discordAvatar;

  return (
    <tr className="row-in border-b border-border/50 transition-colors last:border-0 hover:bg-muted/30" style={{ animationDelay: `${index * 35}ms` }}>
      <td className="px-5 py-3.5">
        <div className="flex items-center gap-2.5">
          {avatarSrc ? (
            <img
              src={avatarSrc}
              alt=""
              className="h-7 w-7 shrink-0 rounded-full object-cover"
            />
          ) : (
            <div className="flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-muted">
              <span className="text-[12px] font-semibold text-muted-foreground">{initial}</span>
            </div>
          )}
          <div className="min-w-0">
            {info.steamName && (
              <p className="truncate text-[13px] font-medium text-foreground">{info.steamName}</p>
            )}
            <p className={`truncate text-muted-foreground ${info.steamName ? "text-[11px]" : "text-[13px]"}`}>
              {player.steam}
            </p>
          </div>
        </div>
      </td>
      <td className="hidden px-5 py-3.5 md:table-cell">
        <div className="flex items-center gap-2">
          {info.discordAvatar && (
            <img src={info.discordAvatar} alt="" className="h-7 w-7 shrink-0 rounded-full object-cover" />
          )}
          <div className="min-w-0">
            {info.discordName && (
              <p className="truncate text-[13px] text-foreground">{info.discordName}</p>
            )}
            {player.discord && (
              <p className={`truncate text-muted-foreground ${info.discordName ? "text-[11px]" : "text-[13px]"}`}>
                {player.discord}
              </p>
            )}
            {!player.discord && !info.discordName && (
              <span className="text-[13px] text-muted-foreground">-</span>
            )}
          </div>
        </div>
      </td>
      <td className="px-5 py-3.5">
        <StatusBadge player={player} />
      </td>
      <td className="px-5 py-3.5 text-right">
        <Button
          variant="ghost"
          size="icon"
          onClick={(e) => onMenu(player, e)}
          className="h-7 w-7 text-muted-foreground hover:text-foreground"
          aria-label="Azioni giocatore"
        >
          <Ellipsis className="h-4 w-4" />
        </Button>
      </td>
    </tr>
  );
}

function PinRow({
  pin,
  onCopy,
  onDelete,
  index = 0,
}: {
  pin: Pin;
  onCopy: (code: string) => void;
  onDelete: (code: string) => void;
  index?: number;
}) {
  const [creator, setCreator] = useState<LookupResult>({});

  useEffect(() => {
    if (!pin.createdBy) return;
    let cancelled = false;
    fetchLookup(undefined, pin.createdBy).then((d) => {
      if (!cancelled) setCreator(d);
    });
    return () => { cancelled = true; };
  }, [pin.createdBy]);

  const state = pin.used
    ? { label: "Usato", cls: "text-muted-foreground", dot: "bg-muted-foreground/50" }
    : pin.expired
      ? { label: "Scaduto", cls: "text-amber-400/80", dot: "bg-amber-400/70" }
      : { label: "Disponibile", cls: "text-emerald-400/80", dot: "bg-emerald-400" };

  return (
    <tr className="row-in border-b border-border/50 transition-colors last:border-0 hover:bg-muted/30" style={{ animationDelay: `${index * 35}ms` }}>
      <td className="px-5 py-3.5">
        <div className="flex items-center gap-2.5">
          <div className="flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-muted">
            <Ticket className="h-3.5 w-3.5 text-muted-foreground" />
          </div>
          <span className="text-[14px] tracking-[0.08em] text-foreground">{pin.code}</span>
        </div>
      </td>
      <td className="px-5 py-3.5">
        <span className={`inline-flex items-center gap-2 text-[12px] font-medium ${state.cls}`}>
          <span className={`h-1.5 w-1.5 shrink-0 rounded-full ${state.dot}`} />
          {state.label}
        </span>
      </td>
      <td className="hidden px-5 py-3.5 md:table-cell">
        <div className="flex items-center gap-2">
          {creator.discordAvatar && (
            <img src={creator.discordAvatar} alt="" className="h-6 w-6 shrink-0 rounded-full object-cover" />
          )}
          <div className="min-w-0">
            {creator.discordName ? (
              <p className="truncate text-[13px] text-foreground">{creator.discordName}</p>
            ) : (
              <p className="truncate text-[12px] text-muted-foreground">{pin.createdBy || "-"}</p>
            )}
            {creator.discordName && pin.createdBy && (
              <p className="truncate text-[11px] text-muted-foreground">{pin.createdBy}</p>
            )}
          </div>
        </div>
      </td>
      <td className="hidden px-5 py-3.5 lg:table-cell">
        <span className="text-[13px] text-muted-foreground">{pin.createdAt || "-"}</span>
      </td>
      <td className="hidden px-5 py-3.5 xl:table-cell">
        <span className="text-[13px] text-muted-foreground">{pin.expiresAt || "-"}</span>
      </td>
      <td className="px-5 py-3.5 text-right">
        <div className="inline-flex items-center gap-1">
          <Button
            variant="ghost"
            size="icon"
            onClick={() => onCopy(pin.code)}
            className="h-7 w-7 text-muted-foreground hover:text-foreground"
            aria-label="Copia PIN"
          >
            <Copy className="h-4 w-4" />
          </Button>
          <Button
            variant="ghost"
            size="icon"
            onClick={() => onDelete(pin.code)}
            disabled={pin.used}
            className="h-7 w-7 text-muted-foreground hover:bg-red-400/[0.08] hover:text-red-400 disabled:pointer-events-none disabled:opacity-30"
            aria-label="Elimina PIN"
          >
            <Trash className="h-4 w-4" />
          </Button>
        </div>
      </td>
    </tr>
  );
}

function StatusBadge({ player }: { player: Player }) {
  if (player.banned) {
    return (
      <span className="inline-flex items-center gap-1.5 text-[11px] font-medium text-red-400/80">
        <Ban className="h-3 w-3" /> Bannato
      </span>
    );
  }
  if (player.online) {
    return (
      <span className="inline-flex items-center gap-1.5 text-[11px] font-medium text-emerald-400/80">
        <Wifi className="h-3 w-3" /> Online
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-1.5 text-[11px] font-medium text-muted-foreground">
      <WifiOff className="h-3 w-3" /> Offline
    </span>
  );
}
