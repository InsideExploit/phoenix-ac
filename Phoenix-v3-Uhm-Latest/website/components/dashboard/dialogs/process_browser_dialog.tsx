'use client';

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';

import {
  AlertCircle,
  AppWindow,
  ArrowLeft,
  Boxes,
  Check,
  ChevronDown,
  ChevronRight,
  Cpu,
  Eye,
  EyeOff,
  Loader2,
  PauseCircle,
  PlayCircle,
  RefreshCw,
  Search,
  TextSearch,
  X,
} from 'lucide-react';

import { AnimatedDialog } from '@/components/ui/animated-dialog';
import { Checkbox } from '@/components/ui/checkbox';

import { formatExtraValue } from '../detections/detection_labels';
import type { ProcessBrowserState } from '../types';

type Proc = {
  pid: number;
  ppid: number;
  name: string;
  path: string;
  user?: string;
  threads: number;
  handles: number;
  sessionId: number;
  createMs: number;
  userNs: number;
  kernelNs: number;
  workingSet: number;
  virtualSize: number;
  privateBytes: number;
  basePriority: number;
};

function classifyUser(u: string | undefined): 'system' | 'service' | 'user' | 'unknown' {
  if (!u) return 'unknown';
  const up = u.toUpperCase();
  if (up.includes('NT AUTHORITY\\SYSTEM')) return 'system';
  if (
    up.includes('NETWORK SERVICE') ||
    up.includes('LOCAL SERVICE') ||
    up.includes('TRUSTEDINSTALLER')
  )
    return 'service';
  return 'user';
}

function ThemedSelect<T extends string>({
  value,
  options,
  onChange,
}: {
  value: T;
  options: readonly {
    value: T;
    label: string;
  }[];
  onChange: (v: T) => void;
}) {
  const [open, setOpen] = useState(false);
  const rootRef = useRef<HTMLDivElement | null>(null);
  useEffect(() => {
    if (!open) return;
    const onDoc = (e: MouseEvent) => {
      if (rootRef.current && !rootRef.current.contains(e.target as Node)) setOpen(false);
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setOpen(false);
    };
    document.addEventListener('mousedown', onDoc);
    document.addEventListener('keydown', onKey);
    return () => {
      document.removeEventListener('mousedown', onDoc);
      document.removeEventListener('keydown', onKey);
    };
  }, [open]);
  const current = options.find((o) => o.value === value) ?? options[0];
  return (
    <div
      ref={rootRef}
      className="relative"
    >
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="flex h-8 min-w-[190px] items-center gap-2 rounded-md border border-white/[0.08] bg-white/[0.015] px-2.5 text-left text-[11.5px] text-white/80 hover:border-white/15 hover:bg-white/[0.04]"
      >
        <span className="min-w-0 flex-1 truncate">{current?.label ?? ''}</span>
        <ChevronDown
          className={`h-3 w-3 text-white/45 transition-transform ${open ? 'rotate-180' : ''}`}
        />
      </button>
      {open && (
        <div className="phx-menu-in absolute left-0 top-[calc(100%+4px)] z-40 min-w-full rounded-md border border-white/[0.08] bg-[#111] p-1 shadow-2xl shadow-black/60">
          {options.map((opt) => {
            const active = opt.value === value;
            return (
              <button
                key={opt.value}
                type="button"
                onClick={() => {
                  onChange(opt.value);
                  setOpen(false);
                }}
                className={`flex w-full items-center justify-between gap-2 rounded px-2 py-1.5 text-left text-[11.5px] transition-colors ${active ? 'bg-white/[0.05] text-white' : 'text-white/75 hover:bg-white/[0.04] hover:text-white'}`}
              >
                <span>{opt.label}</span>
                {active && <Check className="h-3 w-3 text-white/70" />}
              </button>
            );
          })}
        </div>
      )}
    </div>
  );
}

function rowToneClasses(u: string | undefined): {
  row: string;
  hover: string;
} {
  const k = classifyUser(u);
  if (k === 'system') return { row: 'bg-sky-400/[0.045]', hover: 'hover:bg-sky-400/[0.09]' };
  if (k === 'service')
    return { row: 'bg-emerald-400/[0.045]', hover: 'hover:bg-emerald-400/[0.09]' };
  if (k === 'user') return { row: 'bg-orange-400/[0.035]', hover: 'hover:bg-orange-400/[0.08]' };
  return { row: '', hover: 'hover:bg-white/[0.03]' };
}

type Snapshot = {
  tsMs: number;
  processes: Proc[];
  count: number;
};

type Module = {
  name: string;
  path: string;
  base: string;
  size: number;
};

type WindowInfo = {
  hwnd: string;
  className: string;
  title: string;
  style: string;
  exStyle: string;
  visible: boolean;
  rect: {
    l: number;
    t: number;
    r: number;
    b: number;
  };
};

function formatBytes(n: number | undefined): string {
  if (!n && n !== 0) return '';
  if (n < 1024) return `${n} B`;
  const units = ['KB', 'MB', 'GB', 'TB'];
  let v = n / 1024;
  let ui = 0;
  while (v >= 1024 && ui < units.length - 1) {
    v /= 1024;
    ui++;
  }
  return `${v.toFixed(v >= 100 ? 0 : v >= 10 ? 1 : 2)} ${units[ui]}`;
}

function formatDate(ms: number | undefined): string {
  if (!ms) return '';
  try {
    return new Date(ms).toLocaleString();
  } catch {
    return '';
  }
}

function formatUptime(startMs: number, nowMs: number): string {
  if (!startMs || startMs > nowMs) return '';
  const sec = Math.max(0, Math.floor((nowMs - startMs) / 1000));
  if (sec < 60) return `${sec}s`;
  const min = Math.floor(sec / 60);
  if (min < 60) return `${min}m ${sec % 60}s`;
  const hr = Math.floor(min / 60);
  if (hr < 48) return `${hr}h ${min % 60}m`;
  const days = Math.floor(hr / 24);
  return `${days}d ${hr % 24}h`;
}

export function ProcessBrowserDialog({
  state,
  onClose,
  hasElevatedAccess = false,
}: {
  state: ProcessBrowserState;
  onClose: () => void;
  hasElevatedAccess?: boolean;
}) {
  const gated = !!state && !hasElevatedAccess;
  const [snap, setSnap] = useState<Snapshot | null>(null);
  const [prev, setPrev] = useState<Snapshot | null>(null);
  const [loading, setLoad] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [filter, setFilter] = useState('');
  const [selected, setSel] = useState<Proc | null>(null);
  const [mods, setMods] = useState<Module[] | null>(null);
  const [modsLoad, setML] = useState(false);
  const [modsErr, setME] = useState<string | null>(null);
  const [wins, setWins] = useState<WindowInfo[] | null>(null);
  const [winsLoad, setWL] = useState(false);
  const [winsErr, setWE] = useState<string | null>(null);
  const [winsTrunc, setWT] = useState(false);
  const [modsOpen, setModsOpen] = useState(false);
  const [winsOpen, setWinsOpen] = useState(false);
  const [live, setLive] = useState(true);
  const [sortKey, setSort] = useState<'cpu' | 'mem' | 'name' | 'pid'>('pid');
  const [strOpen, setStrOpen] = useState(false);
  const [strMinLen, setStrMinLen] = useState(4);
  const [strAnsi, setStrAnsi] = useState(true);
  const [strUni, setStrUni] = useState(true);
  const [strExt, setStrExt] = useState(false);
  const [strPriv, setStrPriv] = useState(true);
  const [strImg, setStrImg] = useState(false);
  const [strMap, setStrMap] = useState(false);
  const [strRunning, setStrRunning] = useState(false);
  const [strError, setStrError] = useState<string | null>(null);
  const [strResults, setStrResults] = useState<{
    pid: number;
    results: {
      addr: string;
      base: string;
      len: number;
      enc: string;
      s: string;
    }[];
    count: number;
    truncated: boolean;
    scannedBytes: number;
    appliedNeedle: string;
  } | null>(null);
  const [strFilter, setStrFilter] = useState('');
  const [strMode, setStrMode] = useState<'contains' | 'icontains' | 'regex' | 'iregex'>(
    'icontains',
  );
  const steam = state?.steam ?? null;
  const tickRef = useRef<number | null>(null);
  const loadList = useCallback(async () => {
    if (!steam || gated) return;
    setLoad(true);
    setErr(null);
    try {
      const url = new URL('/api/players/proc/list', window.location.origin);
      url.searchParams.set('steam_hex', steam);
      const r = await fetch(url.toString());
      const d = (await r.json().catch(() => null)) as
        | (Snapshot & {
            ok?: boolean;
            error?: string;
          })
        | null;
      if (!r.ok || !d?.ok) {
        setErr(d?.error ?? `HTTP ${r.status}`);
        return;
      }
      setPrev((old) => snap ?? old);
      setSnap({ tsMs: d.tsMs, processes: d.processes ?? [], count: d.count ?? 0 });
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setLoad(false);
    }
  }, [steam, snap, gated]);
  useEffect(() => {
    if (!state) {
      setSnap(null);
      setPrev(null);
      setSel(null);
      setMods(null);
      setErr(null);
      setFilter('');
      setME(null);
      return;
    }
    void loadList();
  }, [state]);
  useEffect(() => {
    if (!state || !live) return;
    tickRef.current = window.setInterval(() => {
      void loadList();
    }, 3500);
    return () => {
      if (tickRef.current) window.clearInterval(tickRef.current);
      tickRef.current = null;
    };
  }, [state, live, loadList]);
  const cpuByPid = useMemo(() => {
    const map = new Map<number, number>();
    if (!snap || !prev) return map;
    const dtMs = snap.tsMs - prev.tsMs;
    if (dtMs <= 0) return map;
    const cores = navigator.hardwareConcurrency || 4;
    const denom = dtMs * 10000 * cores;
    const oldByPid = new Map<number, Proc>();
    for (const p of prev.processes) oldByPid.set(p.pid, p);
    for (const p of snap.processes) {
      const o = oldByPid.get(p.pid);
      if (!o) continue;
      const dCpu = p.userNs + p.kernelNs - (o.userNs + o.kernelNs);
      if (dCpu < 0) continue;
      map.set(p.pid, Math.min(100, (dCpu / denom) * 100));
    }
    return map;
  }, [snap, prev]);
  const [collapsed, setCollapsed] = useState<Set<number>>(new Set());
  const toggleCollapsed = useCallback((pid: number) => {
    setCollapsed((prev) => {
      const next = new Set(prev);
      if (next.has(pid)) next.delete(pid);
      else next.add(pid);
      return next;
    });
  }, []);
  const compareBySort = useCallback(
    (a: Proc, b: Proc): number => {
      if (sortKey === 'name')
        return a.name.localeCompare(b.name, undefined, { sensitivity: 'base' });
      if (sortKey === 'pid') return a.pid - b.pid;
      if (sortKey === 'mem') return b.workingSet - a.workingSet;
      const ca = cpuByPid.get(a.pid) ?? -1;
      const cb = cpuByPid.get(b.pid) ?? -1;
      if (ca !== cb) return cb - ca;
      return b.workingSet - a.workingSet;
    },
    [cpuByPid, sortKey],
  );
  type Row = {
    p: Proc;
    depth: number;
    hasChildren: boolean;
  };
  const rows = useMemo<Row[]>(() => {
    if (!snap) return [];
    const q = filter.trim().toLowerCase();
    const all = snap.processes;
    const byPid = new Map<number, Proc>();
    for (const p of all) byPid.set(p.pid, p);
    const childrenOf = new Map<number, Proc[]>();
    const roots: Proc[] = [];
    for (const p of all) {
      const parent = byPid.get(p.ppid);
      const validParent =
        parent !== undefined &&
        parent.pid !== p.pid &&
        (!parent.createMs || !p.createMs || parent.createMs <= p.createMs);
      if (validParent) {
        const arr = childrenOf.get(p.ppid);
        if (arr) arr.push(p);
        else childrenOf.set(p.ppid, [p]);
      } else {
        roots.push(p);
      }
    }
    for (const [, arr] of childrenOf) arr.sort(compareBySort);
    roots.sort(compareBySort);
    const matches = (p: Proc): boolean => {
      if (!q) return true;
      return (
        p.name.toLowerCase().includes(q) ||
        p.path.toLowerCase().includes(q) ||
        (p.user ?? '').toLowerCase().includes(q) ||
        String(p.pid).includes(q)
      );
    };
    const subtreeMatches = (p: Proc): boolean => {
      if (matches(p)) return true;
      const kids = childrenOf.get(p.pid);
      if (kids) for (const c of kids) if (subtreeMatches(c)) return true;
      return false;
    };
    const out: Row[] = [];
    const walk = (p: Proc, depth: number): void => {
      if (q && !subtreeMatches(p)) return;
      const kids = childrenOf.get(p.pid);
      out.push({ p, depth, hasChildren: !!(kids && kids.length) });
      if (kids && kids.length && !collapsed.has(p.pid)) {
        for (const c of kids) walk(c, depth + 1);
      }
    };
    for (const r of roots) walk(r, 0);
    return out;
  }, [snap, filter, compareBySort, collapsed]);
  const loadModules = useCallback(
    async (p: Proc) => {
      if (!steam || gated) return;
      setMods(null);
      setME(null);
      setML(true);
      try {
        const url = new URL('/api/players/proc/modules', window.location.origin);
        url.searchParams.set('steam_hex', steam);
        url.searchParams.set('pid', String(p.pid));
        const r = await fetch(url.toString());
        const d = (await r.json().catch(() => null)) as {
          ok?: boolean;
          modules?: Module[];
          error?: string;
        } | null;
        if (!r.ok || !d?.ok) {
          setME(d?.error ?? `HTTP ${r.status}`);
          return;
        }
        setMods(d.modules ?? []);
      } catch (e) {
        setME((e as Error).message);
      } finally {
        setML(false);
      }
    },
    [steam, gated],
  );
  const loadWindows = useCallback(
    async (p: Proc) => {
      if (!steam || gated) return;
      setWins(null);
      setWE(null);
      setWT(false);
      setWL(true);
      try {
        const url = new URL('/api/players/proc/windows', window.location.origin);
        url.searchParams.set('steam_hex', steam);
        url.searchParams.set('pid', String(p.pid));
        const r = await fetch(url.toString());
        const d = (await r.json().catch(() => null)) as {
          ok?: boolean;
          windows?: WindowInfo[];
          truncated?: boolean;
          error?: string;
        } | null;
        if (!r.ok || !d?.ok) {
          setWE(d?.error ?? `HTTP ${r.status}`);
          return;
        }
        setWins(d.windows ?? []);
        setWT(!!d.truncated);
      } catch (e) {
        setWE((e as Error).message);
      } finally {
        setWL(false);
      }
    },
    [steam, gated],
  );
  const onSelect = useCallback((p: Proc) => {
    setSel(p);
    setStrOpen(false);
    setStrResults(null);
    setStrError(null);
    setStrFilter('');
    setMods(null);
    setME(null);
    setWins(null);
    setWE(null);
    setWT(false);
    setModsOpen(false);
    setWinsOpen(false);
  }, []);
  useEffect(() => {
    if (modsOpen && selected && !mods && !modsLoad) void loadModules(selected);
  }, [modsOpen, selected, mods, modsLoad, loadModules]);
  useEffect(() => {
    if (winsOpen && selected && !wins && !winsLoad) void loadWindows(selected);
  }, [winsOpen, selected, wins, winsLoad, loadWindows]);
  const runStrings = useCallback(
    async (needle?: string, needleCI?: boolean) => {
      if (!steam || !selected || strRunning) return;
      setStrRunning(true);
      setStrError(null);
      setStrResults(null);
      try {
        const r = await fetch('/api/players/proc/strings', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({
            steam_hex: steam,
            pid: selected.pid,
            min_len: strMinLen,
            detect_ansi: strAnsi,
            detect_unicode: strUni,
            extended: strExt,
            private: strPriv,
            image: strImg,
            mapped: strMap,
            needle: needle ?? '',
            needle_ci: needleCI !== false,
          }),
        });
        const d = (await r.json().catch(() => null)) as {
          ok?: boolean;
          error?: string;
          pid?: number;
          results?: {
            addr: string;
            base: string;
            len: number;
            enc: string;
            s: string;
          }[];
          count?: number;
          truncated?: boolean;
          scannedBytes?: number;
        } | null;
        if (!r.ok || !d?.ok) {
          setStrError(d?.error ?? `HTTP ${r.status}`);
          return;
        }
        setStrResults({
          pid: d.pid ?? selected.pid,
          results: d.results ?? [],
          count: d.count ?? 0,
          truncated: !!d.truncated,
          scannedBytes: d.scannedBytes ?? 0,
          appliedNeedle: needle ?? '',
        });
        setStrOpen(false);
      } catch (e) {
        setStrError((e as Error).message);
      } finally {
        setStrRunning(false);
      }
    },
    [steam, selected, strRunning, strMinLen, strAnsi, strUni, strExt, strPriv, strImg, strMap],
  );
  const strFiltered = useMemo(() => {
    if (!strResults)
      return [] as {
        addr: string;
        base: string;
        len: number;
        enc: string;
        s: string;
      }[];
    const q = strFilter.trim();
    if (!q) return strResults.results;
    try {
      if (strMode === 'contains') return strResults.results.filter((r) => r.s.includes(q));
      if (strMode === 'icontains') {
        const qi = q.toLowerCase();
        return strResults.results.filter((r) => r.s.toLowerCase().includes(qi));
      }
      if (strMode === 'regex') {
        const re = new RegExp(q);
        return strResults.results.filter((r) => re.test(r.s));
      }
      if (strMode === 'iregex') {
        const re = new RegExp(q, 'i');
        return strResults.results.filter((r) => re.test(r.s));
      }
    } catch {
      return strResults.results;
    }
    return strResults.results;
  }, [strResults, strFilter, strMode]);
  const totalMemory = useMemo(() => {
    if (!snap) return 0;
    return snap.processes.reduce((s, p) => s + p.workingSet, 0);
  }, [snap]);
  return (
    <AnimatedDialog
      open={!!state}
      onClose={onClose}
      panelClassName="max-w-6xl phx-dialog-in"
    >
      {(dismiss) =>
        state ? (
          gated ? (
            <div className="flex w-full flex-col rounded-lg border border-white/[0.08] bg-[#111] p-6 text-center">
              <div className="mx-auto mb-3 flex h-9 w-9 items-center justify-center rounded-md border border-red-400/25 bg-red-400/[0.08] text-red-300">
                <AlertCircle className="h-4 w-4" />
              </div>
              <div className="text-[13px] font-medium text-white">Access restricted</div>
              <div className="mt-1 text-[11.5px] text-white/50">
                Your account is not authorized to view remote processes.
              </div>
              <button
                type="button"
                onClick={dismiss}
                className="mx-auto mt-4 h-7 rounded-md border border-white/[0.08] px-3 text-[11.5px] text-white/70 hover:bg-white/[0.04] hover:text-white"
              >
                Close
              </button>
            </div>
          ) : (
            <div className="relative flex h-[80vh] max-h-[820px] min-h-[540px] w-full flex-col overflow-hidden rounded-lg border border-white/[0.08] bg-[#111]">
              <div className="flex shrink-0 items-center justify-between border-b border-white/[0.06] px-4 py-3">
                <div className="min-w-0">
                  <h2 className="text-[13px] font-medium text-white">Processes</h2>
                  <p className="mt-0.5 truncate font-mono text-[10.5px] text-white/40">
                    {state.steam}
                  </p>
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

              <div className="flex shrink-0 items-center gap-2 border-b border-white/[0.06] px-3 py-2">
                <button
                  type="button"
                  onClick={() => void loadList()}
                  disabled={loading}
                  className="flex h-8 w-8 items-center justify-center rounded-md border border-white/[0.08] text-white/70 hover:bg-white/[0.04] hover:text-white disabled:opacity-40"
                  title="Refresh now"
                >
                  <RefreshCw className={`h-3.5 w-3.5 ${loading ? 'animate-spin' : ''}`} />
                </button>
                <button
                  type="button"
                  onClick={() => setLive((v) => !v)}
                  className={`flex h-8 items-center gap-1.5 rounded-md border px-2.5 text-[11.5px] transition-colors ${
                    live
                      ? 'border-emerald-400/30 bg-emerald-400/[0.08] text-emerald-300'
                      : 'border-white/[0.08] text-white/70 hover:bg-white/[0.04] hover:text-white'
                  }`}
                  title={live ? 'Auto-refresh on' : 'Auto-refresh off'}
                >
                  {live ? (
                    <PlayCircle className="h-3.5 w-3.5" />
                  ) : (
                    <PauseCircle className="h-3.5 w-3.5" />
                  )}
                  {live ? 'Live' : 'Paused'}
                </button>
                <div className="flex items-center gap-1.5 rounded-md border border-white/[0.08] bg-white/[0.02] px-2">
                  <Search className="h-3.5 w-3.5 text-white/40" />
                  <input
                    value={filter}
                    onChange={(e) => setFilter(e.target.value)}
                    placeholder="Filter name / path / PID"
                    className="w-56 bg-transparent py-1.5 text-[11.5px] text-white/85 outline-none placeholder:text-white/30"
                  />
                </div>
                <div className="ml-auto flex items-center gap-1">
                  <span className="text-[10.5px] text-white/40">Sort</span>
                  {(['cpu', 'mem', 'name', 'pid'] as const).map((k) => (
                    <button
                      key={k}
                      type="button"
                      onClick={() => setSort(k)}
                      className={`h-8 rounded-md px-2 text-[11px] transition-colors ${sortKey === k ? 'bg-white/[0.08] text-white' : 'text-white/50 hover:text-white/85'}`}
                    >
                      {k.toUpperCase()}
                    </button>
                  ))}
                </div>
              </div>

              <div className="flex min-h-0 flex-1">
                <div className="min-w-0 flex-1 overflow-y-auto">
                  {loading && !snap && (
                    <div className="flex items-center justify-center gap-2 py-14 text-white/45">
                      <Loader2 className="h-4 w-4 animate-spin" />
                      <span className="text-[11.5px]">Loading…</span>
                    </div>
                  )}
                  {err && !snap && (
                    <div className="mx-4 my-4 flex items-start gap-2 rounded-md border border-red-400/25 bg-red-400/[0.06] p-3 text-[11px] text-red-300/85">
                      <AlertCircle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
                      <span className="break-words">{err}</span>
                    </div>
                  )}
                  {snap && (
                    <div>
                      <div className="sticky top-0 z-10 grid grid-cols-[minmax(0,1fr)_68px_64px_92px_140px_60px] gap-3 border-b border-white/[0.06] bg-[#111] px-4 py-1.5 text-[9.5px] uppercase tracking-wider text-white/40">
                        <div>Name</div>
                        <div className="text-right">PID</div>
                        <div className="text-right">CPU</div>
                        <div className="text-right">Memory</div>
                        <div>User</div>
                        <div className="text-right">Thr</div>
                      </div>
                      {rows.map(({ p, depth, hasChildren }) => {
                        const cpu = cpuByPid.get(p.pid);
                        const active = selected?.pid === p.pid;
                        const isColl = collapsed.has(p.pid);
                        const tone = rowToneClasses(p.user);
                        const shortU = (p.user ?? '')
                          .replace(/^NT AUTHORITY\\/i, '')
                          .replace(/^BUILTIN\\/i, '');
                        return (
                          <div
                            key={p.pid}
                            role="button"
                            tabIndex={0}
                            onClick={() => onSelect(p)}
                            onMouseDown={(ev) => {
                              if (ev.detail > 1) ev.preventDefault();
                            }}
                            className={`grid w-full cursor-pointer select-none grid-cols-[minmax(0,1fr)_68px_64px_92px_140px_60px] gap-3 border-b border-white/[0.03] px-4 py-1 text-left text-[11.5px] transition-colors ${active ? 'bg-white/[0.085] ring-1 ring-inset ring-white/10' : `${tone.row} ${tone.hover}`}`}
                          >
                            <div
                              className="flex min-w-0 items-center gap-1"
                              style={{ paddingLeft: depth * 14 }}
                            >
                              {hasChildren ? (
                                <button
                                  type="button"
                                  onClick={(ev) => {
                                    ev.stopPropagation();
                                    toggleCollapsed(p.pid);
                                  }}
                                  className="flex h-4 w-4 shrink-0 items-center justify-center rounded text-white/45 hover:bg-white/[0.06] hover:text-white/80"
                                  aria-label={isColl ? 'Expand' : 'Collapse'}
                                >
                                  {isColl ? (
                                    <ChevronRight className="h-3 w-3" />
                                  ) : (
                                    <ChevronDown className="h-3 w-3" />
                                  )}
                                </button>
                              ) : (
                                <span className="inline-block h-4 w-4 shrink-0" />
                              )}
                              <span className="truncate text-white/85">{p.name}</span>
                            </div>
                            <div className="text-right font-mono text-white/55">{p.pid}</div>
                            <div className="text-right font-mono text-white/55">
                              {typeof cpu === 'number' ? cpu.toFixed(1) + '%' : '—'}
                            </div>
                            <div className="text-right font-mono text-white/55">
                              {formatBytes(p.workingSet)}
                            </div>
                            <div className="min-w-0 truncate font-mono text-[10.5px] text-white/50">
                              {shortU}
                            </div>
                            <div className="text-right font-mono text-white/45">{p.threads}</div>
                          </div>
                        );
                      })}
                    </div>
                  )}
                </div>

                <aside className="w-[340px] shrink-0 border-l border-white/[0.06] bg-white/[0.015]">
                  {selected ? (
                    <div className="flex h-full flex-col">
                      <div className="border-b border-white/[0.06] p-4">
                        <div className="text-[12px] font-medium text-white break-words">
                          {selected.name}
                        </div>
                        <div className="mt-0.5 font-mono text-[10.5px] text-white/45">
                          PID {selected.pid} · PPID {selected.ppid}
                        </div>
                        {selected.user && (
                          <div className="mt-1 font-mono text-[10.5px] text-white/60">
                            {selected.user}
                          </div>
                        )}
                        {selected.path && (
                          <div className="mt-2 break-all font-mono text-[10px] text-white/55">
                            {selected.path}
                          </div>
                        )}
                        <div className="mt-3 flex items-center gap-2">
                          <button
                            type="button"
                            onClick={() => setStrOpen((v) => !v)}
                            className="inline-flex h-7 items-center gap-1.5 rounded-md border border-white/[0.08] px-2.5 text-[11px] text-white/80 hover:bg-white/[0.04] hover:text-white"
                          >
                            <TextSearch className="h-3 w-3" />
                            Search strings
                          </button>
                        </div>
                      </div>

                      <div className="grid grid-cols-2 gap-3 border-b border-white/[0.06] p-4 text-[11px]">
                        <div>
                          <div className="text-[9.5px] uppercase tracking-wider text-white/40">
                            Working set
                          </div>
                          <div className="mt-0.5 font-mono text-white/75">
                            {formatBytes(selected.workingSet)}
                          </div>
                        </div>
                        <div>
                          <div className="text-[9.5px] uppercase tracking-wider text-white/40">
                            Virtual
                          </div>
                          <div className="mt-0.5 font-mono text-white/75">
                            {formatBytes(selected.virtualSize)}
                          </div>
                        </div>
                        <div>
                          <div className="text-[9.5px] uppercase tracking-wider text-white/40">
                            Threads
                          </div>
                          <div className="mt-0.5 font-mono text-white/75">{selected.threads}</div>
                        </div>
                        <div>
                          <div className="text-[9.5px] uppercase tracking-wider text-white/40">
                            Handles
                          </div>
                          <div className="mt-0.5 font-mono text-white/75">{selected.handles}</div>
                        </div>
                        <div>
                          <div className="text-[9.5px] uppercase tracking-wider text-white/40">
                            Session
                          </div>
                          <div className="mt-0.5 font-mono text-white/75">{selected.sessionId}</div>
                        </div>
                        <div>
                          <div className="text-[9.5px] uppercase tracking-wider text-white/40">
                            Priority
                          </div>
                          <div className="mt-0.5 font-mono text-white/75">
                            {selected.basePriority}
                          </div>
                        </div>
                        <div className="col-span-2">
                          <div className="text-[9.5px] uppercase tracking-wider text-white/40">
                            Started
                          </div>
                          <div className="mt-0.5 font-mono text-white/75">
                            {formatDate(selected.createMs)}
                            {snap && (
                              <span className="ml-2 text-white/45">
                                ({formatUptime(selected.createMs, snap.tsMs)})
                              </span>
                            )}
                          </div>
                        </div>
                      </div>

                      <div className="flex-1 overflow-y-auto p-4">
                        <button
                          type="button"
                          onClick={() => setModsOpen((v) => !v)}
                          className="mb-2 flex w-full items-center gap-1.5 rounded px-1 py-1 text-[9.5px] uppercase tracking-wider text-white/50 transition-colors hover:bg-white/[0.03] hover:text-white/70"
                        >
                          {modsOpen ? (
                            <ChevronDown className="h-3 w-3" />
                          ) : (
                            <ChevronRight className="h-3 w-3" />
                          )}
                          <Boxes className="h-3 w-3" />
                          <span>Modules</span>
                          {mods && <span className="text-white/30">· {mods.length}</span>}
                        </button>
                        {modsOpen && modsLoad && (
                          <div className="flex items-center gap-2 text-[11px] text-white/50">
                            <Loader2 className="h-3 w-3 animate-spin" />
                            <span>Loading modules…</span>
                          </div>
                        )}
                        {modsOpen && !modsLoad && modsErr && (
                          <div className="text-[11px] text-red-300/80">{modsErr}</div>
                        )}
                        {modsOpen && !modsLoad && !modsErr && mods && mods.length === 0 && (
                          <div className="text-[11px] text-white/40">No modules reported.</div>
                        )}
                        {modsOpen && !modsLoad && mods && mods.length > 0 && (
                          <div className="space-y-1">
                            {mods.map((m) => (
                              <div
                                key={m.base + m.name}
                                className="rounded border border-white/[0.05] bg-white/[0.02] px-2 py-1.5"
                              >
                                <div className="truncate text-[11px] text-white/80">{m.name}</div>
                                <div className="mt-0.5 flex items-center justify-between font-mono text-[9.5px] text-white/40">
                                  <span>{m.base}</span>
                                  <span>{formatBytes(m.size)}</span>
                                </div>
                                {m.path && (
                                  <div className="mt-0.5 truncate font-mono text-[9.5px] text-white/35">
                                    {m.path}
                                  </div>
                                )}
                              </div>
                            ))}
                          </div>
                        )}

                        <button
                          type="button"
                          onClick={() => setWinsOpen((v) => !v)}
                          className="mt-5 mb-2 flex w-full items-center gap-1.5 rounded px-1 py-1 text-[9.5px] uppercase tracking-wider text-white/50 transition-colors hover:bg-white/[0.03] hover:text-white/70"
                        >
                          {winsOpen ? (
                            <ChevronDown className="h-3 w-3" />
                          ) : (
                            <ChevronRight className="h-3 w-3" />
                          )}
                          <AppWindow className="h-3 w-3" />
                          <span>Windows</span>
                          {wins && (
                            <span className="text-white/30">
                              · {wins.length}
                              {winsTrunc ? ' (truncated)' : ''}
                            </span>
                          )}
                        </button>
                        {winsOpen && winsLoad && (
                          <div className="flex items-center gap-2 text-[11px] text-white/50">
                            <Loader2 className="h-3 w-3 animate-spin" />
                            <span>Enumerating windows…</span>
                          </div>
                        )}
                        {winsOpen && !winsLoad && winsErr && (
                          <div className="text-[11px] text-red-300/80">{winsErr}</div>
                        )}
                        {winsOpen && !winsLoad && !winsErr && wins && wins.length === 0 && (
                          <div className="text-[11px] text-white/40">No windows.</div>
                        )}
                        {winsOpen && !winsLoad && wins && wins.length > 0 && (
                          <div className="space-y-1.5">
                            {wins.map((w) => {
                              const w_ = w.rect.r - w.rect.l;
                              const h_ = w.rect.b - w.rect.t;
                              const styleFlags = formatExtraValue('style', w.style);
                              const exStyleFlags = formatExtraValue('exStyle', w.exStyle);
                              return (
                                <div
                                  key={w.hwnd}
                                  className="rounded border border-white/[0.05] bg-white/[0.02] px-2 py-1.5"
                                >
                                  <div className="flex items-center gap-1.5">
                                    {w.visible ? (
                                      <Eye className="h-3 w-3 shrink-0 text-emerald-400/80" />
                                    ) : (
                                      <EyeOff className="h-3 w-3 shrink-0 text-white/30" />
                                    )}
                                    <div className="min-w-0 flex-1 truncate text-[11px] text-white/85">
                                      {w.title || (
                                        <span className="italic text-white/40">(no title)</span>
                                      )}
                                    </div>
                                    <div className="shrink-0 font-mono text-[9px] text-white/40">
                                      {w.hwnd}
                                    </div>
                                  </div>
                                  <div className="mt-1 font-mono text-[9.5px] text-white/55">
                                    <span className="text-white/40">class:</span>{' '}
                                    {w.className || '(none)'}
                                  </div>
                                  <div className="mt-1 font-mono text-[9px] text-white/45">
                                    {w_}×{h_} @ {w.rect.l},{w.rect.t}
                                  </div>
                                  {styleFlags && styleFlags !== '0' && (
                                    <div className="mt-1">
                                      <div className="text-[9px] uppercase tracking-wider text-white/35">
                                        Style {w.style}
                                      </div>
                                      <div className="mt-0.5 font-mono text-[9.5px] leading-snug text-white/60 break-words">
                                        {styleFlags}
                                      </div>
                                    </div>
                                  )}
                                  {exStyleFlags && exStyleFlags !== '0' && (
                                    <div className="mt-1">
                                      <div className="text-[9px] uppercase tracking-wider text-white/35">
                                        Ex-Style {w.exStyle}
                                      </div>
                                      <div className="mt-0.5 font-mono text-[9.5px] leading-snug text-white/60 break-words">
                                        {exStyleFlags}
                                      </div>
                                    </div>
                                  )}
                                </div>
                              );
                            })}
                          </div>
                        )}
                      </div>
                    </div>
                  ) : (
                    <div className="flex h-full items-center justify-center px-6 text-center text-[11px] text-white/40">
                      Select a process to see details and its loaded modules.
                    </div>
                  )}
                </aside>
              </div>

              {strOpen && selected && (
                <div className="absolute inset-0 z-30 flex items-center justify-center bg-black/60 backdrop-blur-sm">
                  <div className="w-[420px] rounded-lg border border-white/[0.08] bg-[#111] p-4">
                    <div className="mb-3 flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <TextSearch className="h-3.5 w-3.5 text-white/60" />
                        <div className="text-[12px] font-medium text-white">String search</div>
                      </div>
                      <button
                        type="button"
                        onClick={() => setStrOpen(false)}
                        className="text-white/45 hover:text-white"
                        aria-label="Close"
                      >
                        <X className="h-4 w-4" />
                      </button>
                    </div>
                    <div className="mb-3 grid grid-cols-[92px_1fr] items-center gap-2">
                      <label
                        htmlFor="strmin"
                        className="text-[11px] text-white/60"
                      >
                        Minimum
                      </label>
                      <input
                        id="strmin"
                        type="number"
                        min={2}
                        max={128}
                        value={strMinLen}
                        onChange={(e) =>
                          setStrMinLen(Math.max(2, Math.min(128, Number(e.target.value) | 0)))
                        }
                        className="h-8 rounded-md border border-white/[0.08] bg-white/[0.02] px-2 font-mono text-[12px] text-white/85 outline-none focus:border-white/25"
                      />
                    </div>
                    <div className="mb-3 grid grid-cols-2 gap-x-3 gap-y-1.5">
                      <label className="flex cursor-pointer items-center gap-2 text-[11px] text-white/75">
                        <Checkbox
                          checked={strAnsi}
                          onCheckedChange={(v) => setStrAnsi(v === true)}
                        />
                        Detect ANSI
                      </label>
                      <label className="flex cursor-pointer items-center gap-2 text-[11px] text-white/75">
                        <Checkbox
                          checked={strUni}
                          onCheckedChange={(v) => setStrUni(v === true)}
                        />
                        Detect Unicode
                      </label>
                      <label className="col-span-2 flex cursor-pointer items-center gap-2 text-[11px] text-white/75">
                        <Checkbox
                          checked={strExt}
                          onCheckedChange={(v) => setStrExt(v === true)}
                        />
                        Extended Unicode (CJK / accents)
                      </label>
                    </div>
                    <div className="mb-4">
                      <div className="mb-1.5 text-[9.5px] uppercase tracking-wider text-white/40">
                        Search in the following memory types
                      </div>
                      <div className="grid grid-cols-3 gap-1.5">
                        {[
                          { k: 'priv', label: 'Private', v: strPriv, set: setStrPriv },
                          { k: 'img', label: 'Image', v: strImg, set: setStrImg },
                          { k: 'map', label: 'Mapped', v: strMap, set: setStrMap },
                        ].map((o) => (
                          <label
                            key={o.k}
                            className="flex cursor-pointer items-center gap-2 text-[11px] text-white/75"
                          >
                            <Checkbox
                              checked={o.v}
                              onCheckedChange={(v) => o.set(v === true)}
                            />
                            {o.label}
                          </label>
                        ))}
                      </div>
                    </div>
                    {strError && (
                      <div className="mb-3 flex items-start gap-1.5 rounded-md border border-red-400/25 bg-red-400/[0.06] p-2 text-[10.5px] text-red-300/85">
                        <AlertCircle className="mt-0.5 h-3 w-3 shrink-0" />
                        <span className="break-words">{strError}</span>
                      </div>
                    )}
                    <div className="flex justify-end gap-2">
                      <button
                        type="button"
                        onClick={() => setStrOpen(false)}
                        className="h-8 rounded-md border border-white/[0.08] px-3 text-[11.5px] text-white/70 hover:bg-white/[0.04] hover:text-white"
                      >
                        Cancel
                      </button>
                      <button
                        type="button"
                        onClick={() => void runStrings()}
                        disabled={strRunning}
                        className="inline-flex h-8 items-center gap-1.5 rounded-md bg-white px-3 text-[11.5px] font-medium text-black hover:bg-white/90 disabled:opacity-60"
                      >
                        {strRunning ? (
                          <>
                            <Loader2 className="h-3 w-3 animate-spin" /> Scanning…
                          </>
                        ) : (
                          <>OK</>
                        )}
                      </button>
                    </div>
                  </div>
                </div>
              )}

              {strResults && selected && (
                <div className="absolute inset-0 z-30 flex flex-col bg-[#111]">
                  <div className="flex shrink-0 items-center justify-between border-b border-white/[0.06] px-4 py-3">
                    <div className="min-w-0">
                      <div className="text-[13px] font-medium text-white">
                        {strFiltered.length.toLocaleString()} of {strResults.count.toLocaleString()}{' '}
                        results
                        {strResults.truncated && (
                          <span className="ml-2 text-amber-300/80">· truncated</span>
                        )}
                      </div>
                      <div className="mt-0.5 font-mono text-[10.5px] text-white/40">
                        {selected.name} · PID {selected.pid} · scanned{' '}
                        {formatBytes(strResults.scannedBytes)}
                        {strResults.appliedNeedle && (
                          <span className="ml-2 text-emerald-300/80">
                            · needle &quot;{strResults.appliedNeedle}&quot;
                          </span>
                        )}
                      </div>
                    </div>
                    <button
                      type="button"
                      onClick={() => setStrResults(null)}
                      className="inline-flex h-7 items-center gap-1 rounded-md border border-white/[0.08] px-2.5 text-[11.5px] text-white/70 hover:bg-white/[0.04] hover:text-white"
                    >
                      <ArrowLeft className="h-3 w-3" />
                      Back
                    </button>
                  </div>
                  <div className="flex shrink-0 items-center gap-2 border-b border-white/[0.06] px-3 py-2">
                    <ThemedSelect<typeof strMode>
                      value={strMode}
                      onChange={setStrMode}
                      options={[
                        { value: 'contains', label: 'Contains' },
                        { value: 'icontains', label: 'Contains (case-insensitive)' },
                        { value: 'regex', label: 'Regex' },
                        { value: 'iregex', label: 'Regex (case-insensitive)' },
                      ]}
                    />
                    <div className="flex flex-1 items-center gap-1.5 rounded-md border border-white/[0.08] bg-white/[0.02] px-2">
                      <Search className="h-3.5 w-3.5 text-white/40" />
                      <input
                        value={strFilter}
                        onChange={(e) => setStrFilter(e.target.value)}
                        placeholder="Filter"
                        className="w-full bg-transparent py-1.5 text-[11.5px] text-white/85 outline-none placeholder:text-white/30"
                      />
                    </div>
                    <button
                      type="button"
                      disabled={strRunning || !strFilter.trim()}
                      onClick={() =>
                        void runStrings(
                          strFilter.trim(),
                          strMode === 'icontains' || strMode === 'iregex',
                        )
                      }
                      title="Re-scan process memory using the current filter as a substring — bypasses the truncation limit"
                      className="inline-flex h-8 items-center gap-1.5 rounded-md border border-brand-border bg-brand-soft px-2.5 text-[11.5px] font-medium text-brand-strong hover:bg-brand-soft/80 hover:text-white disabled:cursor-not-allowed disabled:opacity-40"
                      style={{
                        borderColor: 'rgba(249, 96, 31, 0.45)',
                        backgroundColor: 'rgba(249, 96, 31, 0.10)',
                        color: '#ffb18a',
                      }}
                    >
                      {strRunning ? (
                        <>
                          <Loader2 className="h-3 w-3 animate-spin" /> Searching…
                        </>
                      ) : (
                        <>
                          <TextSearch className="h-3 w-3" /> Search in memory
                        </>
                      )}
                    </button>
                  </div>
                  <div className="min-h-0 flex-1 overflow-y-auto">
                    <div className="sticky top-0 z-10 grid grid-cols-[130px_130px_60px_50px_minmax(0,1fr)] gap-3 border-b border-white/[0.06] bg-[#111] px-4 py-1.5 text-[9.5px] uppercase tracking-wider text-white/40">
                      <div>Address</div>
                      <div>Base</div>
                      <div className="text-right">Length</div>
                      <div>Enc</div>
                      <div>Result</div>
                    </div>
                    {strFiltered.slice(0, 5000).map((r, i) => (
                      <div
                        key={i}
                        className="grid select-text grid-cols-[130px_130px_60px_50px_minmax(0,1fr)] gap-3 border-b border-white/[0.03] px-4 py-1 font-mono text-[10.5px] text-white/70"
                      >
                        <div className="truncate">{r.addr}</div>
                        <div className="truncate text-white/45">{r.base}</div>
                        <div className="text-right text-white/55">{r.len}</div>
                        <div className={r.enc === 'u' ? 'text-sky-300/80' : 'text-emerald-300/80'}>
                          {r.enc.toUpperCase()}
                        </div>
                        <div className="truncate text-white/85">{r.s}</div>
                      </div>
                    ))}
                    {strFiltered.length > 5000 && (
                      <div className="border-t border-white/[0.06] px-4 py-2 text-[10.5px] text-amber-300/80">
                        Rendering the first 5000 rows. Refine the filter to see fewer.
                      </div>
                    )}
                  </div>
                </div>
              )}

              <div className="flex shrink-0 items-center justify-between border-t border-white/[0.06] px-4 py-2 text-[10.5px] text-white/45">
                <div className="flex items-center gap-3">
                  {snap && (
                    <>
                      <span>
                        {rows.length} of {snap.count} processes
                      </span>
                      <span className="text-white/25">·</span>
                      <span className="flex items-center gap-1.5">
                        <Cpu className="h-3 w-3" />
                        RAM: {formatBytes(totalMemory)}
                      </span>
                    </>
                  )}
                </div>
                <button
                  type="button"
                  onClick={dismiss}
                  className="inline-flex items-center gap-1 text-white/50 hover:text-white"
                >
                  <ArrowLeft className="h-3 w-3" />
                  Close
                </button>
              </div>
            </div>
          )
        ) : null
      }
    </AnimatedDialog>
  );
}
