'use client';

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';

import {
  Activity,
  AlertCircle,
  Bug,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  CircleHelp,
  Copy,
  FileWarning,
  Filter,
  Loader2,
  Play,
  ScanSearch,
  Search,
  Shield,
  ShieldCheck,
  ShieldOff,
  StopCircle,
  X,
} from 'lucide-react';

import { AnimatedDialog } from '@/components/ui/animated-dialog';
import { Checkbox } from '@/components/ui/checkbox';

import type { ScansState } from '../types';

type Hit = {
  path: string;
  size: number;
  mtimeMs: number;
  ctimeMs: number;
  probablyFalse: boolean;
  signature: {
    status: string;
    signer?: string;
    issuer?: string;
    algo?: string;
    serial?: string;
    notBeforeMs?: number;
    notAfterMs?: number;
  };
  version?: {
    company?: string;
    product?: string;
    description?: string;
    fileVersion?: string;
    productVersion?: string;
    original?: string;
    copyright?: string;
  };
};

type Summary = {
  visited: number;
  scanned: number;
  hits: number;
  signedSkipped: number;
  canceled: boolean;
};

const SIG_STATUS_LABEL: Record<string, string> = {
  trusted: 'Trusted',
  unsigned: 'Not signed',
  untrusted: 'Untrusted',
  distrusted: 'Distrusted',
  error: 'Verification error',
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

function basename(p: string): string {
  const norm = p.replace(/\//g, '\\');
  const i = norm.lastIndexOf('\\');
  return i >= 0 ? norm.slice(i + 1) : norm;
}

function Stat({
  label,
  value,
  accent,
  muted,
}: {
  label: string;
  value: string;
  accent?: boolean;
  muted?: boolean;
}) {
  return (
    <span className="inline-flex items-baseline gap-1.5">
      <span
        className={`text-[9.5px] uppercase tracking-wider ${muted ? 'text-white/30' : 'text-white/40'}`}
      >
        {label}
      </span>
      <span
        className={`font-mono ${accent ? 'text-orange-300/95' : muted ? 'text-white/50' : 'text-white/85'}`}
      >
        {value}
      </span>
    </span>
  );
}

export function ScansDialog({
  state,
  onClose,
  hasElevatedAccess = false,
}: {
  state: ScansState;
  onClose: () => void;
  hasElevatedAccess?: boolean;
}) {
  const steam = state?.steam ?? '';
  const [includeSigned, setIncludeSigned] = useState(false);
  const [scanId, setScanId] = useState<number | null>(null);
  const [phase, setPhase] = useState<'idle' | 'enum' | 'scan' | 'done' | 'canceled' | 'error'>(
    'idle',
  );
  const [visited, setVisited] = useState(0);
  const [queued, setQueued] = useState(0);
  const [scanned, setScanned] = useState(0);
  const [hits, setHits] = useState<Hit[]>([]);
  const [summary, setSummary] = useState<Summary | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [starting, setStarting] = useState(false);
  const [expanded, setExpanded] = useState<Record<string, boolean>>({});
  const [filter, setFilter] = useState('');
  const [hideFalse, setHideFalse] = useState(false);
  const esRef = useRef<EventSource | null>(null);
  const doneRef = useRef(false);
  const closeStream = useCallback(() => {
    doneRef.current = true;
    if (esRef.current) {
      try {
        esRef.current.close();
      } catch {}
      esRef.current = null;
    }
  }, []);
  const reset = useCallback(() => {
    setScanId(null);
    setPhase('idle');
    setVisited(0);
    setQueued(0);
    setScanned(0);
    setHits([]);
    setSummary(null);
    setError(null);
    setExpanded({});
    setFilter('');
    setHideFalse(false);
  }, []);
  useEffect(() => {
    if (!state) {
      closeStream();
      reset();
    }
  }, [state, closeStream, reset]);
  useEffect(() => () => closeStream(), [closeStream]);
  const startScan = useCallback(async () => {
    if (!steam || starting || scanId) return;
    setStarting(true);
    setError(null);
    reset();
    try {
      const r = await fetch('/api/players/scans/start', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ steam_hex: steam, scan_type: 1, include_signed: includeSigned }),
      });
      const d = (await r.json().catch(() => null)) as {
        ok?: boolean;
        error?: string;
        scanId?: number;
      } | null;
      if (!r.ok || !d?.ok || typeof d.scanId !== 'number') {
        setError(d?.error ?? `start failed (${r.status})`);
        setPhase('error');
        return;
      }
      setScanId(d.scanId);
      setPhase('enum');
      doneRef.current = false;
      const url = new URL('/api/players/scans/events', window.location.origin);
      url.searchParams.set('steam_hex', steam);
      url.searchParams.set('scan_id', String(d.scanId));
      const es = new EventSource(url.toString(), { withCredentials: true });
      esRef.current = es;
      es.onmessage = (evt) => {
        try {
          const msg = JSON.parse(evt.data) as
            | {
                type: 'progress';
                phase: 'enum' | 'scan' | 'done' | 'canceled';
                visited: number;
                queued: number;
                scanned: number;
              }
            | {
                type: 'hit';
                hit: Hit;
              }
            | {
                type: 'done';
                summary: Summary;
              }
            | {
                type: 'error';
                error: string;
              };
          if (msg.type === 'progress') {
            setPhase(
              msg.phase === 'canceled' ? 'canceled' : msg.phase === 'done' ? 'done' : msg.phase,
            );
            setVisited(msg.visited);
            setQueued(msg.queued);
            setScanned(msg.scanned);
          } else if (msg.type === 'hit') {
            setHits((prev) => [...prev, msg.hit]);
          } else if (msg.type === 'done') {
            setSummary(msg.summary);
            setPhase(msg.summary.canceled ? 'canceled' : 'done');
            closeStream();
          } else if (msg.type === 'error') {
            setError(msg.error);
            setPhase('error');
            closeStream();
          }
        } catch {}
      };
      es.onerror = () => {
        if (doneRef.current) return;
        setError((prev) => prev ?? 'connection lost');
      };
    } catch (e) {
      setError((e as Error).message);
      setPhase('error');
    } finally {
      setStarting(false);
    }
  }, [steam, starting, scanId, includeSigned, reset, closeStream]);
  const cancelScan = useCallback(async () => {
    if (!steam || !scanId) return;
    try {
      await fetch('/api/players/scans/cancel', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ steam_hex: steam, scan_id: scanId }),
      });
    } catch {}
  }, [steam, scanId]);
  const filteredHits = useMemo(() => {
    const q = filter.trim().toLowerCase();
    return hits.filter((h) => {
      if (hideFalse && h.probablyFalse) return false;
      if (!q) return true;
      return (
        h.path.toLowerCase().includes(q) ||
        (h.signature.signer ?? '').toLowerCase().includes(q) ||
        (h.version?.product ?? '').toLowerCase().includes(q) ||
        (h.version?.description ?? '').toLowerCase().includes(q)
      );
    });
  }, [hits, filter, hideFalse]);
  const scanRunning = phase === 'enum' || phase === 'scan';
  const percent =
    phase === 'done' || phase === 'canceled'
      ? 100
      : queued > 0
        ? Math.min(99, Math.floor((scanned * 100) / queued))
        : 0;
  const gated = !hasElevatedAccess;
  return (
    <AnimatedDialog
      open={!!state}
      onClose={onClose}
      panelClassName="max-w-5xl phx-dialog-in"
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
                Your account is not authorized to run scans.
              </div>
              <button
                type="button"
                onClick={dismiss}
                className="mx-auto mt-4 h-7 rounded-md bg-white/[0.08] px-3 text-[11.5px] text-white hover:bg-white/[0.14]"
              >
                Close
              </button>
            </div>
          ) : (
            <div className="flex h-[80vh] max-h-[860px] min-h-[540px] w-full flex-col overflow-hidden rounded-lg border border-white/[0.08] bg-[#111]">
              <div className="flex shrink-0 items-center justify-between border-b border-white/[0.06] px-4 py-3">
                <div className="flex items-center gap-2">
                  <ScanSearch className="h-3.5 w-3.5 text-white/60" />
                  <div>
                    <h2 className="text-[13px] font-medium text-white">Scans</h2>
                    <p className="mt-0.5 truncate font-mono text-[10.5px] text-white/40">
                      {state.steam}
                    </p>
                  </div>
                </div>
                <button
                  type="button"
                  onClick={() => {
                    closeStream();
                    dismiss();
                  }}
                  className="text-white/45 hover:text-white"
                  aria-label="Close"
                >
                  <X className="h-4 w-4" />
                </button>
              </div>

              <div className="flex min-h-0 flex-1">
                <aside className="shrink-0 border-r border-white/[0.05] p-2 sm:w-[188px]">
                  <div className="flex w-full items-center gap-2 rounded bg-white/[0.07] px-2 py-[6px] text-left text-[11.5px] text-white">
                    <Bug className="h-3.5 w-3.5 text-orange-400/85" />
                    Manual mapper
                  </div>
                  <p className="mt-3 px-2 text-[9.5px] uppercase tracking-wider text-white/25">
                    More soon…
                  </p>
                </aside>

                <main className="flex min-w-0 flex-1 flex-col">
                  <div className="shrink-0 border-b border-white/[0.05] bg-white/[0.015] px-4 py-3">
                    <div className="flex flex-wrap items-center gap-3">
                      <div className="min-w-0 flex-1">
                        <div className="flex items-center gap-2 text-[12px] font-medium text-white">
                          <Bug className="h-3.5 w-3.5 text-orange-400/85" />
                          Manual mapper scan
                        </div>
                        <div className="mt-0.5 text-[10.5px] text-white/45">
                          Scans every fixed drive for files containing the manual-mapper signature.
                        </div>
                      </div>
                      <label className="inline-flex cursor-pointer items-center gap-2 text-[11px] text-white/70">
                        <Checkbox
                          checked={includeSigned}
                          onCheckedChange={(v) => setIncludeSigned(!!v)}
                          disabled={scanRunning}
                        />
                        Include signed files
                      </label>
                      {scanRunning ? (
                        <button
                          type="button"
                          onClick={() => void cancelScan()}
                          className="inline-flex h-8 items-center gap-1.5 rounded-md border border-red-400/30 bg-red-400/[0.08] px-3 text-[11.5px] font-medium text-red-200 hover:bg-red-400/[0.14]"
                        >
                          <StopCircle className="h-3.5 w-3.5" />
                          Cancel
                        </button>
                      ) : (
                        <button
                          type="button"
                          onClick={() => void startScan()}
                          disabled={starting}
                          className="inline-flex h-8 items-center gap-1.5 rounded-md bg-orange-500/90 px-3 text-[11.5px] font-medium text-white hover:bg-orange-500 disabled:opacity-60"
                        >
                          {starting ? (
                            <>
                              <Loader2 className="h-3.5 w-3.5 animate-spin" /> Starting…
                            </>
                          ) : (
                            <>
                              <Play className="h-3.5 w-3.5" /> Start scan
                            </>
                          )}
                        </button>
                      )}
                    </div>

                    {(scanRunning || phase === 'done' || phase === 'canceled') && (
                      <div className="mt-3">
                        <div className="flex items-center justify-between text-[10.5px] text-white/55">
                          <span>
                            {phase === 'enum' && 'Enumerating drives…'}
                            {phase === 'scan' && 'Scanning files'}
                            {phase === 'done' && 'Scan complete'}
                            {phase === 'canceled' && 'Scan canceled'}
                          </span>
                          <span className="font-mono">{percent}%</span>
                        </div>
                        <div className="mt-1 h-1.5 w-full overflow-hidden rounded-full bg-white/[0.05]">
                          <div
                            className={`h-full transition-all ${phase === 'canceled' ? 'bg-red-400/70' : 'bg-orange-400/80'}`}
                            style={{ width: `${percent}%` }}
                          />
                        </div>
                        <div className="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-[10.5px] text-white/55">
                          <Stat
                            label="Enumerated"
                            value={visited.toLocaleString()}
                          />
                          <Stat
                            label="Candidates"
                            value={queued.toLocaleString()}
                          />
                          <Stat
                            label="Scanned"
                            value={scanned.toLocaleString()}
                          />
                          <Stat
                            label="Hits"
                            value={hits.length.toLocaleString()}
                            accent={hits.length > 0}
                          />
                          {summary && summary.signedSkipped > 0 && (
                            <Stat
                              label="Signed skipped"
                              value={summary.signedSkipped.toLocaleString()}
                              muted
                            />
                          )}
                        </div>
                      </div>
                    )}

                    {error && (
                      <div className="mt-3 flex items-start gap-2 rounded-md border border-red-400/25 bg-red-400/[0.06] p-2.5 text-[11px] text-red-300/85">
                        <AlertCircle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
                        <span className="break-words">{error}</span>
                      </div>
                    )}
                  </div>

                  <div className="flex shrink-0 items-center gap-2 border-b border-white/[0.05] px-4 py-2">
                    <div className="relative min-w-0 flex-1">
                      <Search className="pointer-events-none absolute left-2 top-1/2 h-3 w-3 -translate-y-1/2 text-white/30" />
                      <input
                        value={filter}
                        onChange={(e) => setFilter(e.target.value)}
                        placeholder={
                          hits.length ? 'Filter hits by path, signer, product…' : 'No hits yet.'
                        }
                        className="h-7 w-full rounded-md border border-white/[0.06] bg-white/[0.02] pl-7 pr-2 text-[11.5px] text-white placeholder:text-white/30 focus:border-white/[0.14] focus:outline-none"
                      />
                    </div>
                    <label className="inline-flex cursor-pointer items-center gap-1.5 whitespace-nowrap text-[10.5px] text-white/60">
                      <Filter className="h-3 w-3 text-white/40" />
                      <Checkbox
                        checked={hideFalse}
                        onCheckedChange={(v) => setHideFalse(!!v)}
                      />
                      Hide probable false flags
                    </label>
                  </div>

                  <div className="flex-1 overflow-y-auto p-3">
                    {hits.length === 0 && phase === 'idle' && (
                      <div className="flex flex-col items-center gap-3 py-16 text-white/45">
                        <div className="flex h-10 w-10 items-center justify-center rounded-full border border-white/[0.06] bg-white/[0.02]">
                          <ScanSearch className="h-4 w-4" />
                        </div>
                        <p className="text-[11.5px]">
                          Start a scan to hunt for manual-mapper leftovers.
                        </p>
                      </div>
                    )}
                    {hits.length === 0 && scanRunning && (
                      <div className="flex flex-col items-center gap-3 py-16 text-white/50">
                        <div className="flex h-10 w-10 items-center justify-center rounded-full border border-orange-400/20 bg-orange-400/[0.06]">
                          <Loader2 className="h-4 w-4 animate-spin text-orange-400/80" />
                        </div>
                        <p className="text-[11.5px]">
                          Combing through {scanned.toLocaleString()} files…
                        </p>
                      </div>
                    )}
                    {hits.length === 0 && (phase === 'done' || phase === 'canceled') && (
                      <div className="flex flex-col items-center gap-3 py-16 text-emerald-300/80">
                        <div className="flex h-10 w-10 items-center justify-center rounded-full border border-emerald-400/20 bg-emerald-400/[0.06]">
                          <ShieldCheck className="h-4 w-4" />
                        </div>
                        <p className="text-[11.5px]">
                          {phase === 'canceled'
                            ? 'Scan canceled. No hits before cancel.'
                            : 'Nothing suspicious found.'}
                        </p>
                      </div>
                    )}
                    {filteredHits.length > 0 && (
                      <div className="space-y-1.5">
                        {filteredHits.map((h) => {
                          const key = h.path;
                          const isOpen = !!expanded[key];
                          const sigLabel =
                            SIG_STATUS_LABEL[h.signature.status] ?? h.signature.status ?? '';
                          const sigStatus = h.signature.status;
                          const sigTone =
                            sigStatus === 'trusted'
                              ? 'text-emerald-300/85 border-emerald-400/25 bg-emerald-400/[0.06]'
                              : sigStatus === 'unsigned' || sigStatus === ''
                                ? 'text-white/45 border-white/[0.08] bg-white/[0.03]'
                                : 'text-amber-200/85 border-amber-400/25 bg-amber-400/[0.06]';
                          const SigIcon =
                            sigStatus === 'trusted'
                              ? ShieldCheck
                              : sigStatus === 'unsigned' || sigStatus === ''
                                ? ShieldOff
                                : Shield;
                          return (
                            <div
                              key={key}
                              className={`rounded-md border transition-colors ${
                                h.probablyFalse
                                  ? 'border-amber-400/25 bg-amber-400/[0.03] hover:bg-amber-400/[0.05]'
                                  : 'border-red-400/25 bg-red-400/[0.03] hover:bg-red-400/[0.05]'
                              } ${isOpen ? 'shadow-[0_0_0_1px_rgba(255,255,255,0.03)]' : ''}`}
                            >
                              <button
                                type="button"
                                onClick={() => setExpanded((s) => ({ ...s, [key]: !s[key] }))}
                                className="flex w-full items-center gap-2 px-2.5 py-2 text-left"
                              >
                                {isOpen ? (
                                  <ChevronDown className="h-3 w-3 shrink-0 text-white/50" />
                                ) : (
                                  <ChevronRight className="h-3 w-3 shrink-0 text-white/50" />
                                )}
                                {h.probablyFalse ? (
                                  <CircleHelp className="h-4 w-4 shrink-0 text-amber-400/85" />
                                ) : (
                                  <FileWarning className="h-4 w-4 shrink-0 text-red-400/90" />
                                )}
                                <div className="min-w-0 flex-1">
                                  <div className="truncate text-[11.5px] font-medium text-white/90">
                                    {basename(h.path)}
                                  </div>
                                  <div className="truncate font-mono text-[10px] text-white/40">
                                    {h.path}
                                  </div>
                                </div>
                                <span
                                  className={`inline-flex shrink-0 items-center gap-1 rounded-sm border px-1.5 py-0.5 text-[9px] uppercase tracking-wider ${sigTone}`}
                                >
                                  <SigIcon className="h-2.5 w-2.5" />
                                  {sigLabel || 'Unknown'}
                                </span>
                                {h.probablyFalse && (
                                  <span className="shrink-0 rounded-sm border border-amber-400/30 bg-amber-400/[0.08] px-1.5 py-0.5 text-[9px] uppercase tracking-wider text-amber-200/85">
                                    Probable false
                                  </span>
                                )}
                                <div className="shrink-0 font-mono text-[10px] text-white/50">
                                  {formatBytes(h.size)}
                                </div>
                              </button>
                              {isOpen && (
                                <div className="border-t border-white/[0.05] px-3 py-2.5 text-[11px] text-white/75">
                                  <div className="mb-2 flex flex-wrap items-center gap-2">
                                    <button
                                      type="button"
                                      onClick={() => void navigator.clipboard?.writeText(h.path)}
                                      className="inline-flex h-7 items-center gap-1.5 rounded-md border border-white/[0.08] px-2.5 text-[11px] text-white/70 hover:bg-white/[0.04] hover:text-white"
                                      title="Copy full path"
                                    >
                                      <Copy className="h-3 w-3" />
                                      Copy path
                                    </button>
                                  </div>

                                  <div className="grid gap-x-4 gap-y-2 md:grid-cols-2">
                                    <section>
                                      <div className="mb-1 flex items-center gap-1.5 text-[9.5px] uppercase tracking-wider text-white/45">
                                        {h.signature.status === 'trusted' ? (
                                          <ShieldCheck className="h-3 w-3 text-emerald-400/85" />
                                        ) : h.signature.status === 'unsigned' ? (
                                          <ShieldOff className="h-3 w-3 text-white/40" />
                                        ) : (
                                          <Shield className="h-3 w-3 text-amber-400/85" />
                                        )}
                                        Signature — {sigLabel}
                                      </div>
                                      {h.signature.status !== 'unsigned' && (
                                        <div className="space-y-0.5 text-[10.5px]">
                                          {h.signature.signer && (
                                            <div>
                                              <span className="text-white/45">Signer:</span>{' '}
                                              <span className="break-words">
                                                {h.signature.signer}
                                              </span>
                                            </div>
                                          )}
                                          {h.signature.issuer && (
                                            <div>
                                              <span className="text-white/45">Issuer:</span>{' '}
                                              <span className="break-words">
                                                {h.signature.issuer}
                                              </span>
                                            </div>
                                          )}
                                          {h.signature.algo && (
                                            <div>
                                              <span className="text-white/45">Algorithm:</span>{' '}
                                              {h.signature.algo}
                                            </div>
                                          )}
                                          {(!!h.signature.notBeforeMs ||
                                            !!h.signature.notAfterMs) && (
                                            <div className="font-mono text-white/55">
                                              {formatDate(h.signature.notBeforeMs)} —{' '}
                                              {formatDate(h.signature.notAfterMs)}
                                            </div>
                                          )}
                                          {h.signature.serial && (
                                            <div className="break-all font-mono text-[9.5px] text-white/45">
                                              SN {h.signature.serial}
                                            </div>
                                          )}
                                        </div>
                                      )}
                                    </section>

                                    <section>
                                      <div className="mb-1 text-[9.5px] uppercase tracking-wider text-white/45">
                                        File
                                      </div>
                                      <div className="space-y-0.5 text-[10.5px]">
                                        <div>
                                          <span className="text-white/45">Size:</span>{' '}
                                          <span className="font-mono">{formatBytes(h.size)}</span>
                                        </div>
                                        {h.mtimeMs > 0 && (
                                          <div>
                                            <span className="text-white/45">Modified:</span>{' '}
                                            <span className="font-mono">
                                              {formatDate(h.mtimeMs)}
                                            </span>
                                          </div>
                                        )}
                                        {h.ctimeMs > 0 && (
                                          <div>
                                            <span className="text-white/45">Created:</span>{' '}
                                            <span className="font-mono">
                                              {formatDate(h.ctimeMs)}
                                            </span>
                                          </div>
                                        )}
                                      </div>
                                    </section>

                                    {h.version && (
                                      <section className="md:col-span-2">
                                        <div className="mb-1 text-[9.5px] uppercase tracking-wider text-white/45">
                                          Version info
                                        </div>
                                        <div className="space-y-0.5 text-[10.5px] text-white/75">
                                          {h.version.description && (
                                            <div className="break-words">
                                              {h.version.description}
                                            </div>
                                          )}
                                          {h.version.product &&
                                            h.version.product !== h.version.description && (
                                              <div className="text-white/60">
                                                {h.version.product}
                                              </div>
                                            )}
                                          {h.version.company && (
                                            <div className="text-white/55">{h.version.company}</div>
                                          )}
                                          {(h.version.fileVersion || h.version.productVersion) && (
                                            <div className="pt-0.5 font-mono text-[10px] text-white/45">
                                              {h.version.fileVersion
                                                ? 'v' + h.version.fileVersion
                                                : ''}
                                              {h.version.productVersion &&
                                              h.version.productVersion !== h.version.fileVersion
                                                ? ' · product v' + h.version.productVersion
                                                : ''}
                                            </div>
                                          )}
                                          {h.version.original && (
                                            <div className="pt-0.5 font-mono text-[10px] text-white/40">
                                              original: {h.version.original}
                                            </div>
                                          )}
                                          {h.version.copyright && (
                                            <div className="pt-0.5 text-[10px] text-white/40">
                                              {h.version.copyright}
                                            </div>
                                          )}
                                        </div>
                                      </section>
                                    )}
                                  </div>
                                </div>
                              )}
                            </div>
                          );
                        })}
                      </div>
                    )}
                  </div>
                </main>
              </div>

              <div className="flex shrink-0 items-center justify-between gap-2 border-t border-white/[0.06] px-4 py-3 text-[10.5px] text-white/50">
                <div className="flex items-center gap-2">
                  {scanRunning ? (
                    <Activity className="h-3 w-3 animate-pulse text-orange-400/85" />
                  ) : phase === 'done' ? (
                    <CheckCircle2 className="h-3 w-3 text-emerald-400/85" />
                  ) : phase === 'canceled' || phase === 'error' ? (
                    <AlertCircle className="h-3 w-3 text-red-400/85" />
                  ) : (
                    <ScanSearch className="h-3 w-3 text-white/40" />
                  )}
                  <span>
                    {summary
                      ? `${summary.hits} hit${summary.hits === 1 ? '' : 's'} · ${summary.scanned.toLocaleString()} files scanned · ${summary.visited.toLocaleString()} visited`
                      : scanRunning
                        ? 'Scan in progress'
                        : phase === 'error'
                          ? 'Scan errored'
                          : 'Idle'}
                  </span>
                </div>
                <button
                  onClick={() => {
                    closeStream();
                    dismiss();
                  }}
                  className="h-7 rounded-md bg-white/[0.08] px-3 text-[11.5px] font-medium text-white hover:bg-white/[0.14]"
                >
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
