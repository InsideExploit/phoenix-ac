'use client';

import { Ban, Cpu, HardDrive, Loader2, Monitor, Network, X } from 'lucide-react';

import { AnimatedDialog } from '@/components/ui/animated-dialog';

type Sys = {
  windows?: {
    productName?: string;
    displayVersion?: string;
    majorVersion?: number;
    minorVersion?: number;
    buildNumber?: number;
    ubr?: number;
    servicePack?: string;
  };
  computerName?: string;
  uptimeMs?: number;
  motherboard?: {
    manufacturer?: string;
    product?: string;
    version?: string;
    biosVendor?: string;
    biosVersion?: string;
  };
  processor?: {
    name?: string;
    vendor?: string;
    identifier?: string;
    mhz?: number;
    logicalCores?: number;
  };
  gpus?: {
    name?: string;
    vendorId?: number;
    deviceId?: number;
    subSysId?: number;
    revision?: number;
    dedicatedVideoMemory?: number;
    dedicatedSystemMemory?: number;
    sharedSystemMemory?: number;
  }[];
  disks?: {
    root?: string;
    label?: string;
    fileSystem?: string;
    driveType?: string;
    totalBytes?: number;
    freeBytes?: number;
  }[];
  networks?: {
    name?: string;
    description?: string;
    friendly?: string;
    ifType?: number;
    operStatus?: string;
    receiveSpeedBps?: number;
    transmitSpeedBps?: number;
    mac?: string;
    ips?: string[];
  }[];
};

export type SysInfoState =
  | {
      state: 'loading';
      steam: string;
    }
  | {
      state: 'ready';
      steam: string;
      info: Sys;
    }
  | {
      state: 'error';
      steam: string;
      error: string;
    }
  | null;

export function SysInfoDialog({
  state,
  onClose,
  onRetry,
}: {
  state: SysInfoState;
  onClose: () => void;
  onRetry: (steam: string) => void;
}) {
  return (
    <AnimatedDialog
      open={!!state}
      onClose={onClose}
      panelClassName="max-w-5xl phx-dialog-in"
    >
      {(dismiss) =>
        state ? (
          <div className="flex max-h-[85vh] w-full flex-col overflow-hidden rounded-lg border border-white/[0.08] bg-[#111]">
            <div className="flex shrink-0 items-center justify-between border-b border-white/[0.06] px-4 py-3">
              <div className="min-w-0">
                <h2 className="text-[13px] font-medium text-white">System info</h2>
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

            <div className="min-h-0 flex-1 overflow-y-auto p-4">
              {state.state === 'loading' && (
                <div className="flex flex-col items-center gap-2.5 py-14 text-white/45">
                  <Loader2 className="h-5 w-5 animate-spin" />
                  <p className="text-[11.5px]">Collecting on client…</p>
                </div>
              )}
              {state.state === 'error' && (
                <div className="flex flex-col items-center gap-2 py-14 text-red-400/80">
                  <Ban className="h-5 w-5" />
                  <p className="text-[11.5px]">{state.error}</p>
                </div>
              )}
              {state.state === 'ready' && <Body info={state.info} />}
            </div>

            <div className="flex shrink-0 justify-end gap-2 border-t border-white/[0.06] px-4 py-3">
              {state.state !== 'loading' && (
                <button
                  onClick={() => onRetry(state.steam)}
                  className="h-7 rounded-md border border-white/[0.08] px-3 text-[11.5px] text-white/70 hover:bg-white/[0.04] hover:text-white"
                >
                  Refresh
                </button>
              )}
              <button
                onClick={dismiss}
                className="h-7 rounded-md bg-white/[0.08] px-3 text-[11.5px] font-medium text-white hover:bg-white/[0.14]"
              >
                Close
              </button>
            </div>
          </div>
        ) : null
      }
    </AnimatedDialog>
  );
}

function fmtBytes(n?: number): string {
  if (typeof n !== 'number' || !Number.isFinite(n) || n < 0) return '—';
  const K = 1024,
    M = K * K,
    G = K * M,
    T = K * G;
  if (n >= T) return (n / T).toFixed(2) + ' TB';
  if (n >= G) return (n / G).toFixed(2) + ' GB';
  if (n >= M) return (n / M).toFixed(2) + ' MB';
  if (n >= K) return (n / K).toFixed(2) + ' KB';
  return n + ' B';
}

function fmtLinkSpeed(bps?: number): string {
  if (typeof bps !== 'number' || !Number.isFinite(bps) || bps <= 0) return '—';
  if (bps >= 100000000000) return 'unlimited';
  if (bps >= 1000000000) return (bps / 1000000000).toFixed(1).replace(/\.0$/, '') + ' Gbps';
  if (bps >= 1000000) return (bps / 1000000).toFixed(0) + ' Mbps';
  if (bps >= 1000) return (bps / 1000).toFixed(0) + ' Kbps';
  return bps + ' bps';
}

function fmtUptime(ms?: number): string {
  if (typeof ms !== 'number' || ms < 0) return '—';
  const s = Math.floor(ms / 1000);
  const d = Math.floor(s / 86400);
  const h = Math.floor((s % 86400) / 3600);
  const m = Math.floor((s % 3600) / 60);
  const parts: string[] = [];
  if (d) parts.push(d + 'd');
  if (h) parts.push(h + 'h');
  parts.push(m + 'm');
  return parts.join(' ');
}

function fmtHex(n?: number): string {
  if (typeof n !== 'number') return '—';
  return '0x' + n.toString(16).toUpperCase().padStart(4, '0');
}

function statusPill(s?: string): {
  label: string;
  cls: string;
} {
  const t = (s ?? '').toLowerCase();
  if (t === 'up')
    return { label: 'Up', cls: 'text-emerald-300/90 border-emerald-400/25 bg-emerald-400/[0.06]' };
  if (t === 'down' || t === 'lower-down')
    return { label: t, cls: 'text-red-300/90 border-red-400/25 bg-red-400/[0.06]' };
  if (t === 'not-present')
    return { label: 'Not present', cls: 'text-white/45 border-white/[0.10] bg-white/[0.03]' };
  if (t === 'dormant')
    return { label: 'Dormant', cls: 'text-amber-300/90 border-amber-400/25 bg-amber-400/[0.06]' };
  return { label: s || 'unknown', cls: 'text-white/55 border-white/[0.10] bg-white/[0.03]' };
}

function Body({ info }: { info: Sys }) {
  const win = info.windows ?? {};
  const winTitle = `${win.productName || 'Windows'} ${win.displayVersion || ''}`.trim();
  const winBuild = `${win.majorVersion ?? '?'}.${win.minorVersion ?? '?'}.${win.buildNumber ?? '?'}.${win.ubr ?? '?'}`;
  return (
    <div className="space-y-3">
      <Section
        title="System"
        icon={<Cpu className="h-3 w-3 text-sky-300/90" />}
      >
        <div className="grid grid-cols-2 gap-x-4 gap-y-2 p-3 sm:grid-cols-4">
          <Stat
            label="Computer"
            value={info.computerName || '—'}
            mono
          />
          <Stat
            label="Windows"
            value={winTitle}
          />
          <Stat
            label="Build"
            value={winBuild}
            mono
          />
          <Stat
            label="Uptime"
            value={fmtUptime(info.uptimeMs)}
            mono
          />

          <Stat
            label="Processor"
            value={<CpuValue proc={info.processor} />}
            className="col-span-2 sm:col-span-2"
          />
          <Stat
            label="Motherboard"
            value={<BoardValue board={info.motherboard} />}
            className="col-span-2 sm:col-span-2"
          />
        </div>
      </Section>

      <div className="grid gap-3 lg:grid-cols-2">
        <div className="space-y-3">
          <Section
            title={`GPUs (${info.gpus?.length ?? 0})`}
            icon={<Monitor className="h-3 w-3 text-emerald-300/90" />}
          >
            {info.gpus && info.gpus.length > 0 ? (
              <div className="divide-y divide-white/[0.04]">
                {info.gpus.map((g, i) => (
                  <div
                    key={i}
                    className="flex items-start justify-between gap-3 px-3 py-2"
                  >
                    <div className="min-w-0 flex-1">
                      <p className="truncate text-[12px] font-medium text-white">{g.name || '—'}</p>
                      <p className="mt-0.5 font-mono text-[10.5px] text-white/50">
                        VID={fmtHex(g.vendorId)} · DID={fmtHex(g.deviceId)}
                        {typeof g.subSysId === 'number' && <> · SUB={fmtHex(g.subSysId)}</>}
                        {typeof g.revision === 'number' && <> · REV={g.revision}</>}
                      </p>
                    </div>
                    <div className="shrink-0 text-right">
                      <div className="text-[12px] font-medium tabular-nums text-white">
                        {fmtBytes(g.dedicatedVideoMemory)}
                      </div>
                      {g.sharedSystemMemory || g.dedicatedSystemMemory ? (
                        <div className="text-[10px] tabular-nums text-white/40">
                          shared {fmtBytes(g.sharedSystemMemory)}
                        </div>
                      ) : null}
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <Empty />
            )}
          </Section>

          <Section
            title={`Disks (${info.disks?.length ?? 0})`}
            icon={<HardDrive className="h-3 w-3 text-amber-300/90" />}
          >
            {info.disks && info.disks.length > 0 ? (
              <div className="divide-y divide-white/[0.04]">
                {info.disks.map((d, i) => {
                  const used =
                    typeof d.totalBytes === 'number' && typeof d.freeBytes === 'number'
                      ? d.totalBytes - d.freeBytes
                      : undefined;
                  const pct =
                    typeof used === 'number' && typeof d.totalBytes === 'number' && d.totalBytes > 0
                      ? Math.round((used / d.totalBytes) * 100)
                      : undefined;
                  return (
                    <div
                      key={i}
                      className="px-3 py-2"
                    >
                      <div className="flex items-start justify-between gap-3">
                        <div className="flex min-w-0 items-center gap-2">
                          <span className="font-mono text-[12px] font-medium text-white">
                            {d.root || '—'}
                          </span>
                          {d.label && (
                            <span className="truncate text-[11.5px] text-white/70">{d.label}</span>
                          )}
                          <span className="shrink-0 rounded border border-white/[0.10] bg-white/[0.03] px-1.5 py-[1px] text-[10px] text-white/60">
                            {d.fileSystem || '?'}
                          </span>
                          <span className="shrink-0 text-[10px] uppercase tracking-wider text-white/35">
                            {d.driveType}
                          </span>
                        </div>
                        <div className="shrink-0 text-right tabular-nums text-[11.5px] text-white/80">
                          {fmtBytes(used)}{' '}
                          <span className="text-white/40">/ {fmtBytes(d.totalBytes)}</span>
                          <div className="text-[10px] text-white/40">
                            {fmtBytes(d.freeBytes)} free {typeof pct === 'number' && `· ${pct}%`}
                          </div>
                        </div>
                      </div>
                      {typeof pct === 'number' && (
                        <div className="mt-1.5 h-1 w-full overflow-hidden rounded-full bg-white/[0.05]">
                          <div
                            className={`h-full ${pct > 90 ? 'bg-red-400/80' : pct > 75 ? 'bg-amber-400/80' : 'bg-emerald-400/70'}`}
                            style={{ width: `${pct}%` }}
                          />
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            ) : (
              <Empty />
            )}
          </Section>
        </div>

        <div className="space-y-3">
          <Section
            title={`Network adapters (${info.networks?.length ?? 0})`}
            icon={<Network className="h-3 w-3 text-purple-300/90" />}
          >
            {info.networks && info.networks.length > 0 ? (
              <div className="divide-y divide-white/[0.04]">
                {info.networks.map((n, i) => {
                  const st = statusPill(n.operStatus);
                  return (
                    <div
                      key={i}
                      className="px-3 py-2"
                    >
                      <div className="flex flex-wrap items-baseline gap-x-2 gap-y-0.5">
                        <span className="truncate text-[12px] font-medium text-white">
                          {n.friendly || n.description || n.name || '—'}
                        </span>
                        <span
                          className={`shrink-0 rounded border px-1.5 py-[1px] text-[10px] ${st.cls}`}
                        >
                          {st.label}
                        </span>
                        {n.description && n.description !== n.friendly && (
                          <span className="truncate text-[10.5px] text-white/40">
                            · {n.description}
                          </span>
                        )}
                      </div>
                      <div className="mt-0.5 flex flex-wrap items-baseline gap-x-3 gap-y-0.5 font-mono text-[10.5px] text-white/55">
                        <span>{n.mac || '—'}</span>
                        <span>rx {fmtLinkSpeed(n.receiveSpeedBps)}</span>
                        <span>tx {fmtLinkSpeed(n.transmitSpeedBps)}</span>
                      </div>
                      {n.ips && n.ips.length > 0 && (
                        <div className="mt-1 flex flex-wrap gap-1">
                          {n.ips.map((ip, k) => (
                            <span
                              key={k}
                              className="rounded border border-white/[0.08] bg-white/[0.02] px-1.5 py-[1px] font-mono text-[10px] text-white/70"
                            >
                              {ip}
                            </span>
                          ))}
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            ) : (
              <Empty />
            )}
          </Section>
        </div>
      </div>
    </div>
  );
}

function Section({
  title,
  icon,
  children,
}: {
  title: string;
  icon: React.ReactNode;
  children: React.ReactNode;
}) {
  return (
    <div className="overflow-hidden rounded-md border border-white/[0.06] bg-white/[0.015]">
      <div className="flex items-center gap-2 border-b border-white/[0.05] bg-white/[0.02] px-3 py-1.5">
        {icon}
        <p className="text-[11.5px] font-medium text-white">{title}</p>
      </div>
      <div>{children}</div>
    </div>
  );
}

function Stat({
  label,
  value,
  mono,
  className,
}: {
  label: string;
  value: React.ReactNode;
  mono?: boolean;
  className?: string;
}) {
  const isNode = typeof value === 'object' && value !== null && !Array.isArray(value);
  return (
    <div className={`min-w-0 ${className ?? ''}`}>
      <div className="text-[9.5px] font-medium uppercase tracking-wider text-white/35">{label}</div>
      {isNode ? (
        <div className="mt-0.5 min-w-0 text-[12px] text-white/90">{value}</div>
      ) : (
        <div className={`mt-0.5 truncate text-[12px] text-white/90 ${mono ? 'font-mono' : ''}`}>
          {value}
        </div>
      )}
    </div>
  );
}

function CpuValue({ proc }: { proc?: Sys['processor'] }) {
  if (!proc || !proc.name) return <span className="text-white/40">—</span>;
  const mhz = proc.mhz;
  const cores = proc.logicalCores;
  return (
    <div className="min-w-0">
      <p className="truncate">{proc.name}</p>
      <p className="mt-0.5 font-mono text-[10.5px] text-white/45">
        {proc.vendor || '?'}
        {typeof cores === 'number' && cores > 0 && ` · ${cores} cores`}
        {typeof mhz === 'number' && mhz > 0 && ` · ${mhz.toLocaleString()} MHz`}
      </p>
    </div>
  );
}

function BoardValue({ board }: { board?: Sys['motherboard'] }) {
  if (!board) return <span className="text-white/40">—</span>;
  const title = [board.manufacturer, board.product].filter(Boolean).join(' ').trim();
  if (!title && !board.biosVersion) return <span className="text-white/40">—</span>;
  return (
    <div className="min-w-0">
      <p className="truncate">{title || '—'}</p>
      <p className="mt-0.5 font-mono text-[10.5px] text-white/45">
        {board.version && `v${board.version}`}
        {board.biosVersion && `${board.version ? ' · ' : ''}BIOS ${board.biosVersion}`}
      </p>
    </div>
  );
}

function Empty() {
  return <p className="px-3 py-3 text-[11.5px] text-white/35">— none —</p>;
}
