'use client';

import { useEffect, useMemo, useState } from 'react';

import {
  AlertTriangle,
  Ban,
  ChevronDown,
  ChevronRight,
  Copy,
  Cpu,
  Download,
  FileWarning,
  Filter,
  Loader2,
  ScanSearch,
  Search,
  Server,
  Shield,
  Wrench,
  X,
} from 'lucide-react';

import { AnimatedDialog } from '@/components/ui/animated-dialog';

export type PciDevice = {
  instanceId: string;
  description: string;
  friendlyName?: string;
  className?: string;
  classGuid?: string;
  manufacturer?: string;
  service?: string;
  driverPath?: string;
  driverKey?: string;
  location?: string;
  vendorId?: string;
  deviceId?: string;
  subsysId?: string;
  revision?: string;
  bus: number | null;
  device: number;

  function: number;
  present: boolean;
  status: number;
  problem: number;
  hardwareIds: string[];
  memoryRanges: {
    start: number;
    end: number;
  }[];
  hasResources: boolean;
  hasMemoryRange: boolean;
  hasDriver?: boolean;
  isPci?: boolean;
  isPciBus0?: boolean;
  fpgaCapable?: boolean;
  suspiciousDma: boolean;
  suspiciousReasons?: string[];
  dates: {
    install?: string;
    firstInstall?: string;
    lastArrival?: string;
    lastRemoval?: string;
  };
  link?: {
    currentSpeed?: number;
    currentWidth?: number;
    maxSpeed?: number;
    maxWidth?: number;
  };
};

type Tree = {
  devices: PciDevice[];
};

export type MinidumpsData = {
  folder?: string;
  dumps: MinidumpEntry[];
};

export type MinidumpEntry = {
  name: string;
  path?: string;
  size: number;
  modifiedAt?: string;
  bugcheck?: number;
  args?: string[];
  exceptionAddress?: string;
  os?: {
    major?: number;
    minor?: number;
    build?: number;
    processorArch?: number;
    numberOfProcessors?: number;
  };
  moduleCount?: number;
  modules?: {
    name: string;
    base: string;
    size: number;
    timestamp: number;
    versionMS: number;
    versionLS: number;
  }[];
  crashedModule?: string;
  processName?: string;
  stackFrames?: {
    sp: string;
    ret: string;
    mod?: string;
    off?: string;
  }[];
  dumpKind?: 'kernel' | 'user';
  mmCopyVirtualMemory?: boolean;
  error?: string;
};

export type ToolsDialogState =
  | {
      steam: string;
      tool: 'pci';
      state: 'loading';
    }
  | {
      steam: string;
      tool: 'pci';
      state: 'ready';
      data: Tree;
    }
  | {
      steam: string;
      tool: 'pci';
      state: 'error';
      error: string;
    }
  | {
      steam: string;
      tool: 'minidumps';
      state: 'loading';
    }
  | {
      steam: string;
      tool: 'minidumps';
      state: 'ready';
      data: MinidumpsData;
    }
  | {
      steam: string;
      tool: 'minidumps';
      state: 'error';
      error: string;
    }
  | null;

export function ToolsDialog({
  state,
  onClose,
  onCopy,
  onLoadPci,
  onLoadMinidumps,
  onDownloadDump,
  downloadingDump,
  onOpenProcesses,
  onOpenScans,
  hasElevatedAccess = false,
}: {
  state: ToolsDialogState;
  onClose: () => void;
  onCopy: (v: string) => void;
  onLoadPci: (steam: string) => void;
  onLoadMinidumps: (steam: string) => void;
  onDownloadDump: (steam: string, name: string) => void;
  downloadingDump: string | null;
  onOpenProcesses?: (steam: string) => void;
  onOpenScans?: (steam: string) => void;
  hasElevatedAccess?: boolean;
}) {
  return (
    <AnimatedDialog
      open={!!state}
      onClose={onClose}
      panelClassName="max-w-6xl phx-dialog-in"
    >
      {(dismiss) =>
        state ? (
          <div className="flex max-h-[88vh] w-full flex-col overflow-hidden rounded-lg border border-white/[0.08] bg-[#111]">
            <div className="flex shrink-0 items-center justify-between border-b border-white/[0.06] px-4 py-3">
              <div className="flex items-center gap-2">
                <Wrench className="h-3.5 w-3.5 text-white/60" />
                <div>
                  <h2 className="text-[13px] font-medium text-white">Tools</h2>
                  <p className="mt-0.5 truncate font-mono text-[10.5px] text-white/40">
                    {state.steam}
                  </p>
                </div>
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

            <div className="flex min-h-0 flex-1">
              <aside className="shrink-0 border-r border-white/[0.05] p-2 sm:w-[168px]">
                <ToolPill
                  active={state.tool === 'pci'}
                  onClick={() => onLoadPci(state.steam)}
                  icon={<Server className="h-3.5 w-3.5" />}
                  label="PCI devices"
                />
                <ToolPill
                  active={state.tool === 'minidumps'}
                  onClick={() => onLoadMinidumps(state.steam)}
                  icon={<FileWarning className="h-3.5 w-3.5" />}
                  label="Mini dumps"
                />
                {hasElevatedAccess && onOpenProcesses && (
                  <ToolPill
                    active={false}
                    onClick={() => onOpenProcesses(state.steam)}
                    icon={<Cpu className="h-3.5 w-3.5" />}
                    label="Processes"
                  />
                )}
                {hasElevatedAccess && onOpenScans && (
                  <ToolPill
                    active={false}
                    onClick={() => onOpenScans(state.steam)}
                    icon={<ScanSearch className="h-3.5 w-3.5" />}
                    label="Scans"
                  />
                )}
                <p className="mt-3 px-2 text-[9.5px] uppercase tracking-wider text-white/25">
                  More soon…
                </p>
                <div className="mt-1 space-y-0.5">
                  <DisabledPill
                    icon={<Shield className="h-3.5 w-3.5" />}
                    label="Modules"
                  />
                </div>
              </aside>

              <main className="min-w-0 flex-1 overflow-y-auto">
                {state.tool === 'pci' && (
                  <PciTreeContent
                    state={
                      state.state === 'loading'
                        ? { kind: 'loading' }
                        : state.state === 'error'
                          ? { kind: 'error', error: state.error }
                          : { kind: 'ready', data: state.data }
                    }
                    onCopy={onCopy}
                  />
                )}
                {state.tool === 'minidumps' && (
                  <MinidumpsContent
                    state={
                      state.state === 'loading'
                        ? { kind: 'loading' }
                        : state.state === 'error'
                          ? { kind: 'error', error: state.error }
                          : { kind: 'ready', data: state.data }
                    }
                    onCopy={onCopy}
                    onDownload={(name) => onDownloadDump(state.steam, name)}
                    downloading={downloadingDump}
                  />
                )}
              </main>
            </div>

            <div className="flex shrink-0 justify-end gap-2 border-t border-white/[0.06] px-4 py-3">
              {state.tool === 'pci' && state.state !== 'loading' && (
                <button
                  onClick={() => onLoadPci(state.steam)}
                  className="h-7 rounded-md border border-white/[0.08] px-3 text-[11.5px] text-white/70 hover:bg-white/[0.04] hover:text-white"
                >
                  Refresh
                </button>
              )}
              {state.tool === 'minidumps' && state.state !== 'loading' && (
                <button
                  onClick={() => onLoadMinidumps(state.steam)}
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

function ToolPill({
  icon,
  label,
  active,
  onClick,
}: {
  icon: React.ReactNode;
  label: string;
  active: boolean;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={
        'flex w-full items-center gap-2 rounded px-2 py-[6px] text-left text-[11.5px] transition-colors ' +
        (active
          ? 'bg-white/[0.07] text-white'
          : 'text-white/60 hover:bg-white/[0.03] hover:text-white/90')
      }
    >
      {icon} {label}
    </button>
  );
}

function DisabledPill({ icon, label }: { icon: React.ReactNode; label: string }) {
  return (
    <div className="flex w-full items-center gap-2 rounded px-2 py-[6px] text-left text-[11.5px] text-white/25">
      {icon} {label}
    </div>
  );
}

type PciContent =
  | {
      kind: 'loading';
    }
  | {
      kind: 'error';
      error: string;
    }
  | {
      kind: 'ready';
      data: Tree;
    };

function PciTreeContent({ state, onCopy }: { state: PciContent; onCopy: (v: string) => void }) {
  const [query, setQuery] = useState('');
  const [onlySuspicious, setOnlySuspicious] = useState(false);
  const [selected, setSelected] = useState<PciDevice | null>(null);
  const [collapsedClasses, setCollapsedClasses] = useState<Record<string, boolean>>({});
  useEffect(() => {
    if (state.kind === 'ready' && !selected && state.data.devices.length > 0) {
      setSelected(state.data.devices[0]);
    }
  }, [state, selected]);
  const confirmed = useMemo(
    () =>
      state.kind === 'ready' ? detectConfirmedDma(state.data.devices) : new Map<string, string>(),
    [state],
  );
  if (state.kind === 'loading') {
    return (
      <div className="flex flex-col items-center gap-2.5 py-14 text-white/45">
        <Loader2 className="h-5 w-5 animate-spin" />
        <p className="text-[11.5px]">Scanning PCI devices on client…</p>
      </div>
    );
  }
  if (state.kind === 'error') {
    return (
      <div className="flex flex-col items-center gap-2 py-14 text-red-400/80">
        <Ban className="h-5 w-5" />
        <p className="text-[11.5px]">{state.error}</p>
      </div>
    );
  }
  const devs = state.data.devices;
  const suspiciousCount = devs.filter((d) => d.suspiciousDma).length;
  const confirmedCount = confirmed.size;
  const q = query.trim().toLowerCase();
  const filtered = devs.filter((d) => {
    if (onlySuspicious && !d.suspiciousDma) return false;
    if (!q) return true;
    return (
      d.description?.toLowerCase().includes(q) ||
      d.friendlyName?.toLowerCase().includes(q) ||
      d.manufacturer?.toLowerCase().includes(q) ||
      d.vendorId?.toLowerCase().includes(q) ||
      d.deviceId?.toLowerCase().includes(q) ||
      d.instanceId?.toLowerCase().includes(q) ||
      d.service?.toLowerCase().includes(q)
    );
  });
  const byBus = new Map<string, PciDevice[]>();
  for (const d of filtered) {
    const key = d.bus === null || d.bus === undefined ? '?' : String(d.bus);
    if (!byBus.has(key)) byBus.set(key, []);
    byBus.get(key)!.push(d);
  }
  const busKeys = Array.from(byBus.keys()).sort((a, b) => {
    if (a === '?') return 1;
    if (b === '?') return -1;
    return Number(a) - Number(b);
  });
  return (
    <div className="flex min-h-full">
      <div className="flex min-w-0 flex-1 flex-col border-r border-white/[0.05]">
        <div className="sticky top-0 z-10 flex flex-wrap items-center gap-2 border-b border-white/[0.05] bg-[#111]/95 px-3 py-2 backdrop-blur">
          <div className="relative min-w-[180px] flex-1">
            <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-white/35" />
            <input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Search device, VID, DID, driver…"
              className="h-8 w-full rounded-md border border-white/[0.06] bg-white/[0.02] pl-8 pr-2.5 text-[12px] text-white placeholder:text-white/30 focus:border-white/15 focus:outline-none"
            />
          </div>
          {confirmedCount > 0 && (
            <span className="inline-flex h-8 items-center gap-1.5 rounded-md border border-red-500/40 bg-red-500/[0.08] px-2.5 text-[11.5px] font-medium text-red-300">
              <AlertTriangle className="h-3 w-3" />
              DMA Detected
              <span className="ml-1 text-[10.5px] text-red-300/70">{confirmedCount}</span>
            </span>
          )}
          <button
            type="button"
            onClick={() => setOnlySuspicious((v) => !v)}
            className={
              'inline-flex h-8 items-center gap-1.5 rounded-md border px-2.5 text-[11.5px] transition-colors ' +
              (onlySuspicious
                ? 'border-amber-400/40 bg-amber-400/[0.06] text-amber-200/90 hover:bg-amber-400/[0.10]'
                : 'border-white/[0.08] text-white/70 hover:bg-white/[0.04] hover:text-white')
            }
            title="Devices with no allocated memory range or resources"
          >
            <Filter className="h-3 w-3" />
            Possible DMA
            <span className="ml-1 text-[10.5px] text-white/40">{suspiciousCount}</span>
          </button>
          <div className="text-[10.5px] tabular-nums text-white/45">
            {filtered.length} / {devs.length}
          </div>
        </div>

        <div className="min-h-0 flex-1 overflow-y-auto">
          {busKeys.map((busKey) => {
            const items = byBus.get(busKey)!;
            const collapsed = collapsedClasses[busKey] ?? true;
            const label = busKey === '?' ? 'Unknown bus' : `PCI Bus #${busKey}`;
            return (
              <div
                key={busKey}
                className="border-b border-white/[0.04] last:border-0"
              >
                <button
                  type="button"
                  onClick={() =>
                    setCollapsedClasses((c) => ({ ...c, [busKey]: !(c[busKey] ?? true) }))
                  }
                  className="flex w-full items-center gap-1.5 bg-white/[0.02] px-3 py-1.5 text-left hover:bg-white/[0.04]"
                >
                  {collapsed ? (
                    <ChevronRight className="h-3 w-3 text-white/50" />
                  ) : (
                    <ChevronDown className="h-3 w-3 text-white/50" />
                  )}
                  <span className="text-[11.5px] font-medium text-white/85">{label}</span>
                  <span className="text-[10.5px] text-white/35">· {items.length}</span>
                </button>
                {!collapsed && (
                  <div>
                    {items.map((d) => {
                      const active = selected?.instanceId === d.instanceId;
                      const name = d.friendlyName || d.description || d.instanceId;
                      const dmaReason = confirmed.get(d.instanceId) ?? null;
                      const isConfirmed = dmaReason !== null;
                      const reasons = isConfirmed
                        ? []
                        : (d.suspiciousReasons ?? []).map(reasonLabel).filter(Boolean);
                      return (
                        <button
                          key={d.instanceId}
                          type="button"
                          onClick={() => setSelected(d)}
                          className={
                            'flex w-full items-center gap-2 px-3 py-1.5 pl-6 text-left transition-colors ' +
                            (isConfirmed
                              ? active
                                ? 'bg-red-500/[0.10]'
                                : 'bg-red-500/[0.05] hover:bg-red-500/[0.09]'
                              : active
                                ? 'bg-white/[0.06]'
                                : 'hover:bg-white/[0.03]')
                          }
                        >
                          <span
                            className={
                              'min-w-0 flex-1 truncate text-[11.5px] ' +
                              (isConfirmed ? 'text-red-100 font-medium' : 'text-white/85')
                            }
                          >
                            {name}
                          </span>
                          {isConfirmed && (
                            <span className="shrink-0 rounded border border-red-500/45 bg-red-500/[0.15] px-1.5 py-[0.5px] text-[9.5px] font-medium uppercase tracking-wider text-red-200">
                              DMA Detected
                            </span>
                          )}
                          {isConfirmed && dmaReason && (
                            <span className="shrink-0 rounded border border-red-500/30 bg-red-500/[0.08] px-1.5 py-[0.5px] text-[9.5px] text-red-200/90">
                              {dmaReason}
                            </span>
                          )}
                          {reasons.map((r, i) => (
                            <span
                              key={i}
                              className="shrink-0 rounded border border-amber-400/25 bg-amber-400/[0.05] px-1.5 py-[0.5px] text-[9.5px] text-amber-200/85"
                            >
                              {r}
                            </span>
                          ))}
                          {!isConfirmed && d.isPci && d.fpgaCapable === false && (
                            <span
                              className="shrink-0 rounded border border-cyan-400/30 bg-cyan-400/[0.06] px-1.5 py-[0.5px] text-[9.5px] text-cyan-200/85"
                              title="Max PCIe link speed > 5 GT/s — outside the FPGA DMA-card range (Gen 1/Gen 2)"
                            >
                              Not FPGA/DMA
                            </span>
                          )}
                          {!d.present && (
                            <span className="shrink-0 rounded border border-white/[0.10] bg-white/[0.03] px-1 py-[1px] text-[9.5px] text-white/50">
                              hidden
                            </span>
                          )}
                          {isConfirmed ? (
                            <AlertTriangle className="h-3 w-3 shrink-0 text-red-400" />
                          ) : d.suspiciousDma ? (
                            <AlertTriangle className="h-3 w-3 shrink-0 text-amber-400/80" />
                          ) : null}
                        </button>
                      );
                    })}
                  </div>
                )}
              </div>
            );
          })}

          {filtered.length === 0 && (
            <p className="px-4 py-10 text-center text-[12px] text-white/40">
              No devices match your filters.
            </p>
          )}
        </div>
      </div>

      <div className="hidden min-w-0 shrink-0 sm:block sm:w-[380px] lg:w-[440px]">
        {selected ? (
          <PciDetail
            device={selected}
            confirmedDma={confirmed.get(selected.instanceId) ?? null}
            onCopy={onCopy}
          />
        ) : (
          <p className="px-4 py-10 text-center text-[12px] text-white/40">Select a device.</p>
        )}
      </div>
    </div>
  );
}

function PciDetail({
  device: d,
  confirmedDma,
  onCopy,
}: {
  device: PciDevice;
  confirmedDma: string | null;
  onCopy: (v: string) => void;
}) {
  const title = d.friendlyName || d.description || d.instanceId;
  const pciLoc = d.isPci
    ? `PCI bus ${d.bus ?? '?'}, device ${d.device}, function ${d.function}`
    : '';
  const location = d.location || pciLoc;
  const dates = d.dates ?? {};
  const reasonLabels = (d.suspiciousReasons ?? []).map(reasonLabel).filter(Boolean);
  return (
    <div className="space-y-3 p-3">
      <div>
        <div className="flex items-start justify-between gap-2">
          <p
            className={
              'min-w-0 text-[12.5px] font-medium leading-snug ' +
              (confirmedDma ? 'text-red-100' : 'text-white')
            }
          >
            {title}
          </p>
          {confirmedDma ? (
            <span className="shrink-0 rounded border border-red-500/45 bg-red-500/[0.14] px-1.5 py-[1px] text-[10px] font-semibold uppercase tracking-wider text-red-200">
              DMA Detected
            </span>
          ) : d.suspiciousDma ? (
            <span className="shrink-0 rounded border border-amber-400/30 bg-amber-400/[0.07] px-1.5 py-[1px] text-[10px] font-medium text-amber-200/90">
              Possible DMA
            </span>
          ) : d.isPci && d.fpgaCapable === false ? (
            <span
              className="shrink-0 rounded border border-cyan-400/30 bg-cyan-400/[0.07] px-1.5 py-[1px] text-[10px] font-medium text-cyan-200/90"
              title="Max PCIe link speed > 5 GT/s — outside the FPGA DMA-card range (Gen 1/Gen 2)"
            >
              Not FPGA/DMA
            </span>
          ) : null}
        </div>
        <p className="mt-1 truncate font-mono text-[10.5px] text-white/40">{d.instanceId}</p>
        {confirmedDma && (
          <div className="mt-2 rounded-md border border-red-500/25 bg-red-500/[0.06] px-2.5 py-1.5 text-[11px] text-red-100">
            {confirmedDma}
          </div>
        )}
        {!confirmedDma && d.suspiciousDma && reasonLabels.length > 0 && (
          <div className="mt-2 flex flex-wrap gap-1">
            {reasonLabels.map((r, i) => (
              <span
                key={i}
                className="rounded border border-amber-400/25 bg-amber-400/[0.05] px-1.5 py-[1px] text-[10px] text-amber-200/85"
              >
                {r}
              </span>
            ))}
          </div>
        )}
      </div>

      <Section title="Identity">
        <MonoRow
          label="VID"
          value={d.vendorId ? '0x' + d.vendorId : '—'}
          onCopy={onCopy}
        />
        <MonoRow
          label="DID"
          value={d.deviceId ? '0x' + d.deviceId : '—'}
          onCopy={onCopy}
        />
        <MonoRow
          label="SUBSYS"
          value={d.subsysId ? '0x' + d.subsysId : '—'}
          onCopy={onCopy}
        />
        <MonoRow
          label="REV"
          value={d.revision ? '0x' + d.revision : '—'}
          onCopy={onCopy}
        />
        <MonoRow
          label="Class"
          value={d.className || '—'}
        />
        <MonoRow
          label="Vendor"
          value={d.manufacturer || '—'}
          wide
        />
      </Section>

      {(d.isPci || location) && (
        <Section title="Location">
          {location && (
            <MonoRow
              label="Location"
              value={location}
              wide
            />
          )}
          {d.isPci && (
            <>
              <MonoRow
                label="Bus"
                value={d.bus === null ? '—' : String(d.bus)}
              />
              <MonoRow
                label="Device"
                value={String(d.device)}
              />
              <MonoRow
                label="Function"
                value={String(d.function)}
              />
            </>
          )}
        </Section>
      )}

      {d.isPci && (
        <Section title="Link">
          <MonoRow
            label="Current"
            value={fmtLink(d.link?.currentSpeed, d.link?.currentWidth)}
          />
          <MonoRow
            label="Max"
            value={fmtLink(d.link?.maxSpeed, d.link?.maxWidth)}
          />
        </Section>
      )}

      <Section title="Driver">
        <MonoRow
          label="Service"
          value={d.service || '—'}
          onCopy={onCopy}
        />
        <MonoRow
          label="Path"
          value={d.driverPath || '—'}
          onCopy={onCopy}
          wide
        />
      </Section>

      {(d.isPci || d.memoryRanges.length > 0) && (
        <Section title={`Resources${d.suspiciousDma ? ' · empty' : ''}`}>
          {d.memoryRanges.length === 0 ? (
            <p className="px-3 py-2 text-[11px] text-white/40">No memory ranges allocated.</p>
          ) : (
            <div className="divide-y divide-white/[0.04]">
              {d.memoryRanges.map((r, i) => (
                <div
                  key={i}
                  className="flex items-baseline justify-between gap-2 px-3 py-1.5 font-mono text-[10.5px] text-white/75"
                >
                  <span>
                    {fmtHex64(r.start)} — {fmtHex64(r.end)}
                  </span>
                  <span className="text-white/40">{fmtBytes(r.end - r.start + 1)}</span>
                </div>
              ))}
            </div>
          )}
        </Section>
      )}

      <Section title="Hardware IDs">
        <div className="space-y-1 px-3 py-2">
          {d.hardwareIds.length === 0 ? (
            <p className="text-[11px] text-white/40">— none —</p>
          ) : (
            d.hardwareIds.map((h, i) => (
              <div
                key={i}
                className="flex items-center gap-1.5"
              >
                <span className="min-w-0 flex-1 truncate font-mono text-[10.5px] text-white/70">
                  {h}
                </span>
                <button
                  onClick={() => onCopy(h)}
                  className="text-white/25 hover:text-white/70"
                  aria-label="Copy hardware ID"
                >
                  <Copy className="h-3 w-3" />
                </button>
              </div>
            ))
          )}
        </div>
      </Section>

      <Section title="Events">
        <MonoRow
          label="Installed"
          value={fmtDate(dates.install) || '—'}
        />
        <MonoRow
          label="First install"
          value={fmtDate(dates.firstInstall) || '—'}
        />
        <MonoRow
          label="Last arrival"
          value={fmtDate(dates.lastArrival) || '—'}
        />
        <MonoRow
          label="Last removal"
          value={fmtDate(dates.lastRemoval) || '—'}
        />
      </Section>

      <Section title="State">
        <MonoRow
          label="Present"
          value={d.present ? 'yes' : 'no (hidden / phantom)'}
        />
        <MonoRow
          label="Status"
          value={'0x' + d.status.toString(16).toUpperCase().padStart(8, '0')}
        />
        <MonoRow
          label="Problem"
          value={d.problem === 0 ? '0 (none)' : String(d.problem)}
        />
      </Section>
    </div>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="overflow-hidden rounded-md border border-white/[0.06] bg-white/[0.015]">
      <div className="border-b border-white/[0.05] bg-white/[0.02] px-3 py-1.5 text-[10.5px] font-medium uppercase tracking-wider text-white/45">
        {title}
      </div>
      <div>{children}</div>
    </div>
  );
}

function MonoRow({
  label,
  value,
  onCopy,
  wide,
}: {
  label: string;
  value: string;
  onCopy?: (v: string) => void;
  wide?: boolean;
}) {
  return (
    <div
      className={`grid ${wide ? 'grid-cols-[92px_1fr]' : 'grid-cols-[92px_1fr]'} items-start gap-2 px-3 py-1.5`}
    >
      <span className="pt-[2px] text-[9.5px] font-medium uppercase tracking-wider text-white/35">
        {label}
      </span>
      <div className="flex min-w-0 items-start gap-1.5">
        <span
          className={`min-w-0 flex-1 font-mono text-[11px] text-white/80 ${wide ? 'whitespace-pre-wrap break-all' : 'truncate'}`}
        >
          {value}
        </span>
        {onCopy && value && value !== '—' && (
          <button
            onClick={() => onCopy(value)}
            className="shrink-0 text-white/25 hover:text-white/70"
            aria-label={`Copy ${label}`}
          >
            <Copy className="h-3 w-3" />
          </button>
        )}
      </div>
    </div>
  );
}

function fmtHex64(n: number): string {
  if (!Number.isFinite(n) || n < 0) return '—';
  if (n <= 0xffffffff) return '0x' + n.toString(16).toUpperCase().padStart(8, '0');
  return '0x' + n.toString(16).toUpperCase().padStart(16, '0');
}

function fmtBytes(n: number): string {
  if (!Number.isFinite(n) || n < 0) return '—';
  const K = 1024,
    M = K * K,
    G = K * M;
  if (n >= G) return (n / G).toFixed(2) + ' GiB';
  if (n >= M) return (n / M).toFixed(2) + ' MiB';
  if (n >= K) return (n / K).toFixed(2) + ' KiB';
  return n + ' B';
}

type MinidumpsContentState =
  | {
      kind: 'loading';
    }
  | {
      kind: 'error';
      error: string;
    }
  | {
      kind: 'ready';
      data: MinidumpsData;
    };

const BUGCHECK_LABELS: Record<number, string> = {
  0x0a: 'IRQL_NOT_LESS_OR_EQUAL',
  0x1e: 'KMODE_EXCEPTION_NOT_HANDLED',
  0x24: 'NTFS_FILE_SYSTEM',
  0x3b: 'SYSTEM_SERVICE_EXCEPTION',
  0x4e: 'PFN_LIST_CORRUPT',
  0x50: 'PAGE_FAULT_IN_NONPAGED_AREA',
  0x7e: 'SYSTEM_THREAD_EXCEPTION_NOT_HANDLED',
  0x7f: 'UNEXPECTED_KERNEL_MODE_TRAP',
  0x9f: 'DRIVER_POWER_STATE_FAILURE',
  0xc1: 'SPECIAL_POOL_DETECTED_MEMORY_CORRUPTION',
  0xc4: 'DRIVER_VERIFIER_DETECTED_VIOLATION',
  0xc5: 'DRIVER_CORRUPTED_EXPOOL',
  0xc7: 'TIMER_OR_DPC_INVALID',
  0xce: 'DRIVER_UNLOADED_WITHOUT_CANCELLING_PENDING_OPERATIONS',
  0xd1: 'DRIVER_IRQL_NOT_LESS_OR_EQUAL',
  0xe4: 'WORKER_INVALID',
  0xef: 'CRITICAL_PROCESS_DIED',
  0xf4: 'CRITICAL_OBJECT_TERMINATION',
  0x109: 'CRITICAL_STRUCTURE_CORRUPTION',
  0x116: 'VIDEO_TDR_ERROR',
  0x117: 'VIDEO_TDR_TIMEOUT_DETECTED',
  0x124: 'WHEA_UNCORRECTABLE_ERROR',
  0x139: 'KERNEL_SECURITY_CHECK_FAILURE',
  0x144: 'USB_BUGCODE',
  0x14a: 'KERNEL_MODE_HEAP_CORRUPTION',
  0x154: 'UNEXPECTED_STORE_EXCEPTION',
  0x18b: 'KERNEL_AUTO_BOOST_INVALID_LOCK_RELEASE',
  0x18e: 'KERNEL_MODE_HEAP_CORRUPTION',
};

function bugcheckLabel(code?: number): string {
  if (typeof code !== 'number') return '—';
  return BUGCHECK_LABELS[code] ?? 'UNKNOWN';
}

function MinidumpsContent({
  state,
  onCopy,
  onDownload,
  downloading,
}: {
  state: MinidumpsContentState;
  onCopy: (v: string) => void;
  onDownload: (name: string) => void;
  downloading: string | null;
}) {
  const [selected, setSelected] = useState<MinidumpEntry | null>(null);
  const [onlyFiveM, setOnlyFiveM] = useState(false);
  const [query, setQuery] = useState('');
  useEffect(() => {
    if (state.kind === 'ready' && state.data.dumps.length > 0) {
      setSelected((cur) => cur ?? state.data.dumps[0]);
    }
  }, [state]);
  if (state.kind === 'loading') {
    return (
      <div className="flex flex-col items-center gap-2.5 py-14 text-white/45">
        <Loader2 className="h-5 w-5 animate-spin" />
        <p className="text-[11.5px]">Reading dumps from client…</p>
      </div>
    );
  }
  if (state.kind === 'error') {
    return (
      <div className="flex flex-col items-center gap-2 py-14 text-red-400/80">
        <Ban className="h-5 w-5" />
        <p className="text-[11.5px]">{state.error}</p>
      </div>
    );
  }
  const dumps = state.data.dumps;
  const q = query.trim().toLowerCase();
  const isFiveM = (d: MinidumpEntry) => (d.processName || '').toLowerCase().includes('fivem');
  const filtered = dumps.filter((d) => {
    if (onlyFiveM && !isFiveM(d)) return false;
    if (!q) return true;
    return (
      d.name.toLowerCase().includes(q) ||
      (d.crashedModule || '').toLowerCase().includes(q) ||
      (d.processName || '').toLowerCase().includes(q) ||
      bugcheckLabel(d.bugcheck).toLowerCase().includes(q)
    );
  });
  const fiveMCount = dumps.filter(isFiveM).length;
  return (
    <div className="flex min-h-full">
      <div className="flex min-w-0 flex-1 flex-col border-r border-white/[0.05]">
        <div className="sticky top-0 z-10 flex flex-wrap items-center gap-2 border-b border-white/[0.05] bg-[#111]/95 px-3 py-2 backdrop-blur">
          <div className="relative min-w-[160px] flex-1">
            <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-white/35" />
            <input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Search name, module, bugcheck…"
              className="h-8 w-full rounded-md border border-white/[0.06] bg-white/[0.02] pl-8 pr-2.5 text-[12px] text-white placeholder:text-white/30 focus:border-white/15 focus:outline-none"
            />
          </div>
          <button
            type="button"
            onClick={() => setOnlyFiveM((v) => !v)}
            className={
              'inline-flex h-8 items-center gap-1.5 rounded-md border px-2.5 text-[11.5px] transition-colors ' +
              (onlyFiveM
                ? 'border-sky-400/40 bg-sky-400/[0.06] text-sky-200/90 hover:bg-sky-400/[0.10]'
                : 'border-white/[0.08] text-white/70 hover:bg-white/[0.04] hover:text-white')
            }
            title="Dumps whose crashing process name contains FiveM"
          >
            <Filter className="h-3 w-3" />
            FiveM
            <span className="ml-1 text-[10.5px] text-white/40">{fiveMCount}</span>
          </button>
          <div className="text-[10.5px] tabular-nums text-white/45">
            {filtered.length} / {dumps.length}
          </div>
        </div>

        <div className="min-h-0 flex-1 overflow-y-auto">
          {filtered.length === 0 && (
            <p className="px-4 py-10 text-center text-[12px] text-white/40">
              {dumps.length === 0 ? 'No minidumps on client.' : 'No dumps match your filters.'}
            </p>
          )}
          {filtered.map((d) => {
            const active = selected?.name === d.name;
            const label = bugcheckLabel(d.bugcheck);
            const isFm = isFiveM(d);
            return (
              <button
                key={d.name}
                type="button"
                onClick={() => setSelected(d)}
                className={
                  'flex w-full items-start gap-2 border-b border-white/[0.04] px-3 py-2 text-left transition-colors last:border-0 ' +
                  (active ? 'bg-white/[0.06]' : 'hover:bg-white/[0.03]')
                }
              >
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="truncate font-mono text-[11.5px] text-white/90">{d.name}</span>
                    <span className="shrink-0 rounded border border-white/[0.10] bg-white/[0.03] px-1.5 py-[0.5px] font-mono text-[9.5px] text-white/60">
                      0x{(d.bugcheck ?? 0).toString(16).toUpperCase()}
                    </span>
                    <span className="shrink-0 text-[10.5px] text-white/60">{label}</span>
                    {isFm && (
                      <span className="shrink-0 rounded border border-sky-400/40 bg-sky-400/[0.08] px-1.5 py-[0.5px] text-[9.5px] font-medium text-sky-200">
                        FiveM
                      </span>
                    )}
                  </div>
                  <div className="mt-0.5 flex flex-wrap gap-x-3 gap-y-0.5 text-[10.5px] text-white/40">
                    {d.crashedModule && (
                      <span>
                        Module: <span className="text-white/70">{d.crashedModule}</span>
                      </span>
                    )}
                    {d.modifiedAt && <span>· {fmtDate(d.modifiedAt)}</span>}
                    <span>· {fmtBytes(d.size)}</span>
                  </div>
                </div>
              </button>
            );
          })}
        </div>
      </div>

      <div className="hidden min-w-0 shrink-0 sm:block sm:w-[420px]">
        {selected ? (
          <MinidumpDetail
            dump={selected}
            onCopy={onCopy}
            onDownload={onDownload}
            downloading={downloading === selected.name}
          />
        ) : (
          <p className="px-4 py-10 text-center text-[12px] text-white/40">Select a dump.</p>
        )}
      </div>
    </div>
  );
}

function MinidumpDetail({
  dump: d,
  onCopy,
  onDownload,
  downloading,
}: {
  dump: MinidumpEntry;
  onCopy: (v: string) => void;
  onDownload: (name: string) => void;
  downloading: boolean;
}) {
  const label = bugcheckLabel(d.bugcheck);
  const codeHex = '0x' + (d.bugcheck ?? 0).toString(16).toUpperCase();
  const isFm = (d.processName || '').toLowerCase().includes('fivem');
  const os = d.os ?? {};
  return (
    <div className="space-y-3 p-3">
      <div>
        <div className="flex items-start justify-between gap-2">
          <p className="min-w-0 text-[12.5px] font-medium leading-snug text-white">{label}</p>
          <div className="flex shrink-0 items-center gap-1.5">
            {isFm && (
              <span className="rounded border border-sky-400/40 bg-sky-400/[0.08] px-1.5 py-[0.5px] text-[9.5px] font-medium text-sky-200">
                FiveM
              </span>
            )}
            <span className="rounded border border-white/[0.10] bg-white/[0.03] px-1.5 py-[1px] font-mono text-[10px] text-white/70">
              {codeHex}
            </span>
          </div>
        </div>
        <p className="mt-1 truncate font-mono text-[10.5px] text-white/40">{d.name}</p>
        {d.error && (
          <div className="mt-2 rounded-md border border-red-500/25 bg-red-500/[0.06] px-2.5 py-1.5 text-[11px] text-red-200">
            Parse error: {d.error}
          </div>
        )}
      </div>

      <Section title="Basics">
        <MonoRow
          label="Modified"
          value={fmtDate(d.modifiedAt) || '—'}
        />
        <MonoRow
          label="Size"
          value={fmtBytes(d.size)}
        />
        <MonoRow
          label="Path"
          value={d.path || '—'}
          onCopy={onCopy}
          wide
        />
      </Section>

      {typeof d.bugcheck === 'number' && (
        <Section title="Bugcheck">
          <MonoRow
            label="Code"
            value={`${codeHex} (${label})`}
          />
          {(d.args ?? []).map((a, i) => (
            <MonoRow
              key={i}
              label={`Arg${i + 1}`}
              value={a}
              onCopy={onCopy}
            />
          ))}
          {d.exceptionAddress && (
            <MonoRow
              label="ExAddr"
              value={d.exceptionAddress}
              onCopy={onCopy}
            />
          )}
        </Section>
      )}

      <Section title="Failure">
        <MonoRow
          label="Module"
          value={d.crashedModule || '—'}
        />
        <MonoRow
          label="Process"
          value={d.processName || '—'}
        />
      </Section>

      <Section title="OS">
        <MonoRow
          label="Version"
          value={`${os.major ?? '?'}.${os.minor ?? '?'}.${os.build ?? '?'}`}
        />
        <MonoRow
          label="Arch"
          value={
            os.processorArch === 9
              ? 'x64'
              : os.processorArch === 0
                ? 'x86'
                : os.processorArch === 12
                  ? 'ARM64'
                  : String(os.processorArch ?? '?')
          }
        />
        <MonoRow
          label="CPUs"
          value={String(os.numberOfProcessors ?? '?')}
        />
      </Section>

      <div className="p-3">
        <button
          type="button"
          onClick={() => onDownload(d.name)}
          disabled={downloading}
          className="inline-flex h-8 w-full items-center justify-center gap-1.5 rounded-md border border-white/[0.10] bg-white/[0.03] px-3 text-[11.5px] text-white/80 transition-colors hover:bg-white/[0.06] hover:text-white disabled:cursor-not-allowed disabled:opacity-50"
        >
          {downloading ? (
            <>
              <Loader2 className="h-3.5 w-3.5 animate-spin" />
              Downloading…
            </>
          ) : (
            <>
              <Download className="h-3.5 w-3.5" />
              Download this dump
            </>
          )}
        </button>
      </div>
    </div>
  );
}

function fmtLink(speed?: number, width?: number): string {
  const speedMap: Record<number, string> = {
    1: '2.5 GT/s (Gen 1)',
    2: '5 GT/s (Gen 2)',
    3: '8 GT/s (Gen 3)',
    4: '16 GT/s (Gen 4)',
    5: '32 GT/s (Gen 5)',
    6: '64 GT/s (Gen 6)',
  };
  const s = typeof speed === 'number' && speed > 0 ? (speedMap[speed] ?? `code ${speed}`) : null;
  const w = typeof width === 'number' && width > 0 ? `x${width}` : null;
  if (!s && !w) return '—';
  return [s, w].filter(Boolean).join(' · ');
}

function fmtDate(iso?: string): string {
  if (!iso) return '';
  const t = Date.parse(iso);
  if (!Number.isFinite(t)) return iso;
  return new Date(t).toLocaleString();
}

function reasonLabel(code: string): string {
  switch (code) {
    case 'driver-missing':
      return 'Driver missing';
    case 'driver-problem':
      return 'Driver problem';
    case 'no-resources':
      return 'No resources allocated';
    case 'no-memory-range':
      return 'No memory range';
    default:
      return code;
  }
}

const KNOWN_DMA_IDS: {
  vid: string;
  did: string;
  label: string;
}[] = [
  { vid: '8301', did: '00AC', label: 'ISA Bridge' },
  { vid: '1D6A', did: '07B1', label: 'C110/ASUS' },
  { vid: '8086', did: '125C', label: 'I226-V' },
];

const DUPE_LATEST_IDS: {
  vid: string;
  did: string;
  label: string;
}[] = [{ vid: '1B21', did: '2142', label: 'ASMedia Technology Inc.' }];

function isIsaBridge(d: PciDevice): boolean {
  const s = ((d.description || '') + ' ' + (d.friendlyName || '')).toLowerCase();
  return s.includes('isa bridge');
}

function deviceInstalledAt(d: PciDevice): number {
  const dates = d.dates ?? {};
  const t1 = dates.install ? Date.parse(dates.install) : NaN;
  const t2 = dates.firstInstall ? Date.parse(dates.firstInstall) : NaN;
  const t3 = dates.lastArrival ? Date.parse(dates.lastArrival) : NaN;
  const arr = [t1, t2, t3].filter((x) => Number.isFinite(x));
  return arr.length > 0 ? Math.max(...arr) : 0;
}

function detectConfirmedDma(devices: PciDevice[]): Map<string, string> {
  const out = new Map<string, string>();
  for (const d of devices) {
    const vid = (d.vendorId || '').toUpperCase();
    const did = (d.deviceId || '').toUpperCase();
    if (vid === '0000') {
      out.set(d.instanceId, 'Hidden Firmware');
      continue;
    }
    for (const k of KNOWN_DMA_IDS) {
      if (vid === k.vid.toUpperCase() && did === k.did.toUpperCase()) {
        out.set(d.instanceId, k.label);
      }
    }
  }
  const isa = devices.filter(isIsaBridge);
  if (isa.length >= 2) {
    for (const d of isa) {
      if (d.bus !== null && d.bus !== 0) {
        if (!out.has(d.instanceId)) {
          out.set(d.instanceId, 'ISA Bridge');
        }
      }
    }
  }
  for (const d of devices) {
    const vid = (d.vendorId || '').toUpperCase();
    const did = (d.deviceId || '').toUpperCase();
    if (vid === '1022' && did === '1485' && d.link?.currentSpeed === 2) {
      if (!out.has(d.instanceId)) out.set(d.instanceId, 'Starship AMD PCI');
    }
  }
  for (const rule of DUPE_LATEST_IDS) {
    const matches = devices.filter(
      (d) =>
        (d.vendorId || '').toUpperCase() === rule.vid.toUpperCase() &&
        (d.deviceId || '').toUpperCase() === rule.did.toUpperCase(),
    );
    if (matches.length < 2) continue;
    let latest = matches[0];
    let latestT = deviceInstalledAt(latest);
    for (let i = 1; i < matches.length; ++i) {
      const t = deviceInstalledAt(matches[i]);
      if (t > latestT) {
        latest = matches[i];
        latestT = t;
      }
    }
    if (!out.has(latest.instanceId)) out.set(latest.instanceId, rule.label);
  }
  return out;
}
