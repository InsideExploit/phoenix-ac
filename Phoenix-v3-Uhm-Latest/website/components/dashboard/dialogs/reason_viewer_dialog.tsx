'use client';

import { Ban, Copy, Eye, EyeOff, PauseCircle, Pencil, X } from 'lucide-react';

import { AnimatedDialog } from '@/components/ui/animated-dialog';

import { categoryLabel, type LookupResult, type Player } from '../types';

export function ReasonViewerDialog({
  player,
  lookups,
  onClose,
  onCopy,
  onEditBan,
  onEditSuspend,
}: {
  player: Player | null;
  lookups: Record<string, LookupResult>;
  onClose: () => void;
  onCopy: (v: string) => void;
  onEditBan?: (p: Player) => void;
  onEditSuspend?: (p: Player) => void;
}) {
  return (
    <AnimatedDialog
      open={!!player}
      onClose={onClose}
      panelClassName="max-w-md phx-dialog-in"
    >
      {(dismiss) =>
        player ? (
          <div className="w-full rounded-lg border border-white/[0.08] bg-[#111] p-4">
            <div className="mb-3 flex items-center justify-between">
              <h2 className="text-[13px] font-medium text-white">Enforcement details</h2>
              <button
                type="button"
                onClick={dismiss}
                className="text-white/45 hover:text-white"
                aria-label="Close"
              >
                <X className="h-4 w-4" />
              </button>
            </div>

            <div className="mb-3 flex items-center gap-1.5">
              <span className="truncate font-mono text-[10.5px] text-white/50">{player.steam}</span>
              <button
                onClick={() => onCopy(player.steam)}
                className="text-white/25 hover:text-white/70"
                aria-label="Copy Steam HEX"
              >
                <Copy className="h-3 w-3" />
              </button>
            </div>

            {player.banned && (
              <Section
                icon={<Ban className="h-3 w-3" />}
                accent="text-red-400/90"
                title="Banned"
                chip={{ label: categoryLabel(player.banCategory), tone: 'red' }}
                onEdit={
                  onEditBan
                    ? () => {
                        onEditBan(player);
                        dismiss();
                      }
                    : undefined
                }
              >
                <Row label="Reason">
                  <p className="whitespace-pre-wrap text-[12px] leading-relaxed text-white/85">
                    {player.banReason || <span className="text-white/35">— none —</span>}
                  </p>
                </Row>
                <Row label="Visible to player">
                  <span className="inline-flex items-center gap-1.5 text-[11.5px] text-white/70">
                    {player.banReasonPublic ? (
                      <>
                        <Eye className="h-3 w-3 text-sky-400" />
                        Full reason
                      </>
                    ) : (
                      <>
                        <EyeOff className="h-3 w-3 text-white/40" />
                        Category label only
                      </>
                    )}
                  </span>
                </Row>
                <Row label="By">
                  <Actor
                    id={player.bannedBy}
                    lookups={lookups}
                  />
                </Row>
                <Row label="At">
                  <span className="font-mono text-[11px] tabular-nums text-white/60">
                    {player.bannedAt || '—'}
                  </span>
                </Row>
              </Section>
            )}

            {player.suspended && (
              <Section
                icon={<PauseCircle className="h-3 w-3" />}
                accent="text-amber-400/90"
                title="Suspended"
                subtitle="Anticheat bypass granted"
                onEdit={
                  onEditSuspend
                    ? () => {
                        onEditSuspend(player);
                        dismiss();
                      }
                    : undefined
                }
              >
                <Row label="Reason">
                  <p className="whitespace-pre-wrap text-[12px] leading-relaxed text-white/85">
                    {player.suspendReason || <span className="text-white/35">— none —</span>}
                  </p>
                </Row>
                <Row label="By">
                  <Actor
                    id={player.suspendedBy}
                    lookups={lookups}
                  />
                </Row>
                <Row label="At">
                  <span className="font-mono text-[11px] tabular-nums text-white/60">
                    {player.suspendedAt || '—'}
                  </span>
                </Row>
              </Section>
            )}

            {!player.banned && !player.suspended && (
              <p className="text-[12.5px] text-white/45">No active enforcement on this player.</p>
            )}

            <div className="mt-4 flex justify-end">
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

function Section({
  icon,
  accent,
  title,
  subtitle,
  chip,
  onEdit,
  children,
}: {
  icon: React.ReactNode;
  accent: string;
  title: string;
  subtitle?: string;
  chip?: {
    label: string;
    tone: 'red' | 'amber';
  };
  onEdit?: () => void;
  children: React.ReactNode;
}) {
  const chipTone =
    chip?.tone === 'red'
      ? 'border-red-400/25 bg-red-400/[0.08] text-red-300/90'
      : 'border-amber-400/25 bg-amber-400/[0.08] text-amber-300/90';
  return (
    <div className="mb-3 overflow-hidden rounded-md border border-white/[0.06] bg-white/[0.015] last:mb-0">
      <div className="flex items-center justify-between gap-2 border-b border-white/[0.05] bg-white/[0.02] px-3 py-2">
        <div className="flex items-center gap-2">
          <span className={accent}>{icon}</span>
          <p className="text-[12px] font-medium text-white">{title}</p>
          {subtitle && <p className="text-[10.5px] text-white/40">{subtitle}</p>}
        </div>
        <div className="flex items-center gap-1.5">
          {chip && (
            <span className={`rounded border ${chipTone} px-1.5 py-[1px] text-[10px] font-medium`}>
              {chip.label}
            </span>
          )}
          {onEdit && (
            <button
              type="button"
              onClick={onEdit}
              className="inline-flex h-5 items-center gap-1 rounded border border-white/[0.10] bg-white/[0.03] px-1.5 text-[10px] font-medium text-white/75 hover:border-white/25 hover:bg-white/[0.08] hover:text-white"
              title="Edit"
            >
              <Pencil className="h-2.5 w-2.5" />
              Edit
            </button>
          )}
        </div>
      </div>
      <div className="divide-y divide-white/[0.04]">{children}</div>
    </div>
  );
}

function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="grid grid-cols-[104px_1fr] items-start gap-3 px-3 py-2">
      <span className="pt-[3px] text-[10px] font-medium uppercase tracking-wider text-white/35">
        {label}
      </span>
      <div className="min-w-0">{children}</div>
    </div>
  );
}

function Actor({ id, lookups }: { id: string | null; lookups: Record<string, LookupResult> }) {
  if (!id) return <span className="text-[11.5px] text-white/35">— unknown —</span>;
  const info = lookups[`|${id}`] ?? {};
  const name = info.discordName;
  const avatar = info.discordAvatar;
  const initial = (name || id).charAt(0).toUpperCase();
  return (
    <div className="flex min-w-0 items-center gap-2">
      {avatar ? (
        <img
          src={avatar}
          alt=""
          className="h-5 w-5 shrink-0 rounded-full object-cover"
        />
      ) : (
        <div className="flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-white/[0.06]">
          <span className="text-[9px] font-semibold text-white/60">{initial}</span>
        </div>
      )}
      <div className="min-w-0">
        <p className="truncate text-[12px] text-white">{name || id}</p>
        {name && <p className="truncate font-mono text-[9.5px] text-white/35">{id}</p>}
      </div>
    </div>
  );
}
