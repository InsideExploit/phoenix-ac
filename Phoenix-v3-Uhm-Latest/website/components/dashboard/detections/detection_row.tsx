'use client';

import { Camera, Radar } from 'lucide-react';

import type { Detection } from '../types';
import { detectionTone, formatDetectionReason, prettyDetectionType } from './detection_labels';

export function DetectionRow({
  detection,
  index,
  onOpen,
}: {
  detection: Detection;
  index: number;
  onOpen: (d: Detection) => void;
}) {
  const tone = detectionTone(detection.type);
  const pretty = prettyDetectionType(detection.type);
  const prettyReason = formatDetectionReason(detection.type, detection.reason);
  const time = new Date(detection.createdAt).toLocaleTimeString(undefined, {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  });
  return (
    <button
      type="button"
      onClick={() => onOpen(detection)}
      style={{ animationDelay: `${index * 22}ms` }}
      className="row-in flex w-full items-center gap-3 rounded-md border border-white/[0.05] bg-white/[0.015] px-3 py-2.5 text-left transition-colors hover:border-white/15 hover:bg-white/[0.04]"
    >
      <div
        className={`flex h-8 w-8 shrink-0 items-center justify-center rounded-md border ${tone.border} ${tone.bg}`}
      >
        <Radar className={`h-3.5 w-3.5 ${tone.text}`} />
      </div>

      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-2">
          <p className="truncate text-[12.5px] font-medium text-white">{pretty}</p>
          {detection.screenshotPath && (
            <Camera
              className="h-3 w-3 shrink-0 text-white/45"
              aria-label="Screenshot attached"
            />
          )}
        </div>
        <div className="mt-0.5 flex flex-wrap items-center gap-x-2 gap-y-0.5 text-[10.5px] text-white/45">
          <span className="font-mono">{detection.steamHex}</span>
          {prettyReason && <span className="truncate text-white/60">{prettyReason}</span>}
        </div>
      </div>

      <span className="shrink-0 whitespace-nowrap font-mono text-[10.5px] tabular-nums text-white/40">
        {time}
      </span>
    </button>
  );
}
