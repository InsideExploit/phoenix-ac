"use client";

import { useEffect, useState } from "react";
import { ChevronDown, ChevronRight, Copy, ExternalLink, Info, Radar, X } from "lucide-react";
import { AnimatedDialog } from "@/components/ui/animated-dialog";
import type { Detection } from "../types";
import {
  detectionTone,
  prettyDetectionType,
  readableExtras,
  formatDetectionReason,
} from "../detections/detection_labels";

export function DetectionViewerDialog({
  detection,
  onClose,
  onCopy,
}: {
  detection: Detection | null;
  onClose: () => void;
  onCopy: (v: string) => void;
}) {
  return (
    <AnimatedDialog open={!!detection} onClose={onClose} panelClassName="max-w-2xl phx-dialog-in">
      {(dismiss) => detection ? (
        <div className="flex max-h-[85vh] w-full flex-col overflow-hidden rounded-lg border border-white/[0.08] bg-[#111]">
          <div className="flex shrink-0 items-center justify-between border-b border-white/[0.06] px-4 py-3">
            <h2 className="text-[13px] font-medium text-white">Detection details</h2>
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
            <Body detection={detection} onCopy={onCopy} />
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

function Body({ detection, onCopy }: { detection: Detection; onCopy: (v: string) => void }) {
  const tone = detectionTone(detection.type);
  const pretty = prettyDetectionType(detection.type);
  const when = new Date(detection.createdAt).toLocaleString();
  const extras = readableExtras(detection.extras);

  const [extrasOpen, setExtrasOpen] = useState(false);
  useEffect(() => { setExtrasOpen(false); }, [detection.id]);

  return (
    <div className="overflow-hidden rounded-md border border-white/[0.06] bg-white/[0.015]">
      <div className="flex items-center justify-between gap-2 border-b border-white/[0.05] bg-white/[0.02] px-3 py-2">
        <div className="flex items-center gap-2">
          <Radar className={`h-3 w-3 ${tone.text}`} />
          <p className="text-[12px] font-medium text-white">{pretty}</p>
        </div>
      </div>

      <div className="divide-y divide-white/[0.04]">
        <Row label="Reason">
          <p className="whitespace-pre-wrap break-words text-[12px] leading-relaxed text-white/85">
            {formatDetectionReason(detection.type, detection.reason) || <span className="text-white/35">— none —</span>}
          </p>
        </Row>

        {detection.offendingPath && (
          <Row label="Offender">
            <div className="flex items-start gap-1.5">
              <p className="min-w-0 flex-1 whitespace-pre-wrap break-all font-mono text-[11px] text-white/75">
                {detection.offendingPath}
              </p>
              <button
                onClick={() => onCopy(detection.offendingPath!)}
                className="shrink-0 text-white/25 hover:text-white/70"
                aria-label="Copy offender path"
              >
                <Copy className="h-3 w-3" />
              </button>
            </div>
          </Row>
        )}

        <Row label="Screenshot">
          {detection.screenshotPath ? (
            <div className="space-y-2">
              <div className="overflow-hidden rounded-md border border-white/[0.06] bg-black">
                <img
                  src={`/api/screenshots/${detection.screenshotPath}`}
                  alt=""
                  className="block max-h-[60vh] w-full object-contain"
                />
              </div>
              <a
                href={`/api/screenshots/${detection.screenshotPath}`}
                target="_blank"
                rel="noreferrer noopener"
                className="inline-flex items-center gap-1 text-[11px] text-white/60 hover:text-white"
              >
                <ExternalLink className="h-3 w-3" />
                Open original
              </a>
            </div>
          ) : (
            <span className="text-[11.5px] text-white/35">— none —</span>
          )}
        </Row>

        <Row label="Steam HEX">
          <div className="flex items-center gap-1.5">
            <span className="truncate font-mono text-[11.5px] text-white/85">{detection.steamHex}</span>
            <button
              onClick={() => onCopy(detection.steamHex)}
              className="text-white/25 hover:text-white/70"
              aria-label="Copy Steam HEX"
            >
              <Copy className="h-3 w-3" />
            </button>
          </div>
        </Row>

        {detection.clientIp && (
          <Row label="Client IP">
            <span className="font-mono text-[11.5px] text-white/70">{detection.clientIp}</span>
          </Row>
        )}

        {detection.hardwareId && (
          <Row label="Hardware ID">
            <span className="truncate font-mono text-[11px] text-white/60">{detection.hardwareId}</span>
          </Row>
        )}

        {detection.sessionId && (
          <Row label="Session ID">
            <span className="font-mono text-[11.5px] tabular-nums text-white/70">{detection.sessionId}</span>
          </Row>
        )}

        <Row label="At">
          <span className="font-mono text-[11px] tabular-nums text-white/70">{when}</span>
        </Row>
      </div>

      {extras.length > 0 && (
        <div className="border-t border-white/[0.05]">
          <button
            type="button"
            onClick={() => setExtrasOpen((v) => !v)}
            className="flex w-full items-center justify-between gap-2 px-3 py-2 text-left transition-colors hover:bg-white/[0.03]"
          >
            <div className="flex items-center gap-2">
              <Info className="h-3 w-3 text-white/50" />
              <span className="text-[11.5px] font-medium text-white/80">
                {extrasOpen ? "Hide extra info" : "Show extra info"}
              </span>
              <span className="text-[10.5px] text-white/35">
                ({extras.length} {extras.length === 1 ? "field" : "fields"})
              </span>
            </div>
            {extrasOpen
              ? <ChevronDown  className="h-3.5 w-3.5 text-white/40" />
              : <ChevronRight className="h-3.5 w-3.5 text-white/40" />}
          </button>

          {extrasOpen && (
            <div className="border-t border-white/[0.04] divide-y divide-white/[0.04]">
              {extras.map((e) => (
                <ExtraRow key={e.key} label={e.label} value={e.value} onCopy={onCopy} />
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="grid grid-cols-[104px_1fr] items-baseline gap-3 px-3 py-2">
      <span className="text-[10px] font-medium uppercase tracking-wider leading-none text-white/35">
        {label}
      </span>
      <div className="min-w-0 leading-none">{children}</div>
    </div>
  );
}

function ExtraRow({
  label,
  value,
  onCopy,
}: {
  label: string;
  value: string;
  onCopy: (v: string) => void;
}) {
  const hasPipes = value.includes(" | ");
  const hasNewline = value.includes("\n");
  const long = value.length > 40;
  const wrap = hasPipes || hasNewline || long;
  return (
    <div className="grid grid-cols-[130px_1fr] items-baseline gap-3 px-3 py-2">
      <span className="text-[10px] font-medium uppercase tracking-wider leading-none text-white/35">
        {label}
      </span>
      <div className="flex min-w-0 items-baseline gap-1.5">
        <span
          className={`min-w-0 flex-1 font-mono text-[11px] leading-none text-white/80 ${wrap ? "whitespace-pre-wrap break-words" : "truncate"}`}
        >
          {value}
        </span>
        <button
          onClick={() => onCopy(value)}
          className="shrink-0 text-white/25 hover:text-white/70"
          aria-label={`Copy ${label}`}
        >
          <Copy className="h-3 w-3" />
        </button>
      </div>
    </div>
  );
}
