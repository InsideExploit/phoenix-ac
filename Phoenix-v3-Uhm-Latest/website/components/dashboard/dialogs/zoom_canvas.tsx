'use client';

import { useCallback, useEffect, useRef, useState, type RefObject } from 'react';

import { Maximize2, Minus, Plus } from 'lucide-react';

const MIN_SCALE = 1;
const MAX_SCALE = 8;

function clamp(v: number, lo: number, hi: number): number {
  return Math.max(lo, Math.min(hi, v));
}

export function ZoomCanvas({
  canvasRef,
  className = '',
  overlay,
  active = true,
}: {
  canvasRef: RefObject<HTMLCanvasElement | null>;
  className?: string;
  overlay?: React.ReactNode;
  active?: boolean;
}) {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const [scale, setScale] = useState(1);
  const [ox, setOx] = useState(0);
  const [oy, setOy] = useState(0);
  const [dragging, setDragging] = useState(false);
  const dragStart = useRef<{
    cx: number;
    cy: number;
    ox: number;
    oy: number;
  } | null>(null);
  const zoomAt = useCallback((delta: number, clientX?: number, clientY?: number) => {
    const el = containerRef.current;
    if (!el) return;
    const rect = el.getBoundingClientRect();
    const cx = clientX ?? rect.left + rect.width / 2;
    const cy = clientY ?? rect.top + rect.height / 2;
    const px = cx - rect.left - rect.width / 2;
    const py = cy - rect.top - rect.height / 2;
    setScale((s) => {
      const nextRaw = s * (1 + delta);
      const next = clamp(nextRaw, MIN_SCALE, MAX_SCALE);
      const factor = next / s;
      setOx((v) => (next === MIN_SCALE ? 0 : v * factor + px * (1 - factor)));
      setOy((v) => (next === MIN_SCALE ? 0 : v * factor + py * (1 - factor)));
      return next;
    });
  }, []);
  const reset = useCallback(() => {
    setScale(1);
    setOx(0);
    setOy(0);
  }, []);
  const zoomed = scale > 1.0001;
  useEffect(() => {
    const el = containerRef.current;
    if (!el) return;
    const onWheel = (e: WheelEvent) => {
      if (!active) return;
      e.preventDefault();
      e.stopPropagation();
      zoomAt(e.deltaY > 0 ? -0.15 : 0.18, e.clientX, e.clientY);
    };
    el.addEventListener('wheel', onWheel, { passive: false });
    return () => el.removeEventListener('wheel', onWheel);
  }, [active, zoomAt]);
  return (
    <div
      ref={containerRef}
      className={`relative overflow-hidden ${className}`}
      onPointerDown={(e) => {
        if (!active || !zoomed) return;
        (e.currentTarget as HTMLDivElement).setPointerCapture(e.pointerId);
        setDragging(true);
        dragStart.current = { cx: e.clientX, cy: e.clientY, ox, oy };
      }}
      onPointerMove={(e) => {
        if (!dragging || !dragStart.current) return;
        setOx(dragStart.current.ox + (e.clientX - dragStart.current.cx));
        setOy(dragStart.current.oy + (e.clientY - dragStart.current.cy));
      }}
      onPointerUp={(e) => {
        if (dragging) {
          setDragging(false);
          try {
            (e.currentTarget as HTMLDivElement).releasePointerCapture(e.pointerId);
          } catch {}
        }
      }}
      onPointerCancel={() => setDragging(false)}
      onDoubleClick={(e) => {
        if (!active) return;
        if (zoomed) reset();
        else zoomAt(1.0, e.clientX, e.clientY);
      }}
      style={{
        cursor: !active ? undefined : zoomed ? (dragging ? 'grabbing' : 'grab') : 'zoom-in',
        touchAction: 'none',
      }}
    >
      <div
        className="flex h-full w-full items-center justify-center"
        style={{
          transform: `translate(${ox}px, ${oy}px) scale(${scale})`,
          transformOrigin: 'center center',
          transition: dragging ? 'none' : 'transform 90ms ease-out',
        }}
      >
        <canvas
          ref={canvasRef}
          className="max-h-full max-w-full object-contain"
          draggable={false}
        />
      </div>
      {overlay}
      <div className="pointer-events-none absolute bottom-1.5 left-1.5 flex items-center gap-1">
        <button
          type="button"
          onClick={(e) => {
            e.stopPropagation();
            zoomAt(0.25);
          }}
          className="pointer-events-auto flex h-6 w-6 items-center justify-center rounded-md border border-white/[0.08] bg-black/60 text-white/70 hover:bg-black/80 hover:text-white"
          title="Zoom in"
        >
          <Plus className="h-3 w-3" />
        </button>
        <button
          type="button"
          onClick={(e) => {
            e.stopPropagation();
            zoomAt(-0.25);
          }}
          className="pointer-events-auto flex h-6 w-6 items-center justify-center rounded-md border border-white/[0.08] bg-black/60 text-white/70 hover:bg-black/80 hover:text-white disabled:opacity-40"
          disabled={!zoomed}
          title="Zoom out"
        >
          <Minus className="h-3 w-3" />
        </button>
        <button
          type="button"
          onClick={(e) => {
            e.stopPropagation();
            reset();
          }}
          className="pointer-events-auto flex h-6 w-6 items-center justify-center rounded-md border border-white/[0.08] bg-black/60 text-white/70 hover:bg-black/80 hover:text-white disabled:opacity-40"
          disabled={!zoomed}
          title="Fit"
        >
          <Maximize2 className="h-3 w-3" />
        </button>
        {zoomed && (
          <span className="pointer-events-none rounded bg-black/60 px-1.5 py-0.5 font-mono text-[9px] text-white/60">
            {scale.toFixed(2)}x
          </span>
        )}
      </div>
    </div>
  );
}
