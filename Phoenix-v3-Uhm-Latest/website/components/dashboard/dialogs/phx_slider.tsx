'use client';

import { useCallback, useRef, useState } from 'react';

export function PhxSlider({
  value,
  min,
  max,
  step = 1,
  onChange,
  disabled,
}: {
  value: number;
  min: number;
  max: number;
  step?: number;
  onChange: (v: number) => void;
  disabled?: boolean;
}) {
  const trackRef = useRef<HTMLDivElement | null>(null);
  const [drag, setDrag] = useState(false);
  const clamp = useCallback(
    (v: number) => {
      const s = step > 0 ? step : 1;
      const stepped = Math.round((v - min) / s) * s + min;
      return Math.max(min, Math.min(max, stepped));
    },
    [min, max, step],
  );
  const updateFromX = useCallback(
    (clientX: number) => {
      const el = trackRef.current;
      if (!el) return;
      const rect = el.getBoundingClientRect();
      const t = rect.width <= 0 ? 0 : (clientX - rect.left) / rect.width;
      const raw = min + Math.max(0, Math.min(1, t)) * (max - min);
      onChange(clamp(raw));
    },
    [min, max, onChange, clamp],
  );
  const pct = max === min ? 0 : ((value - min) / (max - min)) * 100;
  const onPointerDown = useCallback(
    (e: React.PointerEvent<HTMLDivElement>) => {
      if (disabled) return;
      e.preventDefault();
      (e.currentTarget as HTMLDivElement).setPointerCapture(e.pointerId);
      setDrag(true);
      updateFromX(e.clientX);
    },
    [disabled, updateFromX],
  );
  const onPointerMove = useCallback(
    (e: React.PointerEvent<HTMLDivElement>) => {
      if (!drag || disabled) return;
      e.preventDefault();
      updateFromX(e.clientX);
    },
    [drag, disabled, updateFromX],
  );
  const stopDrag = useCallback(
    (e: React.PointerEvent<HTMLDivElement>) => {
      if (!drag) return;
      setDrag(false);
      try {
        (e.currentTarget as HTMLDivElement).releasePointerCapture(e.pointerId);
      } catch {}
    },
    [drag],
  );
  return (
    <div
      ref={trackRef}
      role="slider"
      tabIndex={disabled ? -1 : 0}
      aria-valuemin={min}
      aria-valuemax={max}
      aria-valuenow={value}
      aria-disabled={disabled}
      onPointerDown={onPointerDown}
      onPointerMove={onPointerMove}
      onPointerUp={stopDrag}
      onPointerCancel={stopDrag}
      onLostPointerCapture={() => setDrag(false)}
      onKeyDown={(e) => {
        if (disabled) return;
        if (e.key === 'ArrowLeft' || e.key === 'ArrowDown') {
          e.preventDefault();
          onChange(clamp(value - step));
        }
        if (e.key === 'ArrowRight' || e.key === 'ArrowUp') {
          e.preventDefault();
          onChange(clamp(value + step));
        }
        if (e.key === 'Home') {
          e.preventDefault();
          onChange(min);
        }
        if (e.key === 'End') {
          e.preventDefault();
          onChange(max);
        }
      }}
      style={{ touchAction: 'none', WebkitUserSelect: 'none', userSelect: 'none' }}
      className={`relative h-6 w-full select-none focus:outline-none ${disabled ? 'cursor-not-allowed opacity-50' : 'cursor-pointer'}`}
    >
      <div className="pointer-events-none absolute inset-x-0 top-1/2 h-1 -translate-y-1/2 overflow-hidden rounded-full bg-white/[0.08]">
        <div
          className="h-full rounded-full bg-white/70"
          style={{ width: `${pct}%` }}
          draggable={false}
        />
      </div>
      <div
        className="pointer-events-none absolute top-1/2 h-3 w-3 -translate-x-1/2 -translate-y-1/2 rounded-full border border-white/20 bg-white shadow-sm shadow-black/40"
        style={{ left: `${pct}%` }}
        draggable={false}
      />
    </div>
  );
}
