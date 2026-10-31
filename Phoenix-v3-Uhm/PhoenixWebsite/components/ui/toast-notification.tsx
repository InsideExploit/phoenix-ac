"use client";

import { createPortal } from "react-dom";
import { useEffect, useRef, useState } from "react";
import { AlertTriangle, CheckCircle2, Info, X } from "lucide-react";
import { cn } from "@/lib/utils";

export const TOAST_EXIT_MS = 160;

type Tone = "success" | "error" | "info";

function detectTone(msg: string): Tone {
  const m = msg.toLowerCase();
  if (
    m.includes("error")     || m.includes("errore")  ||
    m.includes("failed")    || m.includes("fallita") || m.includes("fallito") ||
    m.includes("unable")    || m.includes("non riuscita") ||
    m.includes("unauthor")  || m.includes("forbidden") ||
    m.includes("network")   || m.includes("timeout")
  ) return "error";

  if (
    m.includes("added")     || m.includes("aggiunto")   ||
    m.includes("updated")   || m.includes("aggiornato") ||
    m.includes("deleted")   || m.includes("eliminato")  ||
    m.includes("removed")   || m.includes("rimosso")    ||
    m.includes("saved")     || m.includes("salvato")    ||
    m.includes("copied")    || m.includes("copiato")    ||
    m.includes("generated") || m.includes("generato")   ||
    m.includes("resumed")   || m.includes("riattivato") ||
    m.includes("suspended") || m.includes("sospeso")    ||
    m.includes("banned")    || m.includes("kicked")
  ) return "success";

  return "info";
}

const TONE: Record<Tone, { icon: React.ElementType; iconCls: string; iconBg: string }> = {
  success: { icon: CheckCircle2,  iconCls: "text-emerald-400", iconBg: "bg-emerald-400/[0.08]" },
  error:   { icon: AlertTriangle, iconCls: "text-red-400",     iconBg: "bg-red-400/[0.08]"     },
  info:    { icon: Info,          iconCls: "text-sky-400",     iconBg: "bg-sky-400/[0.08]"     },
};

type ToastNotificationProps = {
  message: string | null;
  onClear?: () => void;
  tone?: Tone;
  duration?: number;
};

export function ToastNotification({
  message,
  onClear,
  tone,
  duration,
}: ToastNotificationProps) {
  const [visible, setVisible] = useState(false);
  const [leaving, setLeaving] = useState(false);
  const [text, setText] = useState<string | null>(null);
  const [activeTone, setActiveTone] = useState<Tone>("info");
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);

  const onClearRef = useRef(onClear);
  onClearRef.current = onClear;
  const durationRef = useRef(duration);
  durationRef.current = duration;

  const dismiss = () => {
    if (timer.current) clearTimeout(timer.current);
    setLeaving(true);
  };

  useEffect(() => {
    if (!message) return;

    if (timer.current) clearTimeout(timer.current);
    setText(message);
    setActiveTone(tone ?? detectTone(message));
    setLeaving(false);
    setVisible(true);

    const ms = durationRef.current ?? 7000;
    timer.current = setTimeout(() => {
      setLeaving(true);
    }, ms);

    return () => {
      if (timer.current) clearTimeout(timer.current);
    };
  }, [message, tone]);

  useEffect(() => {
    return () => {
      if (timer.current) clearTimeout(timer.current);
    };
  }, []);

  const handleAnimationEnd = () => {
    if (!leaving) return;
    setVisible(false);
    setLeaving(false);
    setText(null);
    onClearRef.current?.();
  };

  if (!visible || !text) return null;

  const { icon: Icon, iconCls, iconBg } = TONE[activeTone];

  return createPortal(
    <div
      role="status"
      aria-live="polite"
      className="pointer-events-none fixed bottom-4 right-4 z-[99999] flex max-w-[min(92vw,440px)] justify-end"
    >
      <div
        onAnimationEnd={handleAnimationEnd}
        className={cn(
          "pointer-events-auto inline-flex w-fit max-w-full items-start gap-2.5 rounded-lg border border-white/[0.08] bg-[#111] py-2.5 pl-2.5 pr-1.5 shadow-2xl shadow-black/60",
          leaving
            ? "animate-out fade-out-0 slide-out-to-bottom-2 duration-150 ease-out fill-mode-forwards"
            : "animate-in fade-in-0 slide-in-from-bottom-2 duration-150 ease-out",
        )}
      >
        <div className={cn("mt-[1px] flex h-6 w-6 shrink-0 items-center justify-center rounded-md", iconBg)}>
          <Icon className={cn("h-3.5 w-3.5", iconCls)} />
        </div>
        <p className="min-w-0 flex-1 whitespace-pre-wrap break-words py-[3px] text-[12.5px] font-medium leading-snug text-white/90">
          {text}
        </p>
        <button
          type="button"
          onClick={dismiss}
          aria-label="Dismiss"
          className="mt-[1px] inline-flex h-6 w-6 shrink-0 items-center justify-center rounded-md text-white/40 transition-colors duration-100 hover:bg-white/[0.06] hover:text-white/80"
        >
          <X className="h-3 w-3" />
        </button>
      </div>
    </div>,
    document.body,
  );
}
