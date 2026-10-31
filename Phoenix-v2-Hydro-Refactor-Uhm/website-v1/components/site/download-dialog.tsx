"use client";

import Link from "next/link";
import { useEffect, useRef, useState } from "react";
import { Download, X, AlertTriangle } from "lucide-react";
import { createPortal } from "react-dom";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Separator } from "@/components/ui/separator";
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogDescription,
} from "@/components/ui/dialog";

type Step = "tos" | "pin" | "done";

export function DownloadDialog({
  open,
  onClose,
}: {
  open: boolean;
  onClose: () => void;
}) {
  const [accepted, setAccepted] = useState(false);
  const [step, setStep] = useState<Step>("tos");
  const [dir, setDir] = useState<"fwd" | "back">("fwd");
  const [pin, setPin] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [toastVisible, setToastVisible] = useState(false);
  const [toastLeaving, setToastLeaving] = useState(false);
  const toastTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  const showToast = (msg: string) => {
    if (toastTimer.current) clearTimeout(toastTimer.current);
    setError(msg);
    setToastLeaving(false);
    setToastVisible(true);
    toastTimer.current = setTimeout(() => dismissToast(), 4000);
  };

  const dismissToast = () => {
    setToastLeaving(true);
    setTimeout(() => {
      setToastVisible(false);
      setToastLeaving(false);
      setError(null);
    }, 230);
  };

  const goto = (next: Step, direction: "fwd" | "back" = "fwd") => {
    setDir(direction);
    setStep(next);
  };

  useEffect(() => {
    if (!open) {
      setAccepted(false);
      setStep("tos");
      setPin("");
      setError(null);
      setToastVisible(false);
      setToastLeaving(false);
      setSubmitting(false);
      if (toastTimer.current) clearTimeout(toastTimer.current);
    }
  }, [open]);

  async function handleDownload() {
    const code = pin.trim();
    if (!code || submitting) return;
    setSubmitting(true);
    setError(null);
    try {
      const res = await fetch("/api/download", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ pin: code }),
      });
      const ct = res.headers.get("content-type") || "";

      if (res.ok && ct.includes("application/octet-stream")) {
        const filename =
          res.headers.get("x-download-filename") || "PhoenixAC-Launcher.zip";
        const blob = await res.blob();
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        a.remove();
        URL.revokeObjectURL(url);
        setStep("done");
      } else {
        const data = await res.json().catch(() => ({}));
        showToast(data.error || "PIN non valido.");
      }
    } catch {
      showToast("Errore di rete. Riprova.");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <Dialog open={open} onOpenChange={(v) => !v && onClose()}>
      <DialogContent className="overflow-hidden">
        {step === "tos" && (
          <div key="tos" className={`step-enter-${dir}`}>
            <div className="px-6 pt-6">
              <DialogHeader className="gap-1.5 text-left">
                <DialogTitle>Termini di Servizio</DialogTitle>
                <DialogDescription>
                  Per scaricare il launcher devi accettare i{" "}
                  <Link
                    href="/tos"
                    target="_blank"
                    className="text-primary underline underline-offset-4 hover:text-primary/80"
                  >
                    Termini di Servizio
                  </Link>
                  .
                </DialogDescription>
              </DialogHeader>
              <div className="mt-5 flex items-center gap-3">
                <Checkbox
                  id="tos-accept"
                  checked={accepted}
                  onCheckedChange={(v) => setAccepted(v === true)}
                />
                <Label htmlFor="tos-accept" className="text-sm leading-snug text-muted-foreground cursor-pointer">
                  Ho letto e accetto i Termini di Servizio di PhoenixAC.
                </Label>
              </div>
            </div>
            <Separator className="mt-6" />
            <DialogFooter className="px-6 py-4">
              <Button
                disabled={!accepted}
                onClick={() => goto("pin", "fwd")}
                className="h-10 w-full text-sm"
              >
                Continua
              </Button>
            </DialogFooter>
          </div>
        )}

        {step === "pin" && (
          <div key="pin" className={`step-enter-${dir}`}>
            <div className="px-6 pt-6">
              <DialogHeader className="gap-1.5 text-left">
                <DialogTitle>Inserisci il PIN</DialogTitle>
                <DialogDescription>
                  Ogni PIN è valido una sola volta. Inserisci il codice ricevuto dallo staff.
                </DialogDescription>
              </DialogHeader>
              <div className="mt-5">
                <label
                  htmlFor="download-pin"
                  className="mb-2 block text-[11px] font-medium uppercase tracking-[0.14em] text-muted-foreground"
                >
                  Codice PIN
                </label>
                <Input
                  id="download-pin"
                  value={pin}
                  onChange={(e) => {
                    setPin(e.target.value.toUpperCase().replace(/[^A-Z0-9]/g, "").slice(0, 8));
                    setError(null);
                  }}
                  onKeyDown={(e) => {
                    if (e.key === "Enter") handleDownload();
                  }}
                  autoFocus
                  placeholder="Inserisci codice PIN"
                  className="h-12 rounded-xl border-border/70 bg-muted/25 px-4 text-center text-[17px] font-medium tabular-nums shadow-none placeholder:text-[14px] placeholder:font-normal placeholder:tracking-normal placeholder:text-muted-foreground/40 focus-visible:border-primary/40 focus-visible:bg-background focus-visible:ring-primary/20 [&:not(:placeholder-shown)]:text-[19px] [&:not(:placeholder-shown)]:tracking-[0.18em]"
                />
              </div>
            </div>
            <Separator className="mt-6" />
            <DialogFooter className="gap-2 px-6 py-4 sm:justify-between">
              <Button
                variant="ghost"
                onClick={() => goto("tos", "back")}
                className="h-10 text-sm text-muted-foreground"
              >
                Indietro
              </Button>
              <Button
                disabled={pin.trim().length === 0 || submitting}
                onClick={handleDownload}
                className="h-10 gap-2 text-sm"
              >
                <Download className="size-4" />
                {submitting ? "Verifica…" : "Scarica"}
              </Button>
            </DialogFooter>
          </div>
        )}

        {step === "done" && (
          <div key="done" className={`step-enter-${dir}`}>
            <div className="px-6 pt-6 pb-2 text-center">
              <DialogHeader className="gap-1.5 text-center sm:text-center">
                <DialogTitle>Download avviato</DialogTitle>
                <DialogDescription>
                  Se il file non parte automaticamente, controlla le impostazioni del browser.
                </DialogDescription>
              </DialogHeader>
            </div>
            <Separator className="mt-4" />
            <DialogFooter className="px-6 py-4">
              <Button onClick={onClose} className="h-10 w-full text-sm">
                Chiudi
              </Button>
            </DialogFooter>
          </div>
        )}
      </DialogContent>

      {toastVisible && typeof window !== "undefined" && createPortal(
        <div
          className={`fixed top-5 left-1/2 z-[99999] -translate-x-1/2 ${toastLeaving ? "toast-out" : "toast-in"}`}
        >
          <div className="flex items-center gap-3 rounded-xl border border-destructive/30 bg-card px-4 py-3 shadow-xl shadow-black/40 backdrop-blur-sm">
            <AlertTriangle className="size-4 shrink-0 text-destructive" />
            <p className="text-sm text-foreground">{error}</p>
            <button
              type="button"
              onClick={dismissToast}
              className="ml-2 rounded-md p-0.5 text-muted-foreground transition-colors hover:text-foreground"
            >
              <X className="size-3.5" />
            </button>
          </div>
        </div>,
        document.body,
      )}
    </Dialog>
  );
}
