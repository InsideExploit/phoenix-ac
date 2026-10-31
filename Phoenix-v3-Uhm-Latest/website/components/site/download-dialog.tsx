'use client';

import { useEffect, useState } from 'react';

import Link from 'next/link';

import { Download } from 'lucide-react';

import { Button } from '@/components/ui/button';
import { Checkbox } from '@/components/ui/checkbox';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { Input } from '@/components/ui/input';
import { Separator } from '@/components/ui/separator';
import { ToastNotification } from '@/components/ui/toast-notification';

type Step = 'tos' | 'pin' | 'done';
const STEAM_ERRORS: Record<string, string> = {
  'not-authorized': 'Il tuo account Steam non è nella lista dei player autorizzati.',
  banned: 'Il tuo account risulta bannato.',
  suspended: 'Il tuo account è temporaneamente sospeso.',
  openid: "Impossibile verificare l'accesso Steam. Riprova.",
  rate: 'Troppi tentativi. Attendi un minuto.',
};

const SteamLogo = () => (
  <svg
    className="size-4"
    viewBox="0 0 24 24"
    fill="currentColor"
    aria-hidden="true"
  >
    <path d="M12 0C5.523 0 .264 4.997 0 11.323l6.446 2.669c.545-.371 1.203-.588 1.911-.588.064 0 .126.002.189.005l2.867-4.14v-.058c0-2.487 2.028-4.51 4.518-4.51 2.492 0 4.518 2.023 4.518 4.51 0 2.487-2.026 4.512-4.518 4.512-.033 0-.067 0-.101-.001l-4.079 2.904c0 .053.003.105.003.157 0 1.869-1.521 3.389-3.389 3.389-1.638 0-3.011-1.171-3.32-2.719L.219 15.6C1.688 20.492 6.415 24 12 24c6.626 0 12-5.373 12-12 0-6.628-5.374-12-12-12zM7.531 18.201c1.406.586 3.019-.078 3.606-1.485.286-.68.286-1.435-.001-2.114-.287-.68-.822-1.211-1.503-1.494-.678-.281-1.408-.271-2.049-.027l1.628.673c1.037.432 1.526 1.622 1.094 2.658-.432 1.037-1.624 1.526-2.661 1.093l-1.569-.652c.264.594.755 1.087 1.455 1.348zm10.987-8.678c0-1.658-1.35-3.008-3.011-3.008-1.66 0-3.011 1.35-3.011 3.008 0 1.66 1.351 3.01 3.011 3.01 1.66 0 3.011-1.35 3.011-3.01zm-5.263-.005c0-1.246 1.01-2.257 2.259-2.257 1.246 0 2.256 1.011 2.256 2.257 0 1.247-1.01 2.258-2.256 2.258-1.249 0-2.259-1.011-2.259-2.258z" />
  </svg>
);

export function DownloadDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
  const [accepted, setAccepted] = useState(false);
  const [step, setStep] = useState<Step>('tos');
  const [dir, setDir] = useState<'fwd' | 'back'>('fwd');
  const [pin, setPin] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [toast, setToast] = useState<string | null>(null);
  const [steamAuthed, setSteamAuthed] = useState(false);
  const [steamPending, setSteamPending] = useState(false);
  const showToast = (msg: string) => setToast(msg);
  const goto = (next: Step, direction: 'fwd' | 'back' = 'fwd') => {
    setDir(direction);
    setStep(next);
  };
  useEffect(() => {
    if (!open) {
      setAccepted(false);
      setStep('tos');
      setPin('');
      setToast(null);
      setSubmitting(false);
      setSteamAuthed(false);
      setSteamPending(false);
    }
  }, [open]);
  useEffect(() => {
    if (!open) return;
    const onMessage = (e: MessageEvent) => {
      if (e.origin !== window.location.origin) return;
      const d = e.data;
      if (!d || d.source !== 'phoenixac-steam') return;
      setSteamPending(false);
      if (d.ok) {
        setSteamAuthed(true);
        setToast(null);
      } else {
        setSteamAuthed(false);
        showToast(STEAM_ERRORS[d.err] || 'Accesso Steam fallito. Riprova.');
      }
    };
    window.addEventListener('message', onMessage);
    return () => window.removeEventListener('message', onMessage);
  }, [open]);

  function loginWithSteam() {
    setToast(null);
    setSteamPending(true);
    const w = 520,
      h = 640;
    const y = Math.max(
      0,
      window.top?.outerHeight ? (window.top.outerHeight - h) / 2 + (window.top.screenY || 0) : 100,
    );
    const x = Math.max(
      0,
      window.top?.outerWidth ? (window.top.outerWidth - w) / 2 + (window.top.screenX || 0) : 100,
    );
    const popup = window.open(
      '/api/auth/steam/login',
      'phoenixac-steam-login',
      `popup=1,width=${w},height=${h},left=${x},top=${y}`,
    );
    if (!popup) {
      setSteamPending(false);
      showToast('Popup bloccato dal browser. Consenti i popup e riprova.');
      return;
    }
    const timer = window.setInterval(() => {
      if (popup.closed) {
        window.clearInterval(timer);
        setSteamPending((p) => {
          if (p) showToast('Accesso Steam annullato.');
          return false;
        });
      }
    }, 500);
  }

  async function handleDownload() {
    if (submitting) return;
    const code = pin.trim();
    if (!code && !steamAuthed) return;
    setSubmitting(true);
    setToast(null);
    try {
      const res = code
        ? await fetch('/api/download', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ pin: code }),
          })
        : await fetch('/api/download/steam', { method: 'GET' });
      const ct = res.headers.get('content-type') || '';
      if (res.ok && ct.includes('application/octet-stream')) {
        const filename = res.headers.get('x-download-filename') || 'PhoenixAC-Launcher.zip';
        const blob = await res.blob();
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        a.remove();
        URL.revokeObjectURL(url);
        setStep('done');
      } else {
        const data = await res.json().catch(() => ({}));
        showToast(data.error || (code ? 'PIN non valido.' : 'Download fallito. Riprova.'));
        if (!code) setSteamAuthed(false);
      }
    } catch {
      showToast('Errore di rete. Riprova.');
    } finally {
      setSubmitting(false);
    }
  }
  return (
    <Dialog
      open={open}
      onOpenChange={(v) => !v && onClose()}
    >
      <DialogContent className="overflow-hidden">
        {step === 'tos' && (
          <div
            key="tos"
            className={`step-enter-${dir}`}
          >
            <div className="px-6 pt-6 pb-2">
              <DialogHeader className="gap-1 text-left">
                <DialogTitle>Termini di Servizio</DialogTitle>
                <DialogDescription>
                  Prima di scaricare leggi i{' '}
                  <Link
                    href="/tos"
                    target="_blank"
                    className="text-foreground underline underline-offset-4 hover:text-primary"
                  >
                    Termini di Servizio
                  </Link>
                  .
                </DialogDescription>
              </DialogHeader>
              <label
                htmlFor="tos-accept"
                className="mt-5 flex cursor-pointer items-center gap-3 rounded-lg border border-border/50 px-4 py-3.5 transition-colors hover:border-border hover:bg-muted/20"
              >
                <Checkbox
                  id="tos-accept"
                  checked={accepted}
                  onCheckedChange={(v) => setAccepted(v === true)}
                  className="size-5 rounded-md"
                />
                <span className="text-sm text-muted-foreground">
                  Ho letto e accetto i Termini di Servizio.
                </span>
              </label>
            </div>
            <Separator className="mt-6" />
            <DialogFooter className="px-6 py-4">
              <Button
                disabled={!accepted}
                onClick={() => goto('pin', 'fwd')}
                className="h-10 w-full text-sm"
              >
                Continua
              </Button>
            </DialogFooter>
          </div>
        )}

        {step === 'pin' && (
          <div
            key="pin"
            className={`step-enter-${dir}`}
          >
            <div className="px-6 pt-6 pb-2">
              <DialogHeader className="gap-1 text-left">
                <DialogTitle>Inserisci il PIN</DialogTitle>
                <DialogDescription>
                  Il codice ti è stato fornito dallo staff di Enveart. Ogni PIN è monouso.
                </DialogDescription>
              </DialogHeader>
              <div className="mt-5">
                <Input
                  id="download-pin"
                  value={pin}
                  onChange={(e) => {
                    setPin(
                      e.target.value
                        .toUpperCase()
                        .replace(/[^A-Z0-9]/g, '')
                        .slice(0, 8),
                    );
                    setToast(null);
                  }}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter') handleDownload();
                  }}
                  autoFocus
                  placeholder="Codice PIN"
                  className="h-12 rounded-lg border-border/60 bg-muted/20 px-4 text-center text-base font-semibold tracking-widest uppercase shadow-none placeholder:text-sm placeholder:font-normal placeholder:tracking-normal placeholder:normal-case placeholder:text-muted-foreground/40 focus-visible:border-primary/50 focus-visible:bg-background focus-visible:ring-primary/20"
                />
              </div>
              <div className="mt-5 flex items-center gap-3">
                <div className="h-px flex-1 bg-border/50" />
                <span className="text-[11px] uppercase tracking-wider text-muted-foreground/60">
                  oppure
                </span>
                <div className="h-px flex-1 bg-border/50" />
              </div>
              {steamAuthed ? (
                <div className="mt-4 flex items-center gap-3 rounded-lg border border-emerald-500/25 bg-emerald-500/8 px-4 py-3">
                  <SteamLogo />
                  <span className="text-[13px] font-medium text-emerald-400">
                    Accesso Steam confermato
                  </span>
                </div>
              ) : (
                <Button
                  className="mt-4 h-11 w-full gap-2.5 bg-[#171a21] text-[14px] font-medium text-white hover:bg-[#2a475e] disabled:opacity-70"
                  onClick={loginWithSteam}
                  disabled={steamPending}
                >
                  <SteamLogo />
                  {steamPending ? 'Attendi...' : 'Accedi con Steam'}
                </Button>
              )}
            </div>
            <Separator className="mt-6" />
            <DialogFooter className="gap-2 px-6 py-4 sm:justify-between">
              <Button
                variant="ghost"
                onClick={() => goto('tos', 'back')}
                className="h-10 text-sm text-muted-foreground"
              >
                Indietro
              </Button>
              <Button
                disabled={(pin.trim().length === 0 && !steamAuthed) || submitting}
                onClick={handleDownload}
                className="h-10 gap-2 text-sm"
              >
                <Download className="size-4" />
                {submitting ? 'Verifica…' : 'Scarica'}
              </Button>
            </DialogFooter>
          </div>
        )}

        {step === 'done' && (
          <div
            key="done"
            className={`step-enter-${dir}`}
          >
            <div className="px-6 pt-6 pb-2">
              <DialogHeader className="gap-1 text-left">
                <DialogTitle>Download avviato</DialogTitle>
                <DialogDescription>
                  Il file è in download. Se non parte, controlla i permessi del browser.
                </DialogDescription>
              </DialogHeader>
            </div>
            <Separator className="mt-6" />
            <DialogFooter className="px-6 py-4">
              <Button
                onClick={onClose}
                className="h-10 w-full text-sm"
              >
                Chiudi
              </Button>
            </DialogFooter>
          </div>
        )}
      </DialogContent>

      <ToastNotification
        message={toast}
        onClear={() => setToast(null)}
        tone="error"
        duration={4000}
      />
    </Dialog>
  );
}
