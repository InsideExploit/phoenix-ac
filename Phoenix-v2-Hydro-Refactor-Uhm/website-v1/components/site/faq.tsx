"use client";

import { useState } from "react";
import { Plus } from "lucide-react";
import { Reveal } from "@/components/site/reveal";
import { cn } from "@/lib/utils";

const QA = [
  {
    q: "PhoenixAC funziona con qualsiasi server FiveM?",
    a: "Sì. È pensato per integrarsi con community FiveM di qualsiasi dimensione. Lo staff riceve la parte server, i giocatori scaricano il launcher.",
  },
  {
    q: "Ci sono impatti sulle prestazioni in gioco?",
    a: "No. I controlli pesanti girano nel launcher, non dentro il frame di gioco. Chi gioca pulito non nota nulla.",
  },
  {
    q: "Cosa succede se qualcuno viene rilevato mentre bara?",
    a: "Lo staff riceve un evento con contesto: cosa è stato rilevato, quando, e a quale identità di gioco è collegato. Le azioni successive restano a discrezione del server.",
  },
  {
    q: "I dati raccolti sono al sicuro?",
    a: "Il trattamento avviene in conformità al GDPR. I dettagli sono nei Termini di Servizio: raccogliamo solo ciò che serve a fermare cheater e ban evasion.",
  },
  {
    q: "Come si ottiene un PIN di download?",
    a: "I PIN vengono generati dallo staff del server che adotta PhoenixAC. Sono personali, monouso e vanno inseriti al primo avvio del launcher.",
  },
];

export function Faq() {
  const [open, setOpen] = useState<number | null>(null);

  return (
    <section id="faq" className="relative border-t border-border/60 py-28 sm:py-36">
      <div className="container-page">
        <div className="mx-auto max-w-3xl">
          <Reveal>
            <span className="eyebrow">FAQ</span>
          </Reveal>
          <Reveal delay={60}>
            <h2 className="mt-4 font-heading text-3xl font-semibold tracking-tight sm:text-5xl">
              Domande frequenti.
            </h2>
          </Reveal>

          <Reveal delay={120}>
            <div className="mt-14 overflow-hidden rounded-2xl border border-border/60 bg-card/40 backdrop-blur">
              {QA.map((item, i) => {
                const isOpen = open === i;
                return (
                  <div
                    key={item.q}
                    className="border-b border-border/60 last:border-b-0"
                  >
                    <button
                      type="button"
                      onClick={() => setOpen(isOpen ? null : i)}
                      className={cn(
                        "flex w-full items-center justify-between gap-6 px-6 py-5 text-left transition-colors hover:bg-muted/40",
                        isOpen && "bg-muted/20",
                      )}
                      aria-expanded={isOpen}
                    >
                      <span className="font-heading text-base font-medium">{item.q}</span>
                      <Plus
                        className={cn(
                          "size-4 shrink-0 text-muted-foreground transition-transform duration-300 ease-out",
                          isOpen && "rotate-45 text-primary",
                        )}
                      />
                    </button>

                    <div
                      className={cn(
                        "grid transition-[grid-template-rows] duration-300 ease-[cubic-bezier(0.22,1,0.36,1)]",
                        isOpen ? "grid-rows-[1fr]" : "grid-rows-[0fr]",
                      )}
                    >
                      <div className="min-h-0 overflow-hidden">
                        <div
                          className={cn(
                            "border-t border-border/40 bg-muted/10 px-6 py-4 transition-opacity duration-300",
                            isOpen ? "opacity-100" : "opacity-0",
                          )}
                        >
                          <p className="text-sm leading-relaxed text-muted-foreground">
                            {item.a}
                          </p>
                        </div>
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          </Reveal>
        </div>
      </div>
    </section>
  );
}
