"use client";

import { useState } from "react";
import { Plus } from "lucide-react";
import { Reveal } from "@/components/site/reveal";
import { cn } from "@/lib/utils";

const QA = [
  {
    q: "PhoenixAC è disponibile per tutti?",
    a: "No. PhoenixAC è sviluppato esclusivamente per il server Enveart e non viene distribuito ad altre community.",
  },
  {
    q: "Come ottengo il launcher?",
    a: "Il launcher si scarica direttamente da questa pagina. Per accedere serve un PIN personale rilasciato dallo staff di Enveart.",
  },
  {
    q: "Ci sono impatti sulle prestazioni in gioco?",
    a: "No. Il sistema gira in background come processo separato e non tocca il frame di gioco. Chi gioca pulito non nota nulla.",
  },
  {
    q: "Cosa succede se vengo rilevato?",
    a: "Lo staff riceve una segnalazione con il contesto della detection. Le azioni (ban, kick, avviso) sono a discrezione di Enveart.",
  },
  {
    q: "Quali dati vengono raccolti?",
    a: "Solo quelli necessari a identificare cheat e ban evasion. Il trattamento è conforme al GDPR e i dettagli sono nei Termini di Servizio.",
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
