"use client";

import { Download } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Reveal } from "@/components/site/reveal";

export function Cta({ onDownload }: { onDownload?: () => void }) {
  return (
    <section id="download" className="relative border-t border-border/60 py-28 sm:py-36">
      <div className="container-page">
        <Reveal>
          <div className="relative overflow-hidden rounded-3xl border border-border/60 bg-card/40 p-10 sm:p-14">
            <div
              aria-hidden="true"
              className="pointer-events-none absolute inset-0 grid-bg opacity-40 [mask-image:radial-gradient(ellipse_at_top_right,black_0%,transparent_70%)]"
            />
            <div
              aria-hidden="true"
              className="pointer-events-none absolute -right-24 -top-24 h-72 w-72 rounded-full bg-primary/25 blur-3xl"
            />

            <div className="relative flex flex-col items-start gap-8 lg:flex-row lg:items-center lg:justify-between">
              <div className="max-w-xl">
                <h2 className="font-heading text-3xl font-semibold tracking-tight sm:text-4xl">
                  Vuoi giocare su Enveart?
                </h2>
                <p className="mt-4 text-base leading-relaxed text-muted-foreground">
                  Contatta lo staff per ricevere il tuo PIN, scarica il launcher e sei pronto. Ci vogliono pochi minuti.
                </p>
              </div>
              <Button size="lg" className="h-12 shrink-0 px-6 text-sm" onClick={onDownload}>
                <Download />
                Scarica ora
              </Button>
            </div>
          </div>
        </Reveal>
      </div>
    </section>
  );
}
