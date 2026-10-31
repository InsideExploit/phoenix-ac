"use client";

import { ArrowRight, Download } from "lucide-react";
import { Button } from "@/components/ui/button";
import { SectionLink } from "@/components/site/section-link";
import { Reveal } from "@/components/site/reveal";
import { cn } from "@/lib/utils";

export function Hero({ onDownload }: { onDownload?: () => void }) {
  return (
    <section className="relative overflow-hidden pt-40 pb-28 sm:pt-48 sm:pb-36">
      <div
        aria-hidden="true"
        className="pointer-events-none absolute inset-0 grid-bg [mask-image:radial-gradient(ellipse_at_center,black_0%,transparent_65%)]"
      />
      <div
        aria-hidden="true"
        className="hero-glow pointer-events-none absolute left-1/2 top-24 -z-10 h-[560px] w-[560px] rounded-full bg-primary/20 blur-3xl"
      />

      <div className="container-page relative">
        <div className="mx-auto max-w-3xl text-center">
          <Reveal>
            <h1 className="font-heading text-4xl font-semibold leading-[1.05] tracking-tight text-foreground sm:text-6xl md:text-7xl">
              Proteggi il tuo server.
              <br />
              <span className="text-primary">Senza compromessi.</span>
            </h1>
          </Reveal>

          <Reveal delay={80}>
            <p className="mx-auto mt-6 max-w-xl text-base leading-relaxed text-muted-foreground sm:text-lg">
              PhoenixAC è l'anticheat per community FiveM che vogliono giocare pulito.
              Rilevamenti aggiornati, log leggibili, zero rumore inutile.
            </p>
          </Reveal>

          <Reveal delay={160}>
            <div className="mt-10 flex flex-col items-center justify-center gap-3 sm:flex-row">
              <Button size="lg" className="h-11 px-6 text-sm" onClick={onDownload}>
                <Download />
                Scarica il launcher
              </Button>
              <SectionLink
                href="#features"
                className={cn(
                  "inline-flex h-11 items-center justify-center gap-2 rounded-md px-4 text-sm",
                  "text-muted-foreground transition-colors hover:bg-muted/50 hover:text-foreground",
                )}
              >
                Scopri di più
                <ArrowRight className="size-4" />
              </SectionLink>
            </div>
          </Reveal>
        </div>
      </div>
    </section>
  );
}
