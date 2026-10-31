import Link from "next/link";
import { ArrowLeft } from "lucide-react";
import { PageShell } from "@/components/site/page-shell";
import { Reveal } from "@/components/site/reveal";
import { Button } from "@/components/ui/button";
import { Separator } from "@/components/ui/separator";

export const metadata = {
  title: "Chi siamo",
  description:
    "PhoenixAC: anticheat per server FiveM sviluppato e gestito da Enveart per community che vogliono giocare pulito.",
};

const COMPANY = {
  brand: "PhoenixAC",
  operator: "Enveart",
};

const FACTS = [
  { label: "Marchio", value: COMPANY.brand },
  { label: "Gestore", value: COMPANY.operator },
];

const VALUES = [
  {
    n: "01",
    title: "Fatto per Enveart",
    text: "PhoenixAC non è un prodotto generico adattato al FiveM. È stato costruito attorno alle esigenze specifiche del server.",
  },
  {
    n: "02",
    title: "Aggiornato con il server",
    text: "Quando qualcosa cambia nel server, i controlli vengono aggiornati di conseguenza. Non è un prodotto abbandonato.",
  },
  {
    n: "03",
    title: "Dati al minimo",
    text: "Raccogliamo solo quello che serve per far funzionare il sistema. I dettagli sono nei Termini di Servizio.",
  },
];

export default function ChiSiamoPage() {
  return (
    <PageShell>
      <Reveal>
        <Button
          variant="ghost"
          size="sm"
          className="mb-14 -ml-2 text-muted-foreground hover:text-foreground"
          nativeButton={false}
          render={<Link href="/" />}
        >
          <ArrowLeft className="size-4" />
          Torna alla home
        </Button>
      </Reveal>

      <div className="relative max-w-3xl">
        <div
          aria-hidden="true"
          className="pointer-events-none absolute -top-6 left-0 h-px w-20 bg-gradient-to-r from-primary/80 to-transparent"
        />
        <Reveal delay={60}>
          <span className="eyebrow text-primary">Chi siamo</span>
        </Reveal>
        <Reveal delay={120}>
          <h1 className="mt-4 font-heading text-4xl font-semibold leading-[1.08] tracking-tight md:text-5xl">
            PhoenixAC è il sistema anticheat{" "}
            <span className="text-primary">ufficiale di Enveart.</span>
          </h1>
        </Reveal>
        <Reveal delay={180}>
          <p className="mt-6 text-[15px] leading-relaxed text-muted-foreground">
            È stato sviluppato internamente per proteggere il server da cheat e ban evasion. Non è distribuito ad altre community.
          </p>
        </Reveal>
      </div>

      <Reveal delay={260}>
        <div className="mt-16 grid gap-3 sm:grid-cols-3">
          {VALUES.map((v) => (
            <div
              key={v.title}
              className="rounded-xl border border-border/60 bg-card/30 p-6 backdrop-blur-sm"
            >
              <span className="text-[11px] font-semibold tracking-widest text-primary">
                {v.n}
              </span>
              <h3 className="mt-4 font-heading text-[15px] font-semibold leading-snug">
                {v.title}
              </h3>
              <p className="mt-2 text-sm leading-relaxed text-muted-foreground">
                {v.text}
              </p>
            </div>
          ))}
        </div>
      </Reveal>

      <Reveal delay={320}>
        <Separator className="mt-16 bg-border/50" />
      </Reveal>

      <Reveal delay={380}>
        <div className="mt-20 grid gap-10 md:grid-cols-[220px_1fr]">
          <div>
            <span className="eyebrow text-primary">Il progetto</span>
            <h2 className="mt-4 font-heading text-xl font-semibold leading-snug">
              Come è nato.
            </h2>
          </div>
          <div className="space-y-4 text-[14px] leading-relaxed text-muted-foreground">
            <p>
              <span className="font-medium text-foreground">{COMPANY.operator}</span> ha sviluppato PhoenixAC per rispondere a un problema specifico: i sistemi anticheat esistenti non erano adatti alle esigenze di un server FiveM italiano con una community attiva.
            </p>
            <p>
              Il risultato è un sistema che gira in background sul PC del giocatore, non richiede configurazioni particolari e si aggiorna automaticamente. Lo staff riceve segnalazioni chiare quando qualcosa non va.
            </p>
            <p>
              PhoenixAC non viene venduto o concesso in licenza. È uno strumento interno di Enveart.
            </p>
          </div>
        </div>
      </Reveal>

    </PageShell>
  );
}
