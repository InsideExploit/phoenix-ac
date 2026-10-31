import Link from "next/link";
import { ArrowLeft } from "lucide-react";
import { PageShell } from "@/components/site/page-shell";
import { Reveal } from "@/components/site/reveal";
import { Button } from "@/components/ui/button";
import { Separator } from "@/components/ui/separator";

export const metadata = {
  title: "Chi siamo",
  description:
    "PhoenixAC: anticheat per server FiveM per community che vogliono giocare pulito.",
};

const COMPANY = {
  brand: "PhoenixAC",
  operator: "REDACTED",
  vat: "REDACTED",
  contact: "REDACTED",
};

const FACTS = [
  { label: "Marchio", value: COMPANY.brand },
  { label: "Gestore", value: COMPANY.operator },
  { label: "Partita IVA", value: COMPANY.vat },
  { label: "Contatto", value: COMPANY.contact },
];

const VALUES = [
  {
    n: "01",
    title: "Vicini allo staff",
    text: "Costruiamo funzionalità con chi le usa ogni giorno. Nessun feedback ignorato.",
  },
  {
    n: "02",
    title: "Pragmatici sul rilevamento",
    text: "Rilevamenti verificabili, log leggibili. Nessuna magia, nessuna promessa vuota.",
  },
  {
    n: "03",
    title: "Trasparenti sui dati",
    text: "Raccogliamo solo ciò che serve a fermare cheat e ban evasion. Documentato nei Termini.",
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
            Costruito da chi modera,{" "}
            <span className="text-primary">non da chi vende.</span>
          </h1>
        </Reveal>
        <Reveal delay={180}>
          <p className="mt-6 text-[15px] leading-relaxed text-muted-foreground">
            PhoenixAC nasce da un'esigenza concreta: dare a chi gestisce una
            community FiveM uno strumento affidabile, senza il rumore di
            prodotti generalisti. Meno dashboard fumose, più segnali che
            contano davvero.
          </p>
        </Reveal>
      </div>

      <Reveal delay={260}>
        <div className="mt-16 grid divide-y divide-border/40 sm:divide-x sm:divide-y-0 sm:grid-cols-3">
          {VALUES.map((v) => (
            <div
              key={v.title}
              className="py-8 sm:px-8 sm:py-0 first:sm:pl-0 last:sm:pr-0"
            >
              <span className="font-mono text-xs font-medium text-primary/50">
                {v.n}
              </span>
              <h3 className="mt-3 font-heading text-[15px] font-semibold">
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
              Un ecosistema coerente, non una raccolta di tool.
            </h2>
          </div>
          <div className="space-y-4 text-[14px] leading-relaxed text-muted-foreground">
            <p>
              Sviluppato e gestito da{" "}
              <span className="font-medium text-foreground">
                {COMPANY.operator}
              </span>
              , PhoenixAC integra launcher client, aggiornamenti di
              rilevamento e infrastruttura web in un unico ecosistema pensato
              per chi lavora sul campo.
            </p>
            <p>
              Lavoriamo con community italiane da anni. Sappiamo che la
              sicurezza non deve essere invasiva, per questo puntiamo su
              controlli verificabili, log leggibili e un supporto reale, non
              un ticket aperto nel vuoto.
            </p>
            <p>
              Ogni aggiornamento al modulo di rilevamento è testato su
              scenari reali prima di essere distribuito. La stabilità del
              server della community viene prima di ogni altra metrica.
            </p>
          </div>
        </div>
      </Reveal>

      <Reveal delay={440}>
        <Separator className="mt-20 bg-border/50" />
      </Reveal>

      <Reveal delay={500}>
        <div className="mt-20 grid gap-10 md:grid-cols-[220px_1fr]">
          <div>
            <span className="eyebrow text-primary">Dati del gestore</span>
            <h2 className="mt-4 font-heading text-xl font-semibold leading-snug">
              Informazioni legali.
            </h2>
          </div>
          <div className="overflow-hidden rounded-2xl border border-border/60 bg-card/40 backdrop-blur">
            <div className="grid grid-cols-2">
              {FACTS.map((f, i) => (
                <div
                  key={f.label}
                  className={[
                    "px-6 py-5",
                    i < 2 ? "border-b border-border/60" : "",
                    i % 2 === 0 ? "border-r border-border/60" : "",
                  ]
                    .filter(Boolean)
                    .join(" ")}
                >
                  <p className="text-[10px] font-medium uppercase tracking-[0.15em] text-muted-foreground">
                    {f.label}
                  </p>
                  <p className="mt-2 text-sm font-medium text-foreground">
                    {f.value}
                  </p>
                </div>
              ))}
            </div>
          </div>
        </div>
      </Reveal>
    </PageShell>
  );
}
