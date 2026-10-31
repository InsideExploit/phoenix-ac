import {
  Radar,
  ShieldHalf,
  Fingerprint,
  Terminal,
  Zap,
  RefreshCcw,
} from "lucide-react";
import { Reveal } from "@/components/site/reveal";

const ITEMS = [
  {
    icon: ShieldHalf,
    title: "Protezione lato client",
    text: "Verifiche mirate su processi, moduli e file di gioco per intercettare cheat e inject prima che partano.",
  },
  {
    icon: Radar,
    title: "Rilevamenti aggiornati",
    text: "Nuove firme e controlli distribuiti in continuo senza toccare la build che gira in produzione.",
  },
  {
    icon: Fingerprint,
    title: "Anti ban evasion",
    text: "Riconoscimento dispositivi e correlazione account per fermare chi rientra dopo un ban.",
  },
  {
    icon: Terminal,
    title: "Log leggibili",
    text: "Eventi strutturati e verificabili. Nessuna parete di JSON: lo staff capisce subito cosa è successo.",
  },
  {
    icon: Zap,
    title: "Zero impatto in game",
    text: "Il launcher fa il lavoro pesante fuori dal frame di gioco. Il player non se ne accorge.",
  },
  {
    icon: RefreshCcw,
    title: "Aggiornamenti automatici",
    text: "Il client si mantiene sempre aggiornato. Nessuna azione richiesta al giocatore o allo staff.",
  },
];

export function Features() {
  return (
    <section id="features" className="relative py-28 sm:py-36">
      <div className="container-page">
        <div className="max-w-2xl">
          <Reveal>
            <span className="eyebrow">Funzionalità</span>
          </Reveal>
          <Reveal delay={60}>
            <h2 className="mt-4 font-heading text-3xl font-semibold tracking-tight sm:text-5xl">
              Costruito per chi modera davvero.
            </h2>
          </Reveal>
          <Reveal delay={120}>
            <p className="mt-4 text-base leading-relaxed text-muted-foreground">
              Tutto quello che serve per proteggere la tua community, senza fronzoli
              né configurazioni infinite.
            </p>
          </Reveal>
        </div>

        <div className="mt-16 grid grid-cols-1 gap-px overflow-hidden rounded-2xl border border-border/60 bg-border/60 md:grid-cols-2 lg:grid-cols-3">
          {ITEMS.map((item, i) => (
            <Reveal key={item.title} delay={i * 40}>
              <div className="group flex h-full flex-col gap-4 bg-background p-8 transition-colors hover:bg-card">
                <div className="flex size-10 items-center justify-center rounded-lg border border-border bg-card text-primary transition-colors group-hover:border-primary/30 group-hover:bg-primary/5">
                  <item.icon className="size-5" />
                </div>
                <div>
                  <h3 className="font-heading text-base font-semibold">{item.title}</h3>
                  <p className="mt-2 text-sm leading-relaxed text-muted-foreground">
                    {item.text}
                  </p>
                </div>
              </div>
            </Reveal>
          ))}
        </div>
      </div>
    </section>
  );
}
