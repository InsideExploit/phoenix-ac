import { Reveal } from "@/components/site/reveal";

const STEPS = [
  {
    n: "01",
    title: "Ricevi il PIN",
    text: "Lo staff genera un PIN monouso dalla dashboard. Vale un download, poi si chiude.",
  },
  {
    n: "02",
    title: "Scarica il launcher",
    text: "Un file, un click. Il launcher si tiene aggiornato da solo, senza pesare sul PC.",
  },
  {
    n: "03",
    title: "Entra in gioco",
    text: "PhoenixAC gira in background. Chi tenta di barare finisce nei log dello staff.",
  },
];

export function How() {
  return (
    <section id="how" className="relative border-t border-border/60 py-28 sm:py-36">
      <div className="container-page">
        <div className="grid gap-16 lg:grid-cols-[1fr_2fr] lg:gap-24">
          <div className="lg:self-start">
            <Reveal>
              <span className="eyebrow">Come funziona</span>
            </Reveal>
            <Reveal delay={60}>
              <h2 className="mt-4 font-heading text-3xl font-semibold tracking-tight sm:text-5xl">
                Tre passi.
                <br />
                Nessuna cerimonia.
              </h2>
            </Reveal>
            <Reveal delay={120}>
              <p className="mt-4 max-w-md text-base leading-relaxed text-muted-foreground">
                Dal PIN al gioco protetto passano pochi minuti. PhoenixAC è pensato
                per essere invisibile a chi gioca pulito.
              </p>
            </Reveal>
          </div>

          <ol className="relative space-y-10">
            {STEPS.map((s, i) => (
              <Reveal key={s.n} delay={i * 80} as="li">
                <div className="relative rounded-2xl border border-border/60 bg-card/40 p-8 backdrop-blur transition-colors hover:border-primary/30 hover:bg-card/60">
                  <div className="absolute left-0 top-6 bottom-6 w-0.5 rounded-full bg-primary/50" />
                  <div className="flex items-baseline gap-4">
                    <span className="font-heading text-4xl font-semibold text-primary">
                      {s.n}
                    </span>
                    <h3 className="font-heading text-xl font-semibold sm:text-2xl">
                      {s.title}
                    </h3>
                  </div>
                  <p className="mt-3 text-sm leading-relaxed text-muted-foreground sm:text-base">
                    {s.text}
                  </p>
                </div>
              </Reveal>
            ))}
          </ol>
        </div>
      </div>
    </section>
  );
}
