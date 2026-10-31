import { Reveal } from "@/components/site/reveal";

const STEPS = [
  {
    n: "01",
    title: "Ricevi il PIN",
    text: "Lo staff di Enveart ti fornisce un PIN personale. Serve per scaricare il launcher e non è riutilizzabile.",
  },
  {
    n: "02",
    title: "Scarica e avvia",
    text: "Scarichi il launcher, lo avvii prima di entrare in gioco e non devi fare altro. Si aggiorna da solo ogni volta.",
  },
  {
    n: "03",
    title: "Gioca normalmente",
    text: "PhoenixAC lavora in background senza che tu te ne accorga. Se rispetti le regole, non cambia nulla per te.",
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
                Come iniziare.
              </h2>
            </Reveal>
            <Reveal delay={120}>
              <p className="mt-4 max-w-md text-base leading-relaxed text-muted-foreground">
                Bastano pochi minuti per essere operativo. Dopo il primo avvio non devi fare nient'altro.
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
