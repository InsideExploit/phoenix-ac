import { Reveal } from '@/components/site/reveal';

const ITEMS = [
  {
    tag: 'Client',
    title: 'Protezione lato client',
    text: 'Monitora continuamente i processi attivi sul PC del giocatore e interviene se rileva qualcosa di sospetto.',
  },
  {
    tag: 'Rilevamenti',
    title: 'Sempre aggiornato',
    text: 'I controlli vengono aggiornati in background senza che il giocatore debba fare nulla. Nessun aggiornamento manuale.',
  },
  {
    tag: 'Identity',
    title: 'Anti ban evasion',
    text: 'Chi prova a rientrare dopo un ban cambiando account viene riconosciuto e bloccato prima di entrare nel server.',
  },
  {
    tag: 'Staff',
    title: 'Log chiari',
    text: "Ogni segnalazione è comprensibile a colpo d'occhio. Lo staff vede subito cosa è successo, senza interpretare dati tecnici.",
  },
  {
    tag: 'Performance',
    title: 'Nessun impatto in game',
    text: 'Il sistema lavora in background senza toccare il gioco. Il player non nota rallentamenti né interruzioni durante la sessione.',
  },
  {
    tag: 'Ops',
    title: 'Aggiornamenti automatici',
    text: "Il client si aggiorna da solo all'avvio. Nessuna notifica, nessuna azione richiesta al giocatore o allo staff.",
  },
];

export function Features() {
  return (
    <section
      id="features"
      className="relative py-28 sm:py-36"
    >
      <div className="container-page">
        <div className="max-w-2xl">
          <Reveal>
            <span className="eyebrow">Funzionalità</span>
          </Reveal>
          <Reveal delay={60}>
            <h2 className="mt-4 font-heading text-3xl font-semibold tracking-tight sm:text-5xl">
              Cosa fa PhoenixAC.
            </h2>
          </Reveal>
          <Reveal delay={120}>
            <p className="mt-4 text-base leading-relaxed text-muted-foreground">
              Una panoramica di quello che gira in background ogni volta che entri nel server.
            </p>
          </Reveal>
        </div>

        <div className="mt-16 grid grid-cols-1 gap-px overflow-hidden rounded-2xl border border-border/60 bg-border/60 md:grid-cols-2 lg:grid-cols-3">
          {ITEMS.map((item, i) => (
            <Reveal
              key={item.title}
              delay={i * 40}
            >
              <div className="group flex h-full flex-col gap-5 bg-background p-8 transition-colors hover:bg-card">
                <span className="w-fit rounded-md border border-primary/20 bg-primary/5 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-widest text-primary">
                  {item.tag}
                </span>
                <div>
                  <h3 className="font-heading text-base font-semibold leading-snug">
                    {item.title}
                  </h3>
                  <p className="mt-2 text-sm leading-relaxed text-muted-foreground">{item.text}</p>
                </div>
              </div>
            </Reveal>
          ))}
        </div>
      </div>
    </section>
  );
}
