import Link from "next/link";
import { ArrowLeft } from "lucide-react";
import { PageShell } from "@/components/site/page-shell";
import { Reveal } from "@/components/site/reveal";
import TosToc from "@/components/tos/tos_toc";
import { Button } from "@/components/ui/button";

export const metadata = {
  title: "Termini di Servizio",
  description:
    "Termini di Servizio del launcher PhoenixAC: permessi, trattamento dati, condotte vietate, sanzioni e riferimenti normativi.",
};

const UPDATED = "2 luglio 2026";
const VERSION = "v1.1";

type Block =
  | { type: "p"; text: string }
  | { type: "list"; items: { label?: string; text: string }[] };

type Section = {
  id: string;
  num: string;
  toc: string;
  title: string;
  blocks: Block[];
};

const SECTIONS: Section[] = [
  {
    id: "accettazione",
    num: "01",
    toc: "Accettazione",
    title: "Accettazione dei termini",
    blocks: [
      {
        type: "p",
        text: "Scaricando, installando o utilizzando il launcher PhoenixAC dichiari di aver letto, compreso e accettato integralmente i presenti Termini di Servizio. Se non accetti anche una sola clausola, non installare il software e rimuovilo dal dispositivo.",
      },
      {
        type: "p",
        text: "I Termini si applicano al launcher client, ai componenti server collegati, agli aggiornamenti automatici e a ogni servizio accessorio messo a disposizione sotto il marchio PhoenixAC.",
      },
    ],
  },
  {
    id: "permessi",
    num: "02",
    toc: "Permessi",
    title: "Permessi e accesso al sistema",
    blocks: [
      {
        type: "p",
        text: "PhoenixAC è un software di sicurezza. Per eseguire i controlli anti-cheat può richiedere privilegi elevati (amministratore), analizzare processi in esecuzione, verificare l'integrità di file e moduli e comunicare con i server PhoenixAC. Avviando il software con tali permessi presti consenso esplicito a queste operazioni.",
      },
      {
        type: "list",
        items: [
          {
            label: "Titolarità del dispositivo",
            text: "Dichiari di avere il diritto di installare software con privilegi elevati sul computer utilizzato e di non violare policy aziendali, scolastiche o di rete di terzi.",
          },
          {
            label: "Interferenze",
            text: "Per garantire l'efficacia dei controlli, il launcher può richiedere la chiusura di programmi che interferiscono con le verifiche (debugger, hook, tool di iniezione o analisi del traffico applicato al processo di gioco).",
          },
        ],
      },
    ],
  },
  {
    id: "dati",
    num: "03",
    toc: "Dati e privacy",
    title: "Dati raccolti e trattamento",
    blocks: [
      {
        type: "p",
        text: "Il trattamento dei dati personali avviene nel rispetto del Regolamento (UE) 2016/679 («GDPR») e del D.Lgs. 196/2003, come modificato dal D.Lgs. 101/2018. Il titolare del trattamento è Enveart, in qualità di gestore di PhoenixAC.",
      },
      {
        type: "p",
        text: "Per finalità di sicurezza e prevenzione delle frodi, PhoenixAC può raccogliere e trasmettere ai propri server:",
      },
      {
        type: "list",
        items: [
          {
            label: "Identificativi di gioco",
            text: "Steam Hex, license Rockstar, Discord ID e nickname associati alla sessione.",
          },
          {
            label: "Identificativo dispositivo",
            text: "HWID e informazioni di sistema strettamente necessarie al riconoscimento di tentativi di elusione dei ban.",
          },
          {
            label: "Log tecnici",
            text: "Tipo di violazione rilevata, processi o moduli sospetti, data e ora dell'evento, indirizzo IP della connessione.",
          },
        ],
      },
      {
        type: "list",
        items: [
          {
            label: "Base giuridica",
            text: "Esecuzione del servizio richiesto dall'utente (art. 6, co. 1, lett. b GDPR) e legittimo interesse del titolare e delle community ospitanti a garantire un ambiente di gioco leale (art. 6, co. 1, lett. f GDPR).",
          },
          {
            label: "Conservazione",
            text: "I dati sono conservati per il tempo necessario alle finalità di sicurezza, gestione ban e difesa in giudizio, salvo obblighi di legge diversi.",
          },
          {
            label: "Diritti dell'interessato",
            text: "Puoi esercitare i diritti di accesso, rettifica, cancellazione, limitazione, opposizione e portabilità previsti dagli artt. 15-22 GDPR, nonché proporre reclamo al Garante per la protezione dei dati personali, scrivendo ai contatti indicati in fondo al documento.",
          },
          {
            label: "Nessuna vendita",
            text: "I dati non sono venduti né ceduti a terzi per finalità di marketing.",
          },
        ],
      },
    ],
  },
  {
    id: "licenza",
    num: "04",
    toc: "Licenza",
    title: "Licenza d'uso del software",
    blocks: [
      {
        type: "p",
        text: "Ti concediamo una licenza personale, limitata, non esclusiva, non trasferibile e revocabile per utilizzare PhoenixAC al solo fine di connetterti ai server che adottano il sistema.",
      },
      {
        type: "list",
        items: [
          {
            label: "Divieto di ridistribuzione",
            text: "È vietato rivendere, ridistribuire, sublicenziare, pubblicare o caricare i file del software su piattaforme di terzi senza autorizzazione scritta.",
          },
          {
            label: "Integrità del software",
            text: "È vietato rimuovere o alterare avvisi, firme, crediti o meccanismi di protezione presenti nel programma.",
          },
        ],
      },
    ],
  },
  {
    id: "divieti",
    num: "05",
    toc: "Condotte vietate",
    title: "Condotte vietate",
    blocks: [
      {
        type: "p",
        text: "Per preservare l'efficacia dell'anticheat e la sicurezza delle community sono vietate, a titolo esemplificativo e non esaustivo, le seguenti attività:",
      },
      {
        type: "list",
        items: [
          {
            label: "Reverse engineering",
            text: "Decompilare, disassemblare, intercettare o analizzare il funzionamento di PhoenixAC al fine di aggirarlo, riprodurlo o crearne derivati non autorizzati.",
          },
          {
            label: "Bypass e test offensivi",
            text: "Utilizzare il software per testare cheat, injector, macro o qualsiasi strumento finalizzato all'elusione dei controlli.",
          },
          {
            label: "Manomissione",
            text: "Modificare, disattivare, offuscare o interferire con file, processi o comunicazioni del launcher.",
          },
          {
            label: "Cheating",
            text: "Usare software o script di terze parti che alterano il gameplay, la visibilità, la mira o l'economia del server.",
          },
          {
            label: "Ban evasion",
            text: "Tentare di aggirare un ban tramite nuovi account, spoofing hardware o qualsiasi altra tecnica di occultamento dell'identità.",
          },
        ],
      },
      {
        type: "p",
        text: "Le condotte sopra descritte possono integrare, ove ne ricorrano i presupposti, fattispecie di reato previste dalla legge italiana, tra cui l'accesso abusivo a un sistema informatico (art. 615-ter c.p.), il danneggiamento di dati, programmi o sistemi informatici (art. 635-quater c.p.) e le violazioni della disciplina sul diritto d'autore in materia di programmi per elaboratore (art. 171-ter e ss. Legge 22 aprile 1941, n. 633). La violazione di tali norme può comportare responsabilità penale e civile indipendentemente dalle sanzioni applicate all'interno del gioco.",
      },
    ],
  },
  {
    id: "sanzioni",
    num: "06",
    toc: "Sanzioni",
    title: "Rilevamenti, sanzioni e ban",
    blocks: [
      {
        type: "p",
        text: "Il rilevamento di una violazione può comportare, a discrezione del sistema e dello staff della community:",
      },
      {
        type: "list",
        items: [
          { text: "Espulsione immediata (kick) dal server." },
          { text: "Ban permanente o temporaneo sul server interessato." },
          { text: "Ban a livello PhoenixAC esteso agli altri server protetti dal sistema." },
          { text: "Associazione del ban a identificativi account, hardware e altri segnali raccolti." },
        ],
      },
      {
        type: "p",
        text: "Le decisioni automatizzate hanno finalità di sicurezza. Eventuali ricorsi vanno presentati esclusivamente tramite i canali ufficiali del progetto o della community ospitante. Non è garantita la revoca di alcun ban.",
      },
    ],
  },
  {
    id: "pin",
    num: "07",
    toc: "PIN",
    title: "PIN di download",
    blocks: [
      {
        type: "p",
        text: "Il PIN fornito per scaricare il launcher è personale e monouso. Sei responsabile del suo utilizzo: non condividerlo con terzi. Ogni download effettuato con il tuo PIN è attribuito a te agli effetti di questi Termini.",
      },
    ],
  },
  {
    id: "aggiornamenti",
    num: "08",
    toc: "Aggiornamenti",
    title: "Aggiornamenti del software",
    blocks: [
      {
        type: "p",
        text: "PhoenixAC può aggiornarsi automaticamente per contrastare nuove minacce. Gli aggiornamenti possono modificare funzionalità, criteri di rilevamento e requisiti di sistema. L'uso continuato dopo un aggiornamento vale come accettazione della versione in vigore.",
      },
    ],
  },
  {
    id: "minori",
    num: "09",
    toc: "Minori",
    title: "Utenti minorenni",
    blocks: [
      {
        type: "p",
        text: "Se hai meno di 18 anni puoi utilizzare PhoenixAC solo con il consenso di chi esercita la responsabilità genitoriale, che deve leggere e accettare questi Termini e il trattamento dei dati descritto sopra.",
      },
    ],
  },
  {
    id: "normativa",
    num: "10",
    toc: "Normativa",
    title: "Riferimenti normativi",
    blocks: [
      {
        type: "p",
        text: "Oltre a quanto già richiamato, i presenti Termini fanno riferimento, per quanto applicabile, a:",
      },
      {
        type: "list",
        items: [
          {
            text: "Regolamento (UE) 2016/679 relativo alla protezione delle persone fisiche con riguardo al trattamento dei dati personali.",
          },
          {
            text: "Codice in materia di protezione dei dati personali (D.Lgs. 196/2003) e successive modifiche.",
          },
          {
            text: "Codice penale, in particolare gli artt. 615-ter e 635-quater in materia di accesso e danneggiamento di sistemi informatici.",
          },
          {
            text: "Legge 22 aprile 1941, n. 633, sulla protezione del diritto d'autore, per quanto riguarda la riproduzione e l'alterazione non autorizzata del software.",
          },
          {
            text: "D.Lgs. 6 settembre 2005, n. 206 (Codice del consumo), per gli utenti che rivestono la qualifica di consumatori.",
          },
        ],
      },
    ],
  },
  {
    id: "legge",
    num: "11",
    toc: "Legge e contatti",
    title: "Legge applicabile, foro e contatti",
    blocks: [
      {
        type: "p",
        text: "I presenti Termini sono regolati dalla legge italiana. Per gli utenti consumatori restano salve le disposizioni inderogabili del Codice del consumo e il foro del luogo di residenza o domicilio del consumatore, ove applicabile.",
      },
      {
        type: "p",
        text: "Ci riserviamo di aggiornare questo documento in qualsiasi momento. La versione pubblicata su questa pagina fa fede. L'uso del software dopo la pubblicazione di una modifica costituisce accettazione dei nuovi termini.",
      },
      {
        type: "p",
        text: "Per richieste relative ai Termini, al trattamento dei dati o alle sanzioni applicate, contatta lo staff del server tramite i canali ufficiali del progetto.",
      },
    ],
  },
];

function Blocks({ blocks }: { blocks: Block[] }) {
  return (
    <div className="space-y-4">
      {blocks.map((b, i) => {
        if (b.type === "p") {
          return (
            <p key={i} className="text-[0.9375rem] leading-[1.8] text-muted-foreground">
              {b.text}
            </p>
          );
        }
        return (
          <ul
            key={i}
            className="space-y-3 rounded-xl border border-border/60 bg-card/40 px-5 py-4 backdrop-blur"
          >
            {b.items.map((it, j) => (
              <li key={j} className="text-[0.9375rem] leading-[1.75] text-muted-foreground">
                {it.label && (
                  <span className="font-medium text-foreground">{it.label}. </span>
                )}
                {it.text}
              </li>
            ))}
          </ul>
        );
      })}
    </div>
  );
}

export default function TosPage() {
  const tocItems = SECTIONS.map((s) => ({
    id: s.id,
    num: s.num,
    toc: s.toc,
  }));

  return (
    <PageShell>
      <Reveal>
        <Button
          variant="ghost"
          size="sm"
          className="mb-10 -ml-2 text-muted-foreground hover:text-foreground"
          nativeButton={false}
          render={<Link href="/" />}
        >
          <ArrowLeft />
          Torna alla home
        </Button>
      </Reveal>

      <Reveal delay={60}>
        <header className="max-w-3xl">
          <span className="eyebrow">Documento legale</span>
          <h1 className="mt-4 font-heading text-4xl font-semibold leading-[1.1] tracking-tight md:text-5xl">
            Termini di Servizio
          </h1>
          <p className="mt-4 text-sm text-muted-foreground">
            PhoenixAC · {VERSION} · aggiornato il {UPDATED}
          </p>
          <p className="mt-6 max-w-2xl text-[0.9375rem] leading-relaxed text-muted-foreground">
            Questo documento spiega come funziona PhoenixAC e quali regole valgono
            quando installi o usi il launcher. Se qualcosa non è chiaro,
            contattaci prima di procedere.
          </p>
        </header>
      </Reveal>

      <div className="mt-16 grid gap-x-14 gap-y-12 lg:grid-cols-12">
        <aside className="hidden lg:col-span-4 lg:block">
          <Reveal delay={120}>
            <TosToc items={tocItems} />
          </Reveal>
        </aside>

        <main className="lg:col-span-8">
          <div className="space-y-16">
            {SECTIONS.map((s, index) => (
              <Reveal key={s.id} delay={index < 4 ? 160 + index * 40 : 0}>
                <section id={s.id} className="scroll-mt-32">
                  <div className="mb-6 flex items-baseline gap-3">
                    <span className="font-mono text-xs text-primary">{s.num}</span>
                    <h2 className="font-heading text-xl font-semibold sm:text-2xl">
                      {s.title}
                    </h2>
                  </div>
                  <Blocks blocks={s.blocks} />
                </section>
              </Reveal>
            ))}

            <Reveal>
              <p className="border-t border-border/60 pt-8 text-sm leading-relaxed text-muted-foreground">
                Utilizzando PhoenixAC confermi di aver letto e accettato i presenti
                Termini di Servizio.
              </p>
            </Reveal>
          </div>
        </main>
      </div>
    </PageShell>
  );
}
