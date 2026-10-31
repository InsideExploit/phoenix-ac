import Image from "next/image";
import Link from "next/link";
import { SectionLink } from "@/components/site/section-link";
import { sectionIdFromHref } from "@/lib/scroll";

function DiscordIcon({ className }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">
      <path d="M20.317 4.37a19.791 19.791 0 0 0-4.885-1.515.074.074 0 0 0-.079.037c-.21.375-.444.864-.608 1.25a18.27 18.27 0 0 0-5.487 0 12.64 12.64 0 0 0-.617-1.25.077.077 0 0 0-.079-.037A19.736 19.736 0 0 0 3.677 4.37a.07.07 0 0 0-.032.027C.533 9.046-.32 13.58.099 18.057a.082.082 0 0 0 .031.057 19.9 19.9 0 0 0 5.993 3.03.078.078 0 0 0 .084-.028 14.09 14.09 0 0 0 1.226-1.994.076.076 0 0 0-.041-.106 13.107 13.107 0 0 1-1.872-.892.077.077 0 0 1-.008-.128 10.2 10.2 0 0 0 .372-.292.074.074 0 0 1 .077-.01c3.928 1.793 8.18 1.793 12.062 0a.074.074 0 0 1 .078.01c.12.098.246.198.373.292a.077.077 0 0 1-.006.127 12.299 12.299 0 0 1-1.873.892.077.077 0 0 0-.041.107c.36.698.772 1.362 1.225 1.993a.076.076 0 0 0 .084.028 19.839 19.839 0 0 0 6.002-3.03.077.077 0 0 0 .032-.054c.5-5.177-.838-9.674-3.549-13.66a.061.061 0 0 0-.031-.03zM8.02 15.33c-1.183 0-2.157-1.085-2.157-2.419 0-1.333.956-2.419 2.157-2.419 1.21 0 2.176 1.096 2.157 2.42 0 1.333-.956 2.418-2.157 2.418zm7.975 0c-1.183 0-2.157-1.085-2.157-2.419 0-1.333.955-2.419 2.157-2.419 1.21 0 2.176 1.096 2.157 2.42 0 1.333-.946 2.418-2.157 2.418z" />
    </svg>
  );
}

const YEAR = new Date().getFullYear();

const COLS: { title: string; items: { label: string; href: string; external?: boolean; discord?: boolean }[] }[] = [
  {
    title: "Prodotto",
    items: [
      { label: "Funzionalità", href: "/#features" },
      { label: "Come funziona", href: "/#how" },
      { label: "Scarica", href: "/#download" },
    ],
  },
  {
    title: "Progetto",
    items: [
      { label: "Chi siamo", href: "/chi-siamo" },
      { label: "Termini di Servizio", href: "/tos" },
      { label: "Dashboard", href: "/dashboard" },
    ],
  },
  {
    title: "Contatti",
    items: [
      { label: "Discord", href: "#", external: true, discord: true },
    ],
  },
];

export function Footer() {
  return (
    <footer className="border-t border-border/60 py-14">
      <div className="container-page">
        <div className="grid gap-10 md:grid-cols-[1.4fr_1fr_1fr_1fr]">
          <div>
            <Link href="/" className="flex items-center gap-2">
              <Image src="/logo.png" alt="PhoenixAC" width={36} height={36} className="rounded-md" />
              <span className="font-heading text-lg font-semibold tracking-tight">
                Phoenix<span className="text-primary">AC</span>
              </span>
            </Link>
            <p className="mt-4 max-w-xs text-sm leading-relaxed text-muted-foreground">
              Rilevamento attivo, log leggibili, zero rumore. L'anticheat per chi vuole risultati, non promesse.
            </p>
          </div>

          {COLS.map((col) => (
            <div key={col.title}>
              <p className="text-xs font-medium uppercase tracking-[0.16em] text-muted-foreground">
                {col.title}
              </p>
              <ul className="mt-4 space-y-2">
                {col.items.map((it) =>
                  it.external ? (
                    <li key={it.label}>
                      <a
                        href={it.href}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="inline-flex items-center gap-2 text-sm text-muted-foreground transition-colors hover:text-foreground"
                      >
                        {it.discord && <DiscordIcon className="size-4 shrink-0" />}
                        {it.label}
                      </a>
                    </li>
                  ) : sectionIdFromHref(it.href) ? (
                    <li key={it.label}>
                      <SectionLink
                        href={it.href}
                        className="text-sm text-muted-foreground transition-colors hover:text-foreground"
                      >
                        {it.label}
                      </SectionLink>
                    </li>
                  ) : (
                    <li key={it.label}>
                      <Link
                        href={it.href}
                        className="text-sm text-muted-foreground transition-colors hover:text-foreground"
                      >
                        {it.label}
                      </Link>
                    </li>
                  ),
                )}
              </ul>
            </div>
          ))}
        </div>

        <div className="mt-14 flex flex-col items-start justify-between gap-3 border-t border-border/60 pt-6 text-xs text-muted-foreground sm:flex-row sm:items-center">
          <p>© {YEAR} PhoenixAC</p>
        </div>
      </div>
    </footer>
  );
}
