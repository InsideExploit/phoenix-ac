import Image from "next/image";
import Link from "next/link";
import { SectionLink } from "@/components/site/section-link";
import { sectionIdFromHref } from "@/lib/scroll";

const YEAR = new Date().getFullYear();

const COLS: { title: string; items: { label: string; href: string; external?: boolean }[] }[] = [
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
];

export function Footer() {
  return (
    <footer className="border-t border-border/60 py-14">
      <div className="container-page">
        <div className="grid gap-10 md:grid-cols-[1.4fr_1fr_1fr]">
          <div>
            <Link href="/" className="flex items-center gap-2">
              <Image src="/logo.png" alt="PhoenixAC" width={36} height={36} className="rounded-md" />
              <span className="font-heading text-lg font-semibold tracking-tight">
                Phoenix<span className="text-primary">AC</span>
              </span>
            </Link>
            <p className="mt-4 max-w-xs text-sm leading-relaxed text-muted-foreground">
              L'anticheat ufficiale di Enveart per FiveM. Attivo in background, invisibile a chi gioca pulito.
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

        <div className="mt-14 flex flex-col items-start justify-between gap-4 border-t border-border/60 pt-6 text-xs text-muted-foreground sm:flex-row sm:items-center">
          <p className="flex items-center gap-2.5 flex-wrap">
            <span>© {YEAR} PhoenixAC</span>
            <span className="h-3 w-px bg-border/60" aria-hidden="true" />
            <span>Enveart S.r.l.</span>
          </p>
          <nav className="flex items-center gap-5">
            <Link href="/tos" className="transition-colors hover:text-foreground">
              Termini di Servizio
            </Link>
          </nav>
        </div>
      </div>
    </footer>
  );
}
