'use client';

import { useEffect, useState } from 'react';

import { cn } from '@/lib/utils';

export default function TosToc({
  items,
}: {
  items: {
    id: string;
    num: string;
    toc: string;
  }[];
}) {
  const [active, setActive] = useState(items[0]?.id ?? '');
  useEffect(() => {
    const io = new IntersectionObserver(
      (entries) => {
        entries.forEach((e) => {
          if (e.isIntersecting) setActive(e.target.id);
        });
      },
      { rootMargin: '-28% 0px -62% 0px', threshold: 0 },
    );
    items.forEach((it) => {
      const el = document.getElementById(it.id);
      if (el) io.observe(el);
    });
    return () => io.disconnect();
  }, [items]);
  return (
    <nav className="sticky top-28 rounded-2xl border border-border/60 bg-card/40 p-4 backdrop-blur">
      <p className="mb-3 px-2 text-xs font-medium uppercase tracking-[0.16em] text-muted-foreground">
        Indice
      </p>
      <ul className="space-y-0.5">
        {items.map((it) => {
          const on = active === it.id;
          return (
            <li key={it.id}>
              <a
                href={`#${it.id}`}
                className={cn(
                  'flex items-center gap-3 rounded-md px-3 py-2 text-sm transition-colors',
                  on
                    ? 'bg-primary/10 text-foreground'
                    : 'text-muted-foreground hover:bg-muted/50 hover:text-foreground',
                )}
              >
                <span
                  className={cn(
                    'font-mono text-[11px]',
                    on ? 'text-primary' : 'text-muted-foreground/70',
                  )}
                >
                  {it.num}
                </span>
                <span>{it.toc}</span>
              </a>
            </li>
          );
        })}
      </ul>
    </nav>
  );
}
