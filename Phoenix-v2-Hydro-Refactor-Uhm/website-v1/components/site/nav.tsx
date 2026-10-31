"use client";

import Image from "next/image";
import Link from "next/link";
import { useEffect, useState } from "react";
import { Menu } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
  SheetTrigger,
} from "@/components/ui/sheet";
import { SectionLink } from "@/components/site/section-link";
import { navigateToSection, scrollToSection, sectionIdFromHref } from "@/lib/scroll";
import { cn } from "@/lib/utils";

const LINKS = [
  { href: "/#features", label: "Funzionalità" },
  { href: "/#how", label: "Come funziona" },
  { href: "/#faq", label: "FAQ" },
  { href: "/chi-siamo", label: "Chi siamo" },
];

export function Nav({ onDownload }: { onDownload?: () => void }) {
  const [scrolled, setScrolled] = useState(false);
  const [open, setOpen] = useState(false);

  useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY > 12);
    onScroll();
    window.addEventListener("scroll", onScroll, { passive: true });
    return () => window.removeEventListener("scroll", onScroll);
  }, []);

  const download = () => {
    if (onDownload) {
      onDownload();
      return;
    }
    if (window.location.pathname === "/") {
      navigateToSection("/#download");
      return;
    }
    window.location.assign("/#download");
  };

  const linkClass = "text-sm text-muted-foreground transition-colors hover:text-foreground";
  const mobileLinkClass =
    "rounded-md px-3 py-3 text-sm text-muted-foreground hover:bg-muted hover:text-foreground";

  return (
    <header
      className={cn(
        "fixed inset-x-0 top-0 z-50 transition-colors duration-300",
        scrolled
          ? "border-b border-border/60 bg-background/70 backdrop-blur-xl"
          : "border-b border-transparent bg-transparent",
      )}
    >
      <div className="h-px w-full bg-gradient-to-r from-transparent via-primary/60 to-transparent" />
      <nav className="container-page flex h-16 items-center justify-between">
        <Link href="/" className="flex items-center gap-2">
          <Image src="/logo.png" alt="PhoenixAC" width={52} height={52} className="rounded-lg" priority />
          <span className="font-heading text-lg font-semibold tracking-tight">
            Phoenix<span className="text-primary">AC</span>
          </span>
        </Link>

        <div className="hidden items-center gap-8 md:flex">
          {LINKS.map((l) =>
            sectionIdFromHref(l.href) ? (
              <SectionLink key={l.href} href={l.href} className={linkClass}>
                {l.label}
              </SectionLink>
            ) : (
              <Link key={l.href} href={l.href} className={linkClass}>
                {l.label}
              </Link>
            ),
          )}
        </div>

        <div className="hidden items-center gap-2 md:flex">
          <Button
            variant="ghost"
            className="h-9 px-4 text-sm text-muted-foreground hover:text-foreground"
            nativeButton={false}
            render={<Link href="/dashboard" />}
          >
            Dashboard
          </Button>
          <Button className="h-9 px-4 text-sm" onClick={download}>
            Scarica
          </Button>
        </div>

        <Sheet open={open} onOpenChange={setOpen}>
          <SheetTrigger
            render={
              <Button variant="ghost" size="icon-sm" className="md:hidden" aria-label="Apri menu">
                <Menu />
              </Button>
            }
          />
          <SheetContent side="right" className="w-[320px] p-0">
            <SheetHeader className="border-b border-border/60 px-6">
              <SheetTitle className="flex items-center gap-2">
                <Image src="/logo.png" alt="PhoenixAC" width={24} height={24} className="rounded-sm" />
                Phoenix<span className="text-primary">AC</span>
              </SheetTitle>
            </SheetHeader>
            <div className="flex flex-1 flex-col gap-1 px-4 py-6">
              {LINKS.map((l) =>
                sectionIdFromHref(l.href) ? (
                  <SectionLink
                    key={l.href}
                    href={l.href}
                    className={mobileLinkClass}
                    onNavigate={() => setOpen(false)}
                  >
                    {l.label}
                  </SectionLink>
                ) : (
                  <Link
                    key={l.href}
                    href={l.href}
                    onClick={() => setOpen(false)}
                    className={mobileLinkClass}
                  >
                    {l.label}
                  </Link>
                ),
              )}
              <Link
                href="/dashboard"
                onClick={() => setOpen(false)}
                className={mobileLinkClass}
              >
                Dashboard
              </Link>
            </div>
            <div className="border-t border-border/60 p-4">
              <Button
                className="w-full"
                onClick={() => {
                  setOpen(false);
                  download();
                }}
              >
                Scarica
              </Button>
            </div>
          </SheetContent>
        </Sheet>
      </nav>
    </header>
  );
}
