'use client';

import { useEffect, useState } from 'react';

import { Cta } from '@/components/site/cta';
import { DownloadDialog } from '@/components/site/download-dialog';
import { Faq } from '@/components/site/faq';
import { Features } from '@/components/site/features';
import { Footer } from '@/components/site/footer';
import { Hero } from '@/components/site/hero';
import { How } from '@/components/site/how';
import { Nav } from '@/components/site/nav';
import { scrollToSection } from '@/lib/scroll';

export default function HomePage() {
  const [open, setOpen] = useState(false);
  const openDialog = () => setOpen(true);
  useEffect(() => {
    const run = () => {
      const id = window.location.hash.slice(1);
      if (!id) return;
      setTimeout(() => scrollToSection(id), 100);
    };
    run();
    window.addEventListener('hashchange', run);
    return () => window.removeEventListener('hashchange', run);
  }, []);
  return (
    <div className="page-enter min-h-screen bg-background">
      <Nav onDownload={openDialog} />
      <main>
        <Hero onDownload={openDialog} />
        <Features />
        <How />
        <Faq />
        <Cta onDownload={openDialog} />
      </main>
      <Footer />
      <DownloadDialog
        open={open}
        onClose={() => setOpen(false)}
      />
    </div>
  );
}
