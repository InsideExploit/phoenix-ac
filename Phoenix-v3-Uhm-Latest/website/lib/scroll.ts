const NAV_OFFSET = 76;
const DURATION = 700;
let raf: number | null = null;

function ease(t: number) {
  return t < 0.5 ? 2 * t * t : -1 + (4 - 2 * t) * t;
}

function animateTo(target: number) {
  if (raf !== null) cancelAnimationFrame(raf);
  const start = document.documentElement.scrollTop || document.body.scrollTop;
  const delta = target - start;
  if (Math.abs(delta) < 2) return;
  const t0 = performance.now();
  const step = (now: number) => {
    const p = Math.min((now - t0) / DURATION, 1);
    const y = start + delta * ease(p);
    document.documentElement.scrollTop = y;
    document.body.scrollTop = y;
    if (p < 1) {
      raf = requestAnimationFrame(step);
    } else {
      raf = null;
    }
  };
  raf = requestAnimationFrame(step);
}

export function scrollToSection(id: string) {
  const el = document.getElementById(id);
  if (!el) return false;
  const rect = el.getBoundingClientRect();
  const top =
    rect.top + (document.documentElement.scrollTop || document.body.scrollTop) - NAV_OFFSET;
  animateTo(Math.max(0, top));
  return true;
}

export function sectionIdFromHref(href: string) {
  const match = href.match(/^(?:\/)?#([\w-]+)$/);
  return match?.[1] ?? null;
}

export function navigateToSection(href: string, onDone?: () => void) {
  const id = sectionIdFromHref(href);
  if (!id) return false;
  scrollToSection(id);
  onDone?.();
  return true;
}
