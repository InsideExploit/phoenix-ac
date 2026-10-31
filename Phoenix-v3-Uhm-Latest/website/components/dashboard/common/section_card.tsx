import type { ReactNode } from 'react';

export function SectionCard({
  title,
  meta,
  children,
  actions,
}: {
  title?: string;
  meta?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
}) {
  return (
    <div className="overflow-hidden rounded-lg border border-white/[0.06] bg-[#0F0F0F]">
      {(title || meta || actions) && (
        <div className="flex items-center gap-3 border-b border-white/[0.06] px-4 py-3">
          {title && <p className="text-[12.5px] font-medium text-white">{title}</p>}
          {meta && <span className="text-[11px] text-white/45">{meta}</span>}
          {actions && <div className="ml-auto flex items-center gap-2">{actions}</div>}
        </div>
      )}
      {children}
    </div>
  );
}
