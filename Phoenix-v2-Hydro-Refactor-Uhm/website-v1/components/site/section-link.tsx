"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { navigateToSection, sectionIdFromHref } from "@/lib/scroll";
import { cn } from "@/lib/utils";

const buttonReset =
  "cursor-pointer border-0 bg-transparent p-0 font-inherit text-inherit no-underline";

export function SectionLink({
  href,
  className,
  children,
  onNavigate,
}: {
  href: string;
  className?: string;
  children: React.ReactNode;
  onNavigate?: () => void;
}) {
  const pathname = usePathname();
  const sectionId = sectionIdFromHref(href);
  const onHome = pathname === "/";

  if (sectionId && onHome) {
    return (
      <button
        type="button"
        className={cn(buttonReset, className)}
        onClick={() => navigateToSection(href, onNavigate)}
      >
        {children}
      </button>
    );
  }

  return (
    <Link
      href={href}
      scroll={false}
      className={cn(className)}
      onClick={() => onNavigate?.()}
    >
      {children}
    </Link>
  );
}
