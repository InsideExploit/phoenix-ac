import type { Metadata } from "next";
import { Outfit } from "next/font/google";
import { cn } from "@/lib/utils";
import { BgFx } from "@/components/site/bg-fx";
import "./globals.css";

const sans = Outfit({
  subsets: ["latin"],
  variable: "--font-sans",
  display: "swap",
});

export const metadata: Metadata = {
  title: {
    default: "PhoenixAC",
    template: "PhoenixAC - %s",
  },
  description:
    "Anticheat per server FiveM: protezione client e server, launcher e dashboard per lo staff.",
};

export const viewport = { themeColor: "#0a0a0a" };

export default function RootLayout({
  children,
}: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="it" className={cn("dark font-sans", sans.variable)}>
      <body suppressHydrationWarning>
        <BgFx />
        <div aria-hidden="true" className="grain-overlay" />
        {children}
      </body>
    </html>
  );
}
