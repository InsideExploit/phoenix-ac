'use client';

import type { ReactNode } from 'react';

import Image from 'next/image';

import {
  LogOut,
  Menu as MenuIcon,
  Radar,
  ScanFace,
  Ticket,
  TrendingUp,
  UsersRound,
  X,
} from 'lucide-react';

import type { View } from './types';

const NAV: {
  view: View;
  icon: React.ElementType;
  label: string;
}[] = [
  { view: 'players', icon: UsersRound, label: 'Players' },
  { view: 'detections', icon: Radar, label: 'Detections' },
  { view: 'pins', icon: Ticket, label: 'PIN codes' },
  { view: 'stats', icon: TrendingUp, label: 'Statistics' },
  { view: 'evasion', icon: ScanFace, label: 'Ban evasion' },
];

const VIEW_TITLE: Record<
  View,
  {
    title: string;
    subtitle: string;
  }
> = {
  players: { title: 'Players', subtitle: 'Manage authorized players' },
  detections: { title: 'Detections', subtitle: 'Anticheat detection history' },
  pins: { title: 'PIN codes', subtitle: 'Enrollment codes' },
  stats: { title: 'Statistics', subtitle: 'Live player metrics' },
  evasion: { title: 'Ban evasion', subtitle: 'Fingerprint matches' },
};

export function DashboardShell({
  view,
  onView,
  user,
  sidebarOpen,
  setSidebarOpen,
  children,
}: {
  view: View;
  onView: (v: View) => void;
  user: {
    name: string;
    username: string;
    email: string | null;
    avatar: string;
  };
  sidebarOpen: boolean;
  setSidebarOpen: (v: boolean) => void;
  children: ReactNode;
}) {
  const meta = VIEW_TITLE[view];
  return (
    <div className="flex h-screen overflow-hidden bg-[#0A0A0A] text-white">
      <aside
        className={
          'fixed inset-y-0 left-0 z-40 flex w-[220px] flex-col border-r border-white/[0.05] bg-[#0C0C0C] transition-transform duration-200 lg:translate-x-0 ' +
          (sidebarOpen ? 'translate-x-0' : '-translate-x-full lg:translate-x-0')
        }
      >
        <div className="flex h-[52px] shrink-0 items-center gap-2.5 border-b border-white/[0.05] px-4">
          <Image
            src="/logo.png"
            alt="PhoenixAC"
            width={22}
            height={22}
            className="shrink-0"
          />
          <p className="text-[13px] font-semibold text-white">PhoenixAC</p>
          <button
            className="ml-auto text-white/45 hover:text-white lg:hidden"
            onClick={() => setSidebarOpen(false)}
            aria-label="Close menu"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        <nav className="flex flex-1 flex-col gap-0.5 overflow-y-auto p-2">
          {NAV.map(({ view: v, icon: Icon, label }) => {
            const active = view === v;
            return (
              <button
                key={v}
                onClick={() => {
                  onView(v);
                  setSidebarOpen(false);
                }}
                className={
                  'flex items-center gap-2.5 rounded-md px-2.5 py-1.5 text-left text-[12.5px] transition-colors ' +
                  (active
                    ? 'bg-white/[0.06] text-white'
                    : 'text-white/55 hover:bg-white/[0.03] hover:text-white/85')
                }
              >
                <Icon className="h-3.5 w-3.5" />
                {label}
              </button>
            );
          })}
        </nav>

        <div className="shrink-0 border-t border-white/[0.05] p-2">
          <div className="flex items-center gap-2.5 rounded-md px-1.5 py-1.5">
            <div className="flex h-6 w-6 shrink-0 items-center justify-center overflow-hidden rounded-full bg-[#5865F2]">
              <img
                src={user.avatar}
                alt={user.username}
                className="h-full w-full object-cover"
              />
            </div>
            <div className="min-w-0 flex-1">
              <p className="truncate text-[11.5px] font-medium leading-none text-white">
                {user.name}
              </p>
              <p className="mt-0.5 truncate text-[10px] text-white/40">
                {user.email ?? user.username}
              </p>
            </div>
            <a
              href="/api/auth/logout"
              className="text-white/40 hover:text-red-400/85"
              aria-label="Log out"
            >
              <LogOut className="h-3.5 w-3.5" />
            </a>
          </div>
        </div>
      </aside>

      {sidebarOpen && (
        <div
          className="fixed inset-0 z-30 bg-black/60 lg:hidden"
          onClick={() => setSidebarOpen(false)}
        />
      )}

      <div className="flex min-w-0 flex-1 flex-col lg:ml-[220px]">
        <header className="flex h-[52px] shrink-0 items-center gap-3 border-b border-white/[0.05] bg-[#0C0C0C] px-4 lg:px-6">
          <button
            className="text-white/60 hover:text-white lg:hidden"
            onClick={() => setSidebarOpen(true)}
            aria-label="Open menu"
          >
            <MenuIcon className="h-4 w-4" />
          </button>
          <div className="min-w-0">
            <h1 className="truncate text-[13.5px] font-semibold leading-none text-white">
              {meta.title}
            </h1>
            <p className="mt-1 truncate text-[10.5px] text-white/40">{meta.subtitle}</p>
          </div>
        </header>

        <main className="flex-1 overflow-x-hidden overflow-y-auto p-4 lg:p-6">{children}</main>
      </div>
    </div>
  );
}
