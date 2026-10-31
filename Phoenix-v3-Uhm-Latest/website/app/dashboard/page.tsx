import { cookies } from 'next/headers';
import Image from 'next/image';
import Link from 'next/link';

import DashboardClient from '@/components/dashboard/dashboard_client';
import { Button } from '@/components/ui/button';
import {
  avatarUrl,
  hasElevatedAccess,
  isAllowed,
  SESSION_COOKIE,
  verify,
} from '@/lib/auth/session';
import { userKeyB64 } from '@/lib/crypto/api_crypto';
import { getPlayers } from '@/lib/players/players';

export const metadata = { title: 'Dashboard' };

export const runtime = 'nodejs';

export const dynamic = 'force-dynamic';
const ERRORS: Record<string, string> = {
  config: 'Login Discord non configurato. Imposta le credenziali in lib/core/config.ts.',
  state: 'Sessione di login scaduta o non valida. Riprova.',
  token: "Impossibile completare l'autorizzazione con Discord. Riprova.",
  user: 'Impossibile recuperare il profilo Discord. Riprova.',
  forbidden: 'Questo account Discord non è autorizzato ad accedere alla dashboard.',
  rate: 'Troppi tentativi. Attendi un minuto e riprova.',
};

const DiscordLogo = () => (
  <svg
    className="size-4"
    viewBox="0 0 24 24"
    fill="currentColor"
    aria-hidden="true"
  >
    <path d="M20.317 4.369A19.79 19.79 0 0 0 16.558 3.2a.07.07 0 0 0-.074.035c-.16.285-.338.656-.463.948a18.27 18.27 0 0 0-5.04 0 12.6 12.6 0 0 0-.47-.948.073.073 0 0 0-.074-.035 19.736 19.736 0 0 0-3.76 1.169.066.066 0 0 0-.03.027C2.44 7.97 1.79 11.47 2.11 14.93a.08.08 0 0 0 .03.054 19.9 19.9 0 0 0 5.993 3.04.07.07 0 0 0 .078-.027c.462-.63.873-1.295 1.226-1.994a.07.07 0 0 0-.038-.097 13.1 13.1 0 0 1-1.872-.892.07.07 0 0 1-.007-.117c.126-.094.252-.192.372-.291a.07.07 0 0 1 .073-.01c3.927 1.793 8.18 1.793 12.061 0a.07.07 0 0 1 .074.009c.12.099.245.198.372.292a.07.07 0 0 1-.006.116 12.3 12.3 0 0 1-1.873.892.07.07 0 0 0-.037.098c.36.698.772 1.362 1.225 1.993a.07.07 0 0 0 .078.028 19.84 19.84 0 0 0 6.002-3.04.07.07 0 0 0 .03-.053c.5-4.001-.838-7.47-3.549-10.535a.06.06 0 0 0-.03-.028ZM8.02 12.825c-1.182 0-2.156-1.085-2.156-2.419 0-1.333.955-2.418 2.156-2.418 1.21 0 2.175 1.094 2.156 2.418 0 1.334-.955 2.419-2.156 2.419Zm7.974 0c-1.183 0-2.157-1.085-2.157-2.419 0-1.333.955-2.418 2.157-2.418 1.21 0 2.175 1.094 2.156 2.418 0 1.334-.946 2.419-2.156 2.419Z" />
  </svg>
);

export default async function DashboardPage({
  searchParams,
}: {
  searchParams: Promise<{
    error?: string;
  }>;
}) {
  const cookieStore = await cookies();
  const session = verify(cookieStore.get(SESSION_COOKIE)?.value);
  const user = session && (await isAllowed(session.id)) ? session : null;
  const { error } = await searchParams;
  if (user) {
    const firstPage = await getPlayers({ all: true });
    const canScreen = await hasElevatedAccess(user.id);
    return (
      <DashboardClient
        name={user.global_name || user.username}
        username={user.username}
        avatar={avatarUrl(user)}
        email={user.email ?? null}
        players={firstPage.players}
        apiKey={userKeyB64(user.id)}
        hasElevatedAccess={canScreen}
      />
    );
  }
  return (
    <div className="relative flex min-h-screen items-center justify-center overflow-hidden bg-background px-4">
      <div
        aria-hidden="true"
        className="pointer-events-none absolute inset-0 grid-bg [mask-image:radial-gradient(ellipse_at_center,black_0%,transparent_60%)]"
      />
      <div
        aria-hidden="true"
        className="pointer-events-none absolute left-1/2 top-1/3 -z-10 h-[520px] w-[520px] -translate-x-1/2 -translate-y-1/2 rounded-full bg-primary/15 blur-[100px]"
      />

      <div className="relative z-10 w-full max-w-sm">
        <Link
          href="/"
          className="mb-8 flex items-center justify-center gap-2.5"
        >
          <Image
            src="/logo.png"
            alt="PhoenixAC"
            width={40}
            height={40}
            className="rounded-lg"
          />
          <span className="font-heading text-xl font-semibold tracking-tight">
            Phoenix<span className="text-primary">AC</span>
          </span>
        </Link>

        <div className="overflow-hidden rounded-2xl border border-border/60 bg-card/50 backdrop-blur-sm">
          <div className="px-7 pt-7 pb-2">
            <h1 className="font-heading text-[22px] font-semibold tracking-tight">
              Accedi alla dashboard
            </h1>
            <p className="mt-1.5 text-sm leading-relaxed text-muted-foreground">
              Gestisci licenze, PIN e server protetti con il tuo account Discord.
            </p>
          </div>

          {error && ERRORS[error] && (
            <div className="mx-7 mt-4 flex items-start gap-2.5 rounded-xl border border-destructive/25 bg-destructive/8 px-4 py-3">
              <svg
                className="mt-0.5 size-4 shrink-0 text-destructive"
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                strokeWidth="2"
                strokeLinecap="round"
                strokeLinejoin="round"
                aria-hidden="true"
              >
                <circle
                  cx="12"
                  cy="12"
                  r="10"
                />
                <line
                  x1="12"
                  y1="8"
                  x2="12"
                  y2="12"
                />
                <line
                  x1="12"
                  y1="16"
                  x2="12.01"
                  y2="16"
                />
              </svg>
              <p className="text-[13px] leading-snug text-destructive">{ERRORS[error]}</p>
            </div>
          )}

          <div className="px-7 pt-5 pb-7">
            <Button
              className="h-11 w-full gap-2.5 bg-[#5865F2] text-[14px] font-medium text-white hover:bg-[#4752c4]"
              nativeButton={false}
              render={<a href="/api/auth/discord/login" />}
            >
              <DiscordLogo />
              Continua con Discord
            </Button>
          </div>
        </div>

        <div className="mt-5 text-center">
          <Link
            href="/"
            className="text-sm text-muted-foreground transition-colors hover:text-foreground"
          >
            Torna alla home
          </Link>
        </div>
      </div>
    </div>
  );
}
