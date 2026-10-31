import { NextRequest, NextResponse } from 'next/server';

import { readFile } from 'fs/promises';

import { config } from '@/lib/core/config';
import { redeemPin } from '@/lib/players/players';
import { clientIp, rateLimit } from '@/lib/security/security';

export const runtime = 'nodejs';
const NAME_DEFAULT = 'PhoenixAC-Launcher.zip';
const NO_STORE = { 'Cache-Control': 'no-store, no-cache, must-revalidate, max-age=0' };
const fail = (error: string, status: number) =>
  NextResponse.json({ ok: false, error }, { status, headers: NO_STORE });

export async function POST(req: NextRequest) {
  if (!rateLimit(`download:${clientIp(req)}`, 10, 60000))
    return fail('Troppi tentativi. Attendi un minuto.', 429);
  const body = (await req.json().catch(() => null)) as {
    pin?: string;
  } | null;
  const pin = body?.pin?.trim();
  if (!pin) return fail('Inserisci un PIN.', 400);
  const file = config.download_file;
  const name = config.download_name || NAME_DEFAULT;
  let buf: Buffer;
  try {
    buf = await readFile(file);
  } catch {
    return fail('File non disponibile al momento. Contatta lo staff.', 503);
  }
  const redeemed = await redeemPin(pin);
  if (!redeemed.ok) return fail('PIN non valido o già utilizzato.', 403);
  return new NextResponse(new Uint8Array(buf), {
    status: 200,
    headers: {
      'Content-Type': 'application/octet-stream',
      'Content-Disposition': `attachment; filename="${name}"`,
      'Content-Length': String(buf.length),
      'X-Download-Filename': name,
      ...NO_STORE,
    },
  });
}
