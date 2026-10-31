import { NextRequest, NextResponse } from "next/server";
import { readFile } from "fs/promises";
import { rateLimit, clientIp, NO_STORE } from "@/lib/security/security";
import { verifyDownloadToken, STEAM_DL_COOKIE } from "@/lib/auth/steam";
import { findPlayerBySteamHex } from "@/lib/players/players";
import { config } from "@/lib/core/config";

export const runtime = "nodejs";

const fail = (error: string, status: number) =>
  NextResponse.json({ ok: false, error }, { status, headers: NO_STORE });

export async function GET(req: NextRequest) {
  if (!rateLimit(`download-steam:${clientIp(req)}`, 10, 60_000))
    return fail("Troppi tentativi. Attendi un minuto.", 429);

  const cookie = req.cookies.get(STEAM_DL_COOKIE)?.value;
  const tok = verifyDownloadToken(cookie);
  if (!tok) return fail("Accesso Steam scaduto o assente. Riprova.", 401);

  // Re-check ban/suspension state at delivery time — the cookie was issued
  // minutes ago; a fresh DB read closes the TOCTOU window.
  const player = await findPlayerBySteamHex(tok.steamHex);
  if (!player || player.banned || player.suspended)
    return fail("Account non autorizzato.", 403);

  let buf: Buffer;
  try {
    buf = await readFile(config.download_file);
  } catch {
    return fail("File non disponibile al momento. Contatta lo staff.", 503);
  }

  const name = config.download_name || "PhoenixAC.exe";
  const res = new NextResponse(new Uint8Array(buf), {
    status: 200,
    headers: {
      "Content-Type": "application/octet-stream",
      "Content-Disposition": `attachment; filename="${name}"`,
      "Content-Length": String(buf.length),
      "X-Download-Filename": name,
      ...NO_STORE,
    },
  });
  // Consume the token — cookie must not enable a second download.
  res.cookies.set(STEAM_DL_COOKIE, "", { path: "/", maxAge: 0 });
  return res;
}
