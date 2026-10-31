import crypto from "crypto";
import { config } from "@/lib/core/config";

// Steam sign-in uses OpenID 2.0 (not OAuth). We redirect the user to Steam,
// Steam bounces them back with signed OpenID params, and we verify by asking
// Steam's endpoint to `check_authentication`. On success we receive the
// user's SteamID64 in `openid.claimed_id`.

export const STEAM_OPENID_URL = "https://steamcommunity.com/openid/login";
export const STEAM_DL_COOKIE = "phoenixac_dl";

const OPENID_NS = "http://specs.openid.net/auth/2.0";
const OPENID_ID_SELECT = "http://specs.openid.net/auth/2.0/identifier_select";

export function realm(): string {
  const custom = config.steam_openid_realm;
  return (custom || config.site_url).replace(/\/+$/, "");
}

export function returnTo(): string {
  return `${realm()}/api/auth/callback/steam`;
}

export function buildAuthorizeUrl(): string {
  const p = new URLSearchParams();
  p.set("openid.ns",         OPENID_NS);
  p.set("openid.mode",       "checkid_setup");
  p.set("openid.return_to",  returnTo());
  p.set("openid.realm",      realm());
  p.set("openid.identity",   OPENID_ID_SELECT);
  p.set("openid.claimed_id", OPENID_ID_SELECT);
  return `${STEAM_OPENID_URL}?${p.toString()}`;
}

const STEAMID_RE = /^https?:\/\/steamcommunity\.com\/openid\/id\/(\d{17})$/;

export function extractSteamId(claimedId: string | null): string | null {
  if (!claimedId) return null;
  const m = claimedId.match(STEAMID_RE);
  return m ? m[1] : null;
}

// Steam requires a check_authentication roundtrip against every login callback
// to prove the params really came from Steam and haven't been tampered with.
export async function verifyOpenIdCallback(rawParams: URLSearchParams): Promise<{
  ok: boolean;
  steamId64?: string;
}> {
  const claimedId = rawParams.get("openid.claimed_id");
  const steamId64 = extractSteamId(claimedId);
  if (!steamId64) return { ok: false };

  const body = new URLSearchParams();
  for (const [k, v] of rawParams.entries()) body.set(k, v);
  body.set("openid.mode", "check_authentication");

  let text = "";
  try {
    const res = await fetch(STEAM_OPENID_URL, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: body.toString(),
      cache: "no-store",
    });
    text = await res.text();
  } catch {
    return { ok: false };
  }
  if (!/is_valid\s*:\s*true/i.test(text)) return { ok: false };
  return { ok: true, steamId64 };
}

export function steamId64ToHex(id: string): string {
  return BigInt(id).toString(16);
}

// Signed short-lived cookie granting one launcher download. Reuses the same
// AES-256-GCM primitives as the dashboard session so we don't introduce a
// second crypto scheme.
const KEY = crypto.scryptSync(config.session_secret, "phoenixac.dl.key.v1", 32);
const DL_TTL_MS = 10 * 60 * 1000;

type DlToken = { steamHex: string; playerId: number; iat: number };

const b64u = (b: Buffer) => b.toString("base64url");
const fromB64u = (s: string) => Buffer.from(s, "base64url");

export function signDownloadToken(t: Omit<DlToken, "iat">): string {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", KEY, iv);
  const plaintext = Buffer.from(
    JSON.stringify({ ...t, iat: Date.now() } satisfies DlToken),
    "utf8",
  );
  const enc = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return ["v1", b64u(iv), b64u(enc), b64u(tag)].join(".");
}

export function verifyDownloadToken(token: string | undefined | null): DlToken | null {
  if (!token) return null;
  const parts = token.split(".");
  if (parts.length !== 4 || parts[0] !== "v1") return null;
  try {
    const iv  = fromB64u(parts[1]);
    const enc = fromB64u(parts[2]);
    const tag = fromB64u(parts[3]);
    if (iv.length !== 12 || tag.length !== 16) return null;
    const dec = crypto.createDecipheriv("aes-256-gcm", KEY, iv);
    dec.setAuthTag(tag);
    const clear = Buffer.concat([dec.update(enc), dec.final()]).toString("utf8");
    const obj = JSON.parse(clear) as DlToken;
    if (typeof obj.steamHex !== "string" || typeof obj.playerId !== "number") return null;
    if (typeof obj.iat !== "number" || Date.now() - obj.iat > DL_TTL_MS) return null;
    return obj;
  } catch {
    return null;
  }
}
