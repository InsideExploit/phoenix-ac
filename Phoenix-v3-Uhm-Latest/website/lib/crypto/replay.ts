import { createHmac, timingSafeEqual } from 'node:crypto';

import { config } from '@/lib/core/config';

const kWindowSec = 60;
const kNonceTtlMs = 5 * 60 * 1000;
const kNonceCap = 50000;
const kNonceHexLen = 32;
const kSigHexLen = 64;
type NonceEntry = {
  exp: number;
};

const nonces = new Map<string, NonceEntry>();

function isHexLen(s: string | null, n: number): s is string {
  return typeof s === 'string' && s.length === n && /^[0-9a-f]+$/i.test(s);
}

function evictExpired(now: number) {
  for (const [k, v] of nonces) {
    if (v.exp <= now) nonces.delete(k);
  }
}

function rememberNonce(nonce: string, now: number): boolean {
  if (nonces.has(nonce)) return false;
  nonces.set(nonce, { exp: now + kNonceTtlMs });
  if (nonces.size > kNonceCap) evictExpired(now);
  return true;
}

export type ReplayCheckResult =
  | {
      ok: true;
    }
  | {
      ok: false;
      reason: string;
      status: number;
    };

export function verifyReplayAndSig(
  tsHeader: string | null,
  nonceHeader: string | null,
  sigHeader: string | null,
  rawBody: string,
): ReplayCheckResult {
  const secret = config.phoenix_hmac_key;
  if (!secret) return { ok: true };
  if (!tsHeader || !/^\d{1,12}$/.test(tsHeader))
    return { ok: false, reason: 'ts mancante o invalido', status: 400 };
  const ts = Number(tsHeader);
  const nowSec = Math.floor(Date.now() / 1000);
  if (Math.abs(nowSec - ts) > kWindowSec)
    return { ok: false, reason: 'ts fuori finestra', status: 401 };
  if (!isHexLen(nonceHeader, kNonceHexLen))
    return { ok: false, reason: 'nonce mancante o invalido', status: 400 };
  if (!isHexLen(sigHeader, kSigHexLen))
    return { ok: false, reason: 'sig mancante o invalida', status: 400 };
  const sigInput = `${tsHeader}.${nonceHeader.toLowerCase()}.${rawBody}`;
  const expected = createHmac('sha256', secret).update(sigInput).digest();
  const provided = Buffer.from(sigHeader, 'hex');
  if (expected.length !== provided.length) return { ok: false, reason: 'sig length', status: 401 };
  if (!timingSafeEqual(expected, provided))
    return { ok: false, reason: 'sig mismatch', status: 401 };
  const nowMs = Date.now();
  if (!rememberNonce(nonceHeader.toLowerCase(), nowMs))
    return { ok: false, reason: 'nonce replay', status: 409 };
  return { ok: true };
}
