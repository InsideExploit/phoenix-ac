import { createHmac, timingSafeEqual } from 'node:crypto';

import { config } from '@/lib/core/config';

const kWindowSec = 60;
const kNonceTtlMs = 5 * 60 * 1000;
const kNonceCap = 50000;
const MASK64 = (1n << 64n) - 1n;
type NonceEntry = {
  exp: number;
};

const nonces = new Map<string, NonceEntry>();

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

function avalanche64(x: bigint): bigint {
  let v = x & MASK64;
  v ^= v >> 33n;
  v = (v * 0xff51afd7ed558ccdn) & MASK64;
  v ^= v >> 33n;
  v = (v * 0xc4ceb9fe1a85ec53n) & MASK64;
  v ^= v >> 33n;
  return v & MASK64;
}

function rotl64(v: bigint, r: number): bigint {
  r &= 63;
  if (!r) return v & MASK64;
  return ((v << BigInt(r)) | (v >> BigInt(64 - r))) & MASK64;
}

let sessionMix = 0n;

function wireMix(seq: number, opcode: number): bigint {
  if (sessionMix === 0n) {
    const mac = createHmac('sha256', config.phoenix_api_key).update('module-wire-v1').digest();
    const macBits =
      (BigInt(mac[0]!) << 56n) |
      (BigInt(mac[1]!) << 48n) |
      (BigInt(mac[2]!) << 40n) |
      (BigInt(mac[3]!) << 32n) |
      (BigInt(mac[4]!) << 24n) |
      (BigInt(mac[5]!) << 16n) |
      (BigInt(mac[6]!) << 8n) |
      BigInt(mac[7]!);
    sessionMix = avalanche64(macBits ^ 0xc2b2ae3d27d4eb4fn);
  }
  return avalanche64(sessionMix ^ (BigInt(opcode) << 32n) ^ BigInt(seq >>> 0));
}

export function veilApply(data: Buffer, mix: bigint): void {
  let s0 = avalanche64(mix ^ 0x243f6a8885a308d3n);
  let s1 = avalanche64(mix ^ 0x13198a2e03707344n);
  for (let i = 0; i < data.length; i++) {
    const kb =
      Number((s0 >> BigInt((i & 7) * 8)) & 0xffn) ^
      Number((s1 >> BigInt(((i + 3) & 7) * 8)) & 0xffn) ^
      ((i * 29 + 0x5a) & 0xff);
    data[i] = (data[i]! ^ kb) & 0xff;
    s0 = avalanche64(s0 ^ BigInt(kb) ^ BigInt(i));
    s1 = rotl64(s1 ^ BigInt(kb), (i & 31) + 1);
  }
}

export function verifyWireMac(
  ts: bigint,
  nonce: Buffer,
  seq: number,
  opcode: number,
  sealed: Buffer,
  mac: Buffer,
): boolean {
  const secret = config.phoenix_hmac_key;
  if (!secret) return true;
  const nowSec = BigInt(Math.floor(Date.now() / 1000));
  if (nowSec > ts + BigInt(kWindowSec) || ts > nowSec + BigInt(kWindowSec)) return false;
  const nonceHex = nonce.toString('hex');
  if (!rememberNonce(nonceHex, Date.now())) return false;
  const macInput = Buffer.alloc(8 + 16 + 4 + 2 + sealed.length);
  let off = 0;
  for (let i = 7; i >= 0; i--) {
    macInput[off++] = Number((ts >> BigInt(i * 8)) & 0xffn);
  }
  nonce.copy(macInput, off);
  off += 16;
  macInput.writeUInt32BE(seq >>> 0, off);
  off += 4;
  macInput.writeUInt16LE(opcode, off);
  off += 2;
  sealed.copy(macInput, off);
  const expected = createHmac('sha256', secret).update(macInput).digest();
  return expected.length === mac.length && timingSafeEqual(expected, mac);
}

export { avalanche64, wireMix };
