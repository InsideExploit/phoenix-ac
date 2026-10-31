import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import { config } from "@/lib/core/config";

const KEY_BYTES = 32;
const NONCE_BYTES = 12;
const TAG_BYTES = 16;

let cachedKey: Buffer | null = null;

function getKey(): Buffer {
  if (cachedKey) return cachedKey;
  const raw = config.phoenix_crypto_key;
  const hex = raw.replace(/[^0-9a-fA-F]/g, "").slice(0, 64);
  if (hex.length !== 64)
    throw new Error(`PHOENIX_CRYPTO_KEY non valida: raw.len=${raw.length} hex.len=${hex.length}`);
  cachedKey = Buffer.from(hex, "hex");
  return cachedKey;
}

export function encrypt(plaintext: string | Buffer): string {
  const key = getKey();
  const nonce = randomBytes(NONCE_BYTES);
  const cipher = createCipheriv("aes-256-gcm", key, nonce);
  const pt = typeof plaintext === "string" ? Buffer.from(plaintext, "utf8") : plaintext;
  const ct = Buffer.concat([cipher.update(pt), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([nonce, ct, tag]).toString("base64");
}

export function decrypt(envelopeB64: string): string {
  const key = getKey();
  const envelope = Buffer.from(envelopeB64, "base64");
  if (envelope.length < NONCE_BYTES + TAG_BYTES)
    throw new Error("envelope troppo corto");
  const nonce = envelope.subarray(0, NONCE_BYTES);
  const tag = envelope.subarray(envelope.length - TAG_BYTES);
  const ct = envelope.subarray(NONCE_BYTES, envelope.length - TAG_BYTES);
  const decipher = createDecipheriv("aes-256-gcm", key, nonce);
  decipher.setAuthTag(tag);
  const pt = Buffer.concat([decipher.update(ct), decipher.final()]);
  return pt.toString("utf8");
}

export function tryDecrypt(envelopeB64: string): string | null {
  try {
    return decrypt(envelopeB64);
  } catch {
    return null;
  }
}

export function isCryptoConfigured(): boolean {
  const raw = config.phoenix_crypto_key;
  const hex = raw.replace(/[^0-9a-fA-F]/g, "").slice(0, 64);
  return hex.length === 64;
}

let cachedDashKey: Buffer | null = null;

function getDashKey(): Buffer {
  if (cachedDashKey) return cachedDashKey;
  const raw = config.phoenix_dashboard_key;
  const hex = raw.replace(/[^0-9a-fA-F]/g, "").slice(0, 64);
  if (hex.length !== 64)
    throw new Error(`NEXT_PUBLIC_PHOENIX_DASHBOARD_KEY non valida: raw.len=${raw.length} hex.len=${hex.length}`);
  cachedDashKey = Buffer.from(hex, "hex");
  return cachedDashKey;
}

export function encryptDash(plaintext: string | Buffer): string {
  const key = getDashKey();
  const nonce = randomBytes(NONCE_BYTES);
  const cipher = createCipheriv("aes-256-gcm", key, nonce);
  const pt = typeof plaintext === "string" ? Buffer.from(plaintext, "utf8") : plaintext;
  const ct = Buffer.concat([cipher.update(pt), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([nonce, ct, tag]).toString("base64");
}

export function isDashCryptoConfigured(): boolean {
  const raw = config.phoenix_dashboard_key;
  const hex = raw.replace(/[^0-9a-fA-F]/g, "").slice(0, 64);
  return hex.length === 64;
}
