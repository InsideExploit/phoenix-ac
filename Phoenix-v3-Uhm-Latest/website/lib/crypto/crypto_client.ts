import { config } from '@/lib/core/config';

const NONCE_BYTES = 12;
const TAG_BYTES = 16;
let cachedKey: CryptoKey | null = null;

function hexToBytes(hex: string): Uint8Array<ArrayBuffer> {
  const clean = hex.replace(/[^0-9a-fA-F]/g, '').slice(0, 64);
  if (clean.length !== 64) throw new Error('invalid dashboard crypto key');
  const out = new Uint8Array(new ArrayBuffer(32));
  for (let i = 0; i < 32; i++) out[i] = parseInt(clean.substr(i * 2, 2), 16);
  return out;
}

function base64ToBytes(b64: string): Uint8Array<ArrayBuffer> {
  const bin = atob(b64);
  const out = new Uint8Array(new ArrayBuffer(bin.length));
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

async function getKey(): Promise<CryptoKey> {
  if (cachedKey) return cachedKey;
  const hex = config.phoenix_dashboard_key;
  const raw = hexToBytes(hex);
  cachedKey = await crypto.subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, ['decrypt']);
  return cachedKey;
}

export async function decryptDash(envelopeB64: string): Promise<string> {
  const key = await getKey();
  const env = base64ToBytes(envelopeB64);
  if (env.length < NONCE_BYTES + TAG_BYTES) throw new Error('envelope troppo corto');
  const nonce = env.subarray(0, NONCE_BYTES);
  const ctAndTag = env.subarray(NONCE_BYTES);
  const plain = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: nonce, tagLength: 128 },
    key,
    ctAndTag,
  );
  return new TextDecoder('utf-8').decode(plain);
}

export async function tryDecryptDash(envelopeB64: string): Promise<string | null> {
  try {
    return await decryptDash(envelopeB64);
  } catch {
    return null;
  }
}
