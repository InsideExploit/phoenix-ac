import { createCipheriv, createDecipheriv, createHmac, createHash, randomBytes, timingSafeEqual } from 'node:crypto';

export const AES_KEY_LEN   = 32;
export const AES_IV_LEN    = 16;
export const HMAC_KEY_LEN  = 32;
export const HMAC_TAG_LEN  = 32;
export const OBF_KEY_LEN   = 32;
export const NONCE_LEN     = 16;
export const HANDSHAKE_NONCE_LEN = 16;

const HKDF_INFO_ENC  = Buffer.from('phoenixac/session/enc/v1');
const HKDF_INFO_MAC  = Buffer.from('phoenixac/session/mac/v1');
const HKDF_INFO_OBF  = Buffer.from('phoenixac/session/obf/v1');
const HKDF_INFO_SLOT = Buffer.from('phoenixac/session/slot/v1');

function hkdfExtract(salt: Buffer, ikm: Buffer): Buffer {
    return createHmac('sha256', salt).update(ikm).digest();
}

function hkdfExpand(prk: Buffer, info: Buffer, length: number): Buffer {
    const blocks: Buffer[] = [];
    let prev = Buffer.alloc(0);
    let counter = 1;
    let produced = 0;
    while (produced < length) {
        const h = createHmac('sha256', prk);
        h.update(prev);
        h.update(info);
        h.update(Buffer.from([counter]));
        prev = h.digest();
        blocks.push(prev);
        produced += prev.length;
        counter++;
    }
    return Buffer.concat(blocks).subarray(0, length);
}

export interface SessionKeys {
    enc:  Buffer;
    mac:  Buffer;
    obf:  Buffer;
    slot: Buffer;
}

export function deriveSessionKeys(psk: Buffer, clientNonce: Buffer, serverNonce: Buffer): SessionKeys {
    if (clientNonce.length !== HANDSHAKE_NONCE_LEN) throw new Error('bad client nonce length');
    if (serverNonce.length !== HANDSHAKE_NONCE_LEN) throw new Error('bad server nonce length');

    const salt = Buffer.concat([clientNonce, serverNonce]);
    const prk  = hkdfExtract(salt, psk);
    return {
        enc:  hkdfExpand(prk, HKDF_INFO_ENC,  AES_KEY_LEN),
        mac:  hkdfExpand(prk, HKDF_INFO_MAC,  HMAC_KEY_LEN),
        obf:  hkdfExpand(prk, HKDF_INFO_OBF,  OBF_KEY_LEN),
        slot: hkdfExpand(prk, HKDF_INFO_SLOT, HMAC_KEY_LEN),
    };
}

export function xorObfuscate(buf: Buffer, obfKey: Buffer, packetNonce: Buffer): void {
    if (obfKey.length !== OBF_KEY_LEN) throw new Error('bad obf key');
    if (packetNonce.length !== NONCE_LEN) throw new Error('bad packet nonce');
    const rot = packetNonce[0]! & 0x1f;
    for (let i = 0; i < buf.length; i++) {
        const k = obfKey[(i + rot) & 0x1f]!;
        const p = packetNonce[i & 0x0f]!;
        buf[i] = (buf[i]! ^ k ^ p ^ (i * 0x9e) & 0xff) & 0xff;
    }
}

export function aesEncrypt(enc: Buffer, iv: Buffer, plaintext: Buffer): Buffer {
    const c = createCipheriv('aes-256-cbc', enc, iv);
    return Buffer.concat([c.update(plaintext), c.final()]);
}

export function aesDecrypt(enc: Buffer, iv: Buffer, ciphertext: Buffer): Buffer {
    const d = createDecipheriv('aes-256-cbc', enc, iv);
    return Buffer.concat([d.update(ciphertext), d.final()]);
}

export function hmacTag(mac: Buffer, ...parts: Buffer[]): Buffer {
    const h = createHmac('sha256', mac);
    for (const p of parts) h.update(p);
    return h.digest();
}

export function hmacVerify(expected: Buffer, mac: Buffer, ...parts: Buffer[]): boolean {
    const got = hmacTag(mac, ...parts);
    if (got.length !== expected.length) return false;
    return timingSafeEqual(got, expected);
}

export function randomBuf(n: number): Buffer {
    return randomBytes(n);
}

export function sha256(...parts: Buffer[]): Buffer {
    const h = createHash('sha256');
    for (const p of parts) h.update(p);
    return h.digest();
}
