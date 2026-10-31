import {
    AES_IV_LEN,
    HMAC_TAG_LEN,
    NONCE_LEN,
    aesDecrypt,
    aesEncrypt,
    hmacTag,
    hmacVerify,
    randomBuf,
    xorObfuscate,
    type SessionKeys,
} from './crypto.js';
import { FrameKind, Opcode, WIRE_MAGIC, WIRE_VERSION } from './opcodes.js';

export const FRAME_HEADER_LEN = 4 + 2 + 1 + 1 + 4;

export const ENCRYPTED_INNER_HEADER_LEN = 8 + 2 + 4;

export const ENCRYPTED_PAYLOAD_OVERHEAD = NONCE_LEN + AES_IV_LEN + HMAC_TAG_LEN;

export interface EncryptedPacket {
    opcode: Opcode;
    body: Buffer;
    nonce: Buffer;
    timestampMs: number;
}

export interface HandshakeFrame {
    opcode: Opcode;
    body: Buffer;
}

function writeHeader(kind: FrameKind, payloadLen: number): Buffer {
    const h = Buffer.alloc(FRAME_HEADER_LEN);
    h.writeUInt32BE(WIRE_MAGIC, 0);
    h.writeUInt16BE(WIRE_VERSION, 4);
    h.writeUInt8(kind, 6);
    h.writeUInt8(0, 7);
    h.writeUInt32BE(payloadLen, 8);
    return h;
}

function readHeader(buf: Buffer): {
    kind: FrameKind;
    payloadLen: number;
} | null {
    if (buf.length < FRAME_HEADER_LEN) return null;
    if (buf.readUInt32BE(0) !== WIRE_MAGIC) return null;
    if (buf.readUInt16BE(4) !== WIRE_VERSION) return null;
    return {
        kind: buf.readUInt8(6) as FrameKind,
        payloadLen: buf.readUInt32BE(8),
    };
}

export function encodeHandshake(opcode: Opcode, body: Buffer): Buffer {
    const inner = Buffer.alloc(2 + body.length);
    inner.writeUInt16BE(opcode, 0);
    body.copy(inner, 2);
    return Buffer.concat([writeHeader(FrameKind.Handshake, inner.length), inner]);
}

export function decodeHandshake(frame: Buffer): HandshakeFrame | null {
    if (frame.length < 2) return null;
    return {
        opcode: frame.readUInt16BE(0) as Opcode,
        body: frame.subarray(2),
    };
}

export function encodeEncrypted(
    keys: SessionKeys,
    opcode: Opcode,
    body: Buffer,
    nowMs = Date.now(),
    nonce = randomBuf(NONCE_LEN),
): Buffer {
    const inner = Buffer.alloc(ENCRYPTED_INNER_HEADER_LEN + body.length);
    inner.writeBigUInt64BE(BigInt(nowMs), 0);
    inner.writeUInt16BE(opcode, 8);
    inner.writeUInt32BE(body.length, 10);
    body.copy(inner, ENCRYPTED_INNER_HEADER_LEN);
    xorObfuscate(inner, keys.obf, nonce);
    const iv = randomBuf(AES_IV_LEN);
    const ct = aesEncrypt(keys.enc, iv, inner);
    const payloadLen = NONCE_LEN + AES_IV_LEN + ct.length + HMAC_TAG_LEN;
    const header = writeHeader(FrameKind.Encrypted, payloadLen);
    const mac = hmacTag(keys.mac, header, nonce, iv, ct);
    return Buffer.concat([header, nonce, iv, ct, mac]);
}

export function decodeEncrypted(
    keys: SessionKeys,
    header: Buffer,
    payload: Buffer,
): EncryptedPacket | null {
    if (payload.length < ENCRYPTED_PAYLOAD_OVERHEAD + 16) return null;
    const nonce = payload.subarray(0, NONCE_LEN);
    const iv = payload.subarray(NONCE_LEN, NONCE_LEN + AES_IV_LEN);
    const mac = payload.subarray(payload.length - HMAC_TAG_LEN);
    const ct = payload.subarray(NONCE_LEN + AES_IV_LEN, payload.length - HMAC_TAG_LEN);
    if (!hmacVerify(mac, keys.mac, header, nonce, iv, ct)) return null;
    let pt: Buffer;
    try {
        pt = aesDecrypt(keys.enc, iv, ct);
    } catch {
        return null;
    }
    if (pt.length < ENCRYPTED_INNER_HEADER_LEN) return null;
    xorObfuscate(pt, keys.obf, nonce);
    const timestampMs = Number(pt.readBigUInt64BE(0));
    const opcode = pt.readUInt16BE(8) as Opcode;
    const bodyLen = pt.readUInt32BE(10);
    if (pt.length < ENCRYPTED_INNER_HEADER_LEN + bodyLen) return null;
    const body = Buffer.from(
        pt.subarray(ENCRYPTED_INNER_HEADER_LEN, ENCRYPTED_INNER_HEADER_LEN + bodyLen),
    );
    return { opcode, body, nonce: Buffer.from(nonce), timestampMs };
}

export { readHeader, writeHeader };
