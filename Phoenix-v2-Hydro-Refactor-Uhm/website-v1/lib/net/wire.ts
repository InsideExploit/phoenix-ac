import { createDecipheriv, createCipheriv, createHmac, randomBytes } from "node:crypto";
import { config } from "@/lib/core/config";
import { veilApply, verifyWireMac, wireMix } from "@/lib/net/veil";

export const WIRE_MAGIC = 0x31584850;
export const WIRE_VERSION = 1;

export enum WireOpcode {
  AuthCheckReq = 0x0101,
  AuthCheckRsp = 0x0102,
  EventReq = 0x0201,
  EventRsp = 0x0202,
  UpdateCheckReq = 0x0301,
  UpdateCheckRsp = 0x0302,
  UpdateDlReq = 0x0303,
  UpdateDlRsp = 0x0304,
}

export enum WireEventKind {
  Detection = 1,
  Sweep = 2,
  Exit = 3,
  Overlay = 4,
  Internal = 5,
  Mapper = 6,
  Injection = 7,
  ModFingerprint = 8,
  Security = 9,
  InternalFivem = 10,
}

const KEY_BYTES = 32;
const NONCE_BYTES = 12;
const TAG_BYTES = 16;

const TIMESTAMP_WINDOW_S = 30n;
const seenNonces = new Map<string, number>();
let lastPurge = Date.now();

function checkReplay(ts: bigint, nonce: Buffer): void {
  const nowSec = BigInt(Math.floor(Date.now() / 1000));
  if (ts < nowSec - TIMESTAMP_WINDOW_S || ts > nowSec + TIMESTAMP_WINDOW_S)
    throw new Error("timestamp out of window");

  const key = nonce.toString("hex");
  if (seenNonces.has(key))
    throw new Error("replayed nonce");

  seenNonces.set(key, Number(ts) + Number(TIMESTAMP_WINDOW_S) + 5);

  const nowMs = Date.now();
  if (nowMs - lastPurge > 60_000) {
    const nowS = Math.floor(nowMs / 1000);
    for (const [k, exp] of seenNonces)
      if (exp < nowS) seenNonces.delete(k);
    lastPurge = nowMs;
  }
}

let cachedKey: Buffer | null = null;

function getKey(): Buffer {
  if (cachedKey) return cachedKey;
  const hex = config.phoenix_crypto_key.replace(/[^0-9a-fA-F]/g, "").slice(0, 64);
  cachedKey = Buffer.from(hex, "hex");
  return cachedKey;
}

export function encryptBytes(plain: Buffer): Buffer {
  const key = getKey();
  const nonce = randomBytes(NONCE_BYTES);
  const cipher = createCipheriv("aes-256-gcm", key, nonce);
  const ct = Buffer.concat([cipher.update(plain), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([nonce, ct, tag]);
}

export function decryptBytes(envelope: Buffer): Buffer {
  const key = getKey();
  if (envelope.length < NONCE_BYTES + TAG_BYTES)
    throw new Error("envelope too short");
  const nonce = envelope.subarray(0, NONCE_BYTES);
  const tag = envelope.subarray(envelope.length - TAG_BYTES);
  const ct = envelope.subarray(NONCE_BYTES, envelope.length - TAG_BYTES);
  const decipher = createDecipheriv("aes-256-gcm", key, nonce);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ct), decipher.final()]);
}

export type WireFrameHeader = {
  magic: number;
  version: number;
  opcode: number;
  seq: number;
  flags: number;
  bodyLen: number;
};

export function parseHeader(buf: Buffer): WireFrameHeader {
  return {
    magic: buf.readUInt32LE(0),
    version: buf.readUInt16LE(4),
    opcode: buf.readUInt16LE(6),
    seq: buf.readUInt32LE(8),
    flags: buf.readUInt32LE(12),
    bodyLen: buf.readUInt32LE(16),
  };
}

export function buildHeader(opcode: number, seq: number, bodyLen: number): Buffer {
  const h = Buffer.alloc(20);
  h.writeUInt32LE(WIRE_MAGIC, 0);
  h.writeUInt16LE(WIRE_VERSION, 4);
  h.writeUInt16LE(opcode, 6);
  h.writeUInt32LE(seq, 8);
  h.writeUInt32LE(1, 12);
  h.writeUInt32LE(bodyLen, 16);
  return h;
}

export function openBody(opcode: number, seq: number, body: Buffer): Buffer {
  if (body.length < 8 + 16 + 32 + 4) throw new Error("body too short");

  let off = 0;
  let ts = 0n;
  for (let i = 0; i < 8; i++) ts = (ts << 8n) | BigInt(body[off++]!);
  const nonce = body.subarray(off, off + 16);
  off += 16;
  const mac = body.subarray(off, off + 32);
  off += 32;
  const sealedLen = body.readUInt32LE(off);
  off += 4;
  const sealed = body.subarray(off, off + sealedLen);

  if (!verifyWireMac(ts, nonce, seq, opcode, sealed, mac))
    throw new Error("mac invalid");

  checkReplay(ts, nonce);

  const veiled = decryptBytes(sealed);
  veilApply(veiled, wireMix(seq, opcode));
  return veiled;
}

export function sealBody(opcode: number, seq: number, inner: Buffer): Buffer {
  const veiled = Buffer.from(inner);
  veilApply(veiled, wireMix(seq, opcode));
  const sealed = encryptBytes(veiled);

  const ts = BigInt(Math.floor(Date.now() / 1000));
  const nonce = randomBytes(16);

  const macInput = Buffer.alloc(8 + 16 + 4 + 2 + sealed.length);
  let off = 0;
  for (let i = 7; i >= 0; i--) macInput[off++] = Number((ts >> BigInt(i * 8)) & 0xffn);
  nonce.copy(macInput, off);
  off += 16;
  macInput.writeUInt32BE(seq >>> 0, off);
  off += 4;
  macInput.writeUInt16LE(opcode, off);
  off += 2;
  sealed.copy(macInput, off);

  const mac = createHmac("sha256", config.phoenix_hmac_key).update(macInput).digest();

  const out = Buffer.alloc(8 + 16 + 32 + 4 + sealed.length);
  off = 0;
  for (let i = 7; i >= 0; i--) out[off++] = Number((ts >> BigInt(i * 8)) & 0xffn);
  nonce.copy(out, off);
  off += 16;
  mac.copy(out, off);
  off += 32;
  out.writeUInt32LE(sealed.length, off);
  off += 4;
  sealed.copy(out, off);
  return out;
}

export function readString(buf: Buffer, off: { v: number }): string {
  const len = buf.readUInt16LE(off.v);
  off.v += 2;
  const s = buf.subarray(off.v, off.v + len).toString("utf8");
  off.v += len;
  return s;
}

export function readU32(buf: Buffer, off: { v: number }): number {
  const v = buf.readUInt32LE(off.v);
  off.v += 4;
  return v;
}

export function readU64(buf: Buffer, off: { v: number }): bigint {
  const lo = buf.readUInt32LE(off.v);
  const hi = buf.readUInt32LE(off.v + 4);
  off.v += 8;
  return (BigInt(hi) << 32n) | BigInt(lo);
}

export function readPayload(buf: Buffer, off: { v: number }): Buffer {
  const len = buf.readUInt16LE(off.v);
  off.v += 2;
  const p = buf.subarray(off.v, off.v + len);
  off.v += len;
  return p;
}

export function parseEvent(inner: Buffer) {
  const off = { v: 0 };
  const kind = inner[off.v++]!;
  const pid = readU32(inner, off);
  const steamHex = readString(inner, off);
  const exe = readString(inner, off);
  const host = readString(inner, off);
  const payload = readPayload(inner, off);
  return { kind, pid, steamHex, exe, host, payload };
}

export function payloadToJson(kind: WireEventKind, payload: Buffer): Record<string, unknown> {
  const off = { v: 0 };
  switch (kind) {
    case WireEventKind.Detection: {
      const via = readString(payload, off);
      const hookAddr = readU64(payload, off);
      const scAddr = readU64(payload, off);
      return { via, hookAddr: hookAddr.toString(), scAddr: scAddr.toString() };
    }
    case WireEventKind.Sweep:
      return {
        anchorAcc: readU32(payload, off),
        rangeAcc: readU32(payload, off),
        needleSnap: readU32(payload, off),
        ticks: readU32(payload, off),
      };
    case WireEventKind.Exit: {
      const totalA = readU64(payload, off);
      const totalR = readU64(payload, off);
      return {
        totalA: totalA.toString(),
        totalR: totalR.toString(),
        lifetimeSec: readU32(payload, off),
      };
    }
    case WireEventKind.Overlay:
      return {
        windowClass: readString(payload, off),
        score: readU32(payload, off),
        flags: readU32(payload, off),
        overlapPct: readU32(payload, off) / 10000,
      };
    case WireEventKind.Internal:
      return {
        tid: readU32(payload, off),
        addr: readU64(payload, off).toString(),
        hitType: readString(payload, off),
      };
    case WireEventKind.Mapper:
    case WireEventKind.Injection: {
      const hitType = payload[off.v++]!;
      const addr = readU64(payload, off);
      const regionSize = readU32(payload, off);
      const detail = readString(payload, off);
      return { hitType, addr: addr.toString(), regionSize, detail };
    }
    case WireEventKind.ModFingerprint:
      return { hits: readU32(payload, off), modules: readString(payload, off) };
    case WireEventKind.InternalFivem:
      return { title: readString(payload, off), modules: readString(payload, off) };
    case WireEventKind.Security: {
      const category = readString(payload, off);
      const label = readString(payload, off);
      const severity = payload[off.v++]!;
      const body = readString(payload, off);
      const code = readU32(payload, off);
      const reason = readString(payload, off);
      const out: Record<string, unknown> = { category, label, severity };
      if (body) out.body = body;
      if (code) out.code = code;
      if (reason) out.reason = reason;
      return out;
    }
    default:
      return {};
  }
}

export const wireEventTypeName: Record<number, string> = {
  [WireEventKind.Detection]: "detection",
  [WireEventKind.Sweep]: "sweep",
  [WireEventKind.Exit]: "exit",
  [WireEventKind.Overlay]: "overlay",
  [WireEventKind.Internal]: "internal",
  [WireEventKind.Mapper]: "mapper",
  [WireEventKind.Injection]: "injection",
  [WireEventKind.ModFingerprint]: "modfingerprint",
  [WireEventKind.Security]: "security",
  [WireEventKind.InternalFivem]: "internal_fivem",
};
