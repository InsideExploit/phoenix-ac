import type { AuthStatus, ErrorCode } from './opcodes.js';

export const CLIENT_HELLO_LEN = 16 + 2;
export interface ClientHello {
    clientNonce: Buffer;
    protoVersion: number;
}

export function encodeClientHello(v: ClientHello): Buffer {
    const b = Buffer.alloc(CLIENT_HELLO_LEN);
    v.clientNonce.copy(b, 0);
    b.writeUInt16BE(v.protoVersion, 16);
    return b;
}

export function decodeClientHello(b: Buffer): ClientHello | null {
    if (b.length < CLIENT_HELLO_LEN) return null;
    return {
        clientNonce: Buffer.from(b.subarray(0, 16)),
        protoVersion: b.readUInt16BE(16),
    };
}

export const SERVER_HELLO_LEN = 16 + 2;
export interface ServerHello {
    serverNonce: Buffer;
    protoVersion: number;
}

export function encodeServerHello(v: ServerHello): Buffer {
    const b = Buffer.alloc(SERVER_HELLO_LEN);
    v.serverNonce.copy(b, 0);
    b.writeUInt16BE(v.protoVersion, 16);
    return b;
}

export function decodeServerHello(b: Buffer): ServerHello | null {
    if (b.length < SERVER_HELLO_LEN) return null;
    return {
        serverNonce: Buffer.from(b.subarray(0, 16)),
        protoVersion: b.readUInt16BE(16),
    };
}

export interface Authenticate {
    steamHex: string;
    hardwareId: string;
    clientVersion: string;
    hardwareDetails: string;
    screenshot?: Buffer;
}

function writeString(b: Buffer, off: number, s: string): number {
    const bytes = Buffer.from(s, 'utf8');
    if (bytes.length > 0xFFFF) throw new Error('string too long');
    b.writeUInt16BE(bytes.length, off);
    bytes.copy(b, off + 2);
    return off + 2 + bytes.length;
}

function readString(b: Buffer, off: number): { value: string; next: number } | null {
    if (off + 2 > b.length) return null;
    const len = b.readUInt16BE(off);
    if (off + 2 + len > b.length) return null;
    return { value: b.subarray(off + 2, off + 2 + len).toString('utf8'), next: off + 2 + len };
}

export function encodeAuthenticate(v: Authenticate): Buffer {
    const s = Buffer.from(v.steamHex,      'utf8');
    const h = Buffer.from(v.hardwareId,    'utf8');
    const c = Buffer.from(v.clientVersion, 'utf8');
    const d = Buffer.from(v.hardwareDetails, 'utf8');
    const p = v.screenshot ?? Buffer.alloc(0);
    const out = Buffer.alloc(2 + s.length + 2 + h.length + 2 + c.length + 2 + d.length + 4 + p.length);
    let off = 0;
    off = writeString(out, off, v.steamHex);
    off = writeString(out, off, v.hardwareId);
    off = writeString(out, off, v.clientVersion);
    off = writeString(out, off, v.hardwareDetails);
    out.writeUInt32BE(p.length, off);
    off += 4;
    p.copy(out, off);
    off += p.length;
    return out.subarray(0, off);
}

export function decodeAuthenticate(b: Buffer): Authenticate | null {
    const a = readString(b, 0);        if (!a) return null;
    const c = readString(b, a.next);   if (!c) return null;
    const d = readString(b, c.next);   if (!d) return null;
    const e = readString(b, d.next);
    let screenshot: Buffer | undefined;
    const tailOff = e ? e.next : d.next;
    if (tailOff + 4 <= b.length) {
        const pngLen = b.readUInt32BE(tailOff);
        if (pngLen > 0 && tailOff + 4 + pngLen <= b.length)
            screenshot = Buffer.from(b.subarray(tailOff + 4, tailOff + 4 + pngLen));
    }
    return {
        steamHex: a.value,
        hardwareId: c.value,
        clientVersion: d.value,
        hardwareDetails: e ? e.value : '',
        ...(screenshot ? { screenshot } : {}),
    };
}

export interface EnrollmentQuery {
    steamHex: string;
}

export function encodeEnrollmentQuery(v: EnrollmentQuery): Buffer {
    const s = Buffer.from(v.steamHex, 'utf8');
    const out = Buffer.alloc(2 + s.length);
    out.writeUInt16BE(s.length, 0);
    s.copy(out, 2);
    return out;
}

export function decodeEnrollmentQuery(b: Buffer): EnrollmentQuery | null {
    const s = readString(b, 0);
    if (!s) return null;
    return { steamHex: s.value };
}

export interface EnrollmentResult {
    required: boolean;
}

export function encodeEnrollmentResult(v: EnrollmentResult): Buffer {
    const b = Buffer.alloc(1);
    b.writeUInt8(v.required ? 1 : 0, 0);
    return b;
}

export function decodeEnrollmentResult(b: Buffer): EnrollmentResult | null {
    if (b.length < 1) return null;
    return { required: b.readUInt8(0) !== 0 };
}

export interface AuthResult {
    status: AuthStatus;
    sessionId: bigint;
    heartbeatIntervalMs: number;
    message: string;
}

export function encodeAuthResult(v: AuthResult): Buffer {
    const msg = Buffer.from(v.message, 'utf8');
    const out = Buffer.alloc(1 + 8 + 4 + 2 + msg.length);
    out.writeUInt8(v.status, 0);
    out.writeBigUInt64BE(v.sessionId, 1);
    out.writeUInt32BE(v.heartbeatIntervalMs, 9);
    out.writeUInt16BE(msg.length, 13);
    msg.copy(out, 15);
    return out;
}

export function decodeAuthResult(b: Buffer): AuthResult | null {
    if (b.length < 15) return null;
    const msgLen = b.readUInt16BE(13);
    if (b.length < 15 + msgLen) return null;
    return {
        status: b.readUInt8(0),
        sessionId: b.readBigUInt64BE(1),
        heartbeatIntervalMs: b.readUInt32BE(9),
        message: b.subarray(15, 15 + msgLen).toString('utf8'),
    };
}

export interface Heartbeat {
    seq: number;
    clientTsMs: bigint;
}

export function encodeHeartbeat(v: Heartbeat): Buffer {
    const b = Buffer.alloc(12);
    b.writeUInt32BE(v.seq, 0);
    b.writeBigUInt64BE(v.clientTsMs, 4);
    return b;
}

export function decodeHeartbeat(b: Buffer): Heartbeat | null {
    if (b.length < 12) return null;
    return { seq: b.readUInt32BE(0), clientTsMs: b.readBigUInt64BE(4) };
}

export interface Detection {
    detectionType: string;
    reason: string;
    offendingPath: string;
    severity: number;
    payload: Buffer;
}

export function encodeDetection(v: Detection): Buffer {
    const chunks: Buffer[] = [];
    const push = (s: string): void => {
        const b = Buffer.from(s, 'utf8');
        const l = Buffer.alloc(2); l.writeUInt16BE(b.length, 0);
        chunks.push(l, b);
    };
    push(v.detectionType);
    push(v.reason);
    push(v.offendingPath);
    const sev = Buffer.alloc(1); sev.writeUInt8(v.severity, 0); chunks.push(sev);
    const pl = Buffer.alloc(4); pl.writeUInt32BE(v.payload.length, 0);
    chunks.push(pl, v.payload);
    return Buffer.concat(chunks);
}

export function decodeDetection(b: Buffer): Detection | null {
    let off = 0;
    const t = readString(b, off); if (!t) return null; off = t.next;
    const r = readString(b, off); if (!r) return null; off = r.next;
    const p = readString(b, off); if (!p) return null; off = p.next;
    if (off + 1 > b.length) return null;
    const severity = b.readUInt8(off); off += 1;
    if (off + 4 > b.length) return null;
    const plLen = b.readUInt32BE(off); off += 4;
    if (off + plLen > b.length) return null;
    return {
        detectionType: t.value,
        reason: r.value,
        offendingPath: p.value,
        severity,
        payload: Buffer.from(b.subarray(off, off + plLen)),
    };
}

export interface DetectionAck {
    id: bigint;
}

export function encodeDetectionAck(v: DetectionAck): Buffer {
    const b = Buffer.alloc(8);
    b.writeBigUInt64BE(v.id, 0);
    return b;
}

export interface AltAccountEntry {
    kind:       'steam' | 'discord';
    externalId: string;
    username:   string;
    avatar:     string;
}

export function decodeAltAccounts(b: Buffer): AltAccountEntry[] | null {
    if (b.length < 4) return null;
    const count = b.readUInt32BE(0);
    if (count > 4096) return null;
    let off = 4;
    const out: AltAccountEntry[] = [];
    for (let i = 0; i < count; i++) {
        if (off + 1 > b.length) return null;
        const kindByte = b.readUInt8(off); off += 1;
        const kind: AltAccountEntry['kind'] | null =
            kindByte === 1 ? 'steam' :
            kindByte === 2 ? 'discord' : null;
        if (!kind) return null;
        const id = readString(b, off); if (!id) return null; off = id.next;
        const un = readString(b, off); if (!un) return null; off = un.next;
        const av = readString(b, off); if (!av) return null; off = av.next;
        out.push({
            kind,
            externalId: id.value,
            username:   un.value,
            avatar:     av.value,
        });
    }
    return out;
}

export interface AltAccountsAck {
    inserted: number;
    updated:  number;
}

export function encodeAltAccountsAck(v: AltAccountsAck): Buffer {
    const b = Buffer.alloc(8);
    b.writeUInt32BE(v.inserted, 0);
    b.writeUInt32BE(v.updated,  4);
    return b;
}

export interface ProtoError {
    code: ErrorCode;
    message: string;
}

export function encodeProtoError(v: ProtoError): Buffer {
    const m = Buffer.from(v.message, 'utf8');
    const b = Buffer.alloc(1 + 2 + m.length);
    b.writeUInt8(v.code, 0);
    b.writeUInt16BE(m.length, 1);
    m.copy(b, 3);
    return b;
}
