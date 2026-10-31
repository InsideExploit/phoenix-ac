export const UPDATE_PROTO_VERSION = 0x0001;

export const enum UpdateOpcode {
    ServerHello = 0x0002,
    ClientHello = 0x0001,
    UpdateManifest = 0x0300,
    UpdateChunkAgent = 0x0301,
    UpdateChunkDriver = 0x0302,
    UpdateEnd = 0x0303,
    UpdateError = 0x03ff,
}

export const UPDATE_CHUNK_MAX = 64 * 1024;

export const UPDATE_MAX_PACKET_BYTES = 128 * 1024;

export interface UpdateManifest {
    agentVersion: {
        major: number;
        minor: number;
        build: number;
        revision: number;
    };
    driverVersion: {
        major: number;
        minor: number;
        build: number;
        revision: number;
    };
    agentSha256: Buffer;
    driverSha256: Buffer;
    agentSize: number;
    driverSize: number;
}

export function encodeManifest(m: UpdateManifest): Buffer {
    if (m.agentSha256.length !== 32) {
        throw new Error('bad agent sha');
    }
    if (m.driverSha256.length !== 32) {
        throw new Error('bad driver sha');
    }
    const buf = Buffer.alloc(2 + 2 + 4 + 2 + 2 + 4 + 32 + 32 + 8 + 8);
    let o = 0;
    buf.writeUInt16BE(m.agentVersion.major, o);
    o += 2;
    buf.writeUInt16BE(m.agentVersion.minor, o);
    o += 2;
    buf.writeUInt32BE((m.agentVersion.build << 16) | (m.agentVersion.revision & 0xffff), o);
    o += 4;
    buf.writeUInt16BE(m.driverVersion.major, o);
    o += 2;
    buf.writeUInt16BE(m.driverVersion.minor, o);
    o += 2;
    buf.writeUInt32BE((m.driverVersion.build << 16) | (m.driverVersion.revision & 0xffff), o);
    o += 4;
    m.agentSha256.copy(buf, o);
    o += 32;
    m.driverSha256.copy(buf, o);
    o += 32;
    buf.writeBigUInt64BE(BigInt(m.agentSize), o);
    o += 8;
    buf.writeBigUInt64BE(BigInt(m.driverSize), o);
    o += 8;
    return buf;
}
