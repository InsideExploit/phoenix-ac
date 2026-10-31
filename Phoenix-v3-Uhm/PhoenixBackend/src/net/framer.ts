import { FRAME_HEADER_LEN, readHeader } from '../proto/packet.js';
import type { FrameKind } from '../proto/opcodes.js';

export interface RawFrame {
    kind: FrameKind;
    header: Buffer;
    payload: Buffer;
}

export class Framer {
    private buf: Buffer = Buffer.alloc(0);
    constructor(private readonly maxPayload: number) {}

    push(chunk: Buffer): void {
        this.buf = this.buf.length === 0 ? chunk : Buffer.concat([this.buf, chunk]);
    }

    next(): RawFrame | null | 'err' {
        if (this.buf.length < FRAME_HEADER_LEN) return null;

        const hdr = readHeader(this.buf);
        if (!hdr) return 'err';
        if (hdr.payloadLen > this.maxPayload) return 'err';

        const total = FRAME_HEADER_LEN + hdr.payloadLen;
        if (this.buf.length < total) return null;

        const header  = Buffer.from(this.buf.subarray(0, FRAME_HEADER_LEN));
        const payload = Buffer.from(this.buf.subarray(FRAME_HEADER_LEN, total));
        this.buf = this.buf.subarray(total);

        return { kind: hdr.kind, header, payload };
    }
}
