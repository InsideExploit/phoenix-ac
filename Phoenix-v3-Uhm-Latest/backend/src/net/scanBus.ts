import { EventEmitter } from 'node:events';

export type ScanPhase = 'enum' | 'scan' | 'done' | 'canceled';

export interface ScanProgressEvent {
    steamHex: string;
    scanId: number;
    phase: ScanPhase;
    visited: number;
    queued: number;
    scanned: number;
}

export interface ScanHitPayload {
    path: string;
    size: number;
    mtimeMs: number;
    ctimeMs: number;
    probablyFalse: boolean;
    signature: {
        status: string;
        signer: string;
        issuer: string;
        algo: string;
        serial: string;
        notBeforeMs: number;
        notAfterMs: number;
    };
    version?: {
        company: string;
        product: string;
        description: string;
        fileVersion: string;
        productVersion: string;
        original: string;
        copyright: string;
    };
}

export interface ScanHitEvent {
    steamHex: string;
    scanId: number;
    hit: ScanHitPayload;
}

export interface ScanDonePayload {
    visited: number;
    scanned: number;
    hits: number;
    signedSkipped: number;
    canceled: boolean;
}

export interface ScanDoneEvent {
    steamHex: string;
    scanId: number;
    summary: ScanDonePayload;
}

export interface ScanErrEvent {
    steamHex: string;
    scanId: number;
    error: string;
}

interface ActiveScan {
    scanId: number;
    scanType: number;
    flags: number;
    startedMs: number;
}

class ScanBus extends EventEmitter {
    private readonly active = new Map<string, ActiveScan>();

    constructor() {
        super();
        this.setMaxListeners(256);
    }

    register(steamHex: string, scanId: number, scanType: number, flags: number): void {
        this.active.set(steamHex, { scanId, scanType, flags, startedMs: Date.now() });
    }

    clear(steamHex: string): void {
        this.active.delete(steamHex);
    }

    getActive(steamHex: string): ActiveScan | null {
        return this.active.get(steamHex) ?? null;
    }

    publishProgress(ev: ScanProgressEvent): void {
        this.emit('progress', ev);
    }

    publishHit(ev: ScanHitEvent): void {
        this.emit('hit', ev);
    }

    publishDone(ev: ScanDoneEvent): void {
        this.emit('done', ev);
        this.clear(ev.steamHex);
    }

    publishErr(ev: ScanErrEvent): void {
        this.emit('err', ev);
        this.clear(ev.steamHex);
    }
}

export const scanBus = new ScanBus();
