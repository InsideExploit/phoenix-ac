import type { Socket } from 'node:net';
import { config } from '../config.js';
import { log } from '../logger.js';
import { Framer, type RawFrame } from '../net/framer.js';
import {
    decodeHandshake, encodeEncrypted, encodeHandshake,
} from '../proto/packet.js';
import { FrameKind, Opcode } from '../proto/opcodes.js';
import { encodeServerHello, decodeClientHello } from '../proto/bodies.js';
import { deriveSessionKeys, randomBuf, type SessionKeys } from '../proto/crypto.js';
import {
    UPDATE_MAX_PACKET_BYTES, UPDATE_CHUNK_MAX,
    UPDATE_PROTO_VERSION, UpdateOpcode, encodeManifest,
} from './proto.js';
import { getBundle, type Artifact } from './artifacts.js';

type State = 'awaiting-hello' | 'streaming' | 'closed';

export class UpdateSession {
    private state: State = 'awaiting-hello';
    private readonly framer = new Framer(UPDATE_MAX_PACKET_BYTES);
    private keys: SessionKeys | null = null;
    private serverNonce: Buffer | null = null;
    private handshakeTimer: NodeJS.Timeout | null = null;

    constructor(
        private readonly socket: Socket,
        private readonly clientIp: string,
        private readonly logger = log.child({
            module: 'update-session',
            peer:   `${clientIp}:${socket.remotePort}`,
        }),
    ) {}

    start(): void {
        this.socket.on('data',  (c) => this.onData(c));
        this.socket.on('error', (e) => this.logger.warn({ err: e.message }, 'socket error'));
        this.socket.on('close', ()  => this.onClose('socket-closed'));
        this.socket.setNoDelay(true);

        this.handshakeTimer = setTimeout(() => {
            if (this.state === 'awaiting-hello') {
                this.logger.info('handshake timeout');
                this.terminate('handshake-timeout');
            }
        }, config.handshakeTimeoutMs);

        this.serverNonce = randomBuf(16);
        this.send(encodeHandshake(Opcode.ServerHello, encodeServerHello({
            serverNonce:  this.serverNonce,
            protoVersion: UPDATE_PROTO_VERSION,
        })));
    }

    private send(buf: Buffer): void {
        if (this.state === 'closed') return;
        if (!this.socket.writable) return;
        this.socket.write(buf);
    }

    private sendEncrypted(opcode: UpdateOpcode, body: Buffer): void {
        if (!this.keys) return;
        this.send(encodeEncrypted(this.keys, opcode as unknown as Opcode, body));
    }

    private onData(chunk: Buffer): void {
        this.framer.push(chunk);
        for (;;) {
            const f = this.framer.next();
            if (f === null) return;
            if (f === 'err') { this.terminate('bad-frame'); return; }
            try { this.dispatch(f); }
            catch (e) {
                this.logger.warn({ err: (e as Error).message }, 'dispatch failed');
                this.terminate('dispatch-error');
                return;
            }
            if (this.state === 'closed') return;
        }
    }

    private dispatch(frame: RawFrame): void {
        if (frame.kind !== FrameKind.Handshake) { this.terminate('bad-kind'); return; }
        if (this.state !== 'awaiting-hello')    { this.terminate('unexpected-frame'); return; }

        const parsed = decodeHandshake(frame.payload);
        if (!parsed || (parsed.opcode as number) !== UpdateOpcode.ClientHello) {
            this.terminate('bad-client-hello');
            return;
        }
        const hello = decodeClientHello(parsed.body);
        if (!hello) { this.terminate('bad-client-hello-body'); return; }
        if (hello.protoVersion !== UPDATE_PROTO_VERSION) { this.terminate('bad-proto-version'); return; }

        this.keys = deriveSessionKeys(config.psk, hello.clientNonce, this.serverNonce!);
        this.state = 'streaming';
        if (this.handshakeTimer) { clearTimeout(this.handshakeTimer); this.handshakeTimer = null; }

        void this.stream().catch((e: Error) => {
            this.logger.warn({ err: e.message }, 'stream failed');
            this.terminate('stream-error');
        });
    }

    private async stream(): Promise<void> {
        const bundle = getBundle();
        if (!bundle) {
            const msg = 'update artifacts missing on server (backend/artifacts/PhoenixAgent.exe + PhoenixDrv.sys)';
            this.sendEncrypted(UpdateOpcode.UpdateError, Buffer.from(msg, 'utf8'));
            this.logger.error('no bundle — rejecting client; drop the binaries in backend/artifacts/ and restart');
            await new Promise<void>((resolve) => {
                if (!this.socket.writable) return resolve();
                this.socket.end(() => resolve());
                setTimeout(resolve, 1500).unref();
            });
            this.terminate('no-bundle');
            return;
        }

        this.sendEncrypted(UpdateOpcode.UpdateManifest, encodeManifest({
            agentVersion:  bundle.agent.version,
            driverVersion: bundle.driver.version,
            agentSha256:   bundle.agent.sha256,
            driverSha256:  bundle.driver.sha256,
            agentSize:     bundle.agent.size,
            driverSize:    bundle.driver.size,
        }));

        await this.streamArtifact(bundle.agent,  UpdateOpcode.UpdateChunkAgent);
        await this.streamArtifact(bundle.driver, UpdateOpcode.UpdateChunkDriver);

        this.sendEncrypted(UpdateOpcode.UpdateEnd, Buffer.alloc(0));
        this.logger.info({
            agentBytes: bundle.agent.size,
            drvBytes:   bundle.driver.size,
        }, 'update stream complete');

        setTimeout(() => this.terminate('stream-done'), 250);
    }

    private streamArtifact(a: Artifact, opcode: UpdateOpcode): Promise<void> {
        return new Promise((resolve) => {
            let off = 0;
            const pump = (): void => {
                if (this.state === 'closed') { resolve(); return; }
                if (off >= a.size) { resolve(); return; }
                const end = Math.min(off + UPDATE_CHUNK_MAX, a.size);
                const body = Buffer.alloc(8 + (end - off));
                body.writeBigUInt64BE(BigInt(off), 0);
                a.bytes.copy(body, 8, off, end);
                off = end;

                this.sendEncrypted(opcode, body);
                if (this.socket.writableNeedDrain) {
                    this.socket.once('drain', pump);
                } else {
                    setImmediate(pump);
                }
            };
            pump();
        });
    }

    private terminate(reason: string): void {
        if (this.state === 'closed') return;
        this.state = 'closed';
        if (this.handshakeTimer) { clearTimeout(this.handshakeTimer); this.handshakeTimer = null; }
        try { this.socket.end(); } catch { /* ignore */ }
        setTimeout(() => { try { this.socket.destroy(); } catch { /* ignore */ } }, 500);
        this.logger.info({ reason }, 'update session closed');
    }

    private onClose(reason: string): void {
        if (this.state === 'closed') return;
        this.terminate(reason);
    }
}
