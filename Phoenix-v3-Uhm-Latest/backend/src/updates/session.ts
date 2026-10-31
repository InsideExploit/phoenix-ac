import type { Socket } from 'node:net';

import { config } from '../config.js';
import { findPlayerBySteamHex, playerAgentMode } from '../db/players.js';
import { log } from '../logger.js';
import { Framer, type RawFrame } from '../net/framer.js';
import { decodeClientHello, encodeServerHello } from '../proto/bodies.js';
import { deriveSessionKeys, randomBuf, type SessionKeys } from '../proto/crypto.js';
import { FrameKind, Opcode } from '../proto/opcodes.js';
import { decodeHandshake, encodeEncrypted, encodeHandshake } from '../proto/packet.js';
import { emptyDriverSha, getBundle, type AgentMode, type Artifact } from './artifacts.js';
import {
    UPDATE_CHUNK_MAX,
    UPDATE_MAX_PACKET_BYTES,
    UPDATE_PROTO_VERSION,
    UpdateOpcode,
    encodeManifest,
} from './proto.js';

type State = 'awaiting-hello' | 'streaming' | 'closed';

export class UpdateSession {
    private state: State = 'awaiting-hello';
    private agentMode: AgentMode = 'kernel';
    private steamHex = '';
    private readonly framer = new Framer(UPDATE_MAX_PACKET_BYTES);
    private keys: SessionKeys | null = null;
    private serverNonce: Buffer | null = null;
    private handshakeTimer: NodeJS.Timeout | null = null;

    constructor(
        private readonly socket: Socket,
        private readonly clientIp: string,
        private readonly logger = log.child({
            module: 'update-session',
            peer: `${clientIp}:${socket.remotePort}`,
        }),
    ) {}

    start(): void {
        this.socket.on('data', (c) => this.onData(c));
        this.socket.on('error', (e) => this.logger.warn({ err: e.message }, 'socket error'));
        this.socket.on('close', () => this.onClose('socket-closed'));
        this.socket.setNoDelay(true);
        this.handshakeTimer = setTimeout(() => {
            if (this.state === 'awaiting-hello') {
                this.logger.info('handshake timeout');
                this.terminate('handshake-timeout');
            }
        }, config.handshakeTimeoutMs);
        this.serverNonce = randomBuf(16);
        this.send(
            encodeHandshake(
                Opcode.ServerHello,
                encodeServerHello({
                    serverNonce: this.serverNonce,
                    protoVersion: UPDATE_PROTO_VERSION,
                }),
            ),
        );
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
            if (f === 'err') {
                this.terminate('bad-frame');
                return;
            }
            try {
                this.dispatch(f);
            } catch (e) {
                this.logger.warn({ err: (e as Error).message }, 'dispatch failed');
                this.terminate('dispatch-error');
                return;
            }
            if (this.state === 'closed') return;
        }
    }

    private dispatch(frame: RawFrame): void {
        if (frame.kind !== FrameKind.Handshake) {
            this.terminate('bad-kind');
            return;
        }
        if (this.state !== 'awaiting-hello') {
            this.terminate('unexpected-frame');
            return;
        }
        const parsed = decodeHandshake(frame.payload);
        if (!parsed || (parsed.opcode as number) !== UpdateOpcode.ClientHello) {
            this.terminate('bad-client-hello');
            return;
        }
        const hello = decodeClientHello(parsed.body);
        if (!hello) {
            this.terminate('bad-client-hello-body');
            return;
        }
        if (hello.protoVersion !== UPDATE_PROTO_VERSION) {
            this.terminate('bad-proto-version');
            return;
        }
        this.steamHex = hello.steamHex ? hello.steamHex.trim().toLowerCase() : '';
        this.agentMode = hello.agentMode;
        this.keys = deriveSessionKeys(config.psk, hello.clientNonce, this.serverNonce!);
        this.state = 'streaming';
        if (this.handshakeTimer) {
            clearTimeout(this.handshakeTimer);
            this.handshakeTimer = null;
        }
        void this.stream().catch((e: Error) => {
            this.logger.warn({ err: e.message }, 'stream failed');
            this.terminate('stream-error');
        });
    }

    private async stream(): Promise<void> {
        if (this.steamHex) {
            let hex = this.steamHex;
            try {
                const stripped = hex.startsWith('0x') ? hex.slice(2) : hex;
                if (/^[0-9a-f]{1,16}$/.test(stripped)) hex = BigInt('0x' + stripped).toString(16);
            } catch {}
            this.steamHex = hex;
            const player = await findPlayerBySteamHex(hex);
            this.agentMode = playerAgentMode(player);
            this.logger.info(
                { steamHex: hex, mode: this.agentMode, found: !!player },
                'update mode from dashboard',
            );
        }
        const bundle = getBundle(this.agentMode);
        if (!bundle || (this.agentMode === 'kernel' && !bundle.driver)) {
            const msg =
                this.agentMode === 'kernel'
                    ? 'kernel artifacts missing (backend/artifacts/kernel/PhoenixAgent.exe + PhoenixDrv.sys)'
                    : 'usermode artifact missing (backend/artifacts/usermode/PhoenixAgent.exe)';
            this.sendEncrypted(UpdateOpcode.UpdateError, Buffer.from(msg, 'utf8'));
            this.logger.error({ mode: this.agentMode }, 'no bundle — rejecting client');
            await new Promise<void>((resolve) => {
                if (!this.socket.writable) return resolve();
                this.socket.end(() => resolve());
                setTimeout(resolve, 1500).unref();
            });
            this.terminate('no-bundle');
            return;
        }
        const driver = bundle.driver;
        this.sendEncrypted(
            UpdateOpcode.UpdateManifest,
            encodeManifest({
                agentVersion: bundle.agent.version,
                driverVersion: driver?.version ?? { major: 0, minor: 0, build: 0, revision: 0 },
                agentSha256: bundle.agent.sha256,
                driverSha256: driver?.sha256 ?? emptyDriverSha(),
                agentSize: bundle.agent.size,
                driverSize: driver?.size ?? 0,
            }),
        );
        await this.streamArtifact(bundle.agent, UpdateOpcode.UpdateChunkAgent);
        if (driver) await this.streamArtifact(driver, UpdateOpcode.UpdateChunkDriver);
        this.sendEncrypted(UpdateOpcode.UpdateEnd, Buffer.alloc(0));
        this.logger.info(
            {
                mode: this.agentMode,
                agentBytes: bundle.agent.size,
                drvBytes: driver?.size ?? 0,
            },
            'update stream complete',
        );
        setTimeout(() => this.terminate('stream-done'), 250);
    }

    private streamArtifact(a: Artifact, opcode: UpdateOpcode): Promise<void> {
        return new Promise((resolve) => {
            let off = 0;
            const pump = (): void => {
                if (this.state === 'closed') {
                    resolve();
                    return;
                }
                if (off >= a.size) {
                    resolve();
                    return;
                }
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
        if (this.handshakeTimer) {
            clearTimeout(this.handshakeTimer);
            this.handshakeTimer = null;
        }
        try {
            this.socket.end();
        } catch {}
        setTimeout(() => {
            try {
                this.socket.destroy();
            } catch {}
        }, 500);
        this.logger.info({ reason }, 'update session closed');
    }

    private onClose(reason: string): void {
        if (this.state === 'closed') return;
        this.terminate(reason);
    }
}
