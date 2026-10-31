import type { Socket } from 'node:net';
import * as fs from 'node:fs/promises';
import * as path from 'node:path';
import { config } from '../config.js';
import { log } from '../logger.js';
import { Framer, type RawFrame } from './framer.js';
import {
    decodeEncrypted, decodeHandshake, encodeEncrypted, encodeHandshake,
} from '../proto/packet.js';
import {
    AuthStatus, ErrorCode, FrameKind, Opcode,
} from '../proto/opcodes.js';
import {
    decodeAltAccounts, decodeAuthenticate, decodeClientHello, decodeDetection,
    decodeEnrollmentQuery, decodeHeartbeat, encodeAltAccountsAck, encodeAuthResult,
    encodeDetectionAck, encodeEnrollmentResult, encodeHeartbeat, encodeProtoError,
    encodeServerHello,
} from '../proto/bodies.js';
import { NonceCache } from '../proto/nonce.js';
import { deriveSessionKeys, randomBuf, type SessionKeys } from '../proto/crypto.js';
import { bindPlayerHardwareId, findPlayerBySteamHex, touchLastSeen, type PlayerRow } from '../db/players.js';
import { bumpHeartbeat, endSession, startSession } from '../db/sessions.js';
import { insertDetection } from '../db/detections.js';
import { upsertAltAccounts } from '../db/altAccounts.js';
import { registerSession, unregisterSession, type LiveAgent } from './registry.js';
import { channelForDetection, detectionAttribution, fire, prettyDetectionType } from '../discord/webhook.js';

const PROTO_VERSION = 0x0001;

type State = 'awaiting-hello' | 'awaiting-auth' | 'ready' | 'closed';

interface PendingShot {
    resolve:      (buf: Buffer) => void;
    reject:       (err: Error)  => void;
    timer:        NodeJS.Timeout;
    buffer:       Buffer | null;
    receivedBytes: number;
    totalBytes:    number;
}

interface PendingSysInfo {
    resolve: (json: string) => void;
    reject:  (err: Error)   => void;
    timer:   NodeJS.Timeout;
}

interface PendingPciTree {
    resolve: (json: string) => void;
    reject:  (err: Error)   => void;
    timer:   NodeJS.Timeout;
}

interface PendingMinidumps {
    resolve: (json: string) => void;
    reject:  (err: Error)   => void;
    timer:   NodeJS.Timeout;
}

interface PendingDumpFile {
    resolve:      (buf: Buffer) => void;
    reject:       (err: Error)  => void;
    timer:        NodeJS.Timeout;
    buffer:       Buffer | null;
    receivedBytes: number;
    totalBytes:    number;
}

export class AgentSession implements LiveAgent {
    private state: State = 'awaiting-hello';
    private readonly framer = new Framer(config.maxPacketBytes);
    private readonly nonceCache = new NonceCache(config.replayWindowMs);
    private keys: SessionKeys | null = null;
    private serverNonce: Buffer | null = null;
    private clientNonce: Buffer | null = null;

    private sessionId: bigint | null = null;
    private player: PlayerRow | null = null;
    private steamHex: string | null = null;
    private hardwareId: string | null = null;

    private lastRxMs = Date.now();
    private lastPingSeq = 0;
    private hbTimer: NodeJS.Timeout | null = null;
    private watchdog: NodeJS.Timeout | null = null;
    private handshakeTimer: NodeJS.Timeout | null = null;

    private clockOffsetMs: number | null = null;

    private pendingShot: PendingShot | null = null;
    private pendingSysInfo: PendingSysInfo | null = null;
    private pendingPciTree: PendingPciTree | null = null;
    private pendingMinidumps: PendingMinidumps | null = null;
    private pendingDumpFile: PendingDumpFile | null = null;

    private lastSeenTouchedMs = 0;

    constructor(
        private readonly socket: Socket,
        private readonly clientIp: string,
        private readonly logger = log.child({ peer: `${clientIp}:${socket.remotePort}` }),
    ) {}

    start(): void {
        this.socket.on('data',  (c) => this.onData(c));
        this.socket.on('error', (e) => this.logger.warn({ err: e.message }, 'socket error'));
        this.socket.on('close', ()  => this.onClose('socket-closed'));
        this.socket.setNoDelay(true);
        this.socket.setKeepAlive(true, 10_000);

        this.handshakeTimer = setTimeout(() => {
            if (this.state !== 'ready') {
                this.logger.info({ state: this.state }, 'handshake timeout');
                this.terminate('handshake-timeout');
            }
        }, config.handshakeTimeoutMs);

        this.serverNonce = randomBuf(16);
        this.send(encodeHandshake(Opcode.ServerHello, encodeServerHello({
            serverNonce: this.serverNonce, protoVersion: PROTO_VERSION,
        })));
    }

    private send(buf: Buffer): void {
        if (this.state === 'closed') return;
        if (!this.socket.writable) return;
        this.socket.write(buf);
    }

    private sendEncrypted(opcode: Opcode, body: Buffer): void {
        if (!this.keys) return;
        this.send(encodeEncrypted(this.keys, opcode, body));
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
        this.lastRxMs = Date.now();
        if (frame.kind === FrameKind.Handshake) {
            if (this.state !== 'awaiting-hello') { this.terminate('unexpected-handshake'); return; }
            this.onHandshake(frame.payload);
            return;
        }
        if (frame.kind === FrameKind.Encrypted) {
            if (!this.keys) { this.terminate('no-session-key'); return; }
            const pkt = decodeEncrypted(this.keys, frame.header, frame.payload);
            if (!pkt) { this.terminate('bad-mac'); return; }

            const serverNowMs = Date.now();

            if (this.clockOffsetMs === null) {
                const initialOffset = pkt.timestampMs - serverNowMs;
                if (Math.abs(initialOffset) > 24 * 60 * 60 * 1000) {
                    this.logger.warn({ offsetMs: initialOffset }, 'implausible clock offset on first packet');
                    this.terminate('bad-clock');
                    return;
                }
                this.clockOffsetMs = initialOffset;
                this.logger.debug({ offsetMs: initialOffset }, 'anchored client clock offset');
            } else {
                const drift = Math.abs(pkt.timestampMs - this.clockOffsetMs - serverNowMs);
                if (drift > config.replayWindowMs) {
                    this.logger.info({ driftMs: drift, offsetMs: this.clockOffsetMs }, 'drift');
                    this.terminate('drift');
                    return;
                }
            }

            if (!this.nonceCache.check(pkt.nonce, serverNowMs, serverNowMs)) {
                this.terminate('replay');
                return;
            }

            this.onEncrypted(pkt.opcode, pkt.body);
            return;
        }
        this.terminate('bad-kind');
    }

    private onHandshake(body: Buffer): void {
        const parsed = decodeHandshake(body);
        if (!parsed || parsed.opcode !== Opcode.ClientHello) { this.terminate('bad-client-hello'); return; }
        const hello = decodeClientHello(parsed.body);
        if (!hello) { this.terminate('bad-client-hello-body'); return; }
        if (hello.protoVersion !== PROTO_VERSION) { this.terminate('bad-proto-version'); return; }

        this.clientNonce = hello.clientNonce;
        this.keys = deriveSessionKeys(config.psk, this.clientNonce, this.serverNonce!);
        this.state = 'awaiting-auth';
        this.logger.debug('handshake complete');
    }

    private async onEncrypted(opcode: Opcode, body: Buffer): Promise<void> {
        switch (opcode) {
            case Opcode.EnrollmentQuery:  await this.onEnrollmentQuery(body); return;
            case Opcode.Authenticate:     await this.onAuth(body); return;
            case Opcode.HeartbeatPing:    this.onPing(body); return;
            case Opcode.HeartbeatPong:    this.onPong(body); return;
            case Opcode.Detection:        await this.onDetection(body); return;
            case Opcode.ScreenshotResponse: this.onScreenshotResponse(body); return;
            case Opcode.ScreenshotChunk:    this.onScreenshotChunk(body); return;
            case Opcode.SysInfoResponse:    this.onSysInfoResponse(body); return;
            case Opcode.PciTreeResponse:    this.onPciTreeResponse(body); return;
            case Opcode.MinidumpsResponse:  this.onMinidumpsResponse(body); return;
            case Opcode.DumpFileChunk:      this.onDumpFileChunk(body); return;
            case Opcode.DumpFileError:      this.onDumpFileError(); return;
            case Opcode.AltAccounts:        await this.onAltAccounts(body); return;
            case Opcode.ClientShutdown:   this.terminate('client-shutdown'); return;
            default:
                this.sendEncrypted(Opcode.Error, encodeProtoError({
                    code: ErrorCode.BadOpcode, message: `unknown opcode ${opcode}`,
                }));
        }
    }

    private async onEnrollmentQuery(body: Buffer): Promise<void> {
        if (this.state !== 'awaiting-auth') { this.terminate('enroll-wrong-state'); return; }
        const req = decodeEnrollmentQuery(body);
        if (!req) { this.terminate('bad-enroll'); return; }

        const steamHex = normalizeSteamHex(req.steamHex);
        if (!steamHex) {
            this.sendEncrypted(Opcode.EnrollmentResult, encodeEnrollmentResult({ required: false }));
            this.terminate('bad-steam');
            return;
        }

        let required = false;
        try {
            const player = await findPlayerBySteamHex(steamHex);
            required = !!player && !player.banned && !player.suspended;
        } catch (e) {
            this.logger.error({ err: (e as Error).message }, 'enroll lookup failed');
            this.sendEncrypted(Opcode.Error, encodeProtoError({
                code: ErrorCode.Internal, message: 'server error',
            }));
            this.terminate('db-error');
            return;
        }

        this.sendEncrypted(Opcode.EnrollmentResult, encodeEnrollmentResult({ required }));
        this.logger.info({ steamHex, required }, 'enrollment probe');
        this.terminate('enrollment-probe');
    }

    private async onAuth(body: Buffer): Promise<void> {
        if (this.state !== 'awaiting-auth') { this.terminate('auth-wrong-state'); return; }
        const req = decodeAuthenticate(body);
        if (!req) { this.terminate('bad-auth'); return; }

        const steamHex = normalizeSteamHex(req.steamHex);
        if (!steamHex) {
            this.sendEncrypted(Opcode.AuthResult, encodeAuthResult({
                status: AuthStatus.BadHardware, sessionId: 0n,
                heartbeatIntervalMs: config.heartbeatIntervalMs,
                message: 'invalid steam id',
            }));
            this.terminate('bad-steam');
            return;
        }

        let player: PlayerRow | null;
        try {
            player = await findPlayerBySteamHex(steamHex);
        } catch (e) {
            this.logger.error({ err: (e as Error).message }, 'db lookup failed');
            this.sendEncrypted(Opcode.AuthResult, encodeAuthResult({
                status: AuthStatus.ServerError, sessionId: 0n,
                heartbeatIntervalMs: config.heartbeatIntervalMs, message: 'server error',
            }));
            this.terminate('db-error');
            return;
        }

        if (!player) {
            fire('auth', {
                title: 'Authentication Rejected',
                description: 'Steam ID is not enrolled.',
                fields: [
                    { name: 'SteamID64',       value: '`' + steamHex + '`',          inline: true },
                    { name: 'Client Version',  value: req.clientVersion, inline: true },
                    { name: 'Peer',            value: '`' + this.clientIp + '`',     inline: true },
                    { name: 'Reason',          value: 'not-enrolled' },
                ],
            });
            this.sendEncrypted(Opcode.AuthResult, encodeAuthResult({
                status: AuthStatus.NotEnrolled, sessionId: 0n,
                heartbeatIntervalMs: config.heartbeatIntervalMs,
                message: 'steam id not enrolled',
            }));
            this.terminate('not-enrolled');
            return;
        }

        if (player.banned) {
            fire('auth', {
                title: 'Authentication Rejected',
                description: 'Player is banned.',
                fields: [
                    { name: 'SteamID64', value: '`' + steamHex + '`',          inline: true },
                    { name: 'Peer',      value: '`' + this.clientIp + '`',     inline: true },
                    { name: 'Reason',    value: 'banned' },
                ],
            });
            this.sendEncrypted(Opcode.AuthResult, encodeAuthResult({
                status: AuthStatus.Banned, sessionId: 0n,
                heartbeatIntervalMs: config.heartbeatIntervalMs, message: 'banned',
            }));
            this.terminate('banned');
            return;
        }
        if (player.suspended) {
            fire('auth', {
                title: 'Authentication Rejected',
                description: 'Player is suspended.',
                fields: [
                    { name: 'SteamID64', value: '`' + steamHex + '`',      inline: true },
                    { name: 'Peer',      value: '`' + this.clientIp + '`', inline: true },
                    { name: 'Reason',    value: 'suspended' },
                ],
            });
            this.sendEncrypted(Opcode.AuthResult, encodeAuthResult({
                status: AuthStatus.Suspended, sessionId: 0n,
                heartbeatIntervalMs: config.heartbeatIntervalMs, message: 'suspended',
            }));
            this.terminate('suspended');
            return;
        }

        const submittedHwid = (req.hardwareId || '').slice(0, 128).toLowerCase();
        if (!submittedHwid || submittedHwid === 'hwid-unknown') {
            fire('auth', {
                title: 'Authentication Rejected',
                description: 'Client did not submit a hardware fingerprint.',
                fields: [
                    { name: 'SteamID64', value: '`' + steamHex + '`',      inline: true },
                    { name: 'Peer',      value: '`' + this.clientIp + '`', inline: true },
                    { name: 'Reason',    value: 'no-hwid' },
                ],
            });
            this.sendEncrypted(Opcode.AuthResult, encodeAuthResult({
                status: AuthStatus.BadHardware, sessionId: 0n,
                heartbeatIntervalMs: config.heartbeatIntervalMs,
                message: 'no hardware id',
            }));
            this.terminate('no-hwid');
            return;
        }

        const wasFirstBind = !player.hardware_id;

        if (!player.hardware_id) {
            try {
                await bindPlayerHardwareId(player.id, submittedHwid);
                this.logger.info({ steamHex, playerId: player.id, hwid: submittedHwid }, 'hwid bound on first auth');
            } catch (e) {
                this.logger.error({ err: (e as Error).message }, 'hwid bind failed');
                fire('errors', {
                    title: 'Hardware ID Bind Failed',
                    description: (e as Error).message,
                    fields: [
                        { name: 'SteamID64', value: '`' + steamHex + '`',      inline: true },
                        { name: 'Peer',      value: '`' + this.clientIp + '`', inline: true },
                        { name: 'Component', value: 'db.players' },
                    ],
                });
                this.sendEncrypted(Opcode.AuthResult, encodeAuthResult({
                    status: AuthStatus.ServerError, sessionId: 0n,
                    heartbeatIntervalMs: config.heartbeatIntervalMs, message: 'server error',
                }));
                this.terminate('hwid-bind-failed');
                return;
            }
        } else if (player.hardware_id.toLowerCase() !== submittedHwid) {
            this.logger.warn({
                steamHex, playerId: player.id,
                expected: player.hardware_id, got: submittedHwid,
            }, 'hwid mismatch');
            fire('hwid-mismatch', {
                title: 'Hardware ID Mismatch',
                description: 'A returning player presented a fingerprint that differs from the one previously bound to their Steam account.',
                fields: [
                    { name: 'SteamID64',        value: '`' + steamHex + '`',                                          inline: true },
                    { name: 'Peer',             value: '`' + this.clientIp + '`',                                     inline: true },
                    { name: 'Enrolled HWID',    value: '`' + player.hardware_id.slice(0, 32) + '`' },
                    { name: 'Submitted HWID',   value: '`' + submittedHwid.slice(0, 32) + '`' },
                    { name: 'Client Version',   value: req.clientVersion,                                 inline: true },
                ],
            });
            fire('auth', {
                title: 'Authentication Rejected',
                description: 'Hardware fingerprint does not match the enrolled machine.',
                fields: [
                    { name: 'SteamID64', value: '`' + steamHex + '`',      inline: true },
                    { name: 'Peer',      value: '`' + this.clientIp + '`', inline: true },
                    { name: 'Reason',    value: 'hwid-mismatch' },
                ],
            });
            this.sendEncrypted(Opcode.AuthResult, encodeAuthResult({
                status: AuthStatus.BadHardware, sessionId: 0n,
                heartbeatIntervalMs: config.heartbeatIntervalMs,
                message: 'hardware id does not match enrolled machine',
            }));
            this.terminate('hwid-mismatch');
            return;
        }

        this.player = player;
        this.steamHex = steamHex;
        this.hardwareId = req.hardwareId.slice(0, 128);

        let hwDetails: string | null = null;
        if (req.hardwareDetails && req.hardwareDetails.length > 0) {
            const trimmed = req.hardwareDetails.slice(0, 4096);
            try {
                JSON.parse(trimmed);
                hwDetails = trimmed;
            } catch {
                hwDetails = null;
            }
        }

        try {
            this.sessionId = await startSession({
                steamHex,
                playerId: player.id,
                hardwareId: this.hardwareId,
                hardwareDetails: hwDetails,
                clientIp: this.clientIp,
                clientVersion: req.clientVersion.slice(0, 32),
            });
            await touchLastSeen(player.id);
        } catch (e) {
            this.logger.error({ err: (e as Error).message }, 'session start failed');
            this.terminate('db-error');
            return;
        }

        this.state = 'ready';
        if (this.handshakeTimer) { clearTimeout(this.handshakeTimer); this.handshakeTimer = null; }

        registerSession(steamHex, this.keys!.slot, this);

        this.sendEncrypted(Opcode.AuthResult, encodeAuthResult({
            status: AuthStatus.Ok,
            sessionId: this.sessionId,
            heartbeatIntervalMs: config.heartbeatIntervalMs,
            message: 'ok',
        }));

        this.logger.info({ steamHex, playerId: player.id, sessionId: this.sessionId.toString() }, 'agent online');

        fire('auth', {
            title: 'Authentication Successful',
            fields: [
                { name: 'SteamID64',       value: '`' + steamHex + '`',                     inline: true },
                { name: 'Client Version',  value: req.clientVersion,            inline: true },
                { name: 'Peer',            value: '`' + this.clientIp + '`',                inline: true },
                { name: 'Session ID',      value: this.sessionId.toString(),    inline: true },
                { name: 'HWID',            value: '`' + submittedHwid.slice(0, 32) + '`' },
            ],
        });

        fire('sessions', {
            title: 'Session Started',
            fields: [
                { name: 'SteamID64',      value: '`' + steamHex + '`',                  inline: true },
                { name: 'Session ID',     value: this.sessionId.toString(), inline: true },
                { name: 'Peer',           value: '`' + this.clientIp + '`',             inline: true },
                { name: 'Client Version', value: req.clientVersion,         inline: true },
            ],
        });

        if (wasFirstBind) {
            let regShot: string | null = null;
            if (req.screenshot && req.screenshot.length > 4 &&
                req.screenshot[0] === 0x89 && req.screenshot[1] === 0x50 &&
                req.screenshot[2] === 0x4E && req.screenshot[3] === 0x47) {
                try {
                    const dir = path.join('screenshots', steamHex);
                    await fs.mkdir(dir, { recursive: true });
                    const ts = new Date().toISOString().replace(/[:.]/g, '-');
                    const fname = `${ts}_registration.png`;
                    regShot = path.join(dir, fname);
                    await fs.writeFile(regShot, req.screenshot);
                    this.logger.info({ path: regShot, bytes: req.screenshot.length }, 'registration screenshot saved');
                } catch (e) {
                    this.logger.warn({ err: (e as Error).message }, 'registration screenshot save failed');
                    regShot = null;
                }
            }

            fire('registrations', {
                title: 'New Player Registered',
                description: 'This Steam ID successfully authenticated for the first time. Hardware fingerprint has been bound.',
                fields: [
                    { name: 'SteamID64',      value: '`' + steamHex + '`',          inline: true },
                    { name: 'Player ID',      value: String(player.id), inline: true },
                    { name: 'Peer',           value: '`' + this.clientIp + '`',     inline: true },
                    { name: 'Client Version', value: req.clientVersion, inline: true },
                    { name: 'HWID',           value: '`' + submittedHwid.slice(0, 32) + '`' },
                ],
            }, regShot);
        }

        this.startHeartbeat();
    }

    private startHeartbeat(): void {
        this.hbTimer = setInterval(() => {
            this.lastPingSeq = (this.lastPingSeq + 1) >>> 0;
            this.sendEncrypted(Opcode.HeartbeatPing, encodeHeartbeat({
                seq: this.lastPingSeq, clientTsMs: BigInt(Date.now()),
            }));
        }, config.heartbeatIntervalMs);

        this.watchdog = setInterval(() => {
            const idle = Date.now() - this.lastRxMs;
            if (idle > config.heartbeatTimeoutMs) {
                this.logger.info({ idleMs: idle }, 'heartbeat timeout');
                this.terminate('heartbeat-timeout');
            }
        }, Math.max(1000, Math.floor(config.heartbeatIntervalMs / 2)));
    }

    private touchPlayerSeen(): void {
        if (!this.player) return;
        const now = Date.now();
        if (now - this.lastSeenTouchedMs < 6000) return;
        this.lastSeenTouchedMs = now;
        const pid = this.player.id;
        void touchLastSeen(pid).catch((e) =>
            this.logger.warn({ err: (e as Error).message }, 'touchLastSeen failed'));
    }

    private onPing(body: Buffer): void {
        const hb = decodeHeartbeat(body);
        if (!hb) return;
        this.sendEncrypted(Opcode.HeartbeatPong, encodeHeartbeat({
            seq: hb.seq, clientTsMs: hb.clientTsMs,
        }));
        if (this.sessionId) void bumpHeartbeat(this.sessionId).catch(() => {});
        this.touchPlayerSeen();
    }

    private onPong(body: Buffer): void {
        const hb = decodeHeartbeat(body);
        if (!hb) return;
        if (this.sessionId) void bumpHeartbeat(this.sessionId).catch(() => {});
        this.touchPlayerSeen();
    }

    private async onDetection(body: Buffer): Promise<void> {
        if (this.state !== 'ready' || !this.player || !this.steamHex) {
            this.logger.warn({
                state: this.state,
                hasPlayer: !!this.player,
                hasSteamHex: !!this.steamHex,
                bodyBytes: body.length,
            }, 'detection dropped: session not ready');
            this.terminate('detection-not-ready');
            return;
        }
        const det = decodeDetection(body);
        if (!det) {
            this.logger.warn({ bodyBytes: body.length }, 'detection dropped: decode failed');
            this.terminate('bad-detection');
            return;
        }
        this.logger.info({
            type: det.detectionType,
            reason: det.reason,
            severity: det.severity,
            payloadBytes: det.payload.length,
        }, 'detection received');

        let jsonPart: Buffer = Buffer.alloc(0);
        let pngPart:  Buffer = Buffer.alloc(0);
        if (det.payload.length >= 4) {
            const jsonLen = det.payload.readUInt32BE(0);
            if (4 + jsonLen <= det.payload.length) {
                jsonPart = det.payload.subarray(4, 4 + jsonLen);
                pngPart  = det.payload.subarray(4 + jsonLen);
            }
        }

        let screenshotPath: string | null = null;
        if (pngPart.length > 4 && pngPart[0] === 0x89 && pngPart[1] === 0x50 &&
            pngPart[2] === 0x4E && pngPart[3] === 0x47) {
            try {
                const dir = path.join('screenshots', this.steamHex);
                await fs.mkdir(dir, { recursive: true });
                const ts = new Date().toISOString().replace(/[:.]/g, '-');
                const fname = `${ts}_${det.detectionType}_${(det.reason || 'x').replace(/[^\w.-]/g, '_')}.png`;
                screenshotPath = path.join(dir, fname);
                await fs.writeFile(screenshotPath, pngPart);
                this.logger.info({ path: screenshotPath, bytes: pngPart.length }, 'screenshot saved');
            } catch (e) {
                this.logger.warn({ err: (e as Error).message }, 'screenshot save failed');
                screenshotPath = null;
            }
        }

        const dbPayload = jsonPart.length > 0
            ? Buffer.from(JSON.stringify({
                  json: jsonPart.toString('utf8'),
                  shot: screenshotPath,
              }))
            : null;

        try {
            const id = await insertDetection({
                sessionId: this.sessionId,
                playerId: this.player.id,
                steamHex: this.steamHex,
                hardwareId: this.hardwareId,
                clientIp: this.clientIp,
                detectionType: det.detectionType,
                detectionReason: det.reason || null,
                offendingPath: det.offendingPath || null,
                severity: det.severity,
                payload: dbPayload,
            });
            this.sendEncrypted(Opcode.DetectionAck, encodeDetectionAck({ id }));
            this.logger.warn({
                steamHex: this.steamHex,
                type: det.detectionType,
                reason: det.reason,
                severity: det.severity,
                id: id.toString(),
                shot: screenshotPath,
            }, 'detection recorded');

            const channel     = channelForDetection(det.detectionType);
            const pretty      = prettyDetectionType(det.detectionType);
            const attribution = detectionAttribution(det.detectionType);
            const titleSuffix = det.detectionType === 'cheat-host' && det.reason
                              ? ` - ${det.reason}` : '';
            const fields: { name: string; value: string; inline?: boolean }[] = [
                { name: 'SteamID64',    value: '`' + this.steamHex + '`',  inline: true },
                { name: 'Session ID',   value: this.sessionId!.toString(), inline: true },
                { name: 'Severity',     value: String(det.severity),       inline: true },
                { name: 'Detection ID', value: id.toString(),              inline: true },
                { name: 'Peer',         value: '`' + this.clientIp + '`',  inline: true },
            ];
            if (det.offendingPath) {
                const offenderLabel = det.detectionType === 'susp-key' ? 'Key' : 'Offender';
                fields.push({ name: offenderLabel, value: '`' + det.offendingPath.slice(0, 512) + '`' });
            }
            for (const f of extrasToFields(jsonPart)) fields.push(f);
            fire(channel, {
                title: `${pretty} Detected${titleSuffix}`,
                ...(attribution ? { description: attribution } : {}),
                fields,
            }, screenshotPath);
        } catch (e) {
            this.logger.error({ err: (e as Error).message }, 'detection insert failed');
            fire('errors', {
                title: 'Detection Insert Failed',
                description: (e as Error).message,
                fields: [
                    { name: 'SteamID64', value: '`' + (this.steamHex || 'n/a') + '`',      inline: true },
                    { name: 'Type',      value: det.detectionType,           inline: true },
                    { name: 'Component', value: 'db.detections' },
                ],
            });
            this.sendEncrypted(Opcode.Error, encodeProtoError({
                code: ErrorCode.Internal, message: 'detection write failed',
            }));
        }
    }

    private async onAltAccounts(body: Buffer): Promise<void> {
        if (this.state !== 'ready' || !this.player || !this.steamHex) return;
        const entries = decodeAltAccounts(body);
        if (!entries) { this.logger.warn('bad alt-accounts payload'); return; }
        if (entries.length === 0) {
            this.sendEncrypted(Opcode.AltAccountsAck, encodeAltAccountsAck({ inserted: 0, updated: 0 }));
            return;
        }
        try {
            const res = await upsertAltAccounts(this.player.id, this.steamHex, entries.map((e) => ({
                kind:       e.kind,
                externalId: e.externalId,
                username:   e.username || null,
                avatar:     e.avatar   || null,
            })));
            this.sendEncrypted(Opcode.AltAccountsAck, encodeAltAccountsAck(res));
            this.logger.info({
                playerId: this.player.id,
                steamHex: this.steamHex,
                count: entries.length,
                inserted: res.inserted,
                updated: res.updated,
            }, 'alt accounts upserted');
        } catch (e) {
            this.logger.warn({ err: (e as Error).message }, 'alt accounts upsert failed');
        }
    }

    private onScreenshotResponse(body: Buffer): void {
        if (!this.pendingShot) return;
        const pending = this.pendingShot;
        this.pendingShot = null;
        clearTimeout(pending.timer);
        if (body.length > 4 && body[0] === 0x89 && body[1] === 0x50 && body[2] === 0x4E && body[3] === 0x47)
            pending.resolve(Buffer.from(body));
        else
            pending.reject(new Error('invalid png in response'));
    }

    private onScreenshotChunk(body: Buffer): void {
        if (!this.pendingShot) return;
        if (body.length < 8) return;

        const offset = body.readUInt32BE(0);
        const total  = body.readUInt32BE(4);
        const data   = body.subarray(8);

        const pending = this.pendingShot;

        if (total === 0 || total > 32 * 1024 * 1024) {
            this.pendingShot = null;
            clearTimeout(pending.timer);
            pending.reject(new Error('screenshot chunk bad total'));
            return;
        }
        if (offset + data.length > total) {
            this.pendingShot = null;
            clearTimeout(pending.timer);
            pending.reject(new Error('screenshot chunk overflow'));
            return;
        }

        if (!pending.buffer || pending.totalBytes !== total) {
            pending.buffer        = Buffer.alloc(total);
            pending.totalBytes    = total;
            pending.receivedBytes = 0;
        }

        data.copy(pending.buffer, offset);
        pending.receivedBytes += data.length;

        if (pending.receivedBytes >= pending.totalBytes) {
            const buf = pending.buffer;
            this.pendingShot = null;
            clearTimeout(pending.timer);
            if (buf.length > 4 && buf[0] === 0x89 && buf[1] === 0x50 && buf[2] === 0x4E && buf[3] === 0x47)
                pending.resolve(buf);
            else
                pending.reject(new Error('invalid png in reassembled chunks'));
        }
    }

    private onSysInfoResponse(body: Buffer): void {
        if (!this.pendingSysInfo) return;
        const pending = this.pendingSysInfo;
        this.pendingSysInfo = null;
        clearTimeout(pending.timer);
        if (body.length === 0) {
            pending.reject(new Error('empty system info payload'));
            return;
        }
        try {
            const s = body.toString('utf8');
            pending.resolve(s);
        } catch (e) {
            pending.reject(new Error((e as Error).message));
        }
    }

    private onPciTreeResponse(body: Buffer): void {
        if (!this.pendingPciTree) return;
        const pending = this.pendingPciTree;
        this.pendingPciTree = null;
        clearTimeout(pending.timer);
        if (body.length === 0) {
            pending.reject(new Error('empty pci tree payload'));
            return;
        }
        try {
            pending.resolve(body.toString('utf8'));
        } catch (e) {
            pending.reject(new Error((e as Error).message));
        }
    }

    requestPciTree(timeoutMs = 20000): Promise<string> {
        return new Promise<string>((resolve, reject) => {
            if (this.state !== 'ready') {
                reject(new Error('agent not ready'));
                return;
            }
            if (this.pendingPciTree) {
                reject(new Error('pci tree already in flight'));
                return;
            }
            const timer = setTimeout(() => {
                if (this.pendingPciTree) {
                    const p = this.pendingPciTree;
                    this.pendingPciTree = null;
                    p.reject(new Error('pci tree timeout'));
                }
            }, timeoutMs);
            this.pendingPciTree = { resolve, reject, timer };
            this.sendEncrypted(Opcode.PciTreeRequest, Buffer.alloc(0));
        });
    }

    private onMinidumpsResponse(body: Buffer): void {
        if (!this.pendingMinidumps) return;
        const pending = this.pendingMinidumps;
        this.pendingMinidumps = null;
        clearTimeout(pending.timer);
        if (body.length === 0) {
            pending.reject(new Error('empty minidumps payload'));
            return;
        }
        pending.resolve(body.toString('utf8'));
    }

    private onDumpFileError(): void {
        if (!this.pendingDumpFile) return;
        const pending = this.pendingDumpFile;
        this.pendingDumpFile = null;
        clearTimeout(pending.timer);
        pending.reject(new Error('agent refused or missing dump'));
    }

    private onDumpFileChunk(body: Buffer): void {
        if (!this.pendingDumpFile) return;
        if (body.length < 8) return;
        const offset = body.readUInt32BE(0);
        const total  = body.readUInt32BE(4);
        const data   = body.subarray(8);
        const pending = this.pendingDumpFile;

        if (total === 0 || total > 32 * 1024 * 1024) {
            this.pendingDumpFile = null;
            clearTimeout(pending.timer);
            pending.reject(new Error('dump chunk bad total'));
            return;
        }
        if (offset + data.length > total) {
            this.pendingDumpFile = null;
            clearTimeout(pending.timer);
            pending.reject(new Error('dump chunk overflow'));
            return;
        }
        if (!pending.buffer || pending.totalBytes !== total) {
            pending.buffer        = Buffer.alloc(total);
            pending.totalBytes    = total;
            pending.receivedBytes = 0;
        }
        data.copy(pending.buffer, offset);
        pending.receivedBytes += data.length;
        if (pending.receivedBytes >= pending.totalBytes) {
            const buf = pending.buffer;
            this.pendingDumpFile = null;
            clearTimeout(pending.timer);
            pending.resolve(buf);
        }
    }

    requestDumpFile(name: string, timeoutMs = 60000): Promise<Buffer> {
        return new Promise<Buffer>((resolve, reject) => {
            if (this.state !== 'ready') {
                reject(new Error('agent not ready'));
                return;
            }
            if (this.pendingDumpFile) {
                reject(new Error('dump file already in flight'));
                return;
            }
            if (!/^[A-Za-z0-9._-]{5,96}$/.test(name) || !/\.dmp$/i.test(name) || name.includes('..')) {
                reject(new Error('bad dump filename'));
                return;
            }
            const timer = setTimeout(() => {
                if (this.pendingDumpFile) {
                    const p = this.pendingDumpFile;
                    this.pendingDumpFile = null;
                    p.reject(new Error('dump file timeout'));
                }
            }, timeoutMs);
            this.pendingDumpFile = {
                resolve, reject, timer,
                buffer: null, receivedBytes: 0, totalBytes: 0,
            };
            this.sendEncrypted(Opcode.DumpFileRequest, Buffer.from(name, 'utf8'));
        });
    }

    requestMinidumps(timeoutMs = 30000): Promise<string> {
        return new Promise<string>((resolve, reject) => {
            if (this.state !== 'ready') {
                reject(new Error('agent not ready'));
                return;
            }
            if (this.pendingMinidumps) {
                reject(new Error('minidumps already in flight'));
                return;
            }
            const timer = setTimeout(() => {
                if (this.pendingMinidumps) {
                    const p = this.pendingMinidumps;
                    this.pendingMinidumps = null;
                    p.reject(new Error('minidumps timeout'));
                }
            }, timeoutMs);
            this.pendingMinidumps = { resolve, reject, timer };
            this.sendEncrypted(Opcode.MinidumpsRequest, Buffer.alloc(0));
        });
    }

    requestSystemInfo(timeoutMs = 15000): Promise<string> {
        return new Promise<string>((resolve, reject) => {
            if (this.state !== 'ready') {
                reject(new Error('agent not ready'));
                return;
            }
            if (this.pendingSysInfo) {
                reject(new Error('system info already in flight'));
                return;
            }
            const timer = setTimeout(() => {
                if (this.pendingSysInfo) {
                    const p = this.pendingSysInfo;
                    this.pendingSysInfo = null;
                    p.reject(new Error('system info timeout'));
                }
            }, timeoutMs);
            this.pendingSysInfo = { resolve, reject, timer };
            this.sendEncrypted(Opcode.SysInfoRequest, Buffer.alloc(0));
        });
    }

    requestScreenshot(method: number = 0, timeoutMs = 15000): Promise<Buffer> {
        return new Promise<Buffer>((resolve, reject) => {
            if (this.state !== 'ready') {
                reject(new Error('agent not ready'));
                return;
            }
            if (this.pendingShot) {
                reject(new Error('screenshot already in flight'));
                return;
            }
            const m = (method === 1 || method === 2) ? method : 0;
            const timer = setTimeout(() => {
                if (this.pendingShot) {
                    const p = this.pendingShot;
                    this.pendingShot = null;
                    p.reject(new Error('screenshot timeout'));
                }
            }, timeoutMs);
            this.pendingShot = {
                resolve, reject, timer,
                buffer: null, receivedBytes: 0, totalBytes: 0,
            };
            this.sendEncrypted(Opcode.ScreenshotRequest, Buffer.from([m]));
        });
    }

    kick(reason: string): void {
        const safeReason = (reason || 'kicked-by-admin').slice(0, 200);
        this.logger.info({ reason: safeReason }, 'admin kick');
        try {
            this.sendEncrypted(Opcode.Kick, Buffer.from(safeReason, 'utf8'));
        } catch { /* ignore */ }
        setTimeout(() => this.terminate(`admin-kick:${safeReason}`), 200);
    }

    private terminate(reason: string): void {
        if (this.state === 'closed') return;
        this.state = 'closed';
        this.clearTimers();

        if (this.pendingShot) {
            const p = this.pendingShot;
            this.pendingShot = null;
            clearTimeout(p.timer);
            p.reject(new Error('session closed'));
        }
        if (this.pendingSysInfo) {
            const p = this.pendingSysInfo;
            this.pendingSysInfo = null;
            clearTimeout(p.timer);
            p.reject(new Error('session closed'));
        }
        if (this.pendingPciTree) {
            const p = this.pendingPciTree;
            this.pendingPciTree = null;
            clearTimeout(p.timer);
            p.reject(new Error('session closed'));
        }
        if (this.pendingMinidumps) {
            const p = this.pendingMinidumps;
            this.pendingMinidumps = null;
            clearTimeout(p.timer);
            p.reject(new Error('session closed'));
        }
        if (this.pendingDumpFile) {
            const p = this.pendingDumpFile;
            this.pendingDumpFile = null;
            clearTimeout(p.timer);
            p.reject(new Error('session closed'));
        }

        if (this.steamHex) unregisterSession(this.steamHex);

        if (this.sessionId) {
            const sid = this.sessionId;
            void endSession(sid, reason).catch(() => {});
            fire('sessions', {
                title: 'Session Ended',
                fields: [
                    { name: 'SteamID64',  value: '`' + (this.steamHex || 'n/a') + '`', inline: true },
                    { name: 'Session ID', value: sid.toString(),         inline: true },
                    { name: 'Peer',       value: '`' + this.clientIp + '`',          inline: true },
                    { name: 'Reason',     value: reason,                 inline: true },
                ],
            });
        }
        try { this.socket.end(); } catch { /* ignore */ }
        setTimeout(() => { try { this.socket.destroy(); } catch { /* ignore */ } }, 500);

        this.logger.info({ reason }, 'session closed');
    }

    private onClose(reason: string): void {
        if (this.state === 'closed') return;
        this.terminate(reason);
    }

    private clearTimers(): void {
        if (this.hbTimer)        { clearInterval(this.hbTimer);       this.hbTimer = null; }
        if (this.watchdog)       { clearInterval(this.watchdog);      this.watchdog = null; }
        if (this.handshakeTimer) { clearTimeout(this.handshakeTimer); this.handshakeTimer = null; }
    }
}

function normalizeSteamHex(raw: string): string | null {
    const s = raw.trim().toLowerCase();
    const stripped = s.startsWith('0x') ? s.slice(2) : s;
    if (!/^[0-9a-f]{1,16}$/.test(stripped)) return null;
    return BigInt('0x' + stripped).toString(16);
}

function prettifyExtraKey(k: string): string {
    const map: Record<string, string> = {
        className:    'Class Name',
        title:        'Window Title',
        exePath:      'Exe Path',
        pid:          'PID',
        hwnd:         'HWND',
        style:        'Style',
        exStyle:      'Extended Style',
        rect:         'Rect',
        monitor:      'Monitor',
        coveragePct:  'Coverage %',
        trigger:      'Trigger',
        affinity:     'Affinity',
        matchKind:    'Match Kind',
        matchPattern: 'Matched Pattern',
        vendor:       'Vendor',
        vid:          'Vendor ID',
        did:          'Device ID',
        subsys:       'Subsystem',
        rev:          'Revision',
        description:  'Description',
        manufacturer: 'Manufacturer',
        location:     'Location',
        instance:     'Instance',
        address:      'Start Address',
        tid:          'Thread ID',
        nearestModule: 'Nearest Module',
        nearestOffset: 'Nearest Offset',
        dumpBytes:    'Dump Bytes',
        dumpHex:      'Dump (hex)',
        majorFunction: 'IRP Major',
        majorIndex:    'IRP Index',
        driverName:   'Driver',
        deviceName:   'Device',
        symlinkName:  'Symbolic Link',
        host:         'Host',
        source:       'Source',
        brand:        'Brand',
    };
    if (map[k]) return map[k];
    return k.charAt(0).toUpperCase() + k.slice(1).replace(/([A-Z])/g, ' $1');
}

function extrasToFields(jsonPart: Buffer): { name: string; value: string; inline?: boolean }[] {
    if (jsonPart.length === 0) return [];
    let obj: Record<string, unknown>;
    try {
        obj = JSON.parse(jsonPart.toString('utf8')) as Record<string, unknown>;
    } catch { return []; }
    const extras = obj['extras'];
    if (extras === undefined || extras === null) return [];
    let inner: Record<string, unknown>;
    if (typeof extras === 'string') {
        try { inner = JSON.parse(extras) as Record<string, unknown>; } catch { return []; }
    } else if (typeof extras === 'object') {
        inner = extras as Record<string, unknown>;
    } else {
        return [];
    }

    const skipKeys = new Set(['exePath', 'trigger', 'path']);
    const wideKeys = new Set(['title', 'className', 'style', 'exStyle', 'description', 'instance', 'location', 'manufacturer']);
    const fields: { name: string; value: string; inline?: boolean }[] = [];

    for (const [k, v] of Object.entries(inner)) {
        if (v === null || v === undefined) continue;
        if (skipKeys.has(k)) continue;

        let str: string;
        if (k === 'rect' && typeof v === 'object') {
            const r = v as { l?: number; t?: number; r?: number; b?: number };
            const l = r.l ?? 0, t = r.t ?? 0, ri = r.r ?? 0, b = r.b ?? 0;
            str = `${ri - l}x${b - t} @ ${l},${t}`;
        } else if (k === 'monitor' && typeof v === 'object') {
            const m = v as { w?: number; h?: number };
            str = `${m.w ?? 0}x${m.h ?? 0}`;
        } else if (k === 'style' && typeof v === 'string') {
            const n = Number(v);
            str = Number.isFinite(n) ? decodeWinStyle(n) : v;
        } else if (k === 'exStyle' && typeof v === 'string') {
            const n = Number(v);
            str = Number.isFinite(n) ? decodeWinExStyle(n) : v;
        } else if (typeof v === 'object') {
            str = JSON.stringify(v);
        } else {
            str = String(v);
        }
        if (str === '') continue;
        if (str.length > 512) str = str.slice(0, 509) + '...';

        fields.push({
            name:   prettifyExtraKey(k),
            value:  '`' + str + '`',
            inline: !wideKeys.has(k),
        });
        if (fields.length >= 10) break;
    }
    return fields;
}

const WS_FLAGS: [number, string][] = [
    [0x80000000, 'WS_POPUP'],
    [0x40000000, 'WS_CHILD'],
    [0x20000000, 'WS_MINIMIZE'],
    [0x10000000, 'WS_VISIBLE'],
    [0x08000000, 'WS_DISABLED'],
    [0x04000000, 'WS_CLIPSIBLINGS'],
    [0x02000000, 'WS_CLIPCHILDREN'],
    [0x01000000, 'WS_MAXIMIZE'],
    [0x00800000, 'WS_BORDER'],
    [0x00400000, 'WS_DLGFRAME'],
    [0x00200000, 'WS_VSCROLL'],
    [0x00100000, 'WS_HSCROLL'],
    [0x00080000, 'WS_SYSMENU'],
    [0x00040000, 'WS_THICKFRAME'],
    [0x00020000, 'WS_GROUP'],
    [0x00010000, 'WS_TABSTOP'],
];

const WS_EX_FLAGS: [number, string][] = [
    [0x00000001, 'WS_EX_DLGMODALFRAME'],
    [0x00000004, 'WS_EX_NOPARENTNOTIFY'],
    [0x00000008, 'WS_EX_TOPMOST'],
    [0x00000010, 'WS_EX_ACCEPTFILES'],
    [0x00000020, 'WS_EX_TRANSPARENT'],
    [0x00000040, 'WS_EX_MDICHILD'],
    [0x00000080, 'WS_EX_TOOLWINDOW'],
    [0x00000100, 'WS_EX_WINDOWEDGE'],
    [0x00000200, 'WS_EX_CLIENTEDGE'],
    [0x00000400, 'WS_EX_CONTEXTHELP'],
    [0x00001000, 'WS_EX_RIGHT'],
    [0x00002000, 'WS_EX_RTLREADING'],
    [0x00004000, 'WS_EX_LEFTSCROLLBAR'],
    [0x00010000, 'WS_EX_CONTROLPARENT'],
    [0x00020000, 'WS_EX_STATICEDGE'],
    [0x00040000, 'WS_EX_APPWINDOW'],
    [0x00080000, 'WS_EX_LAYERED'],
    [0x00100000, 'WS_EX_NOINHERITLAYOUT'],
    [0x00200000, 'WS_EX_NOREDIRECTIONBITMAP'],
    [0x00400000, 'WS_EX_LAYOUTRTL'],
    [0x02000000, 'WS_EX_COMPOSITED'],
    [0x08000000, 'WS_EX_NOACTIVATE'],
];

function decodeFlagSet(value: number, table: [number, string][]): string {
    const names: string[] = [];
    for (const [bit, name] of table) {
        if ((value & bit) !== 0) names.push(name);
    }
    return names.length > 0 ? names.join(' | ') : '0';
}

function decodeWinStyle(v: number): string {
    return decodeFlagSet(v, WS_FLAGS);
}

function decodeWinExStyle(v: number): string {
    return decodeFlagSet(v, WS_EX_FLAGS);
}
