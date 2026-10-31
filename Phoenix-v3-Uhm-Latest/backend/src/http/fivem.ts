import { promises as fs } from 'node:fs';
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import * as path from 'node:path';
import { URL } from 'node:url';

import { config } from '../config.js';
import {
    BAN_CATEGORIES,
    banPlayerBySteamHex,
    categoryLabel,
    findPlayerBySteamHex,
    findPlayersBySteamHexBulk,
    suspendPlayerBySteamHex,
    unbanPlayerBySteamHex,
    unsuspendPlayerBySteamHex,
    updateBanBySteamHex,
    updateSuspendBySteamHex,
} from '../db/players.js';
import { getLiveSessionStatus, getLiveSessionStatusBulk } from '../db/sessions.js';
import { detectionAttribution, fire, prettyDetectionType } from '../discord/webhook.js';
import { log } from '../logger.js';
import { getLiveAgent, reportSlot, snapshotSlot } from '../net/registry.js';
import {
    scanBus,
    type ScanDoneEvent,
    type ScanErrEvent,
    type ScanHitEvent,
    type ScanProgressEvent,
} from '../net/scanBus.js';

type SteamProfile = {
    steamHex: string;
    personaName: string;
    avatarFull: string;
    avatarMedium: string;
    profileUrl: string;
};

const STEAM_CACHE_MS = 5 * 60 * 1000;

const steamCache = new Map<
    string,
    {
        at: number;
        data: SteamProfile;
    }
>();

async function fetchViaSteamApi(steamHex: string): Promise<SteamProfile | null> {
    if (!config.steamApiKey) return null;
    const steamId64 = BigInt('0x' + steamHex).toString(10);
    const url = new URL('https://api.steampowered.com/ISteamUser/GetPlayerSummaries/v2/');
    url.searchParams.set('key', config.steamApiKey);
    url.searchParams.set('steamids', steamId64);
    const res = await fetch(url.toString());
    if (!res.ok) return null;
    const json = (await res.json()) as {
        response?: {
            players?: Array<{
                personaname?: string;
                avatarfull?: string;
                avatarmedium?: string;
                profileurl?: string;
            }>;
        };
    };
    const p = json.response?.players?.[0];
    if (!p || !p.personaname) return null;
    return {
        steamHex,
        personaName: p.personaname ?? '',
        avatarFull: p.avatarfull ?? '',
        avatarMedium: p.avatarmedium ?? '',
        profileUrl: p.profileurl ?? '',
    };
}

function extractXmlTag(xml: string, tag: string): string {
    const re = new RegExp(`<${tag}>(?:<!\\[CDATA\\[([\\s\\S]*?)\\]\\]>|([\\s\\S]*?))<\\/${tag}>`);
    const m = xml.match(re);
    return (m ? (m[1] ?? m[2] ?? '') : '').trim();
}

async function fetchViaCommunityXml(steamHex: string): Promise<SteamProfile | null> {
    const steamId64 = BigInt('0x' + steamHex).toString(10);
    const url = `https://steamcommunity.com/profiles/${steamId64}?xml=1`;
    const res = await fetch(url, { headers: { 'user-agent': 'PhoenixAgent/1.0' } });
    if (!res.ok) return null;
    const xml = await res.text();
    const persona = extractXmlTag(xml, 'steamID');
    const avatar = extractXmlTag(xml, 'avatarFull');
    if (!persona && !avatar) return null;
    return {
        steamHex,
        personaName: persona,
        avatarFull: avatar,
        avatarMedium: extractXmlTag(xml, 'avatarMedium'),
        profileUrl: `https://steamcommunity.com/profiles/${steamId64}/`,
    };
}

async function fetchSteamProfile(steamHex: string): Promise<SteamProfile | null> {
    const cached = steamCache.get(steamHex);
    if (cached && Date.now() - cached.at < STEAM_CACHE_MS) return cached.data;
    let data: SteamProfile | null = null;
    try {
        data = await fetchViaSteamApi(steamHex);
    } catch (e) {
        httpLog.debug({ err: (e as Error).message }, 'steam api path failed');
    }
    if (!data) {
        try {
            data = await fetchViaCommunityXml(steamHex);
        } catch (e) {
            httpLog.debug({ err: (e as Error).message }, 'steam community xml path failed');
        }
    }
    if (data) steamCache.set(steamHex, { at: Date.now(), data });
    return data;
}

const SLOT_STALE_MS = 30000;

const httpLog = log.child({ module: 'fivem-http' });

function normalizeSteamHex(raw: string): string | null {
    const s = raw.trim().toLowerCase();
    const stripped = s.startsWith('0x') ? s.slice(2) : s;
    if (!/^[0-9a-f]{1,16}$/.test(stripped)) {
        return null;
    }
    return BigInt('0x' + stripped).toString(16);
}

function authorized(req: IncomingMessage): boolean {
    if (!config.httpToken) return false;
    const h = req.headers['authorization'];
    if (typeof h !== 'string') return false;
    if (!h.startsWith('Bearer ')) return false;
    return h.slice(7) === config.httpToken;
}

async function handleSessionStatus(url: URL, res: ServerResponse): Promise<void> {
    const raw = url.searchParams.get('steam_hex') ?? '';
    const steamHex = normalizeSteamHex(raw);
    if (!steamHex) {
        res.writeHead(400, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ error: 'bad steam_hex' }));
        return;
    }
    try {
        const player = await findPlayerBySteamHex(steamHex);
        if (!player) {
            res.writeHead(200, { 'content-type': 'application/json' });
            res.end(
                JSON.stringify({
                    steamHex,
                    healthy: true,
                    reason: 'unregistered',
                    slotHealthy: true,
                }),
            );
            return;
        }
        if (player.banned) {
            res.writeHead(200, { 'content-type': 'application/json' });
            res.end(
                JSON.stringify({
                    steamHex,
                    healthy: false,
                    reason: 'banned',
                    slotHealthy: false,
                }),
            );
            return;
        }
        if (player.suspended) {
            res.writeHead(200, { 'content-type': 'application/json' });
            res.end(
                JSON.stringify({
                    steamHex,
                    healthy: true,
                    reason: 'suspended',
                    slotHealthy: true,
                }),
            );
            return;
        }
        const row = await getLiveSessionStatus(steamHex);
        if (!row) {
            res.writeHead(200, { 'content-type': 'application/json' });
            res.end(
                JSON.stringify({
                    steamHex,
                    healthy: false,
                    reason: 'no-session',
                    slotHealthy: false,
                }),
            );
            return;
        }
        const ageMs = Number(row.age_ms);
        const healthy = ageMs >= 0 && ageMs <= config.sessionStaleMs;
        const slot = snapshotSlot(steamHex);
        const slotHealthy =
            slot.known && slot.lastReportMs !== 0 && slot.ageMs >= 0 && slot.ageMs <= SLOT_STALE_MS;
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(
            JSON.stringify({
                steamHex,
                healthy,
                ageMs,
                reason: healthy ? 'ok' : 'stale',
                slotHealthy,
                slotAgeMs: slot.ageMs,
            }),
        );
    } catch (e) {
        httpLog.error({ err: (e as Error).message }, 'session status query failed');
        res.writeHead(500, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ error: 'server error' }));
    }
}

async function handleSessionStatusBulk(req: IncomingMessage, res: ServerResponse): Promise<void> {
    let payload: {
        steam_hexes?: unknown;
    };
    try {
        const body = await readBody(req, 65536);
        payload = JSON.parse(body.toString('utf8'));
    } catch {
        res.writeHead(400, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ error: 'bad body' }));
        return;
    }
    if (!Array.isArray(payload.steam_hexes)) {
        res.writeHead(400, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ error: 'steam_hexes must be an array' }));
        return;
    }
    const normalized: string[] = [];
    const rawByNormalized = new Map<string, string>();
    for (const raw of payload.steam_hexes) {
        if (typeof raw !== 'string') continue;
        const hex = normalizeSteamHex(raw);
        if (!hex) continue;
        if (!rawByNormalized.has(hex)) {
            normalized.push(hex);
            rawByNormalized.set(hex, raw);
        }
    }
    if (normalized.length > 1024) {
        res.writeHead(400, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ error: 'too many steam_hexes' }));
        return;
    }
    try {
        const [players, sessions] = await Promise.all([
            findPlayersBySteamHexBulk(normalized),
            getLiveSessionStatusBulk(normalized),
        ]);
        const results: Record<
            string,
            {
                healthy: boolean;
                reason: string;
                slotHealthy: boolean;
                ageMs?: number;
                slotAgeMs?: number;
            }
        > = {};
        for (const hex of normalized) {
            const player = players.get(hex);
            if (!player) {
                results[hex] = { healthy: true, reason: 'unregistered', slotHealthy: true };
                continue;
            }
            if (player.banned) {
                results[hex] = { healthy: false, reason: 'banned', slotHealthy: false };
                continue;
            }
            if (player.suspended) {
                results[hex] = { healthy: true, reason: 'suspended', slotHealthy: true };
                continue;
            }
            const row = sessions.get(hex);
            if (!row) {
                results[hex] = { healthy: false, reason: 'no-session', slotHealthy: false };
                continue;
            }
            const ageMs = Number(row.age_ms);
            const healthy = ageMs >= 0 && ageMs <= config.sessionStaleMs;
            const slot = snapshotSlot(hex);
            const slotHealthy =
                slot.known &&
                slot.lastReportMs !== 0 &&
                slot.ageMs >= 0 &&
                slot.ageMs <= SLOT_STALE_MS;
            results[hex] = {
                healthy,
                ageMs,
                reason: healthy ? 'ok' : 'stale',
                slotHealthy,
                slotAgeMs: slot.ageMs,
            };
        }
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ results }));
    } catch (e) {
        httpLog.error({ err: (e as Error).message }, 'bulk session status query failed');
        res.writeHead(500, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ error: 'server error' }));
    }
}

async function readBody(req: IncomingMessage, cap: number): Promise<Buffer> {
    return await new Promise((resolve, reject) => {
        const chunks: Buffer[] = [];
        let total = 0;
        req.on('data', (c: Buffer) => {
            total += c.length;
            if (total > cap) {
                reject(new Error('body too large'));
                req.destroy();
                return;
            }
            chunks.push(c);
        });
        req.on('end', () => resolve(Buffer.concat(chunks)));
        req.on('error', (e) => reject(e));
    });
}

const SLOT_XOR_KEY = 0xb2a889c5 >>> 0;

const SLOT_MAX_SKEW_S = 60;

async function handleSlotReport(req: IncomingMessage, res: ServerResponse): Promise<void> {
    let payload: {
        steam_hex?: unknown;
        value?: unknown;
    };
    try {
        const body = await readBody(req, 4096);
        payload = JSON.parse(body.toString('utf8'));
    } catch {
        res.writeHead(400, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ error: 'bad body' }));
        return;
    }
    const rawHex = typeof payload.steam_hex === 'string' ? payload.steam_hex : '';
    const steamHex = normalizeSteamHex(rawHex);
    if (!steamHex) {
        res.writeHead(400, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ error: 'bad steam_hex' }));
        return;
    }
    const rawValue = typeof payload.value === 'number' ? Math.floor(payload.value) : NaN;
    if (!Number.isFinite(rawValue) || rawValue < 0 || rawValue > 0xffffffff) {
        res.writeHead(400, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ error: 'bad value' }));
        return;
    }
    const encrypted = rawValue >>> 0;
    const decrypted = (encrypted ^ SLOT_XOR_KEY) >>> 0;
    const nowSec = Math.floor(Date.now() / 1000) >>> 0;
    const diff = Math.abs(((nowSec | 0) - (decrypted | 0)) | 0);
    if (diff > SLOT_MAX_SKEW_S) {
        httpLog.warn(
            { steamHex, encrypted, decrypted, nowSec, diff },
            'slot report timestamp out of window',
        );
        res.writeHead(400, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ error: 'stale value', diff }));
        return;
    }
    const r = reportSlot(steamHex);
    if (!r.known) {
        httpLog.warn({ steamHex }, 'slot report for unknown steam');
    } else {
        httpLog.debug({ steamHex, decrypted, diff }, 'slot beat');
    }
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ steamHex, known: r.known }));
}

function resolveAccountStatus(
    player: {
        banned: number;
        suspended: number;
    } | null,
): 'active' | 'banned' | 'suspended' | 'dashboard' {
    if (!player) return 'dashboard';
    if (player.banned) return 'banned';
    if (player.suspended) return 'suspended';
    return 'active';
}

async function handleInsecureBoot(req: IncomingMessage, res: ServerResponse): Promise<void> {
    let payload: {
        steam_hex?: unknown;
        reason?: unknown;
        screenshot_b64?: unknown;
    };
    try {
        const body = await readBody(req, 8 * 1024 * 1024);
        payload = JSON.parse(body.toString('utf8'));
    } catch {
        res.writeHead(400, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ error: 'bad body' }));
        return;
    }
    const rawHex = typeof payload.steam_hex === 'string' ? payload.steam_hex : '';
    const steamHex = normalizeSteamHex(rawHex);
    if (!steamHex) {
        res.writeHead(400, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ error: 'bad steam_hex' }));
        return;
    }
    const reason = typeof payload.reason === 'string' ? payload.reason.slice(0, 128) : '';
    if (!reason) {
        res.writeHead(400, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ error: 'missing reason' }));
        return;
    }
    let screenshotPath: string | null = null;
    if (typeof payload.screenshot_b64 === 'string' && payload.screenshot_b64.length > 0) {
        try {
            const png = Buffer.from(payload.screenshot_b64, 'base64');
            if (
                png.length >= 4 &&
                png[0] === 0x89 &&
                png[1] === 0x50 &&
                png[2] === 0x4e &&
                png[3] === 0x47
            ) {
                const dir = path.join('screenshots', steamHex);
                await fs.mkdir(dir, { recursive: true });
                const ts = new Date().toISOString().replace(/[:.]/g, '-');
                const fname = `${ts}_insecure-boot_${reason.replace(/[^\w.-]/g, '_')}.png`;
                screenshotPath = path.join(dir, fname);
                await fs.writeFile(screenshotPath, png);
            }
        } catch (e) {
            httpLog.warn({ err: (e as Error).message }, 'insecure-boot screenshot save failed');
            screenshotPath = null;
        }
    }
    const clientIp = req.socket.remoteAddress ?? '';
    const pretty = prettyDetectionType('insecure-boot');
    const attribution = detectionAttribution('insecure-boot');
    const fields = [
        { name: 'SteamID64', value: '`' + steamHex + '`', inline: true },
        { name: 'Reason', value: '`' + reason + '`', inline: true },
        { name: 'Peer', value: '`' + clientIp + '`', inline: true },
    ];
    fire(
        'detections-report',
        {
            title: `${pretty} Detected`,
            ...(attribution ? { description: attribution } : {}),
            fields,
        },
        screenshotPath,
    );
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ ok: true }));
}

async function handleSteamProfile(url: URL, res: ServerResponse): Promise<void> {
    const raw = url.searchParams.get('steam_hex') ?? '';
    const steamHex = normalizeSteamHex(raw);
    if (!steamHex) {
        res.writeHead(400, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ error: 'bad steam_hex' }));
        return;
    }
    try {
        const [p, player] = await Promise.all([
            fetchSteamProfile(steamHex),
            findPlayerBySteamHex(steamHex).catch((e) => {
                httpLog.error({ err: (e as Error).message }, 'player lookup failed');
                return null;
            }),
        ]);
        const status = resolveAccountStatus(player);
        const agentMode = player?.agent_mode === 'usermode' ? 'usermode' : 'kernel';
        const allow_no_secure_boot = !!player?.allow_no_secure_boot;
        const allow_no_hvci = !!player?.allow_no_hvci;
        if (!p) {
            res.writeHead(200, { 'content-type': 'application/json' });
            res.end(
                JSON.stringify({
                    steamHex,
                    personaName: '',
                    avatarFull: '',
                    avatarMedium: '',
                    profileUrl: '',
                    status,
                    agent_mode: agentMode,
                    allow_no_secure_boot,
                    allow_no_hvci,
                }),
            );
            return;
        }
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(
            JSON.stringify({
                ...p,
                status,
                agent_mode: agentMode,
                allow_no_secure_boot,
                allow_no_hvci,
            }),
        );
    } catch (e) {
        httpLog.error({ err: (e as Error).message }, 'steam profile fetch failed');
        res.writeHead(502, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ error: 'upstream' }));
    }
}

async function handleAgentProcList(url: URL, res: ServerResponse): Promise<void> {
    const steamHex = normalizeSteamHex(url.searchParams.get('steam_hex') ?? '');
    if (!steamHex) {
        res.writeHead(400, { 'content-type': 'application/json' }).end(
            JSON.stringify({ ok: false, error: 'bad steam_hex' }),
        );
        return;
    }
    const agent = getLiveAgent(steamHex);
    if (!agent) {
        res.writeHead(404, { 'content-type': 'application/json' }).end(
            JSON.stringify({ ok: false, error: 'Player is not currently online.' }),
        );
        return;
    }
    try {
        const json = await agent.requestProcList(15000);
        res.writeHead(200, { 'content-type': 'application/json' }).end(
            JSON.stringify({ ok: true, raw: json }),
        );
    } catch (e) {
        res.writeHead(504, { 'content-type': 'application/json' }).end(
            JSON.stringify({ ok: false, error: (e as Error).message }),
        );
    }
}

async function handleAgentProcModules(url: URL, res: ServerResponse): Promise<void> {
    const steamHex = normalizeSteamHex(url.searchParams.get('steam_hex') ?? '');
    if (!steamHex) {
        res.writeHead(400, { 'content-type': 'application/json' }).end(
            JSON.stringify({ ok: false, error: 'bad steam_hex' }),
        );
        return;
    }
    const pidRaw = url.searchParams.get('pid') ?? '';
    const pid = Number(pidRaw);
    if (!Number.isFinite(pid) || pid < 0 || pid > 0xffffffff) {
        res.writeHead(400, { 'content-type': 'application/json' }).end(
            JSON.stringify({ ok: false, error: 'bad pid' }),
        );
        return;
    }
    const agent = getLiveAgent(steamHex);
    if (!agent) {
        res.writeHead(404, { 'content-type': 'application/json' }).end(
            JSON.stringify({ ok: false, error: 'Player is not currently online.' }),
        );
        return;
    }
    try {
        const json = await agent.requestProcModules(pid | 0, 15000);
        res.writeHead(200, { 'content-type': 'application/json' }).end(
            JSON.stringify({ ok: true, raw: json }),
        );
    } catch (e) {
        res.writeHead(504, { 'content-type': 'application/json' }).end(
            JSON.stringify({ ok: false, error: (e as Error).message }),
        );
    }
}

async function handleAgentProcWindows(url: URL, res: ServerResponse): Promise<void> {
    const steamHex = normalizeSteamHex(url.searchParams.get('steam_hex') ?? '');
    if (!steamHex) {
        res.writeHead(400, { 'content-type': 'application/json' }).end(
            JSON.stringify({ ok: false, error: 'bad steam_hex' }),
        );
        return;
    }
    const pidRaw = url.searchParams.get('pid') ?? '';
    const pid = Number(pidRaw);
    if (!Number.isFinite(pid) || pid < 0 || pid > 0xffffffff) {
        res.writeHead(400, { 'content-type': 'application/json' }).end(
            JSON.stringify({ ok: false, error: 'bad pid' }),
        );
        return;
    }
    const agent = getLiveAgent(steamHex);
    if (!agent) {
        res.writeHead(404, { 'content-type': 'application/json' }).end(
            JSON.stringify({ ok: false, error: 'Player is not currently online.' }),
        );
        return;
    }
    try {
        const json = await agent.requestProcWindows(pid | 0, 15000);
        res.writeHead(200, { 'content-type': 'application/json' }).end(
            JSON.stringify({ ok: true, raw: json }),
        );
    } catch (e) {
        res.writeHead(504, { 'content-type': 'application/json' }).end(
            JSON.stringify({ ok: false, error: (e as Error).message }),
        );
    }
}

async function handleAgentProcStrings(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const body = await readJsonBody(req, 8 * 1024);
    const b = (body ?? {}) as {
        steam_hex?: unknown;
        pid?: unknown;
        min_len?: unknown;
        detect_ansi?: unknown;
        detect_unicode?: unknown;
        extended?: unknown;
        private?: unknown;
        image?: unknown;
        mapped?: unknown;
        needle?: unknown;
        needle_ci?: unknown;
    };
    const steamHex = typeof b.steam_hex === 'string' ? normalizeSteamHex(b.steam_hex) : null;
    if (!steamHex) {
        res.writeHead(400, { 'content-type': 'application/json' }).end(
            JSON.stringify({ ok: false, error: 'bad steam_hex' }),
        );
        return;
    }
    const pidRaw = typeof b.pid === 'number' ? b.pid : Number(b.pid);
    if (!Number.isFinite(pidRaw) || pidRaw < 1 || pidRaw > 0xffffffff) {
        res.writeHead(400, { 'content-type': 'application/json' }).end(
            JSON.stringify({ ok: false, error: 'bad pid' }),
        );
        return;
    }
    const agent = getLiveAgent(steamHex);
    if (!agent) {
        res.writeHead(404, { 'content-type': 'application/json' }).end(
            JSON.stringify({ ok: false, error: 'Player is not currently online.' }),
        );
        return;
    }
    try {
        const json = await agent.requestProcStrings(
            {
                pid: pidRaw | 0,
                minLen: Number.isFinite(Number(b.min_len))
                    ? Math.max(2, Math.min(128, Number(b.min_len) | 0))
                    : 4,
                detectAnsi: b.detect_ansi !== false,
                detectUnicode: !!b.detect_unicode,
                extended: !!b.extended,
                priv: b.private !== false,
                image: !!b.image,
                mapped: !!b.mapped,
                needle: typeof b.needle === 'string' ? b.needle : '',
                needleCI: b.needle_ci !== false,
            },
            300000,
        );
        res.writeHead(200, { 'content-type': 'application/json' }).end(
            JSON.stringify({ ok: true, raw: json }),
        );
    } catch (e) {
        res.writeHead(504, { 'content-type': 'application/json' }).end(
            JSON.stringify({ ok: false, error: (e as Error).message }),
        );
    }
}

async function handleAgentScanStart(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const body = await readJsonBody(req, 4 * 1024);
    const b = (body ?? {}) as {
        steam_hex?: unknown;
        scan_type?: unknown;
        include_signed?: unknown;
    };
    const steamHex = typeof b.steam_hex === 'string' ? normalizeSteamHex(b.steam_hex) : null;
    if (!steamHex) {
        res.writeHead(400, { 'content-type': 'application/json' }).end(
            JSON.stringify({ ok: false, error: 'bad steam_hex' }),
        );
        return;
    }
    const scanTypeRaw = typeof b.scan_type === 'number' ? b.scan_type : Number(b.scan_type);
    const scanType = Number.isFinite(scanTypeRaw) && scanTypeRaw > 0 ? scanTypeRaw | 0 : 1;
    const includeSigned = !!b.include_signed;
    const flags = includeSigned ? 0x00000001 : 0;
    const agent = getLiveAgent(steamHex);
    if (!agent) {
        res.writeHead(404, { 'content-type': 'application/json' }).end(
            JSON.stringify({ ok: false, error: 'Player is not currently online.' }),
        );
        return;
    }
    try {
        const scanId = agent.startScan(scanType, flags);
        res.writeHead(200, { 'content-type': 'application/json' }).end(
            JSON.stringify({ ok: true, scanId }),
        );
    } catch (e) {
        res.writeHead(409, { 'content-type': 'application/json' }).end(
            JSON.stringify({ ok: false, error: (e as Error).message }),
        );
    }
}

async function handleAgentScanCancel(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const body = await readJsonBody(req, 1024);
    const b = (body ?? {}) as {
        steam_hex?: unknown;
        scan_id?: unknown;
    };
    const steamHex = typeof b.steam_hex === 'string' ? normalizeSteamHex(b.steam_hex) : null;
    if (!steamHex) {
        res.writeHead(400, { 'content-type': 'application/json' }).end(
            JSON.stringify({ ok: false, error: 'bad steam_hex' }),
        );
        return;
    }
    const scanIdRaw = typeof b.scan_id === 'number' ? b.scan_id : Number(b.scan_id);
    if (!Number.isFinite(scanIdRaw) || scanIdRaw <= 0 || scanIdRaw > 0xffffffff) {
        res.writeHead(400, { 'content-type': 'application/json' }).end(
            JSON.stringify({ ok: false, error: 'bad scan_id' }),
        );
        return;
    }
    const agent = getLiveAgent(steamHex);
    if (!agent) {
        res.writeHead(404, { 'content-type': 'application/json' }).end(
            JSON.stringify({ ok: false, error: 'Player is not currently online.' }),
        );
        return;
    }
    const ok = agent.cancelScan(scanIdRaw | 0);
    res.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify({ ok }));
}

async function handleAgentScanEvents(
    url: URL,
    req: IncomingMessage,
    res: ServerResponse,
): Promise<void> {
    const steamHex = normalizeSteamHex(url.searchParams.get('steam_hex') ?? '');
    if (!steamHex) {
        res.writeHead(400).end('bad steam_hex');
        return;
    }
    const scanIdRaw = url.searchParams.get('scan_id') ?? '';
    const scanId = Number(scanIdRaw);
    if (!Number.isFinite(scanId) || scanId <= 0 || scanId > 0xffffffff) {
        res.writeHead(400).end('bad scan_id');
        return;
    }
    res.writeHead(200, {
        'content-type': 'text/event-stream',
        'cache-control': 'no-store, no-cache, must-revalidate, max-age=0',
        connection: 'keep-alive',
        'x-accel-buffering': 'no',
    });
    const send = (data: unknown): void => {
        try {
            res.write(`data: ${JSON.stringify(data)}\n\n`);
        } catch {}
    };
    let closed = false;
    const filter = (target: { steamHex: string; scanId: number }): boolean =>
        !closed && target.steamHex === steamHex && target.scanId === scanId;
    const onProgress = (ev: ScanProgressEvent): void => {
        if (!filter(ev)) return;
        send({
            type: 'progress',
            phase: ev.phase,
            visited: ev.visited,
            queued: ev.queued,
            scanned: ev.scanned,
        });
    };
    const onHit = (ev: ScanHitEvent): void => {
        if (!filter(ev)) return;
        send({ type: 'hit', hit: ev.hit });
    };
    const onDone = (ev: ScanDoneEvent): void => {
        if (!filter(ev)) return;
        send({ type: 'done', summary: ev.summary });
    };
    const onErr = (ev: ScanErrEvent): void => {
        if (!filter(ev)) return;
        send({ type: 'error', error: ev.error });
    };
    scanBus.on('progress', onProgress);
    scanBus.on('hit', onHit);
    scanBus.on('done', onDone);
    scanBus.on('err', onErr);
    const ka = setInterval(() => {
        try {
            res.write(': ka\n\n');
        } catch {}
    }, 15000);
    const cleanup = (): void => {
        if (closed) return;
        closed = true;
        clearInterval(ka);
        scanBus.off('progress', onProgress);
        scanBus.off('hit', onHit);
        scanBus.off('done', onDone);
        scanBus.off('err', onErr);
        try {
            res.end();
        } catch {}
    };
    req.on('close', cleanup);
    req.on('error', cleanup);
    res.on('close', cleanup);
    res.on('error', cleanup);
}

async function route(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const url = new URL(req.url ?? '/', 'http://internal');
    if (req.method === 'GET' && url.pathname === '/v1/steam/profile') {
        await handleSteamProfile(url, res);
        return;
    }
    if (req.method === 'POST' && url.pathname === '/v1/detection/insecure-boot') {
        await handleInsecureBoot(req, res);
        return;
    }
    if (req.method === 'POST' && url.pathname === '/v1/agent/screenshot') {
        if (!isLoopback(req)) {
            res.writeHead(403).end();
            return;
        }
        await handleAgentScreenshot(req, res);
        return;
    }
    if (req.method === 'POST' && url.pathname === '/v1/agent/system-info') {
        if (!isLoopback(req)) {
            res.writeHead(403).end();
            return;
        }
        await handleAgentSystemInfo(req, res);
        return;
    }
    if (req.method === 'POST' && url.pathname === '/v1/agent/pci-tree') {
        if (!isLoopback(req)) {
            res.writeHead(403).end();
            return;
        }
        await handleAgentPciTree(req, res);
        return;
    }
    if (req.method === 'POST' && url.pathname === '/v1/agent/minidumps') {
        if (!isLoopback(req)) {
            res.writeHead(403).end();
            return;
        }
        await handleAgentMinidumps(req, res);
        return;
    }
    if (req.method === 'POST' && url.pathname === '/v1/agent/dump-file') {
        if (!isLoopback(req)) {
            res.writeHead(403).end();
            return;
        }
        await handleAgentDumpFile(req, res);
        return;
    }
    if (req.method === 'GET' && url.pathname === '/v1/agent/proc/list') {
        if (!isLoopback(req)) {
            res.writeHead(403).end();
            return;
        }
        await handleAgentProcList(url, res);
        return;
    }
    if (req.method === 'GET' && url.pathname === '/v1/agent/proc/modules') {
        if (!isLoopback(req)) {
            res.writeHead(403).end();
            return;
        }
        await handleAgentProcModules(url, res);
        return;
    }
    if (req.method === 'POST' && url.pathname === '/v1/agent/proc/strings') {
        if (!isLoopback(req)) {
            res.writeHead(403).end();
            return;
        }
        await handleAgentProcStrings(req, res);
        return;
    }
    if (req.method === 'GET' && url.pathname === '/v1/agent/proc/windows') {
        if (!isLoopback(req)) {
            res.writeHead(403).end();
            return;
        }
        await handleAgentProcWindows(url, res);
        return;
    }
    if (req.method === 'POST' && url.pathname === '/v1/agent/scan/start') {
        if (!isLoopback(req)) {
            res.writeHead(403).end();
            return;
        }
        await handleAgentScanStart(req, res);
        return;
    }
    if (req.method === 'POST' && url.pathname === '/v1/agent/scan/cancel') {
        if (!isLoopback(req)) {
            res.writeHead(403).end();
            return;
        }
        await handleAgentScanCancel(req, res);
        return;
    }
    if (req.method === 'GET' && url.pathname === '/v1/agent/scan/events') {
        if (!isLoopback(req)) {
            res.writeHead(403).end();
            return;
        }
        await handleAgentScanEvents(url, req, res);
        return;
    }
    if (req.method === 'GET' && url.pathname.startsWith('/v1/screenshots/')) {
        if (!isLoopback(req)) {
            res.writeHead(403).end();
            return;
        }
        await handleServeScreenshot(url, res);
        return;
    }
    if (req.method === 'POST' && url.pathname === '/v1/admin/kick') {
        if (!isLoopback(req)) {
            res.writeHead(403).end();
            return;
        }
        await handleAdminKick(req, res);
        return;
    }
    if (req.method === 'POST' && url.pathname === '/v1/admin/ban') {
        if (!isLoopback(req)) {
            res.writeHead(403).end();
            return;
        }
        await handleAdminBan(req, res);
        return;
    }
    if (req.method === 'POST' && url.pathname === '/v1/admin/unban') {
        if (!isLoopback(req)) {
            res.writeHead(403).end();
            return;
        }
        await handleAdminUnban(req, res);
        return;
    }
    if (req.method === 'POST' && url.pathname === '/v1/admin/suspend') {
        if (!isLoopback(req)) {
            res.writeHead(403).end();
            return;
        }
        await handleAdminSuspend(req, res);
        return;
    }
    if (req.method === 'POST' && url.pathname === '/v1/admin/unsuspend') {
        if (!isLoopback(req)) {
            res.writeHead(403).end();
            return;
        }
        await handleAdminUnsuspend(req, res);
        return;
    }
    if (req.method === 'POST' && url.pathname === '/v1/admin/ban/update') {
        if (!isLoopback(req)) {
            res.writeHead(403).end();
            return;
        }
        await handleAdminBanUpdate(req, res);
        return;
    }
    if (req.method === 'POST' && url.pathname === '/v1/admin/suspend/update') {
        if (!isLoopback(req)) {
            res.writeHead(403).end();
            return;
        }
        await handleAdminSuspendUpdate(req, res);
        return;
    }
    if (!authorized(req)) {
        res.writeHead(401).end();
        return;
    }
    if (req.method === 'GET' && url.pathname === '/v1/session/status') {
        await handleSessionStatus(url, res);
        return;
    }
    if (req.method === 'POST' && url.pathname === '/v1/session/status/bulk') {
        await handleSessionStatusBulk(req, res);
        return;
    }
    if (req.method === 'POST' && url.pathname === '/v1/slot/report') {
        await handleSlotReport(req, res);
        return;
    }
    res.writeHead(404).end();
}

function isLoopback(req: IncomingMessage): boolean {
    const remote = req.socket.remoteAddress || '';
    if (remote === '127.0.0.1' || remote === '::1' || remote === '::ffff:127.0.0.1') {
        return true;
    }
    return false;
}

async function readJsonBody(req: IncomingMessage, maxBytes = 8 * 1024): Promise<unknown | null> {
    return new Promise((resolve) => {
        const chunks: Buffer[] = [];
        let total = 0;
        req.on('data', (c: Buffer) => {
            total += c.length;
            if (total > maxBytes) {
                req.destroy();
                resolve(null);
                return;
            }
            chunks.push(c);
        });
        req.on('end', () => {
            try {
                resolve(JSON.parse(Buffer.concat(chunks).toString('utf8')));
            } catch {
                resolve(null);
            }
        });
        req.on('error', () => resolve(null));
    });
}

async function handleAgentScreenshot(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const body = await readJsonBody(req);
    const steamHexRaw = (
        body as {
            steam_hex?: unknown;
        }
    )?.steam_hex;
    if (typeof steamHexRaw !== 'string') {
        res.writeHead(400, { 'content-type': 'application/json' }).end(
            JSON.stringify({ ok: false, error: 'steam_hex required' }),
        );
        return;
    }
    const steamHex = normalizeSteamHex(steamHexRaw);
    if (!steamHex) {
        res.writeHead(400, { 'content-type': 'application/json' }).end(
            JSON.stringify({ ok: false, error: 'bad steam_hex' }),
        );
        return;
    }
    const methodRaw = (
        body as {
            method?: unknown;
        }
    )?.method;
    let method = 0;
    if (typeof methodRaw === 'string') {
        const m = methodRaw.toLowerCase();
        if (m === 'nvidia') method = 1;
        else if (m === 'gdi') method = 2;
    } else if (typeof methodRaw === 'number' && (methodRaw === 1 || methodRaw === 2)) {
        method = methodRaw;
    }
    const agent = getLiveAgent(steamHex);
    if (!agent) {
        res.writeHead(404, { 'content-type': 'application/json' }).end(
            JSON.stringify({ ok: false, error: 'Player is not currently online.' }),
        );
        return;
    }
    let png: Buffer | null = null;
    let usedMethod = method;
    let fallback: 'gdi' | null = null;
    let firstErr = '';
    try {
        png = await agent.requestScreenshot(method, 20000);
    } catch (e) {
        firstErr = (e as Error).message;
        if (method === 1) {
            httpLog.warn({ steamHex, err: firstErr }, 'nvidia capture failed, falling back to gdi');
            try {
                png = await agent.requestScreenshot(2, 20000);
                usedMethod = 2;
                fallback = 'gdi';
            } catch (e2) {
                httpLog.warn(
                    { err: (e2 as Error).message, steamHex },
                    'on-demand screenshot failed',
                );
                res.writeHead(504, { 'content-type': 'application/json' }).end(
                    JSON.stringify({
                        ok: false,
                        error: `NVIDIA failed (${firstErr}); GDI fallback failed (${(e2 as Error).message})`,
                    }),
                );
                return;
            }
        } else {
            httpLog.warn({ err: firstErr, steamHex }, 'on-demand screenshot failed');
            res.writeHead(504, { 'content-type': 'application/json' }).end(
                JSON.stringify({ ok: false, error: firstErr }),
            );
            return;
        }
    }
    try {
        const dir = path.join('screenshots', steamHex);
        await fs.mkdir(dir, { recursive: true });
        const ts = new Date().toISOString().replace(/[:.]/g, '-');
        const methodTag = usedMethod === 1 ? 'nvidia' : usedMethod === 2 ? 'gdi' : 'auto';
        const fname = `${ts}_on-demand_${methodTag}.png`;
        const full = path.join(dir, fname);
        await fs.writeFile(full, png!);
        httpLog.info(
            { steamHex, bytes: png!.length, path: full, fallback },
            'on-demand screenshot saved',
        );
        res.writeHead(200, { 'content-type': 'application/json' }).end(
            JSON.stringify({
                ok: true,
                path: `${steamHex}/${fname}`,
                bytes: png!.length,
                method: methodTag,
                ...(fallback ? { fallback, fallback_reason: firstErr } : {}),
            }),
        );
    } catch (e) {
        httpLog.warn({ err: (e as Error).message, steamHex }, 'on-demand screenshot save failed');
        res.writeHead(500, { 'content-type': 'application/json' }).end(
            JSON.stringify({ ok: false, error: (e as Error).message }),
        );
    }
}

async function handleAgentSystemInfo(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const body = await readJsonBody(req);
    const steamHexRaw = (
        body as {
            steam_hex?: unknown;
        }
    )?.steam_hex;
    if (typeof steamHexRaw !== 'string') {
        res.writeHead(400, { 'content-type': 'application/json' }).end(
            JSON.stringify({ ok: false, error: 'steam_hex required' }),
        );
        return;
    }
    const steamHex = normalizeSteamHex(steamHexRaw);
    if (!steamHex) {
        res.writeHead(400, { 'content-type': 'application/json' }).end(
            JSON.stringify({ ok: false, error: 'bad steam_hex' }),
        );
        return;
    }
    const agent = getLiveAgent(steamHex);
    if (!agent) {
        res.writeHead(404, { 'content-type': 'application/json' }).end(
            JSON.stringify({ ok: false, error: 'Player is not currently online.' }),
        );
        return;
    }
    try {
        const json = await agent.requestSystemInfo(20000);
        let parsed: unknown;
        let parseError: string | null = null;
        try {
            parsed = JSON.parse(json);
        } catch (e) {
            parsed = null;
            parseError = (e as Error).message;
        }
        if (parsed === null || typeof parsed !== 'object') {
            httpLog.warn(
                {
                    steamHex,
                    bytes: json.length,
                    parseError,
                    preview: json.slice(0, 200),
                },
                'sysinfo malformed json',
            );
            res.writeHead(502, { 'content-type': 'application/json' }).end(
                JSON.stringify({
                    ok: false,
                    error: `client returned malformed JSON (${parseError ?? 'not an object'})`,
                }),
            );
            return;
        }
        httpLog.info({ steamHex, bytes: json.length }, 'sysinfo delivered');
        res.writeHead(200, { 'content-type': 'application/json' }).end(
            JSON.stringify({
                ok: true,
                info: parsed,
            }),
        );
    } catch (e) {
        httpLog.warn({ err: (e as Error).message, steamHex }, 'sysinfo failed');
        res.writeHead(504, { 'content-type': 'application/json' }).end(
            JSON.stringify({ ok: false, error: (e as Error).message }),
        );
    }
}

async function handleAgentPciTree(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const body = await readJsonBody(req);
    const steamHexRaw = (
        body as {
            steam_hex?: unknown;
        }
    )?.steam_hex;
    if (typeof steamHexRaw !== 'string') {
        res.writeHead(400, { 'content-type': 'application/json' }).end(
            JSON.stringify({ ok: false, error: 'steam_hex required' }),
        );
        return;
    }
    const steamHex = normalizeSteamHex(steamHexRaw);
    if (!steamHex) {
        res.writeHead(400, { 'content-type': 'application/json' }).end(
            JSON.stringify({ ok: false, error: 'bad steam_hex' }),
        );
        return;
    }
    const agent = getLiveAgent(steamHex);
    if (!agent) {
        res.writeHead(404, { 'content-type': 'application/json' }).end(
            JSON.stringify({ ok: false, error: 'Player is not currently online.' }),
        );
        return;
    }
    try {
        const json = await agent.requestPciTree(25000);
        let parsed: unknown;
        let parseError: string | null = null;
        try {
            parsed = JSON.parse(json);
        } catch (e) {
            parsed = null;
            parseError = (e as Error).message;
        }
        if (parsed === null || typeof parsed !== 'object') {
            httpLog.warn(
                {
                    steamHex,
                    bytes: json.length,
                    parseError,
                    preview: json.slice(0, 200),
                },
                'pcitree malformed json',
            );
            res.writeHead(502, { 'content-type': 'application/json' }).end(
                JSON.stringify({
                    ok: false,
                    error: `client returned malformed JSON (${parseError ?? 'not an object'})`,
                }),
            );
            return;
        }
        httpLog.info({ steamHex, bytes: json.length }, 'pcitree delivered');
        res.writeHead(200, { 'content-type': 'application/json' }).end(
            JSON.stringify({
                ok: true,
                tree: parsed,
            }),
        );
    } catch (e) {
        httpLog.warn({ err: (e as Error).message, steamHex }, 'pcitree failed');
        res.writeHead(504, { 'content-type': 'application/json' }).end(
            JSON.stringify({ ok: false, error: (e as Error).message }),
        );
    }
}

async function handleAgentMinidumps(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const body = await readJsonBody(req);
    const steamHexRaw = (
        body as {
            steam_hex?: unknown;
        }
    )?.steam_hex;
    if (typeof steamHexRaw !== 'string') {
        res.writeHead(400, { 'content-type': 'application/json' }).end(
            JSON.stringify({ ok: false, error: 'steam_hex required' }),
        );
        return;
    }
    const steamHex = normalizeSteamHex(steamHexRaw);
    if (!steamHex) {
        res.writeHead(400, { 'content-type': 'application/json' }).end(
            JSON.stringify({ ok: false, error: 'bad steam_hex' }),
        );
        return;
    }
    const agent = getLiveAgent(steamHex);
    if (!agent) {
        res.writeHead(404, { 'content-type': 'application/json' }).end(
            JSON.stringify({ ok: false, error: 'Player is not currently online.' }),
        );
        return;
    }
    try {
        const json = await agent.requestMinidumps(35000);
        let parsed: unknown;
        let parseError: string | null = null;
        try {
            parsed = JSON.parse(json);
        } catch (e) {
            parsed = null;
            parseError = (e as Error).message;
        }
        if (parsed === null || typeof parsed !== 'object') {
            httpLog.warn(
                { steamHex, bytes: json.length, parseError, preview: json.slice(0, 200) },
                'minidumps malformed json',
            );
            res.writeHead(502, { 'content-type': 'application/json' }).end(
                JSON.stringify({
                    ok: false,
                    error: `client returned malformed JSON (${parseError ?? 'not an object'})`,
                }),
            );
            return;
        }
        httpLog.info({ steamHex, bytes: json.length }, 'minidumps delivered');
        res.writeHead(200, { 'content-type': 'application/json' }).end(
            JSON.stringify({ ok: true, dumps: parsed }),
        );
    } catch (e) {
        httpLog.warn({ err: (e as Error).message, steamHex }, 'minidumps failed');
        res.writeHead(504, { 'content-type': 'application/json' }).end(
            JSON.stringify({ ok: false, error: (e as Error).message }),
        );
    }
}

async function handleAgentDumpFile(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const body = await readJsonBody(req);
    const steamHexRaw = (
        body as {
            steam_hex?: unknown;
        }
    )?.steam_hex;
    const nameRaw = (
        body as {
            name?: unknown;
        }
    )?.name;
    if (typeof steamHexRaw !== 'string' || typeof nameRaw !== 'string') {
        res.writeHead(400, { 'content-type': 'application/json' }).end(
            JSON.stringify({ ok: false, error: 'steam_hex and name required' }),
        );
        return;
    }
    const steamHex = normalizeSteamHex(steamHexRaw);
    if (!steamHex) {
        res.writeHead(400, { 'content-type': 'application/json' }).end(
            JSON.stringify({ ok: false, error: 'bad steam_hex' }),
        );
        return;
    }
    const name = nameRaw.trim();
    if (!/^[A-Za-z0-9._-]{5,96}$/.test(name) || !/\.dmp$/i.test(name) || name.includes('..')) {
        res.writeHead(400, { 'content-type': 'application/json' }).end(
            JSON.stringify({ ok: false, error: 'bad dump name' }),
        );
        return;
    }
    const agent = getLiveAgent(steamHex);
    if (!agent) {
        res.writeHead(404, { 'content-type': 'application/json' }).end(
            JSON.stringify({ ok: false, error: 'Player is not currently online.' }),
        );
        return;
    }
    try {
        const buf = await agent.requestDumpFile(name, 60000);
        httpLog.info({ steamHex, name, bytes: buf.length }, 'dumpfile delivered');
        res.writeHead(200, {
            'content-type': 'application/octet-stream',
            'content-length': String(buf.length),
            'content-disposition': `attachment; filename="${name}"`,
        }).end(buf);
    } catch (e) {
        httpLog.warn({ err: (e as Error).message, steamHex, name }, 'dumpfile failed');
        res.writeHead(504, { 'content-type': 'application/json' }).end(
            JSON.stringify({ ok: false, error: (e as Error).message }),
        );
    }
}

async function handleServeScreenshot(url: URL, res: ServerResponse): Promise<void> {
    const relRaw = url.pathname.slice('/v1/screenshots/'.length);
    const rel = decodeURIComponent(relRaw);
    if (!rel || rel.includes('..') || rel.includes('\\') || !rel.endsWith('.png')) {
        res.writeHead(400).end();
        return;
    }
    const abs = path.resolve('screenshots', rel);
    const root = path.resolve('screenshots');
    if (!abs.startsWith(root + path.sep) && abs !== root) {
        res.writeHead(400).end();
        return;
    }
    try {
        const buf = await fs.readFile(abs);
        res.writeHead(200, {
            'content-type': 'image/png',
            'content-length': String(buf.length),
            'cache-control': 'private, max-age=60',
        }).end(buf);
    } catch {
        res.writeHead(404).end();
    }
}

async function handleAdminKick(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const body = await readJsonBody(req);
    const raw = (
        body as {
            steam_hex?: unknown;
        }
    )?.steam_hex;
    const reason = (
        body as {
            reason?: unknown;
        }
    )?.reason;
    if (typeof raw !== 'string') {
        res.writeHead(400, { 'content-type': 'application/json' }).end(
            JSON.stringify({ ok: false, error: 'steam_hex required' }),
        );
        return;
    }
    const steamHex = normalizeSteamHex(raw);
    if (!steamHex) {
        res.writeHead(400, { 'content-type': 'application/json' }).end(
            JSON.stringify({ ok: false, error: 'bad steam_hex' }),
        );
        return;
    }
    const reasonStr = (typeof reason === 'string' ? reason : '').slice(0, 200) || 'kicked-by-admin';
    const agent = getLiveAgent(steamHex);
    if (!agent) {
        res.writeHead(404, { 'content-type': 'application/json' }).end(
            JSON.stringify({ ok: false, error: 'Player is not currently online.' }),
        );
        return;
    }
    try {
        agent.kick(reasonStr);
        httpLog.info({ steamHex, reason: reasonStr }, 'admin kick');
        res.writeHead(200, { 'content-type': 'application/json' }).end(
            JSON.stringify({ ok: true }),
        );
    } catch (e) {
        httpLog.warn({ err: (e as Error).message, steamHex }, 'admin kick failed');
        res.writeHead(500, { 'content-type': 'application/json' }).end(
            JSON.stringify({ ok: false, error: (e as Error).message }),
        );
    }
}

async function handleAdminBan(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const body = await readJsonBody(req);
    const raw = (
        body as {
            steam_hex?: unknown;
        }
    )?.steam_hex;
    const reason = (
        body as {
            reason?: unknown;
        }
    )?.reason;
    const bannedBy = (
        body as {
            banned_by?: unknown;
        }
    )?.banned_by;
    const categoryRaw = (
        body as {
            category?: unknown;
        }
    )?.category;
    const reasonPublicRaw = (
        body as {
            reason_public?: unknown;
        }
    )?.reason_public;
    if (typeof raw !== 'string') {
        res.writeHead(400, { 'content-type': 'application/json' }).end(
            JSON.stringify({ ok: false, error: 'steam_hex required' }),
        );
        return;
    }
    const steamHex = normalizeSteamHex(raw);
    if (!steamHex) {
        res.writeHead(400, { 'content-type': 'application/json' }).end(
            JSON.stringify({ ok: false, error: 'bad steam_hex' }),
        );
        return;
    }
    const reasonStr = (typeof reason === 'string' ? reason : '').slice(0, 255) || 'banned-by-admin';
    const actorStr = (typeof bannedBy === 'string' ? bannedBy : '').slice(0, 64) || 'admin';
    let category: string | null = null;
    if (
        typeof categoryRaw === 'string' &&
        (BAN_CATEGORIES as readonly string[]).includes(categoryRaw)
    ) {
        category = categoryRaw;
    }
    const reasonPublic =
        reasonPublicRaw === true || reasonPublicRaw === 1 || reasonPublicRaw === '1';
    try {
        const affected = await banPlayerBySteamHex(
            steamHex,
            reasonStr,
            actorStr,
            category,
            reasonPublic,
        );
        if (!affected) {
            res.writeHead(404, { 'content-type': 'application/json' }).end(
                JSON.stringify({ ok: false, error: 'player not found' }),
            );
            return;
        }
        const agent = getLiveAgent(steamHex);
        if (agent) {
            const shown = reasonPublic ? reasonStr : categoryLabel(category);
            try {
                agent.kick(`Banned: ${shown}`);
            } catch {}
        }
        httpLog.info(
            { steamHex, reason: reasonStr, category, reasonPublic, bannedBy: actorStr },
            'admin ban',
        );
        res.writeHead(200, { 'content-type': 'application/json' }).end(
            JSON.stringify({ ok: true, kicked: !!agent }),
        );
    } catch (e) {
        httpLog.error({ err: (e as Error).message, steamHex }, 'admin ban failed');
        res.writeHead(500, { 'content-type': 'application/json' }).end(
            JSON.stringify({ ok: false, error: 'server error' }),
        );
    }
}

async function handleAdminBanUpdate(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const body = await readJsonBody(req);
    const raw = (
        body as {
            steam_hex?: unknown;
        }
    )?.steam_hex;
    const reason = (
        body as {
            reason?: unknown;
        }
    )?.reason;
    const categoryRaw = (
        body as {
            category?: unknown;
        }
    )?.category;
    const reasonPublicRaw = (
        body as {
            reason_public?: unknown;
        }
    )?.reason_public;
    if (typeof raw !== 'string') {
        res.writeHead(400, { 'content-type': 'application/json' }).end(
            JSON.stringify({ ok: false, error: 'steam_hex required' }),
        );
        return;
    }
    const steamHex = normalizeSteamHex(raw);
    if (!steamHex) {
        res.writeHead(400, { 'content-type': 'application/json' }).end(
            JSON.stringify({ ok: false, error: 'bad steam_hex' }),
        );
        return;
    }
    const reasonStr = (typeof reason === 'string' ? reason : '').slice(0, 255) || 'banned-by-admin';
    let category: string | null = null;
    if (
        typeof categoryRaw === 'string' &&
        (BAN_CATEGORIES as readonly string[]).includes(categoryRaw)
    ) {
        category = categoryRaw;
    }
    const reasonPublic =
        reasonPublicRaw === true || reasonPublicRaw === 1 || reasonPublicRaw === '1';
    try {
        const affected = await updateBanBySteamHex(steamHex, reasonStr, category, reasonPublic);
        if (!affected) {
            res.writeHead(404, { 'content-type': 'application/json' }).end(
                JSON.stringify({ ok: false, error: 'ban not found' }),
            );
            return;
        }
        httpLog.info({ steamHex, reason: reasonStr, category, reasonPublic }, 'admin ban update');
        res.writeHead(200, { 'content-type': 'application/json' }).end(
            JSON.stringify({ ok: true }),
        );
    } catch (e) {
        httpLog.error({ err: (e as Error).message, steamHex }, 'admin ban update failed');
        res.writeHead(500, { 'content-type': 'application/json' }).end(
            JSON.stringify({ ok: false, error: 'server error' }),
        );
    }
}

async function handleAdminSuspendUpdate(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const body = await readJsonBody(req);
    const raw = (
        body as {
            steam_hex?: unknown;
        }
    )?.steam_hex;
    const reason = (
        body as {
            reason?: unknown;
        }
    )?.reason;
    if (typeof raw !== 'string') {
        res.writeHead(400, { 'content-type': 'application/json' }).end(
            JSON.stringify({ ok: false, error: 'steam_hex required' }),
        );
        return;
    }
    const steamHex = normalizeSteamHex(raw);
    if (!steamHex) {
        res.writeHead(400, { 'content-type': 'application/json' }).end(
            JSON.stringify({ ok: false, error: 'bad steam_hex' }),
        );
        return;
    }
    const reasonStr = (typeof reason === 'string' ? reason : '').slice(0, 255);
    try {
        const affected = await updateSuspendBySteamHex(steamHex, reasonStr);
        if (!affected) {
            res.writeHead(404, { 'content-type': 'application/json' }).end(
                JSON.stringify({ ok: false, error: 'suspend not found' }),
            );
            return;
        }
        httpLog.info({ steamHex, reason: reasonStr }, 'admin suspend update');
        res.writeHead(200, { 'content-type': 'application/json' }).end(
            JSON.stringify({ ok: true }),
        );
    } catch (e) {
        httpLog.error({ err: (e as Error).message, steamHex }, 'admin suspend update failed');
        res.writeHead(500, { 'content-type': 'application/json' }).end(
            JSON.stringify({ ok: false, error: 'server error' }),
        );
    }
}

async function handleAdminSuspend(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const body = await readJsonBody(req);
    const raw = (
        body as {
            steam_hex?: unknown;
        }
    )?.steam_hex;
    const reason = (
        body as {
            reason?: unknown;
        }
    )?.reason;
    const actor = (
        body as {
            suspended_by?: unknown;
        }
    )?.suspended_by;
    if (typeof raw !== 'string') {
        res.writeHead(400, { 'content-type': 'application/json' }).end(
            JSON.stringify({ ok: false, error: 'steam_hex required' }),
        );
        return;
    }
    const steamHex = normalizeSteamHex(raw);
    if (!steamHex) {
        res.writeHead(400, { 'content-type': 'application/json' }).end(
            JSON.stringify({ ok: false, error: 'bad steam_hex' }),
        );
        return;
    }
    const reasonStr = (typeof reason === 'string' ? reason : '').slice(0, 255);
    const actorStr = (typeof actor === 'string' ? actor : '').slice(0, 64) || 'admin';
    try {
        const affected = await suspendPlayerBySteamHex(steamHex, reasonStr, actorStr);
        if (!affected) {
            res.writeHead(404, { 'content-type': 'application/json' }).end(
                JSON.stringify({ ok: false, error: 'player not found' }),
            );
            return;
        }
        httpLog.info({ steamHex, reason: reasonStr, suspendedBy: actorStr }, 'admin suspend');
        res.writeHead(200, { 'content-type': 'application/json' }).end(
            JSON.stringify({ ok: true }),
        );
    } catch (e) {
        httpLog.error({ err: (e as Error).message, steamHex }, 'admin suspend failed');
        res.writeHead(500, { 'content-type': 'application/json' }).end(
            JSON.stringify({ ok: false, error: 'server error' }),
        );
    }
}

async function handleAdminUnsuspend(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const body = await readJsonBody(req);
    const raw = (
        body as {
            steam_hex?: unknown;
        }
    )?.steam_hex;
    if (typeof raw !== 'string') {
        res.writeHead(400, { 'content-type': 'application/json' }).end(
            JSON.stringify({ ok: false, error: 'steam_hex required' }),
        );
        return;
    }
    const steamHex = normalizeSteamHex(raw);
    if (!steamHex) {
        res.writeHead(400, { 'content-type': 'application/json' }).end(
            JSON.stringify({ ok: false, error: 'bad steam_hex' }),
        );
        return;
    }
    try {
        const affected = await unsuspendPlayerBySteamHex(steamHex);
        if (!affected) {
            res.writeHead(404, { 'content-type': 'application/json' }).end(
                JSON.stringify({ ok: false, error: 'player not found' }),
            );
            return;
        }
        httpLog.info({ steamHex }, 'admin unsuspend');
        res.writeHead(200, { 'content-type': 'application/json' }).end(
            JSON.stringify({ ok: true }),
        );
    } catch (e) {
        httpLog.error({ err: (e as Error).message, steamHex }, 'admin unsuspend failed');
        res.writeHead(500, { 'content-type': 'application/json' }).end(
            JSON.stringify({ ok: false, error: 'server error' }),
        );
    }
}

async function handleAdminUnban(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const body = await readJsonBody(req);
    const raw = (
        body as {
            steam_hex?: unknown;
        }
    )?.steam_hex;
    if (typeof raw !== 'string') {
        res.writeHead(400, { 'content-type': 'application/json' }).end(
            JSON.stringify({ ok: false, error: 'steam_hex required' }),
        );
        return;
    }
    const steamHex = normalizeSteamHex(raw);
    if (!steamHex) {
        res.writeHead(400, { 'content-type': 'application/json' }).end(
            JSON.stringify({ ok: false, error: 'bad steam_hex' }),
        );
        return;
    }
    try {
        const affected = await unbanPlayerBySteamHex(steamHex);
        if (!affected) {
            res.writeHead(404, { 'content-type': 'application/json' }).end(
                JSON.stringify({ ok: false, error: 'player not found' }),
            );
            return;
        }
        httpLog.info({ steamHex }, 'admin unban');
        res.writeHead(200, { 'content-type': 'application/json' }).end(
            JSON.stringify({ ok: true }),
        );
    } catch (e) {
        httpLog.error({ err: (e as Error).message, steamHex }, 'admin unban failed');
        res.writeHead(500, { 'content-type': 'application/json' }).end(
            JSON.stringify({ ok: false, error: 'server error' }),
        );
    }
}

export function startHttpServer(): Server {
    const server = createServer((req, res) => {
        void route(req, res).catch((e) => {
            httpLog.error({ err: (e as Error).message }, 'route failed');
            try {
                res.writeHead(500).end();
            } catch {}
        });
    });
    server.on('error', (e) => httpLog.error({ err: e.message }, 'http server error'));
    server.listen(config.httpPort, config.bindHost, () => {
        httpLog.info({ host: config.bindHost, port: config.httpPort }, 'fivem http listening');
    });
    return server;
}
