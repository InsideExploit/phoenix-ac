import { promises as fs } from 'node:fs';
import * as path from 'node:path';
import { createHash } from 'node:crypto';
import { log } from '../logger.js';

export interface Artifact {
    name:    string;
    path:    string;
    bytes:   Buffer;
    size:    number;
    sha256:  Buffer;
    version: Version;
    mtimeMs: number;
}

export interface Version {
    major:    number;
    minor:    number;
    build:    number;
    revision: number;
}

export interface UpdateBundle {
    agent:  Artifact;
    driver: Artifact;
}

const ARTIFACT_DIR = path.resolve('artifacts');
const AGENT_FILE   = 'PhoenixAgent.exe';
const DRIVER_FILE  = 'PhoenixDrv.sys';

const artLog = log.child({ module: 'update-artifacts' });

let cached: UpdateBundle | null = null;
let watchTimer: NodeJS.Timeout | null = null;

function zeroVersion(): Version { return { major: 0, minor: 0, build: 0, revision: 0 }; }

function readVsFixedFileInfo(bytes: Buffer): Version | null {
    const sig = Buffer.from([0xBD, 0x04, 0xEF, 0xFE]);
    let off = 0;
    while (off < bytes.length - 8) {
        const idx = bytes.indexOf(sig, off);
        if (idx < 0) return null;
        if (idx + 4 * 13 > bytes.length) return null;
        const strucVersion = bytes.readUInt32LE(idx + 4);
        if (strucVersion !== 0x00010000) { off = idx + 1; continue; }
        const msFile = bytes.readUInt32LE(idx + 8);
        const lsFile = bytes.readUInt32LE(idx + 12);
        return {
            major:    (msFile >>> 16) & 0xffff,
            minor:    msFile & 0xffff,
            build:    (lsFile >>> 16) & 0xffff,
            revision: lsFile & 0xffff,
        };
    }
    return null;
}

async function loadArtifact(name: string): Promise<Artifact> {
    const p = path.join(ARTIFACT_DIR, name);
    const st = await fs.stat(p);
    const bytes = await fs.readFile(p);
    const sha256 = createHash('sha256').update(bytes).digest();
    const version = readVsFixedFileInfo(bytes) ?? zeroVersion();
    return {
        name,
        path: p,
        bytes,
        size: bytes.length,
        sha256,
        version,
        mtimeMs: st.mtimeMs,
    };
}

export async function loadBundle(): Promise<UpdateBundle> {
    const [agent, driver] = await Promise.all([
        loadArtifact(AGENT_FILE),
        loadArtifact(DRIVER_FILE),
    ]);
    return { agent, driver };
}

export async function startArtifactWatcher(): Promise<UpdateBundle> {
    try { await fs.mkdir(ARTIFACT_DIR, { recursive: true }); } catch { /* ignore */ }

    try {
        cached = await loadBundle();
        artLog.info({
            agentSize: cached.agent.size,
            agentVer:  fmt(cached.agent.version),
            agentHash: cached.agent.sha256.toString('hex').slice(0, 16),
            drvSize:   cached.driver.size,
            drvVer:    fmt(cached.driver.version),
            drvHash:   cached.driver.sha256.toString('hex').slice(0, 16),
        }, 'artifact bundle loaded');
    } catch (e) {
        artLog.error({ err: (e as Error).message, dir: ARTIFACT_DIR },
            'artifact bundle load failed — updater clients will be rejected until artifacts exist');
    }

    if (watchTimer) clearInterval(watchTimer);
    watchTimer = setInterval(() => { void refreshIfChanged(); }, 15_000);
    watchTimer.unref();
    return cached ?? Promise.reject(new Error('no bundle'));
}

async function refreshIfChanged(): Promise<void> {
    try {
        const [agentSt, driverSt] = await Promise.all([
            fs.stat(path.join(ARTIFACT_DIR, AGENT_FILE)),
            fs.stat(path.join(ARTIFACT_DIR, DRIVER_FILE)),
        ]);
        if (cached &&
            agentSt.mtimeMs  === cached.agent.mtimeMs &&
            driverSt.mtimeMs === cached.driver.mtimeMs) {
            return;
        }
        cached = await loadBundle();
        artLog.info({
            agentVer: fmt(cached.agent.version),
            drvVer:   fmt(cached.driver.version),
        }, 'artifact bundle reloaded');
    } catch (e) {
        artLog.warn({ err: (e as Error).message }, 'artifact refresh failed');
    }
}

export function getBundle(): UpdateBundle | null {
    return cached;
}

function fmt(v: Version): string {
    return `${v.major}.${v.minor}.${v.build}.${v.revision}`;
}
