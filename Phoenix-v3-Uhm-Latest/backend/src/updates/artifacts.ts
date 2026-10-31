import { createHash } from 'node:crypto';
import { promises as fs } from 'node:fs';
import * as path from 'node:path';

import { log } from '../logger.js';

export type AgentMode = 'usermode' | 'kernel';

export interface Artifact {
    name: string;
    path: string;
    bytes: Buffer;
    size: number;
    sha256: Buffer;
    version: Version;
    mtimeMs: number;
}

export interface Version {
    major: number;
    minor: number;
    build: number;
    revision: number;
}

export interface UpdateBundle {
    mode: AgentMode;
    agent: Artifact;
    driver: Artifact | null;
}

const ARTIFACT_DIR = path.resolve('artifacts');

const AGENT_FILE = 'PhoenixAgent.exe';

const DRIVER_FILE = 'PhoenixDrv.sys';

const artLog = log.child({ module: 'update-artifacts' });

const cached: Record<AgentMode, UpdateBundle | null> = {
    usermode: null,
    kernel: null,
};

let watchTimer: NodeJS.Timeout | null = null;

function zeroVersion(): Version {
    return { major: 0, minor: 0, build: 0, revision: 0 };
}

function emptySha(): Buffer {
    return Buffer.alloc(32);
}

function readVsFixedFileInfo(bytes: Buffer): Version | null {
    const sig = Buffer.from([0xbd, 0x04, 0xef, 0xfe]);
    let off = 0;
    while (off < bytes.length - 8) {
        const idx = bytes.indexOf(sig, off);
        if (idx < 0) return null;
        if (idx + 4 * 13 > bytes.length) return null;
        const strucVersion = bytes.readUInt32LE(idx + 4);
        if (strucVersion !== 0x00010000) {
            off = idx + 1;
            continue;
        }
        const msFile = bytes.readUInt32LE(idx + 8);
        const lsFile = bytes.readUInt32LE(idx + 12);
        return {
            major: (msFile >>> 16) & 0xffff,
            minor: msFile & 0xffff,
            build: (lsFile >>> 16) & 0xffff,
            revision: lsFile & 0xffff,
        };
    }
    return null;
}

async function loadArtifact(dir: string, name: string): Promise<Artifact> {
    const p = path.join(dir, name);
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

function modeDir(mode: AgentMode): string {
    return path.join(ARTIFACT_DIR, mode);
}

async function resolveAgentDir(mode: AgentMode): Promise<string> {
    const nested = path.join(modeDir(mode), AGENT_FILE);
    try {
        await fs.stat(nested);
        return modeDir(mode);
    } catch {
        return ARTIFACT_DIR;
    }
}

async function loadModeBundle(mode: AgentMode): Promise<UpdateBundle> {
    const dir = await resolveAgentDir(mode);
    const agent = await loadArtifact(dir, AGENT_FILE);
    let driver: Artifact | null = null;
    if (mode === 'kernel') {
        try {
            driver = await loadArtifact(dir, DRIVER_FILE);
        } catch {
            try {
                driver = await loadArtifact(ARTIFACT_DIR, DRIVER_FILE);
            } catch {
                driver = null;
            }
        }
    }
    return { mode, agent, driver };
}

export async function startArtifactWatcher(): Promise<void> {
    try {
        await fs.mkdir(path.join(ARTIFACT_DIR, 'usermode'), { recursive: true });
    } catch {}
    try {
        await fs.mkdir(path.join(ARTIFACT_DIR, 'kernel'), { recursive: true });
    } catch {}
    await refreshAll();
    if (watchTimer) clearInterval(watchTimer);
    watchTimer = setInterval(() => {
        void refreshAll();
    }, 15000);
    watchTimer.unref();
}

async function refreshAll(): Promise<void> {
    for (const mode of ['usermode', 'kernel'] as const) {
        try {
            const next = await loadModeBundle(mode);
            const prev = cached[mode];
            if (
                prev &&
                prev.agent.mtimeMs === next.agent.mtimeMs &&
                (prev.driver?.mtimeMs ?? 0) === (next.driver?.mtimeMs ?? 0)
            ) {
                continue;
            }
            cached[mode] = next;
            artLog.info(
                {
                    mode,
                    agentSize: next.agent.size,
                    agentVer: fmt(next.agent.version),
                    drvSize: next.driver?.size ?? 0,
                },
                'artifact bundle loaded',
            );
        } catch (e) {
            cached[mode] = null;
            artLog.error(
                {
                    err: (e as Error).message,
                    mode,
                    dir: modeDir(mode),
                },
                'artifact bundle load failed',
            );
        }
    }
}

export function getBundle(mode: AgentMode = 'usermode'): UpdateBundle | null {
    return cached[mode];
}

export function emptyDriverSha(): Buffer {
    return emptySha();
}

function fmt(v: Version): string {
    return `${v.major}.${v.minor}.${v.build}.${v.revision}`;
}
