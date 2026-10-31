import 'dotenv/config';

function req(name: string): string {
    const v = process.env[name];
    if (!v || v.length === 0) {
        throw new Error(`missing env ${name}`);
    }
    return v;
}

function optNum(name: string, def: number): number {
    const v = process.env[name];
    if (v === undefined || v === '') return def;
    const n = Number(v);
    if (!Number.isFinite(n)) {
        throw new Error(`invalid number env ${name}`);
    }
    return n;
}

function opt(name: string, def: string): string {
    return process.env[name] ?? def;
}

function hexBuf(name: string, expectLen: number): Buffer {
    const raw = req(name).trim().toLowerCase();
    if (!/^[0-9a-f]+$/.test(raw)) {
        throw new Error(`${name} must be hex`);
    }
    if (raw.length !== expectLen * 2) {
        throw new Error(`${name} must be ${expectLen} bytes hex`);
    }
    return Buffer.from(raw, 'hex');
}

const phoenixEnv = (process.env['PHOENIX_ENV'] ?? '').toLowerCase();

const isLocal = phoenixEnv === 'local' || phoenixEnv === 'dev' || phoenixEnv === 'development';

const defaultBindHost = isLocal ? '127.0.0.1' : '0.0.0.0';

function wh(name: string): string {
    if (isLocal) {
        const local = process.env[`${name}_LOCAL`];
        if (local !== undefined && local !== '') {
            return local;
        }
    }
    return process.env[name] ?? '';
}

export const config = {
    env: opt('NODE_ENV', 'development'),
    logLevel: opt('LOG_LEVEL', 'info'),
    phoenixEnv: isLocal ? 'local' : 'remote',
    bindHost: opt('PAC_BIND_HOST', defaultBindHost),
    bindPort: optNum('PAC_BIND_PORT', 27015),
    httpPort: optNum('PAC_HTTP_PORT', 27016),
    updatePort: optNum('PAC_UPDATE_PORT', 27017),
    httpToken: opt('PAC_HTTP_TOKEN', ''),
    sessionStaleMs: optNum('PAC_SESSION_STALE_MS', 45000),
    steamApiKey: opt('PAC_STEAM_API_KEY', ''),
    psk: hexBuf('PAC_PSK_HEX', 32),
    heartbeatIntervalMs: optNum('PAC_HEARTBEAT_INTERVAL_MS', 5000),
    heartbeatTimeoutMs: optNum('PAC_HEARTBEAT_TIMEOUT_MS', 20000),
    handshakeTimeoutMs: optNum('PAC_HANDSHAKE_TIMEOUT_MS', 8000),
    maxPacketBytes: optNum('PAC_MAX_PACKET_BYTES', 32 * 1024 * 1024),
    replayWindowMs: optNum('PAC_REPLAY_WINDOW_MS', 30000),
    mysql: {
        host: opt('MYSQL_HOST', '127.0.0.1'),
        port: optNum('MYSQL_PORT', 3306),
        user: req('MYSQL_USER'),
        password: process.env['MYSQL_PASSWORD'] ?? '',
        database: req('MYSQL_DATABASE'),
        connectionLimit: optNum('MYSQL_CONNECTION_LIMIT', 16),
    },
    webhooks: {
        enabled:
            (isLocal
                ? opt('PAC_WH_ENABLED_LOCAL', opt('PAC_WH_ENABLED', 'true'))
                : opt('PAC_WH_ENABLED', 'true')
            ).toLowerCase() !== 'false',
        registrations: wh('PAC_WH_REGISTRATIONS'),
        auth: wh('PAC_WH_AUTH'),
        sessions: wh('PAC_WH_SESSIONS'),
        hwidMismatch: wh('PAC_WH_HWID_MISMATCH'),
        detectionsBlocking: wh('PAC_WH_DETECTIONS_BLOCKING'),
        detectionsReport: wh('PAC_WH_DETECTIONS_REPORT'),
        detectionsCheats: wh('PAC_WH_DETECTIONS_CHEATS'),
        errors: wh('PAC_WH_ERRORS'),
    },
} as const;

export type AppConfig = typeof config;
