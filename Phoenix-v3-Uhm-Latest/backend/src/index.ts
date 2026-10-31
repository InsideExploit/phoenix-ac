import { config } from './config.js';
import { runMigrations } from './db/migrate.js';
import { pingDb, pool } from './db/pool.js';
import { pingAllWebhooks } from './discord/webhook.js';
import { startHttpServer } from './http/fivem.js';
import { log } from './logger.js';
import { startServer } from './net/server.js';
import { startArtifactWatcher } from './updates/artifacts.js';
import { startUpdateServer } from './updates/server.js';

async function main(): Promise<void> {
    log.info(
        {
            maxPacketBytes: config.maxPacketBytes,
            heartbeatIntervalMs: config.heartbeatIntervalMs,
            heartbeatTimeoutMs: config.heartbeatTimeoutMs,
        },
        'booting phoenixac backend',
    );

    const mask = (u: string): string => (u ? `${u.slice(0, 42)}…(${u.length})` : '(unset)');

    log.info(
        {
            phoenixEnv: config.phoenixEnv,
            whEnabled: config.webhooks.enabled,
            registrations: mask(config.webhooks.registrations),
            auth: mask(config.webhooks.auth),
            sessions: mask(config.webhooks.sessions),
            hwidMismatch: mask(config.webhooks.hwidMismatch),
            detectionsBlocking: mask(config.webhooks.detectionsBlocking),
            detectionsReport: mask(config.webhooks.detectionsReport),
            detectionsCheats: mask(config.webhooks.detectionsCheats),
            errors: mask(config.webhooks.errors),
        },
        'webhook routing',
    );

    try {
        await pingDb();
        log.info('mysql reachable');
    } catch (e) {
        log.fatal({ err: (e as Error).message }, 'mysql unreachable');
        process.exit(1);
    }

    try {
        await runMigrations();
    } catch (e) {
        log.fatal({ err: (e as Error).message }, 'migration failed');
        process.exit(1);
    }

    try {
        await startArtifactWatcher();
    } catch (e) {
        log.warn({ err: (e as Error).message }, 'artifact watcher unstarted');
    }

    void pingAllWebhooks();

    const server = startServer();
    const httpServer = startHttpServer();
    const updateServer = startUpdateServer();

    const shutdown = async (sig: string): Promise<void> => {
        log.info({ sig }, 'shutting down');
        server.close();
        httpServer.close();
        updateServer.close();
        try {
            await pool.end();
        } catch {}
        setTimeout(() => process.exit(0), 500).unref();
    };

    process.on('SIGINT', () => void shutdown('SIGINT'));
    process.on('SIGTERM', () => void shutdown('SIGTERM'));
    process.on('unhandledRejection', (e) => log.error({ err: String(e) }, 'unhandledRejection'));
    process.on('uncaughtException', (e) =>
        log.error({ err: e.message, stack: e.stack }, 'uncaughtException'),
    );
}

void main();
