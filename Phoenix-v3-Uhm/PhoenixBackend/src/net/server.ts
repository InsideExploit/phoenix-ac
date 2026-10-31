import { createServer, type Server, type Socket } from 'node:net';
import { config } from '../config.js';
import { log } from '../logger.js';
import { AgentSession } from './session.js';

export function startServer(): Server {
    const server = createServer((socket: Socket) => {
        const ip = socket.remoteAddress ?? '0.0.0.0';
        const session = new AgentSession(socket, normalizeIp(ip));
        session.start();
    });

    server.on('error', (e) => log.error({ err: e.message }, 'server error'));
    server.listen(config.bindPort, config.bindHost, () => {
        log.info({ host: config.bindHost, port: config.bindPort }, 'listening');
    });
    return server;
}

function normalizeIp(raw: string): string {
    if (raw.startsWith('::ffff:')) return raw.slice(7);
    return raw;
}
