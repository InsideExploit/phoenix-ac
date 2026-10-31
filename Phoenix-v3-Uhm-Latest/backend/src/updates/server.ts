import { createServer, type Server, type Socket } from 'node:net';

import { config } from '../config.js';
import { log } from '../logger.js';
import { UpdateSession } from './session.js';

export function startUpdateServer(): Server {
    const server = createServer((socket: Socket) => {
        const ip = socket.remoteAddress ?? '0.0.0.0';
        const session = new UpdateSession(socket, normalizeIp(ip));
        session.start();
    });
    server.on('error', (e) => log.error({ err: e.message }, 'update server error'));
    server.listen(config.updatePort, config.bindHost, () => {
        log.info({ host: config.bindHost, port: config.updatePort }, 'update server listening');
    });
    return server;
}

function normalizeIp(raw: string): string {
    if (raw.startsWith('::ffff:')) return raw.slice(7);
    return raw;
}
