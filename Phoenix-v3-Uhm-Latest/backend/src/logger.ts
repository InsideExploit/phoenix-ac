import pino from 'pino';

import { config } from './config.js';

export const log = pino({
    level: config.logLevel,
    base: null,
    transport: {
        target: 'pino-pretty',
        options: {
            colorize: true,
            translateTime: 'SYS:HH:MM:ss.l',
            ignore: 'pid,hostname',
            singleLine: true,
            messageFormat: '{msg}',
        },
    },
});

export type Log = typeof log;
