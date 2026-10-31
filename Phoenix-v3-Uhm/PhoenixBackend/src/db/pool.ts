import mysql from 'mysql2/promise';
import { config } from '../config.js';

export const pool = mysql.createPool({
    host:            config.mysql.host,
    port:            config.mysql.port,
    user:            config.mysql.user,
    password:        config.mysql.password,
    database:        config.mysql.database,
    waitForConnections: true,
    connectionLimit: config.mysql.connectionLimit,
    queueLimit: 0,
    enableKeepAlive: true,
    keepAliveInitialDelay: 10_000,
    dateStrings: false,
    supportBigNumbers: true,
    bigNumberStrings: false,
    timezone: 'Z',
});

export async function pingDb(): Promise<void> {
    const c = await pool.getConnection();
    try { await c.ping(); } finally { c.release(); }
}
