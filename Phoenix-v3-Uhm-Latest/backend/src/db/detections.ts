import type { ResultSetHeader } from 'mysql2';

import { pool } from './pool.js';

export interface DetectionInput {
    sessionId: bigint | null;
    playerId: number | null;
    steamHex: string;
    hardwareId: string | null;
    clientIp: string;
    detectionType: string;
    detectionReason: string | null;
    offendingPath: string | null;
    severity: number;
    payload: Buffer | null;
}

export async function insertDetection(d: DetectionInput): Promise<bigint> {
    const payloadJson = d.payload ? d.payload.toString('utf8') : null;
    const [res] = await pool.execute<ResultSetHeader>(
        `INSERT INTO detections
            (session_id, player_id, steam_hex, hardware_id, type, client_ip,
             reason, severity, offending_path, payload)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [
            d.sessionId,
            d.playerId,
            d.steamHex,
            d.hardwareId,
            d.detectionType.slice(0, 64),
            d.clientIp,
            d.detectionReason?.slice(0, 255) ?? null,
            d.severity & 0xff,
            d.offendingPath?.slice(0, 520) ?? null,
            payloadJson,
        ],
    );
    return BigInt(res.insertId);
}
