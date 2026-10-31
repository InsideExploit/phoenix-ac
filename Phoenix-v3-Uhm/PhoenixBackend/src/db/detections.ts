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
    // Backend detections write into the unified `detections` table (website schema
    // as authority). Column names differ from the legacy backend schema; payload
    // is JSON — callers pass a Buffer holding a valid JSON string.
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
            d.severity & 0xFF,
            d.offendingPath?.slice(0, 520) ?? null,
            payloadJson,
        ],
    );
    return BigInt(res.insertId);
}
