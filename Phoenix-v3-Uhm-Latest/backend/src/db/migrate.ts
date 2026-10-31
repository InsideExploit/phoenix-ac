import { readFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { log } from '../logger.js';
import { pool } from './pool.js';

const migrateLog = log.child({ module: 'migrate' });

const SCHEMA_FILE = resolve(dirname(fileURLToPath(import.meta.url)), '../../sql/schema.sql');

const TOLERABLE_CODES: ReadonlySet<string> = new Set([
    'ER_DUP_FIELDNAME',
    'ER_DUP_KEYNAME',
    'ER_DUP_INDEX',
    'ER_CANT_DROP_FIELD_OR_KEY',
    'ER_BAD_FIELD_ERROR',
    'ER_TABLE_EXISTS_ERROR',
    'ER_DB_CREATE_EXISTS',
    'ER_MULTIPLE_PRI_KEY',
    'ER_FK_DUP_NAME',
]);

function stripSqlComments(sql: string): string {
    return sql.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*--.*$/gm, '');
}

function splitSqlStatements(sql: string): string[] {
    const out: string[] = [];
    let buf = '';
    let inSingle = false;
    let inDouble = false;
    let inBacktick = false;
    for (let i = 0; i < sql.length; ++i) {
        const c = sql[i];
        const prev = i > 0 ? sql[i - 1] : '';
        if (!inDouble && !inBacktick && c === "'" && prev !== '\\') inSingle = !inSingle;
        else if (!inSingle && !inBacktick && c === '"' && prev !== '\\') inDouble = !inDouble;
        else if (!inSingle && !inDouble && c === '`') inBacktick = !inBacktick;
        if (c === ';' && !inSingle && !inDouble && !inBacktick) {
            const t = buf.trim();
            if (t.length > 0) out.push(t);
            buf = '';
        } else {
            buf += c;
        }
    }
    const tail = buf.trim();
    if (tail.length > 0) out.push(tail);
    return out;
}

function shouldSkipStatement(stmt: string): boolean {
    const head = stmt.slice(0, 32).toLowerCase();
    return head.startsWith('use ') || head.startsWith('create database');
}

async function applySchemaFile(): Promise<number> {
    let raw: string;
    try {
        raw = await readFile(SCHEMA_FILE, 'utf8');
    } catch (e) {
        const code =
            (
                e as {
                    code?: string;
                }
            ).code ?? '';
        if (code === 'ENOENT') {
            migrateLog.warn({ path: SCHEMA_FILE }, 'schema.sql not found; skipping file baseline');
            return 0;
        }
        throw e;
    }
    const stmts = splitSqlStatements(stripSqlComments(raw)).filter((s) => !shouldSkipStatement(s));
    const conn = await pool.getConnection();
    try {
        for (const stmt of stmts) {
            try {
                await conn.query(stmt);
            } catch (e) {
                const code =
                    (
                        e as {
                            code?: string;
                        }
                    ).code ?? '';
                if (TOLERABLE_CODES.has(code)) continue;
                throw e;
            }
        }
    } finally {
        conn.release();
    }
    return stmts.length;
}

const STATEMENTS: readonly string[] = [
    `CREATE TABLE IF NOT EXISTS players (
        id             INT UNSIGNED    NOT NULL AUTO_INCREMENT,
        steam_hex      VARCHAR(64)     NOT NULL,
        discord_id     VARCHAR(32)     NULL,
        name           VARCHAR(128)    NULL,
        hardware_id    VARCHAR(128)    NULL,
        banned         TINYINT(1)      NOT NULL DEFAULT 0,
        suspended      TINYINT(1)      NOT NULL DEFAULT 0,
        added_by       VARCHAR(64)     NULL,
        last_edit_by   VARCHAR(64)     NULL,
        last_edit_at   DATETIME        NULL,
        last_seen      DATETIME        NULL,
        created_at     TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at     TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        PRIMARY KEY (id),
        UNIQUE KEY uk_players_steam_hex (steam_hex),
        KEY ix_players_discord_id  (discord_id),
        KEY ix_players_hardware_id (hardware_id),
        KEY ix_players_banned      (banned),
        KEY ix_players_suspended   (suspended),
        KEY ix_players_last_seen   (last_seen)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`,
    `ALTER TABLE players MODIFY COLUMN steam_hex VARCHAR(64) NOT NULL`,
    `ALTER TABLE players ADD COLUMN IF NOT EXISTS name         VARCHAR(128) NULL AFTER discord_id`,
    `ALTER TABLE players ADD COLUMN IF NOT EXISTS hardware_id  VARCHAR(128) NULL AFTER name`,
    `ALTER TABLE players ADD COLUMN IF NOT EXISTS suspended    TINYINT(1)   NOT NULL DEFAULT 0 AFTER banned`,
    `ALTER TABLE players ADD COLUMN IF NOT EXISTS added_by     VARCHAR(64)  NULL AFTER suspended`,
    `ALTER TABLE players ADD COLUMN IF NOT EXISTS last_edit_by VARCHAR(64)  NULL AFTER added_by`,
    `ALTER TABLE players ADD COLUMN IF NOT EXISTS last_edit_at DATETIME     NULL AFTER last_edit_by`,
    `ALTER TABLE players ADD COLUMN IF NOT EXISTS ban_reason        VARCHAR(255) NULL AFTER suspended`,
    `ALTER TABLE players ADD COLUMN IF NOT EXISTS banned_by         VARCHAR(64)  NULL AFTER ban_reason`,
    `ALTER TABLE players ADD COLUMN IF NOT EXISTS banned_at         DATETIME     NULL AFTER banned_by`,
    `ALTER TABLE players ADD COLUMN IF NOT EXISTS ban_category      VARCHAR(32)  NULL AFTER banned_at`,
    `ALTER TABLE players ADD COLUMN IF NOT EXISTS ban_reason_public TINYINT(1)   NOT NULL DEFAULT 0 AFTER ban_category`,
    `ALTER TABLE players ADD COLUMN IF NOT EXISTS suspend_reason    VARCHAR(255) NULL AFTER ban_reason_public`,
    `ALTER TABLE players ADD COLUMN IF NOT EXISTS suspended_by      VARCHAR(64)  NULL AFTER suspend_reason`,
    `ALTER TABLE players ADD COLUMN IF NOT EXISTS suspended_at      DATETIME     NULL AFTER suspended_by`,
    `ALTER TABLE players DROP COLUMN IF EXISTS display_name`,
    `ALTER TABLE players ADD COLUMN IF NOT EXISTS steam_name       VARCHAR(128) NULL AFTER suspended_at`,
    `ALTER TABLE players ADD COLUMN IF NOT EXISTS discord_name     VARCHAR(128) NULL AFTER steam_name`,
    `ALTER TABLE players ADD COLUMN IF NOT EXISTS steam_avatar     VARCHAR(512) NULL AFTER discord_name`,
    `ALTER TABLE players ADD COLUMN IF NOT EXISTS discord_avatar   VARCHAR(512) NULL AFTER steam_avatar`,
    `ALTER TABLE players ADD COLUMN IF NOT EXISTS names_fetched_at DATETIME     NULL AFTER discord_avatar`,
    `CREATE INDEX IF NOT EXISTS ix_players_steam_name   ON players (steam_name)`,
    `CREATE INDEX IF NOT EXISTS ix_players_discord_name ON players (discord_name)`,
    `ALTER TABLE players ADD COLUMN IF NOT EXISTS agent_mode ENUM('usermode','kernel') NOT NULL DEFAULT 'kernel'`,
    `ALTER TABLE players MODIFY COLUMN agent_mode ENUM('usermode','kernel') NOT NULL DEFAULT 'kernel'`,
    `ALTER TABLE players ADD COLUMN IF NOT EXISTS allow_no_secure_boot TINYINT(1) NOT NULL DEFAULT 0`,
    `ALTER TABLE players ADD COLUMN IF NOT EXISTS allow_no_hvci TINYINT(1) NOT NULL DEFAULT 0`,
    `ALTER TABLE players MODIFY COLUMN allow_no_secure_boot TINYINT(1) NOT NULL DEFAULT 0`,
    `ALTER TABLE players MODIFY COLUMN allow_no_hvci TINYINT(1) NOT NULL DEFAULT 0`,
    `CREATE TABLE IF NOT EXISTS admins (
        discord_id VARCHAR(32)  NOT NULL,
        note       VARCHAR(128) NULL,
        added_at   TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (discord_id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`,
    `ALTER TABLE admins ADD COLUMN IF NOT EXISTS sec_level INT NOT NULL DEFAULT 0 AFTER note`,
    `ALTER TABLE admins DROP COLUMN IF EXISTS can_view_screen`,
    `CREATE TABLE IF NOT EXISTS pins (
        id         INT UNSIGNED NOT NULL AUTO_INCREMENT,
        code       VARCHAR(12)  NOT NULL,
        player_id  INT UNSIGNED NULL,
        created_by VARCHAR(32)  NULL,
        used       TINYINT(1)   NOT NULL DEFAULT 0,
        created_at TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
        expires_at DATETIME     NULL,
        PRIMARY KEY (id),
        UNIQUE KEY uk_pins_code (code),
        KEY ix_pins_player      (player_id),
        CONSTRAINT fk_pins_player
            FOREIGN KEY (player_id) REFERENCES players (id)
            ON DELETE SET NULL ON UPDATE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`,
    `CREATE TABLE IF NOT EXISTS sessions (
        id               BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
        steam_hex        VARCHAR(64)     NOT NULL,
        player_id        INT UNSIGNED    NULL,
        hardware_id      VARCHAR(128)    NULL,
        hardware_details MEDIUMTEXT      NULL,
        client_ip        VARCHAR(64)     NOT NULL,
        client_version   VARCHAR(32)     NULL,
        started_at       TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,
        last_heartbeat   DATETIME        NULL,
        ended_at         DATETIME        NULL,
        end_reason       VARCHAR(64)     NULL,
        PRIMARY KEY (id),
        KEY ix_sessions_steam_hex   (steam_hex),
        KEY ix_sessions_player_id   (player_id),
        KEY ix_sessions_hardware_id (hardware_id),
        KEY ix_sessions_active      (ended_at)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`,
    `ALTER TABLE sessions MODIFY COLUMN steam_hex VARCHAR(64) NOT NULL`,
    `ALTER TABLE sessions ADD COLUMN IF NOT EXISTS hardware_details MEDIUMTEXT NULL AFTER hardware_id`,
    `CREATE TABLE IF NOT EXISTS detections (
        id             BIGINT UNSIGNED  NOT NULL AUTO_INCREMENT,
        session_id     BIGINT UNSIGNED  NULL,
        player_id      INT UNSIGNED     NULL,
        steam_hex      VARCHAR(64)      NOT NULL,
        hardware_id    VARCHAR(128)     NULL,
        type           VARCHAR(64)      NOT NULL,
        pid            INT UNSIGNED     NULL,
        exe            VARCHAR(255)     NULL,
        host           VARCHAR(128)     NULL,
        client_ip      VARCHAR(64)      NOT NULL,
        reason         VARCHAR(255)     NULL,
        severity       TINYINT UNSIGNED NULL,
        offending_path VARCHAR(520)     NULL,
        payload        JSON             NULL,
        created_at     TIMESTAMP        NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (id),
        KEY ix_detections_player_time  (player_id, created_at),
        KEY ix_detections_hex_time     (steam_hex, created_at),
        KEY ix_detections_type_time    (type,      created_at),
        KEY ix_detections_session_id   (session_id),
        KEY ix_detections_created_at   (created_at)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`,
    `ALTER TABLE detections MODIFY COLUMN steam_hex VARCHAR(64) NOT NULL`,
    `ALTER TABLE detections ADD COLUMN IF NOT EXISTS type    VARCHAR(64)  NULL AFTER hardware_id`,
    `ALTER TABLE detections ADD COLUMN IF NOT EXISTS pid     INT UNSIGNED NULL AFTER type`,
    `ALTER TABLE detections ADD COLUMN IF NOT EXISTS exe     VARCHAR(255) NULL AFTER pid`,
    `ALTER TABLE detections ADD COLUMN IF NOT EXISTS host    VARCHAR(128) NULL AFTER exe`,
    `ALTER TABLE detections ADD COLUMN IF NOT EXISTS reason  VARCHAR(255) NULL AFTER client_ip`,
    `ALTER TABLE detections ADD COLUMN IF NOT EXISTS offending_path VARCHAR(520) NULL AFTER severity`,
    `UPDATE detections SET type = detection_type WHERE type IS NULL AND detection_type IS NOT NULL`,
    `UPDATE detections SET reason = detection_reason WHERE reason IS NULL AND detection_reason IS NOT NULL`,
    `ALTER TABLE detections MODIFY COLUMN type VARCHAR(64) NOT NULL`,
    `ALTER TABLE detections MODIFY COLUMN severity TINYINT UNSIGNED NULL`,
    `ALTER TABLE detections DROP COLUMN IF EXISTS detection_type`,
    `ALTER TABLE detections DROP COLUMN IF EXISTS detection_reason`,
    `CREATE TABLE IF NOT EXISTS player_fingerprints (
        id         BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
        steam_hex  VARCHAR(64)     NOT NULL,
        fp_type    ENUM('discord','license','license2','token') NOT NULL,
        fp_value   VARCHAR(255)    NOT NULL,
        name       VARCHAR(128)    NULL,
        first_seen TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,
        last_seen  TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        PRIMARY KEY (id),
        UNIQUE KEY uk_fp_hex_type_val (steam_hex, fp_type, fp_value),
        KEY ix_fp_lookup    (fp_type, fp_value),
        KEY ix_fp_last_seen (last_seen)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`,
    `CREATE TABLE IF NOT EXISTS evasion_flags (
        id             BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
        primary_hex    VARCHAR(64)  NOT NULL,
        secondary_hex  VARCHAR(64)  NOT NULL,
        fp_type        ENUM('discord','license','license2','token') NOT NULL,
        fp_value       VARCHAR(255) NOT NULL,
        primary_name   VARCHAR(128) NULL,
        secondary_name VARCHAR(128) NULL,
        client_ip      VARCHAR(64)  NULL,
        created_at     TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (id),
        KEY ix_ef_primary_time   (primary_hex,   created_at),
        KEY ix_ef_secondary_time (secondary_hex, created_at),
        KEY ix_ef_fp_time        (fp_type, fp_value, created_at),
        KEY ix_ef_dedup          (primary_hex, secondary_hex, fp_type, fp_value)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`,
    `CREATE TABLE IF NOT EXISTS alt_accounts (
        id               BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
        player_id        INT UNSIGNED    NOT NULL,
        steam_hex        VARCHAR(64)     NOT NULL,
        kind             ENUM('steam','discord') NOT NULL,
        external_id      VARCHAR(256)    NOT NULL,
        username         VARCHAR(128)    NULL,
        avatar           VARCHAR(512)    NULL,
        names_fetched_at DATETIME        NULL,
        first_seen       DATETIME        NOT NULL,
        last_seen        DATETIME        NOT NULL,
        PRIMARY KEY (id),
        UNIQUE KEY uk_alt_player_kind_ext (player_id, kind, external_id),
        KEY ix_alt_player      (player_id),
        KEY ix_alt_steam_hex   (steam_hex),
        KEY ix_alt_kind_ext    (kind, external_id),
        CONSTRAINT fk_alt_player
            FOREIGN KEY (player_id) REFERENCES players (id)
            ON DELETE CASCADE ON UPDATE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`,
    `ALTER TABLE alt_accounts MODIFY COLUMN avatar VARCHAR(512) NULL`,
    `ALTER TABLE alt_accounts ADD COLUMN IF NOT EXISTS names_fetched_at DATETIME NULL AFTER avatar`,
    `ALTER TABLE alt_accounts MODIFY COLUMN external_id VARCHAR(256) NOT NULL`,
    `ALTER TABLE alt_accounts MODIFY COLUMN kind ENUM('steam','discord') NOT NULL`,
    `CREATE TABLE IF NOT EXISTS kills (
        id                BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
        killer_steam_hex  VARCHAR(64)  NOT NULL,
        killer_discord_id VARCHAR(32)  NULL,
        killer_license    VARCHAR(80)  NULL,
        killer_token      VARCHAR(128) NULL,
        killer_name       VARCHAR(128) NULL,
        victim_steam_hex  VARCHAR(64)  NULL,
        victim_discord_id VARCHAR(32)  NULL,
        victim_license    VARCHAR(80)  NULL,
        victim_token      VARCHAR(128) NULL,
        victim_name       VARCHAR(128) NULL,
        weapon            VARCHAR(64)  NULL,
        created_at        TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (id),
        KEY ix_kills_killer_time (killer_steam_hex, created_at),
        KEY ix_kills_victim_time (victim_steam_hex, created_at),
        KEY ix_kills_created     (created_at)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`,
];

export async function runMigrations(): Promise<void> {
    const fileCount = await applySchemaFile();
    const conn = await pool.getConnection();
    try {
        for (const stmt of STATEMENTS) {
            try {
                await conn.query(stmt);
            } catch (e) {
                const code =
                    (
                        e as {
                            code?: string;
                        }
                    ).code ?? '';
                if (TOLERABLE_CODES.has(code)) continue;
                throw e;
            }
        }
        migrateLog.info(
            { fileStatements: fileCount, migrations: STATEMENTS.length },
            'schema auto-updated',
        );
    } finally {
        conn.release();
    }
}
