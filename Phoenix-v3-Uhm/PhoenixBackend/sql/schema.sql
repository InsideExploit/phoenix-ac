CREATE DATABASE IF NOT EXISTS phoenix
  DEFAULT CHARACTER SET utf8mb4
  DEFAULT COLLATE utf8mb4_unicode_ci;

USE phoenix;

CREATE TABLE IF NOT EXISTS players (
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
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS admins (
    discord_id VARCHAR(32)  NOT NULL,
    note       VARCHAR(128) NULL,
    added_at   TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (discord_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS pins (
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
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS sessions (
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
    KEY ix_sessions_active      (ended_at),
    CONSTRAINT fk_sessions_player
        FOREIGN KEY (player_id) REFERENCES players (id)
        ON DELETE SET NULL ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS detections (
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
    KEY ix_detections_player_time  (player_id,  created_at),
    KEY ix_detections_hex_time     (steam_hex,  created_at),
    KEY ix_detections_type_time    (type,       created_at),
    KEY ix_detections_session_id   (session_id),
    KEY ix_detections_created_at   (created_at),
    CONSTRAINT fk_detections_player
        FOREIGN KEY (player_id)  REFERENCES players  (id) ON DELETE SET NULL ON UPDATE CASCADE,
    CONSTRAINT fk_detections_session
        FOREIGN KEY (session_id) REFERENCES sessions (id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS player_fingerprints (
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
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS evasion_flags (
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
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS alt_accounts (
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
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS kills (
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
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
