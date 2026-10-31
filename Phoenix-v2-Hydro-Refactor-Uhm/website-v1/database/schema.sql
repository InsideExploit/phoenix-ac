CREATE TABLE IF NOT EXISTS `players` (
  `id`         INT UNSIGNED NOT NULL AUTO_INCREMENT,
  `steam_hex`  VARCHAR(64)  NOT NULL,
  `discord_id` VARCHAR(32)  NULL,
  `name`       VARCHAR(128) NULL,
  `banned`     TINYINT(1)   NOT NULL DEFAULT 0,
  `last_seen`  DATETIME     NULL,
  `created_at` TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_steam_hex` (`steam_hex`),
  KEY `idx_last_seen` (`last_seen`),
  KEY `idx_discord` (`discord_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

SET @db := DATABASE();

SET @sql := IF(
  (SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
    WHERE TABLE_SCHEMA = @db AND TABLE_NAME = 'players' AND COLUMN_NAME = 'status') > 0,
  'ALTER TABLE `players` DROP COLUMN `status`',
  'DO 0');
PREPARE s FROM @sql; EXECUTE s; DEALLOCATE PREPARE s;

SET @sql := IF(
  (SELECT COUNT(*) FROM INFORMATION_SCHEMA.STATISTICS
    WHERE TABLE_SCHEMA = @db AND TABLE_NAME = 'players' AND INDEX_NAME = 'idx_status') > 0,
  'ALTER TABLE `players` DROP INDEX `idx_status`',
  'DO 0');
PREPARE s FROM @sql; EXECUTE s; DEALLOCATE PREPARE s;

CREATE TABLE IF NOT EXISTS `admins` (
  `discord_id` VARCHAR(32)  NOT NULL,
  `note`       VARCHAR(128) NULL,
  `added_at`   TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`discord_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `detections` (
  `id`         BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `player_id`  INT UNSIGNED NULL,
  `steam_hex`  VARCHAR(64)  NOT NULL,
  `type`       ENUM('detection','sweep','exit','overlay','internal','mapper','injection','modfingerprint','security') NOT NULL,
  `pid`        INT UNSIGNED NULL,
  `exe`        VARCHAR(255) NULL,
  `host`       VARCHAR(128) NULL,
  `client_ip`  VARCHAR(64)  NULL,
  `payload`    JSON         NOT NULL,
  `created_at` TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_player_time` (`player_id`, `created_at`),
  KEY `idx_hex_time` (`steam_hex`, `created_at`),
  KEY `idx_type_time` (`type`, `created_at`),
  CONSTRAINT `fk_detections_player`
    FOREIGN KEY (`player_id`) REFERENCES `players` (`id`)
    ON DELETE SET NULL ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `pins` (
  `id`         INT UNSIGNED NOT NULL AUTO_INCREMENT,
  `code`       VARCHAR(12)  NOT NULL,
  `player_id`  INT UNSIGNED NULL,
  `created_by` VARCHAR(32)  NULL,
  `used`       TINYINT(1)   NOT NULL DEFAULT 0,
  `created_at` TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `expires_at` DATETIME     NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_code` (`code`),
  KEY `idx_player` (`player_id`),
  CONSTRAINT `fk_pins_player`
    FOREIGN KEY (`player_id`) REFERENCES `players` (`id`)
    ON DELETE SET NULL ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `player_fingerprints` (
  `id`         BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `steam_hex`  VARCHAR(64)  NOT NULL,
  `fp_type`    ENUM('discord','license','license2','token') NOT NULL,
  `fp_value`   VARCHAR(255) NOT NULL,
  `name`       VARCHAR(128) NULL,
  `first_seen` TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `last_seen`  TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_hex_type_val` (`steam_hex`, `fp_type`, `fp_value`),
  KEY `idx_fp_lookup` (`fp_type`, `fp_value`),
  KEY `idx_last_seen` (`last_seen`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `evasion_flags` (
  `id`             BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `primary_hex`    VARCHAR(64)  NOT NULL,
  `secondary_hex`  VARCHAR(64)  NOT NULL,
  `fp_type`        ENUM('discord','license','license2','token') NOT NULL,
  `fp_value`       VARCHAR(255) NOT NULL,
  `primary_name`   VARCHAR(128) NULL,
  `secondary_name` VARCHAR(128) NULL,
  `client_ip`      VARCHAR(64)  NULL,
  `created_at`     TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_primary_time` (`primary_hex`, `created_at`),
  KEY `idx_secondary_time` (`secondary_hex`, `created_at`),
  KEY `idx_fp_time` (`fp_type`, `fp_value`, `created_at`),
  KEY `idx_dedup` (`primary_hex`, `secondary_hex`, `fp_type`, `fp_value`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `kills` (
  `id`                BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `killer_steam_hex`  VARCHAR(64)  NOT NULL,
  `killer_discord_id` VARCHAR(32)  NULL,
  `killer_license`    VARCHAR(80)  NULL,
  `killer_token`      VARCHAR(128) NULL,
  `killer_name`       VARCHAR(128) NULL,
  `victim_steam_hex`  VARCHAR(64)  NULL,
  `victim_discord_id` VARCHAR(32)  NULL,
  `victim_license`    VARCHAR(80)  NULL,
  `victim_token`      VARCHAR(128) NULL,
  `victim_name`       VARCHAR(128) NULL,
  `weapon`            VARCHAR(64)  NULL,
  `created_at`        TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_killer_time` (`killer_steam_hex`, `created_at`),
  KEY `idx_victim_time` (`victim_steam_hex`, `created_at`),
  KEY `idx_created` (`created_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

DELETE FROM `evasion_flags` WHERE `fp_type` = 'ip';
DELETE FROM `player_fingerprints` WHERE `fp_type` = 'ip';

SET @sql := IF(
  (SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
    WHERE TABLE_SCHEMA = @db AND TABLE_NAME = 'player_fingerprints'
      AND COLUMN_NAME = 'fp_type'
      AND COLUMN_TYPE LIKE '%ip%') > 0,
  'ALTER TABLE `player_fingerprints` MODIFY COLUMN `fp_type` ENUM(''discord'',''license'',''license2'',''token'') NOT NULL',
  'DO 0');
PREPARE s FROM @sql; EXECUTE s; DEALLOCATE PREPARE s;

SET @sql := IF(
  (SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
    WHERE TABLE_SCHEMA = @db AND TABLE_NAME = 'evasion_flags'
      AND COLUMN_NAME = 'fp_type'
      AND COLUMN_TYPE LIKE '%ip%') > 0,
  'ALTER TABLE `evasion_flags` MODIFY COLUMN `fp_type` ENUM(''discord'',''license'',''license2'',''token'') NOT NULL',
  'DO 0');
PREPARE s FROM @sql; EXECUTE s; DEALLOCATE PREPARE s;

ALTER TABLE `detections`
  MODIFY COLUMN `type` ENUM(
    'detection',
    'sweep',
    'exit',
    'overlay',
    'internal',
    'mapper',
    'injection',
    'modfingerprint',
    'security'
  ) NOT NULL;