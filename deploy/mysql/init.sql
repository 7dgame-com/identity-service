CREATE DATABASE IF NOT EXISTS `xrugc_identity` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE DATABASE IF NOT EXISTS `xrugc_keycloak` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

CREATE USER IF NOT EXISTS 'identity'@'%' IDENTIFIED BY 'identity_password';
CREATE USER IF NOT EXISTS 'keycloak'@'%' IDENTIFIED BY 'keycloak_password';

GRANT ALL PRIVILEGES ON `xrugc_identity`.* TO 'identity'@'%';
GRANT ALL PRIVILEGES ON `xrugc_keycloak`.* TO 'keycloak'@'%';

FLUSH PRIVILEGES;

USE `xrugc_identity`;

CREATE TABLE IF NOT EXISTS `auth_login_events` (
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `event_key` VARCHAR(128) NOT NULL,
  `legacy_user_id` BIGINT NULL,
  `identity_user_id` VARCHAR(128) NULL,
  `username` VARCHAR(255) NULL,
  `event_type` VARCHAR(64) NOT NULL DEFAULT 'login',
  `success` TINYINT(1) NOT NULL DEFAULT 1,
  `occurred_at` DATETIME(3) NOT NULL,
  `ip_address_hash` CHAR(64) NULL,
  `user_agent_hash` CHAR(64) NULL,
  `source` VARCHAR(64) NOT NULL DEFAULT 'legacy-backend',
  `trace_id` VARCHAR(128) NULL,
  `metadata` JSON NULL,
  `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `idx_auth_login_events_event_key` (`event_key`),
  KEY `idx_auth_login_events_legacy_user` (`legacy_user_id`, `occurred_at`),
  KEY `idx_auth_login_events_username` (`username`, `occurred_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `user_login_stats` (
  `stats_key` VARCHAR(255) NOT NULL,
  `legacy_user_id` BIGINT NULL,
  `identity_user_id` VARCHAR(128) NULL,
  `username` VARCHAR(255) NULL,
  `login_count` BIGINT UNSIGNED NOT NULL DEFAULT 0,
  `failed_login_count` BIGINT UNSIGNED NOT NULL DEFAULT 0,
  `last_login_at` DATETIME(3) NULL,
  `last_failed_login_at` DATETIME(3) NULL,
  `updated_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`stats_key`),
  KEY `idx_user_login_stats_legacy_user` (`legacy_user_id`),
  KEY `idx_user_login_stats_username` (`username`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
