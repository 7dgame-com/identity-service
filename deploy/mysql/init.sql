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

CREATE TABLE IF NOT EXISTS `usage_billing_ledger` (
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `ledger_key` VARCHAR(255) NOT NULL,
  `source_event_id` BIGINT UNSIGNED NOT NULL,
  `subject_type` VARCHAR(32) NOT NULL,
  `subject_id` VARCHAR(128) NOT NULL,
  `usage_type` VARCHAR(64) NOT NULL,
  `quantity` BIGINT NOT NULL DEFAULT 1,
  `unit` VARCHAR(32) NOT NULL DEFAULT 'times',
  `charge_mode` VARCHAR(64) NOT NULL DEFAULT 'shadow',
  `billing_status` VARCHAR(64) NOT NULL DEFAULT 'shadow',
  `occurred_at` DATETIME(3) NOT NULL,
  `metadata` JSON NULL,
  `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `idx_usage_billing_ledger_key` (`ledger_key`),
  KEY `idx_usage_billing_ledger_source` (`source_event_id`),
  KEY `idx_usage_billing_ledger_subject` (`subject_type`, `subject_id`, `usage_type`, `occurred_at`),
  KEY `idx_usage_billing_ledger_status` (`billing_status`, `occurred_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `account_usage_balance_shadow` (
  `subject_type` VARCHAR(32) NOT NULL,
  `subject_id` VARCHAR(128) NOT NULL,
  `usage_type` VARCHAR(64) NOT NULL,
  `included_quota` BIGINT NOT NULL DEFAULT 0,
  `used_quantity` BIGINT NOT NULL DEFAULT 0,
  `remaining_quantity` BIGINT NOT NULL DEFAULT 0,
  `billing_cycle` VARCHAR(64) NOT NULL DEFAULT 'default',
  `updated_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`subject_type`, `subject_id`, `usage_type`, `billing_cycle`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `usage_billing_replay_runs` (
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `run_key` VARCHAR(160) NOT NULL,
  `mode` VARCHAR(32) NOT NULL,
  `status` VARCHAR(32) NOT NULL,
  `started_at` DATETIME(3) NOT NULL,
  `finished_at` DATETIME(3) NULL,
  `processed_count` BIGINT UNSIGNED NOT NULL DEFAULT 0,
  `created_count` BIGINT UNSIGNED NOT NULL DEFAULT 0,
  `skipped_count` BIGINT UNSIGNED NOT NULL DEFAULT 0,
  `metadata` JSON NULL,
  `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `idx_usage_billing_replay_runs_key` (`run_key`),
  KEY `idx_usage_billing_replay_runs_status` (`status`, `started_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `identity_refresh_sessions` (
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `refresh_token_hash` CHAR(64) NOT NULL,
  `session_id` VARCHAR(128) NOT NULL,
  `legacy_user_id` BIGINT NOT NULL,
  `username` VARCHAR(255) NULL,
  `issued_at` DATETIME(3) NOT NULL,
  `expires_at` DATETIME(3) NOT NULL,
  `revoked_at` DATETIME(3) NULL,
  `replaced_by_hash` CHAR(64) NULL,
  `ip_hash` CHAR(64) NULL,
  `user_agent_hash` CHAR(64) NULL,
  `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `idx_identity_refresh_sessions_token_hash` (`refresh_token_hash`),
  KEY `idx_identity_refresh_sessions_legacy_user` (`legacy_user_id`, `expires_at`),
  KEY `idx_identity_refresh_sessions_session` (`session_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `account_lifecycle_operations` (
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `operation_key` VARCHAR(160) NOT NULL,
  `operation_type` VARCHAR(64) NOT NULL,
  `legacy_user_id` BIGINT NULL,
  `identity_user_id` VARCHAR(128) NULL,
  `username` VARCHAR(255) NULL,
  `email` VARCHAR(255) NULL,
  `status` VARCHAR(32) NOT NULL DEFAULT 'pending',
  `requested_at` DATETIME(3) NOT NULL,
  `completed_at` DATETIME(3) NULL,
  `failed_at` DATETIME(3) NULL,
  `error_code` VARCHAR(128) NULL,
  `metadata` JSON NULL,
  `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `idx_account_lifecycle_operations_key` (`operation_key`),
  KEY `idx_account_lifecycle_operations_legacy_user` (`legacy_user_id`, `requested_at`),
  KEY `idx_account_lifecycle_operations_type_status` (`operation_type`, `status`, `requested_at`),
  KEY `idx_account_lifecycle_operations_email` (`email`, `requested_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `invitation_quota_ledger` (
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `ledger_key` VARCHAR(160) NOT NULL,
  `invite_code` VARCHAR(128) NOT NULL,
  `legacy_user_id` BIGINT NULL,
  `delta` INT NOT NULL,
  `reason` VARCHAR(64) NOT NULL,
  `occurred_at` DATETIME(3) NOT NULL,
  `metadata` JSON NULL,
  `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `idx_invitation_quota_ledger_key` (`ledger_key`),
  KEY `idx_invitation_quota_ledger_invite_code` (`invite_code`, `occurred_at`),
  KEY `idx_invitation_quota_ledger_legacy_user` (`legacy_user_id`, `occurred_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `password_reset_challenges` (
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `challenge_key` VARCHAR(160) NOT NULL,
  `legacy_user_id` BIGINT NOT NULL,
  `email` VARCHAR(255) NOT NULL,
  `code_hash` CHAR(64) NOT NULL,
  `attempts` INT NOT NULL DEFAULT 0,
  `expires_at` DATETIME(3) NOT NULL,
  `locked_until` DATETIME(3) NULL,
  `consumed_at` DATETIME(3) NULL,
  `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `idx_password_reset_challenges_key` (`challenge_key`),
  KEY `idx_password_reset_challenges_email` (`email`, `created_at`),
  KEY `idx_password_reset_challenges_user` (`legacy_user_id`, `created_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `email_verification_challenges` (
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `challenge_key` VARCHAR(160) NOT NULL,
  `legacy_user_id` BIGINT NOT NULL,
  `email` VARCHAR(255) NOT NULL,
  `code_hash` CHAR(64) NOT NULL,
  `attempts` INT NOT NULL DEFAULT 0,
  `expires_at` DATETIME(3) NOT NULL,
  `locked_until` DATETIME(3) NULL,
  `consumed_at` DATETIME(3) NULL,
  `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `idx_email_verification_challenges_key` (`challenge_key`),
  KEY `idx_email_verification_challenges_email` (`email`, `created_at`),
  KEY `idx_email_verification_challenges_user` (`legacy_user_id`, `created_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `email_change_tokens` (
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `token_key` VARCHAR(160) NOT NULL,
  `legacy_user_id` BIGINT NOT NULL,
  `token_hash` CHAR(64) NOT NULL,
  `expires_at` DATETIME(3) NOT NULL,
  `consumed_at` DATETIME(3) NULL,
  `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `idx_email_change_tokens_key` (`token_key`),
  KEY `idx_email_change_tokens_user` (`legacy_user_id`, `created_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `identity_invitations` (
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `invite_code` VARCHAR(64) NOT NULL,
  `quota` INT UNSIGNED NOT NULL,
  `remaining` INT NOT NULL,
  `expires_at` BIGINT NOT NULL,
  `creator_legacy_user_id` BIGINT NULL,
  `creator_name` VARCHAR(255) NULL,
  `note` VARCHAR(1024) NULL,
  `legacy_created_at` BIGINT NOT NULL,
  `status` VARCHAR(32) NOT NULL DEFAULT 'active',
  `source` VARCHAR(64) NOT NULL DEFAULT 'legacy-redis',
  `imported_at` DATETIME(3) NULL,
  `last_seen_at` DATETIME(3) NULL,
  `deleted_at` DATETIME(3) NULL,
  `metadata` JSON NULL,
  `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `idx_identity_invitations_code` (`invite_code`),
  KEY `idx_identity_invitations_status_expires` (`status`, `expires_at`),
  KEY `idx_identity_invitations_creator` (`creator_legacy_user_id`, `legacy_created_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `invitation_email_challenges` (
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `challenge_key` VARCHAR(160) NOT NULL,
  `invite_code` VARCHAR(64) NOT NULL,
  `email` VARCHAR(255) NOT NULL,
  `code_hash` CHAR(64) NOT NULL,
  `attempts` INT NOT NULL DEFAULT 0,
  `expires_at` DATETIME(3) NOT NULL,
  `locked_until` DATETIME(3) NULL,
  `consumed_at` DATETIME(3) NULL,
  `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `idx_invitation_email_challenges_key` (`challenge_key`),
  KEY `idx_invitation_email_challenges_email` (`email`, `created_at`),
  KEY `idx_invitation_email_challenges_code` (`invite_code`, `created_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `identity_users` (
  `id` VARCHAR(128) NOT NULL,
  `legacy_user_id` BIGINT NULL,
  `keycloak_subject` VARCHAR(255) NULL,
  `username` VARCHAR(255) NULL,
  `email` VARCHAR(255) NULL,
  `status` VARCHAR(32) NOT NULL DEFAULT 'shadow',
  `source` VARCHAR(64) NOT NULL DEFAULT 'legacy-shadow',
  `metadata` JSON NULL,
  `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `idx_identity_users_legacy_user` (`legacy_user_id`),
  UNIQUE KEY `idx_identity_users_keycloak_subject` (`keycloak_subject`),
  KEY `idx_identity_users_username` (`username`),
  KEY `idx_identity_users_email` (`email`),
  KEY `idx_identity_users_status` (`status`, `updated_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `identity_subject_maps` (
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `identity_user_id` VARCHAR(128) NOT NULL,
  `subject_type` VARCHAR(64) NOT NULL,
  `subject_id` VARCHAR(255) NOT NULL,
  `source` VARCHAR(64) NOT NULL DEFAULT 'legacy-shadow',
  `status` VARCHAR(32) NOT NULL DEFAULT 'active',
  `metadata` JSON NULL,
  `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `idx_identity_subject_maps_subject` (`subject_type`, `subject_id`),
  KEY `idx_identity_subject_maps_identity_user` (`identity_user_id`, `status`),
  KEY `idx_identity_subject_maps_source` (`source`, `updated_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `identity_role_assignments_shadow` (
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `identity_user_id` VARCHAR(128) NULL,
  `legacy_user_id` BIGINT NULL,
  `role_name` VARCHAR(128) NOT NULL,
  `source` VARCHAR(64) NOT NULL DEFAULT 'yii-rbac',
  `status` VARCHAR(32) NOT NULL DEFAULT 'shadow',
  `observed_at` DATETIME(3) NOT NULL,
  `metadata` JSON NULL,
  `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `idx_identity_role_shadow_legacy_role` (`legacy_user_id`, `role_name`, `source`),
  KEY `idx_identity_role_shadow_identity_user` (`identity_user_id`, `status`),
  KEY `idx_identity_role_shadow_role` (`role_name`, `status`),
  KEY `idx_identity_role_shadow_observed` (`observed_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `identity_organization_memberships_shadow` (
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `identity_user_id` VARCHAR(128) NULL,
  `legacy_user_id` BIGINT NULL,
  `organization_id` BIGINT NOT NULL,
  `organization_role` VARCHAR(128) NULL,
  `source` VARCHAR(64) NOT NULL DEFAULT 'legacy-organization',
  `status` VARCHAR(32) NOT NULL DEFAULT 'shadow',
  `observed_at` DATETIME(3) NOT NULL,
  `metadata` JSON NULL,
  `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `idx_identity_org_shadow_legacy_org` (`legacy_user_id`, `organization_id`, `source`),
  KEY `idx_identity_org_shadow_identity_user` (`identity_user_id`, `status`),
  KEY `idx_identity_org_shadow_org` (`organization_id`, `status`),
  KEY `idx_identity_org_shadow_observed` (`observed_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `iam_reconciliation_runs` (
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `run_key` VARCHAR(160) NOT NULL,
  `scope` VARCHAR(64) NOT NULL,
  `mode` VARCHAR(32) NOT NULL DEFAULT 'shadow',
  `status` VARCHAR(32) NOT NULL,
  `started_at` DATETIME(3) NOT NULL,
  `finished_at` DATETIME(3) NULL,
  `sample_count` BIGINT UNSIGNED NOT NULL DEFAULT 0,
  `mismatch_count` BIGINT UNSIGNED NOT NULL DEFAULT 0,
  `p0_count` BIGINT UNSIGNED NOT NULL DEFAULT 0,
  `p1_count` BIGINT UNSIGNED NOT NULL DEFAULT 0,
  `metadata` JSON NULL,
  `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `idx_iam_reconciliation_runs_key` (`run_key`),
  KEY `idx_iam_reconciliation_runs_scope` (`scope`, `started_at`),
  KEY `idx_iam_reconciliation_runs_status` (`status`, `started_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `iam_reconciliation_items` (
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `run_key` VARCHAR(160) NOT NULL,
  `scope` VARCHAR(64) NOT NULL,
  `severity` VARCHAR(16) NOT NULL,
  `legacy_subject_type` VARCHAR(64) NULL,
  `legacy_subject_id` VARCHAR(255) NULL,
  `identity_subject_type` VARCHAR(64) NULL,
  `identity_subject_id` VARCHAR(255) NULL,
  `field_path` VARCHAR(255) NOT NULL,
  `legacy_value_hash` CHAR(64) NULL,
  `identity_value_hash` CHAR(64) NULL,
  `message` VARCHAR(1024) NULL,
  `metadata` JSON NULL,
  `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_iam_reconciliation_items_run` (`run_key`, `severity`),
  KEY `idx_iam_reconciliation_items_legacy` (`legacy_subject_type`, `legacy_subject_id`),
  KEY `idx_iam_reconciliation_items_identity` (`identity_subject_type`, `identity_subject_id`),
  KEY `idx_iam_reconciliation_items_scope` (`scope`, `created_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
