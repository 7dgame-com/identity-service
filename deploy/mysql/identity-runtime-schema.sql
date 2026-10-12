-- Additive runtime tables. Apply to IDENTITY_DB_NAME, never the platform database.
CREATE TABLE IF NOT EXISTS identity_event_clock (id TINYINT NOT NULL PRIMARY KEY) ENGINE=InnoDB;
INSERT IGNORE INTO identity_event_clock (id) VALUES (1);
CREATE TABLE IF NOT EXISTS identity_migration_control (
  id TINYINT NOT NULL PRIMARY KEY, authority ENUM('staging','identity') NOT NULL DEFAULT 'staging',
  activated_at DATETIME(3) NULL
) ENGINE=InnoDB;
INSERT IGNORE INTO identity_migration_control (id) VALUES (1);
CREATE TABLE IF NOT EXISTS identity_organization_name_locks (name VARCHAR(64) NOT NULL PRIMARY KEY)
ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
CREATE TABLE IF NOT EXISTS identity_migration_rows (
  table_name VARCHAR(64) NOT NULL, key_hash CHAR(64) NOT NULL, key_json JSON NOT NULL,
  columns_json JSON NOT NULL, source_hash CHAR(64) NULL, target_hash CHAR(64) NULL,
  PRIMARY KEY (table_name,key_hash)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
CREATE TABLE IF NOT EXISTS identity_subject_events (
  id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
  user_id BIGINT NOT NULL, version BIGINT NOT NULL,
  created_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  KEY identity_subject_events_user (user_id,id)
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS identity_native_operations (
  operation_key CHAR(64) PRIMARY KEY, request_hash CHAR(64) NOT NULL,
  response JSON NULL, created_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3)
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS identity_profile_avatars (
  user_id BIGINT PRIMARY KEY, avatar_id BIGINT NULL
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS identity_legacy_link_email_limits (
  email VARCHAR(255) NOT NULL, kind VARCHAR(16) NOT NULL, last_sent_at BIGINT NOT NULL,
  PRIMARY KEY(email,kind)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
CREATE TABLE IF NOT EXISTS identity_legacy_invitation_days (day DATE NOT NULL PRIMARY KEY) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS identity_legacy_trial_claims (
  claim_key CHAR(64) NOT NULL PRIMARY KEY, invitation_id BIGINT NULL
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS identity_user_revocations (
  user_id BIGINT PRIMARY KEY, revoked_before DATETIME(3) NOT NULL
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS identity_refresh_replays (
  predecessor_hash CHAR(64) PRIMARY KEY, successor_hash CHAR(64) NOT NULL,
  request_hash CHAR(64) NULL, encrypted_response TEXT NOT NULL,
  created_at DATETIME(3) NOT NULL, expires_at DATETIME(3) NOT NULL,
  KEY idx_identity_refresh_replay_expiry (expires_at)
) ENGINE=InnoDB;
