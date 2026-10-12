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
-- Standard OIDC grants have their own namespace; WeChat OAuth bindings remain
-- in identity_oauth_session_bindings. Both prevent generic refresh elevation.
CREATE TABLE IF NOT EXISTS identity_oidc_session_bindings (
  session_id VARCHAR(128) NOT NULL PRIMARY KEY,
  client_id VARCHAR(128) NOT NULL,
  scopes_json JSON NOT NULL,
  KEY identity_oidc_client (client_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

-- Reviewed Yii2 Redis ActiveRecord credentials only. No synthetic issued_at or expiry.
CREATE TABLE IF NOT EXISTS identity_legacy_refresh_credentials (
  credential_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  source_record_id BIGINT UNSIGNED NOT NULL,
  legacy_user_id BIGINT NOT NULL,
  source_kind VARCHAR(16) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  source_revision CHAR(40) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  source_fields_json JSON NOT NULL,
  key_encoding VARCHAR(16) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  a1_compatible BOOLEAN NOT NULL,
  server_compatible BOOLEAN NOT NULL,
  snapshot_at DATETIME(3) NOT NULL,
  account_fingerprint CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  expires_at DATETIME(3) NULL,
  source_revoked_at DATETIME(3) NULL,
  revoked_at DATETIME(3) NULL,
  redeemed_at DATETIME(3) NULL,
  redeemed_consumer VARCHAR(16) CHARACTER SET ascii COLLATE ascii_bin NULL,
  session_id VARCHAR(128) NULL,
  successor_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
  request_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
  encrypted_response TEXT NULL,
  replay_expires_at DATETIME(3) NULL,
  PRIMARY KEY (credential_hash),
  UNIQUE KEY legacy_ar_record (source_record_id),
  KEY legacy_ar_user (legacy_user_id),
  KEY legacy_ar_session (session_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

-- Reviewed ownerless SQL signup bearers. NULL expiry preserves absent source expiry.
CREATE TABLE IF NOT EXISTS identity_legacy_wechat_signup_credentials (
  credential_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  source_database VARCHAR(255) NOT NULL,
  source_record_id BIGINT UNSIGNED NOT NULL,
  source_revision CHAR(40) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  manifest_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  evidence_json JSON NOT NULL,
  provider VARCHAR(64) COLLATE utf8mb4_bin NOT NULL,
  provider_app_id VARCHAR(191) COLLATE utf8mb4_bin NOT NULL,
  open_id VARCHAR(191) COLLATE utf8mb4_bin NOT NULL,
  expires_at DATETIME(3) NULL,
  source_revoked_at DATETIME(3) NULL,
  revoked_at DATETIME(3) NULL,
  consumed_at DATETIME(3) NULL,
  consumed_user_id BIGINT NULL,
  consumed_action VARCHAR(16) CHARACTER SET ascii COLLATE ascii_bin NULL,
  account_fingerprint CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
  session_id VARCHAR(128) NULL,
  successor_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
  request_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
  encrypted_response TEXT NULL,
  replay_expires_at DATETIME(3) NULL,
  PRIMARY KEY (credential_hash),
  UNIQUE KEY legacy_signup_source (source_database,source_record_id),
  UNIQUE KEY legacy_signup_provider (provider,provider_app_id,open_id),
  KEY legacy_signup_user (consumed_user_id),
  KEY legacy_signup_session (session_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
