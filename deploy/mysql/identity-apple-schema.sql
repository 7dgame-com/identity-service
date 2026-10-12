-- Apply in the private Identity database. Apple subjects are scoped to exact audiences.
CREATE TABLE IF NOT EXISTS identity_apple_identities (
  provider_app_id VARCHAR(191) NOT NULL, subject VARCHAR(255) NOT NULL, user_id BIGINT NULL,
  email VARCHAR(255) NULL, email_verified TINYINT NOT NULL DEFAULT 0,
  first_name VARCHAR(255) NULL, last_name VARCHAR(255) NULL, private_email TINYINT NULL,
  created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  updated_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
  PRIMARY KEY(provider_app_id,subject), KEY apple_user(user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
CREATE TABLE IF NOT EXISTS identity_apple_challenges (
  token_hash CHAR(64) NOT NULL PRIMARY KEY, provider_app_id VARCHAR(191) NOT NULL, subject VARCHAR(255) NOT NULL,
  expires_at DATETIME(3) NOT NULL, consumed_at DATETIME(3) NULL, operation_hash CHAR(64) NULL, user_id BIGINT NULL,
  created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3), KEY apple_challenge_expiry(expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
CREATE TABLE IF NOT EXISTS identity_apple_import_runs (
  import_key VARCHAR(160) NOT NULL PRIMARY KEY, source_database VARCHAR(255) NOT NULL, mapping_hash CHAR(64) NOT NULL,
  row_count BIGINT NOT NULL, completed_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
