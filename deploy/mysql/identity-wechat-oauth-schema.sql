-- Identity-owned provider bindings and transient OAuth state. Apply after account/runtime schemas.
CREATE TABLE IF NOT EXISTS identity_wechat_identities (
  provider VARCHAR(64) COLLATE utf8mb4_bin NOT NULL, provider_app_id VARCHAR(191) COLLATE utf8mb4_bin NOT NULL, open_id VARCHAR(191) COLLATE utf8mb4_bin NOT NULL,
  user_id BIGINT NULL, union_id VARCHAR(191) COLLATE utf8mb4_bin NULL, profile_json JSON NULL, signup_token_hash CHAR(64) NULL,
  created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  updated_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
  PRIMARY KEY (provider,provider_app_id,open_id), KEY provider_union (union_id), KEY provider_user (user_id), KEY provider_signup (signup_token_hash)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
CREATE TABLE IF NOT EXISTS identity_auth_subject_maps (
  auth_user_id VARCHAR(128) NOT NULL, user_id BIGINT NOT NULL, status VARCHAR(32) NOT NULL DEFAULT 'active',
  PRIMARY KEY (auth_user_id), KEY auth_canonical_user (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
CREATE TABLE IF NOT EXISTS identity_wechat_oauth_codes (
  code_hash VARCHAR(191) NOT NULL, client_id VARCHAR(128) NOT NULL, user_id BIGINT NOT NULL,
  redirect_uri TEXT NOT NULL, code_challenge VARCHAR(191) NULL, code_challenge_method VARCHAR(16) NULL,
  scopes_json JSON NOT NULL, expires_at DATETIME(3) NOT NULL, consumed_at DATETIME(3) NULL,
  created_at DATETIME(3) NOT NULL, PRIMARY KEY (code_hash)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
CREATE TABLE IF NOT EXISTS identity_oauth_session_bindings (
  session_id VARCHAR(128) NOT NULL, client_id VARCHAR(128) NOT NULL, scopes_json JSON NOT NULL,
  legacy_subject VARCHAR(128) NULL, PRIMARY KEY (session_id), KEY oauth_client (client_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
CREATE TABLE IF NOT EXISTS identity_wechat_import_runs (
  import_key VARCHAR(160) NOT NULL, source_database VARCHAR(255) NOT NULL, row_counts JSON NOT NULL,
  completed_at DATETIME(3) NOT NULL, PRIMARY KEY (import_key)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
