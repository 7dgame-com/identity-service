-- Private Identity state. Apply before enabling independent HTTP traffic.
CREATE TABLE IF NOT EXISTS identity_login_codes (
  code_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL PRIMARY KEY,
  user_id BIGINT NOT NULL,
  issued_at BIGINT UNSIGNED NOT NULL,
  expires_at BIGINT UNSIGNED NOT NULL,
  context_json JSON NULL,
  KEY idx_login_code_user_issue (user_id, issued_at),
  KEY idx_login_code_expiry (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS identity_wechat_scenes (
  scene_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL PRIMARY KEY,
  expires_at BIGINT UNSIGNED NOT NULL,
  provider_app_id VARCHAR(128) COLLATE utf8mb4_bin NULL,
  open_id VARCHAR(255) COLLATE utf8mb4_bin NULL,
  user_id BIGINT NULL,
  signup_token_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
  profile_json JSON NULL,
  KEY idx_wechat_scene_expiry (expires_at),
  KEY idx_wechat_scene_signup (signup_token_hash)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
