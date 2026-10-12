-- Run against IDENTITY_DB_NAME, after init.sql. No business balances or file FK.
CREATE TABLE IF NOT EXISTS `user` (
  id BIGINT NOT NULL AUTO_INCREMENT,
  username VARCHAR(255) NULL,
  auth_key VARCHAR(32) NULL,
  password_hash VARCHAR(255) NULL,
  password_reset_token VARCHAR(255) NULL,
  verification_token VARCHAR(255) NULL,
  email VARCHAR(255) NULL,
  status SMALLINT NOT NULL DEFAULT 10,
  nickname VARCHAR(255) NULL,
  wx_openid VARCHAR(255) COLLATE utf8mb4_bin NULL,
  email_verified_at BIGINT NULL,
  created_at BIGINT NULL,
  updated_at BIGINT NULL,
  deleted_at BIGINT NULL,
  PRIMARY KEY (id), UNIQUE KEY account_username (username), UNIQUE KEY account_email (email)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
CREATE TABLE IF NOT EXISTS user_info (
  id BIGINT NOT NULL AUTO_INCREMENT,
  user_id BIGINT NOT NULL,
  info JSON NULL,
  PRIMARY KEY (id), UNIQUE KEY account_profile_user (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
-- Every legacy identity-profile row is retained separately from the one-row
-- runtime projection. Business balances remain in the business database.
CREATE TABLE IF NOT EXISTS identity_legacy_profile_rows (
  id BIGINT NOT NULL PRIMARY KEY, user_id BIGINT NOT NULL,
  payload_json JSON NOT NULL, selected_profile_id BIGINT NOT NULL,
  is_present TINYINT NOT NULL DEFAULT 1,
  KEY legacy_profile_owner (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
CREATE TABLE IF NOT EXISTS identity_legacy_profile_history (
  id BIGINT NOT NULL, payload_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  payload_json JSON NOT NULL, source_database VARCHAR(255) NOT NULL,
  observed_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  PRIMARY KEY (id,payload_hash)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
CREATE TABLE IF NOT EXISTS auth_rule (
  name VARCHAR(64) NOT NULL, data BLOB NULL, created_at BIGINT NULL, updated_at BIGINT NULL,
  PRIMARY KEY (name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
CREATE TABLE IF NOT EXISTS auth_item (
  name VARCHAR(128) NOT NULL, type SMALLINT NOT NULL, description TEXT NULL,
  rule_name VARCHAR(64) NULL, data BLOB NULL, created_at BIGINT NULL, updated_at BIGINT NULL,
  PRIMARY KEY (name), KEY account_auth_item_type (type)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
CREATE TABLE IF NOT EXISTS auth_item_child (
  parent VARCHAR(128) NOT NULL, child VARCHAR(128) NOT NULL, PRIMARY KEY (parent, child)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
CREATE TABLE IF NOT EXISTS auth_assignment (
  item_name VARCHAR(128) NOT NULL, user_id VARCHAR(64) NOT NULL, created_at BIGINT NULL,
  PRIMARY KEY (item_name, user_id), KEY account_assignment_user (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
CREATE TABLE IF NOT EXISTS organization (
  id BIGINT NOT NULL AUTO_INCREMENT, name VARCHAR(255) NOT NULL, title VARCHAR(255) NOT NULL,
  created_at BIGINT NULL, updated_at BIGINT NULL, PRIMARY KEY (id), KEY account_organization_name (name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
CREATE TABLE IF NOT EXISTS user_organization (
  user_id BIGINT NOT NULL, organization_id BIGINT NOT NULL,
  PRIMARY KEY (user_id, organization_id), KEY account_membership_org (organization_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
CREATE TABLE IF NOT EXISTS wechat (
  id BIGINT NOT NULL AUTO_INCREMENT, openid VARCHAR(255) COLLATE utf8mb4_bin NOT NULL, unionid VARCHAR(255) COLLATE utf8mb4_bin NULL,
  user_id BIGINT NULL, token VARCHAR(255) COLLATE utf8mb4_bin NULL, created_at DATETIME(3) NULL, updated_at DATETIME(3) NULL,
  PRIMARY KEY (id), UNIQUE KEY account_wechat_openid (openid), UNIQUE KEY account_wechat_unionid (unionid),
  UNIQUE KEY account_wechat_token (token), KEY account_wechat_user (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
CREATE TABLE IF NOT EXISTS invitation_record (
  id BIGINT NOT NULL AUTO_INCREMENT, invite_code VARCHAR(64) NOT NULL, inviter_id BIGINT NOT NULL,
  invitee_id BIGINT NOT NULL, created_at BIGINT NOT NULL, PRIMARY KEY (id),
  UNIQUE KEY account_invitation_invitee (invitee_id), KEY account_invitation_code (invite_code)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
-- Historical emailed invitations, distinct from Redis quota invitations.
CREATE TABLE IF NOT EXISTS invitation (
  id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY, code VARCHAR(255) NULL UNIQUE,
  sender_id BIGINT NOT NULL, recipient_id BIGINT NULL, used TINYINT NULL,
  auth_item_name VARCHAR(255) NULL, create_at DATETIME NULL,
  KEY idx_invitation_recipient (recipient_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
CREATE TABLE IF NOT EXISTS identity_account_registration_requests (
  operation_key VARCHAR(160) NOT NULL, user_id BIGINT NULL,
  request_hash CHAR(64) NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, PRIMARY KEY (operation_key)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
CREATE TABLE IF NOT EXISTS identity_registration_email_limits (
  email VARCHAR(255) NOT NULL, last_sent_at BIGINT NOT NULL DEFAULT 0, PRIMARY KEY (email)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
CREATE TABLE IF NOT EXISTS identity_account_import_runs (
  import_key VARCHAR(160) NOT NULL, source_database VARCHAR(255) NOT NULL,
  row_counts JSON NOT NULL, completed_at DATETIME(3) NOT NULL, PRIMARY KEY (import_key)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
INSERT IGNORE INTO auth_item (name, type, description) VALUES
  ('root', 1, 'root'), ('admin', 1, 'admin'), ('manager', 1, 'manager'), ('user', 1, 'user');
CREATE TABLE IF NOT EXISTS identity_account_password_requests (
  operation_key VARCHAR(160) NOT NULL, user_id BIGINT NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, PRIMARY KEY (operation_key)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
