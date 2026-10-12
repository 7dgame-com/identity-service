-- Opaque legacy PHP Redis reset tokens retain their original expiry during cutover.
-- Store only SHA-256 digests of the existing 32-character random bearer tokens.
CREATE TABLE IF NOT EXISTS identity_password_reset_tokens (
  token_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  legacy_user_id BIGINT NOT NULL,
  email VARCHAR(255) NOT NULL,
  issued_at DATETIME(3) NOT NULL,
  expires_at DATETIME(3) NOT NULL,
  consumed_at DATETIME(3) NULL,
  PRIMARY KEY (token_hash),
  KEY idx_identity_password_reset_tokens_user (legacy_user_id, expires_at),
  KEY idx_identity_password_reset_tokens_email (email, expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
