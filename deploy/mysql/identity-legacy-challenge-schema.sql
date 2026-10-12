-- Exact independent Redis attempt/rate windows, retained only for final cutover.
CREATE TABLE IF NOT EXISTS identity_legacy_challenge_limits (
  kind VARCHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  email VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
  attempts INT NOT NULL DEFAULT 0,
  attempts_expires_at DATETIME(3) NULL,
  rate_limit_until DATETIME(3) NULL,
  PRIMARY KEY (kind, email)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

-- Credential-free ledger prevents a repeated/stale manifest from resetting state.
CREATE TABLE IF NOT EXISTS identity_legacy_challenge_imports (
  source_key_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  payload_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  imported_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  PRIMARY KEY (source_key_hash)
) ENGINE=InnoDB DEFAULT CHARSET=ascii COLLATE=ascii_bin;

-- A Redis SETEX deadline can carry milliseconds; keep its inferred issue instant.
ALTER TABLE email_change_tokens MODIFY created_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3);
