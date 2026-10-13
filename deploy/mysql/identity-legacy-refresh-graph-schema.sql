-- Optional offline graph migration. Apply explicitly while sealed/staging.
-- Runtime never creates these tables. All original millisecond deadlines persist.
CREATE TABLE IF NOT EXISTS identity_legacy_refresh_graph_families (
  family_key CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  protocol VARCHAR(8) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  source_family_id CHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  legacy_user_id BIGINT NOT NULL,
  native_session_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  source_json JSON NOT NULL,
  source_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  account_snapshot_json JSON NOT NULL,
  account_snapshot_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  target_cutoff_ms BIGINT NULL,
  current_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
  revoked_at DATETIME(3) NULL,
  PRIMARY KEY (family_key),
  UNIQUE KEY graph_native_session (native_session_id),
  KEY graph_family_user (legacy_user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
CREATE TABLE IF NOT EXISTS identity_legacy_refresh_graph_credentials (
  credential_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  family_key CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  legacy_user_id BIGINT NOT NULL,
  origin VARCHAR(8) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  source_json JSON NOT NULL,
  source_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  state VARCHAR(16) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  successor_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
  consumed_consumer VARCHAR(8) CHARACTER SET ascii COLLATE ascii_bin NULL,
  revoked_at DATETIME(3) NULL,
  PRIMARY KEY (credential_hash),
  KEY graph_credential_family (family_key),
  KEY graph_credential_user (legacy_user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
CREATE TABLE IF NOT EXISTS identity_legacy_refresh_graph_replays (
  replay_key CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  predecessor_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  successor_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  family_key CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  legacy_user_id BIGINT NOT NULL,
  source_json JSON NOT NULL,
  origin VARCHAR(8) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  response_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  access_token_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  encrypted_response MEDIUMTEXT CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  PRIMARY KEY (replay_key),
  KEY graph_replay_predecessor (predecessor_hash),
  KEY graph_replay_family (family_key),
  KEY graph_replay_access (access_token_hash)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
