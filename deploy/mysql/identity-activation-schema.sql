-- Optional explicit activation only. Install while native HTTP is stopped/sealed.
-- No seed, grant, authority change or account mutation.
CREATE TABLE IF NOT EXISTS identity_activation_receipt (
  id TINYINT NOT NULL PRIMARY KEY,
  allocator_manifest_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  compiled_revision CHAR(40) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  request_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  decision_at DATETIME(3) NOT NULL,
  deadline DATETIME(3) NOT NULL,
  created_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
