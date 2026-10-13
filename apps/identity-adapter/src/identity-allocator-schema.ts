export const allocatorSchema = `CREATE TABLE IF NOT EXISTS identity_migration_allocator_state (
 id TINYINT NOT NULL PRIMARY KEY,
 state ENUM('pending','ready') NOT NULL DEFAULT 'pending',
 manifest_json JSON NULL,
 manifest_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
 finalized_at DATETIME(3) NULL,
 updated_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin`;
