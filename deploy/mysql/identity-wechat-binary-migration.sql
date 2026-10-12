-- Upgrade an existing PRIVATE Identity DB before enabling native traffic.
-- Do not apply to the legacy business DB. DDL must run outside an account import transaction.
-- No IDs, proof digests, expiry values or account mappings are changed.
ALTER TABLE user
  MODIFY wx_openid VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NULL;
ALTER TABLE identity_wechat_identities
  MODIFY provider VARCHAR(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
  MODIFY provider_app_id VARCHAR(191) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
  MODIFY open_id VARCHAR(191) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
  MODIFY union_id VARCHAR(191) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NULL;
ALTER TABLE wechat
  MODIFY openid VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
  MODIFY unionid VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NULL,
  MODIFY token VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NULL;
ALTER TABLE identity_wechat_scenes
  MODIFY provider_app_id VARCHAR(128) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NULL,
  MODIFY open_id VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NULL;
