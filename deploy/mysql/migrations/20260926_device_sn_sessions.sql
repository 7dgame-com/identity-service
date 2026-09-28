-- Repeatable upgrade for installations predating device-SN sessions. Run against IDENTITY_DB.
SET @device_sn_auth_method_ddl = IF(
  (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE()
    AND TABLE_NAME = 'identity_refresh_sessions' AND COLUMN_NAME = 'auth_method') = 0,
  'ALTER TABLE identity_refresh_sessions ADD COLUMN auth_method VARCHAR(32) NULL', 'SELECT 1');
PREPARE device_sn_migration FROM @device_sn_auth_method_ddl;
EXECUTE device_sn_migration;
DEALLOCATE PREPARE device_sn_migration;

SET @device_sn_id_ddl = IF(
  (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE()
    AND TABLE_NAME = 'identity_refresh_sessions' AND COLUMN_NAME = 'device_sn_id') = 0,
  'ALTER TABLE identity_refresh_sessions ADD COLUMN device_sn_id INT NULL', 'SELECT 1');
PREPARE device_sn_migration FROM @device_sn_id_ddl;
EXECUTE device_sn_migration;
DEALLOCATE PREPARE device_sn_migration;
