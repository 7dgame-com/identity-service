CREATE DATABASE IF NOT EXISTS `xrugc_identity` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE DATABASE IF NOT EXISTS `xrugc_keycloak` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

CREATE USER IF NOT EXISTS 'identity'@'%' IDENTIFIED BY 'identity_password';
CREATE USER IF NOT EXISTS 'keycloak'@'%' IDENTIFIED BY 'keycloak_password';

GRANT ALL PRIVILEGES ON `xrugc_identity`.* TO 'identity'@'%';
GRANT ALL PRIVILEGES ON `xrugc_keycloak`.* TO 'keycloak'@'%';

FLUSH PRIVILEGES;

